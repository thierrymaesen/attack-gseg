"""BM25 retrieval engine for the ATT&CK knowledge graph.

This module loads the graph and text index produced by Sprint 2
(``build_graph``), builds a BM25 index over technique nodes, and exposes
a search interface that returns ranked techniques together with their
related mitigations.

Usage:
    poetry run python -m gseg.retrieve --query "process injection" --top-k 5
    poetry run python -m gseg.retrieve --query "lateral movement ssh" --top-k 3 --show-mitigations
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx
from rank_bm25 import BM25Okapi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_DATA_DIR: Path = Path("data")
DEFAULT_GRAPH_PATH: Path = DEFAULT_DATA_DIR / "attack_graph.gpickle"
DEFAULT_TEXT_INDEX_PATH: Path = DEFAULT_DATA_DIR / "text_index.json"
DEFAULT_TOP_K: int = 5

TOKEN_PATTERN: str = r"[A-Za-z0-9_\-\.]+"

STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "of",
        "to",
        "a",
        "an",
        "in",
        "for",
        "on",
        "with",
        "is",
        "it",
        "or",
        "by",
        "be",
        "as",
        "at",
        "from",
        "this",
        "that",
        "are",
        "was",
        "can",
        "may",
        "not",
    }
)

logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def normalize_text(text: str) -> str:
    """Lowercase, collapse whitespace, and strip a text string."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def tokenize(text: str) -> List[str]:
    """Tokenize text into a filtered list of terms."""
    raw_tokens: List[str] = re.findall(TOKEN_PATTERN, normalize_text(text))
    return [t for t in raw_tokens if len(t) >= 2 and t not in STOPWORDS]


def load_text_index(path: Path) -> Dict[str, str]:
    """Load the text index JSON produced by ``build_graph``.

    Args:
        path: Path to the ``text_index.json`` file.

    Returns:
        Dictionary mapping node IDs to normalised text strings.
    """
    if not path.exists():
        raise FileNotFoundError(f"Text index file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data: Any = json.load(fh)

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}, got {type(data).__name__}")

    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(f"Text index must map str -> str; invalid entry for key {key!r}")

    logger.info("Loaded text index with %d entries from %s", len(data), path)
    return data


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TechniqueHit:
    """A single ranked result from a BM25 search."""

    technique_id: str
    name: str
    tactics: List[str]
    url: Optional[str]
    bm25_score: float


# ---------------------------------------------------------------------------
# Retriever
# ---------------------------------------------------------------------------


class RetrieverBM25:
    """BM25-based retriever over ATT&CK technique nodes.

    Args:
        graph_path: Path to the pickled NetworkX DiGraph.
        text_index_path: Path to the ``text_index.json`` file.
    """

    def __init__(
        self,
        graph_path: Path = DEFAULT_GRAPH_PATH,
        text_index_path: Path = DEFAULT_TEXT_INDEX_PATH,
    ) -> None:
        if not graph_path.exists():
            raise FileNotFoundError(f"Graph file not found: {graph_path}")

        logger.info("Loading graph from %s ...", graph_path)
        with open(graph_path, "rb") as fh:
            self.graph: nx.DiGraph = pickle.load(fh)

        logger.info(
            "Graph loaded -- %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

        self.text_index: Dict[str, str] = load_text_index(text_index_path)

        self.technique_ids: List[str] = []
        for node_id, attrs in self.graph.nodes(data=True):
            node_type: str | None = attrs.get("type")
            if node_type is None:
                logger.warning("Node %s has no 'type' attribute -- skipping", node_id)
                continue
            if node_type == "technique":
                self.technique_ids.append(node_id)

        if not self.technique_ids:
            raise ValueError(
                "No technique nodes found in the graph. "
                "Ensure build_graph was executed successfully."
            )

        logger.info("Indexed %d technique nodes for BM25", len(self.technique_ids))

        corpus_tokens: List[List[str]] = [
            tokenize(self.text_index.get(tech_id, "")) for tech_id in self.technique_ids
        ]
        self._bm25: BM25Okapi = BM25Okapi(corpus_tokens)

    def get_node_attr(self, node_id: str, key: str, default: Any = None) -> Any:
        """Safely read an attribute from a graph node."""
        if node_id not in self.graph:
            return default
        return self.graph.nodes[node_id].get(key, default)

    def search(self, query: str, top_k: int = DEFAULT_TOP_K) -> List[TechniqueHit]:
        """Run a BM25 search over technique nodes."""
        if not query or not query.strip():
            return []

        query_tokens: List[str] = tokenize(query)
        if not query_tokens:
            logger.debug("Query produced no tokens after filtering: %r", query)
            return []

        scores = self._bm25.get_scores(query_tokens)
        ranked_indices: List[int] = sorted(
            range(len(scores)), key=lambda i: scores[i], reverse=True
        )[:top_k]

        hits: List[TechniqueHit] = []
        for idx in ranked_indices:
            tech_id: str = self.technique_ids[idx]
            score: float = float(scores[idx])
            if score <= 0.0:
                continue
            hits.append(
                TechniqueHit(
                    technique_id=tech_id,
                    name=self.get_node_attr(tech_id, "name", ""),
                    tactics=self.get_node_attr(tech_id, "tactics", []),
                    url=self.get_node_attr(tech_id, "url"),
                    bm25_score=round(score, 4),
                )
            )
        return hits

    def get_mitigations(self, technique_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Return mitigations linked to a technique via the knowledge graph."""
        if technique_id not in self.graph:
            logger.warning("Technique %s not found in graph", technique_id)
            return []

        mitigations: List[Dict[str, Any]] = []
        for predecessor in self.graph.predecessors(technique_id):
            node_type: str | None = self.graph.nodes[predecessor].get("type")
            if node_type != "mitigation":
                continue
            attrs: Dict[str, Any] = self.graph.nodes[predecessor]
            description: str = attrs.get("description", "")
            if len(description) > 300:
                description = description[:297] + "..."
            mitigations.append(
                {
                    "mitigation_id": predecessor,
                    "name": attrs.get("name", ""),
                    "description": description,
                    "url": attrs.get("url", ""),
                }
            )

        mitigations.sort(key=lambda m: m["name"])
        return mitigations[:limit]

    def explain_query(self, query: str) -> Dict[str, Any]:
        """Return debug information about how a query is processed."""
        normalized: str = normalize_text(query)
        tokens: List[str] = tokenize(query)
        return {
            "normalized_query": normalized,
            "tokens": tokens,
            "token_count": len(tokens),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> None:
    """Set up root logging format and level."""
    level: int = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    """CLI entry-point: search ATT&CK techniques via BM25 retrieval."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="BM25 retrieval over ATT&CK technique knowledge graph.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Base data directory (overrides default graph and index paths)",
    )
    parser.add_argument(
        "--graph-path",
        type=Path,
        default=None,
        help="Explicit path to the graph gpickle file",
    )
    parser.add_argument(
        "--text-index-path",
        type=Path,
        default=None,
        help="Explicit path to the text index JSON file",
    )
    parser.add_argument("--query", type=str, required=True, help="Search query string")
    parser.add_argument(
        "--top-k", type=int, default=DEFAULT_TOP_K, help="Number of results to return"
    )
    parser.add_argument(
        "--show-mitigations", action="store_true", help="Display mitigations for each technique hit"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args: argparse.Namespace = parser.parse_args()
    _configure_logging(args.verbose)

    graph_path: Path = DEFAULT_GRAPH_PATH
    text_index_path: Path = DEFAULT_TEXT_INDEX_PATH
    if args.data_dir is not None:
        graph_path = args.data_dir / "attack_graph.gpickle"
        text_index_path = args.data_dir / "text_index.json"
    if args.graph_path is not None:
        graph_path = args.graph_path
    if args.text_index_path is not None:
        text_index_path = args.text_index_path

    try:
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=graph_path,
            text_index_path=text_index_path,
        )

        query_info: Dict[str, Any] = retriever.explain_query(args.query)
        sep: str = "=" * 55
        print(f"\n{sep}")
        print("  BM25 Retrieval -- ATT&CK Techniques")
        print(sep)
        print(f"\n  Query       : {args.query}")
        print(f"  Tokens      : {query_info['tokens']}")
        print(f"  Token count : {query_info['token_count']}")
        print(f"  Top-k       : {args.top_k}")

        hits: List[TechniqueHit] = retriever.search(args.query, top_k=args.top_k)

        if not hits:
            print("\n  No matching techniques found.\n")
            print(sep)
            return

        print(f"\n  Results ({len(hits)}):\n")
        for rank, hit in enumerate(hits, start=1):
            tactics_str: str = ", ".join(hit.tactics) if hit.tactics else "n/a"
            print(
                f"  {rank}) {hit.technique_id} - {hit.name}"
                f" | score={hit.bm25_score:.2f}"
                f" | tactics=[{tactics_str}]"
            )
            if args.show_mitigations:
                mitigations: List[Dict[str, Any]] = retriever.get_mitigations(
                    hit.technique_id, limit=5
                )
                if mitigations:
                    for mit in mitigations:
                        print(f"       -> {mit['mitigation_id']} - {mit['name']}")
                else:
                    print("       (no mitigations)")
        print(f"\n{sep}\n")

    except FileNotFoundError as exc:
        logger.error("Missing file: %s", exc)
        sys.exit(1)
    except ValueError as exc:
        logger.error("Validation error: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during retrieval: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
