"""Module for building ATT&CK knowledge graph from JSON data.

This module constructs a directed graph (NetworkX DiGraph) from the structured
JSON files produced by Sprint 1 (techniques, mitigations, relations), builds
a text index for downstream retrieval, computes graph statistics, and saves
all artefacts to disk.

Usage:
    poetry run python -m gseg.build_graph
    poetry run python -m gseg.build_graph --data-dir data --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import networkx as nx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_DATA_DIR: Path = Path("data")
TECHNIQUES_FILE: str = "techniques.json"
MITIGATIONS_FILE: str = "mitigations.json"
RELATIONS_FILE: str = "relations.json"
GRAPH_OUTPUT: str = "attack_graph.gpickle"
TEXT_INDEX_OUTPUT: str = "text_index.json"

REQUIRED_TECHNIQUE_KEYS: set[str] = {"technique_id", "name", "description", "tactics", "url"}
REQUIRED_MITIGATION_KEYS: set[str] = {"mitigation_id", "name", "description", "url"}
REQUIRED_RELATION_KEYS: set[str] = {"technique_id", "mitigation_id"}

logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JSON loader
# ---------------------------------------------------------------------------


def load_json(file_path: Path) -> List[Dict[str, Any]]:
    """Load a JSON file and return its contents as a list of dicts.

    Args:
        file_path: Path to the JSON file to load.

    Returns:
        Parsed list of dictionaries from the JSON file.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    if not file_path.exists():
        logger.error("File not found: %s", file_path)
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as fh:
        data: Any = json.load(fh)

    if not isinstance(data, list):
        logger.error("Expected a JSON array in %s, got %s", file_path, type(data).__name__)
        raise ValueError(f"Expected a JSON array in {file_path}")

    logger.info("Loaded %d entries from %s", len(data), file_path)
    return data


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph(
    techniques: List[Dict[str, Any]],
    mitigations: List[Dict[str, Any]],
    relations: List[Dict[str, str]],
) -> nx.DiGraph:
    """Build a directed graph from techniques, mitigations, and relations.

    Nodes are created for each technique and mitigation.  Directed edges run
    from mitigation -> technique with a ``relationship="mitigates"`` attribute.

    Args:
        techniques: List of technique dicts (from techniques.json).
        mitigations: List of mitigation dicts (from mitigations.json).
        relations: List of relation dicts (from relations.json).

    Returns:
        A populated ``nx.DiGraph`` instance.
    """
    graph: nx.DiGraph = nx.DiGraph()

    # --- technique nodes ---
    technique_count: int = 0
    for tech in techniques:
        missing: set[str] = REQUIRED_TECHNIQUE_KEYS - tech.keys()
        if missing:
            logger.warning(
                "Technique entry missing keys %s -- skipping: %s",
                missing,
                tech.get("technique_id", "unknown"),
            )
            continue

        graph.add_node(
            tech["technique_id"],
            type="technique",
            name=tech["name"],
            description=tech["description"],
            tactics=tech.get("tactics", []),
            url=tech.get("url", ""),
        )
        technique_count += 1

    # --- mitigation nodes ---
    mitigation_count: int = 0
    for mit in mitigations:
        missing = REQUIRED_MITIGATION_KEYS - mit.keys()
        if missing:
            logger.warning(
                "Mitigation entry missing keys %s -- skipping: %s",
                missing,
                mit.get("mitigation_id", "unknown"),
            )
            continue

        graph.add_node(
            mit["mitigation_id"],
            type="mitigation",
            name=mit["name"],
            description=mit["description"],
            url=mit.get("url", ""),
        )
        mitigation_count += 1

    # --- edges (mitigation -> technique) ---
    edge_count: int = 0
    for rel in relations:
        missing = REQUIRED_RELATION_KEYS - rel.keys()
        if missing:
            logger.warning("Relation entry missing keys %s -- skipping", missing)
            continue
        src: str = rel["mitigation_id"]
        tgt: str = rel["technique_id"]
        if src not in graph:
            logger.warning("Relation source %s not in graph -- skipping edge", src)
            continue
        if tgt not in graph:
            logger.warning("Relation target %s not in graph -- skipping edge", tgt)
            continue
        graph.add_edge(src, tgt, relationship="mitigates")
        edge_count += 1

    logger.info(
        "Graph built -- %d technique nodes, %d mitigation nodes, %d edges",
        technique_count,
        mitigation_count,
        edge_count,
    )
    return graph


# ---------------------------------------------------------------------------
# Text index
# ---------------------------------------------------------------------------


def build_text_index(graph: nx.DiGraph) -> Dict[str, str]:
    """Create a text index mapping each node ID to concatenated searchable text.

    For techniques the index concatenates name, description, and tactics.
    For mitigations it concatenates name and description.
    All text is lowercased and multiple whitespace characters are collapsed.

    Args:
        graph: The knowledge graph produced by ``build_graph``.

    Returns:
        Dictionary ``{node_id: normalised_text}``.
    """
    index: Dict[str, str] = {}
    for node_id, attrs in graph.nodes(data=True):
        node_type: str = attrs.get("type", "")
        if node_type == "technique":
            tactics_str: str = " ".join(attrs.get("tactics", []))
            raw: str = f"{attrs.get('name', '')} {attrs.get('description', '')} {tactics_str}"
        elif node_type == "mitigation":
            raw = f"{attrs.get('name', '')} {attrs.get('description', '')}"
        else:
            logger.debug(
                "Unknown node type '%s' for node %s -- skipping index",
                node_type,
                node_id,
            )
            continue
        cleaned: str = re.sub(r"\s+", " ", raw.lower()).strip()
        index[node_id] = cleaned

    logger.info("Text index built -- %d entries", len(index))
    return index


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def compute_graph_stats(graph: nx.DiGraph) -> Dict[str, Any]:
    """Compute descriptive statistics about the knowledge graph.

    Args:
        graph: The knowledge graph produced by ``build_graph``.

    Returns:
        Dictionary containing graph structure, distribution, connectivity,
        and coverage metrics.
    """
    technique_nodes: List[str] = [
        n for n, d in graph.nodes(data=True) if d.get("type") == "technique"
    ]
    mitigation_nodes: List[str] = [
        n for n, d in graph.nodes(data=True) if d.get("type") == "mitigation"
    ]

    total_nodes: int = graph.number_of_nodes()
    total_edges: int = graph.number_of_edges()

    avg_out_degree: float = (
        sum(d for _, d in graph.out_degree()) / total_nodes if total_nodes else 0.0
    )
    avg_in_degree: float = (
        sum(d for _, d in graph.in_degree()) / total_nodes if total_nodes else 0.0
    )

    all_tactics: List[str] = []
    for node_id in technique_nodes:
        all_tactics.extend(graph.nodes[node_id].get("tactics", []))
    top_5_tactics: List[tuple[str, int]] = Counter(all_tactics).most_common(5)

    techniques_without_mitigations: int = sum(1 for t in technique_nodes if graph.in_degree(t) == 0)
    num_techniques: int = len(technique_nodes)
    mitigations_coverage: float = (
        ((num_techniques - techniques_without_mitigations) / num_techniques * 100.0)
        if num_techniques
        else 0.0
    )

    stats: Dict[str, Any] = {
        "total_nodes": total_nodes,
        "technique_nodes": num_techniques,
        "mitigation_nodes": len(mitigation_nodes),
        "total_edges": total_edges,
        "is_directed": graph.is_directed(),
        "is_connected": nx.is_weakly_connected(graph) if total_nodes > 0 else False,
        "num_weakly_connected_components": (
            nx.number_weakly_connected_components(graph) if total_nodes > 0 else 0
        ),
        "avg_out_degree": round(avg_out_degree, 2),
        "avg_in_degree": round(avg_in_degree, 2),
        "top_5_tactics": top_5_tactics,
        "techniques_without_mitigations": techniques_without_mitigations,
        "mitigations_coverage": round(mitigations_coverage, 2),
    }
    return stats


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_graph(graph: nx.DiGraph, output_path: Path) -> None:
    """Serialise the graph to disk using pickle.

    Args:
        graph: The graph to save.
        output_path: Destination file path (typically ``*.gpickle``).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as fh:
        pickle.dump(graph, fh, protocol=pickle.HIGHEST_PROTOCOL)
    size_mb: float = output_path.stat().st_size / (1024 * 1024)
    logger.info("Graph saved to %s (%.2f MB)", output_path, size_mb)


def save_text_index(index: Dict[str, str], output_path: Path) -> None:
    """Save the text index as a JSON file.

    Args:
        index: The text index mapping node IDs to concatenated text.
        output_path: Destination file path.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
    size_kb: float = output_path.stat().st_size / 1024
    logger.info(
        "Text index saved -- %d entries to %s (%.1f KB)",
        len(index),
        output_path,
        size_kb,
    )


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def display_stats(stats: Dict[str, Any]) -> None:
    """Print formatted graph statistics to stdout.

    Args:
        stats: Statistics dictionary from ``compute_graph_stats``.
    """
    sep: str = "=" * 55
    print(f"\n{sep}")
    print("  ATT&CK Knowledge Graph -- Statistics")
    print(sep)
    print("\n  [Graph Structure]")
    print(f"    Directed       : {stats['is_directed']}")
    print(f"    Total nodes    : {stats['total_nodes']}")
    print(f"    Total edges    : {stats['total_edges']}")
    print("\n  [Node Distribution]")
    print(f"    Techniques     : {stats['technique_nodes']}")
    print(f"    Mitigations    : {stats['mitigation_nodes']}")
    print("\n  [Edge Statistics]")
    print(f"    Avg out-degree : {stats['avg_out_degree']}")
    print(f"    Avg in-degree  : {stats['avg_in_degree']}")
    print("\n  [Connectivity]")
    print(f"    Weakly connected: {stats['is_connected']}")
    print(f"    Components      : {stats['num_weakly_connected_components']}")
    print("\n  [Top Tactics]")
    for rank, (tactic, count) in enumerate(stats["top_5_tactics"], start=1):
        print(f"    {rank}. {tactic:<30s} ({count})")
    print("\n  [Coverage Analysis]")
    print(f"    Techniques w/o mitigation : {stats['techniques_without_mitigations']}")
    print(f"    Mitigation coverage       : {stats['mitigations_coverage']:.1f}%")
    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# CLI & pipeline
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
    """CLI entry-point: build knowledge graph from Sprint 1 JSON artefacts."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Build ATT&CK knowledge graph from ingested JSON data.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Input directory containing techniques/mitigations/relations JSON files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Output directory for graph and text index",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args: argparse.Namespace = parser.parse_args()
    data_dir: Path = args.data_dir
    output_dir: Path = args.output_dir
    _configure_logging(args.verbose)

    try:
        # 1. Load JSON artefacts from Sprint 1
        logger.info("Loading JSON data from %s ...", data_dir)
        techniques: List[Dict[str, Any]] = load_json(data_dir / TECHNIQUES_FILE)
        mitigations: List[Dict[str, Any]] = load_json(data_dir / MITIGATIONS_FILE)
        relations: List[Dict[str, str]] = load_json(data_dir / RELATIONS_FILE)

        # 2. Build knowledge graph
        logger.info("Building knowledge graph ...")
        graph: nx.DiGraph = build_graph(techniques, mitigations, relations)

        # 3. Build text index for retrieval
        logger.info("Building text index ...")
        text_index: Dict[str, str] = build_text_index(graph)

        # 4. Compute statistics
        logger.info("Computing graph statistics ...")
        stats: Dict[str, Any] = compute_graph_stats(graph)

        # 5. Save graph
        graph_path: Path = output_dir / GRAPH_OUTPUT
        save_graph(graph, graph_path)

        # 6. Save text index
        index_path: Path = output_dir / TEXT_INDEX_OUTPUT
        save_text_index(text_index, index_path)

        # 7. Display statistics
        display_stats(stats)

    except FileNotFoundError as exc:
        logger.exception("Missing input file: %s", exc)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        logger.exception("Invalid JSON: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during graph building: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
