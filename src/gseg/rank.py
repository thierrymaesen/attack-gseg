"""Semantic reranking module for ATT&CK technique retrieval.

This module provides a reranker that uses sentence embeddings
(``all-MiniLM-L6-v2`` by default) to reorder BM25 candidate results by
cosine similarity to the query.  It also exposes a convenience function
``combine_retrieval_rerank`` that wires the BM25 retriever from Sprint 3
together with the reranker in a single call.

Usage:
    poetry run python -m gseg.rank --query "process injection"
    poetry run python -m gseg.rank --query "lateral movement" --use-retriever
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from sentence_transformers import SentenceTransformer, util

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL_NAME: str = "all-MiniLM-L6-v2"
DEFAULT_DEVICE: str = "cpu"
DEFAULT_BM25_K: int = 20
DEFAULT_FINAL_K: int = 5

logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RerankHit:
    """A single result after semantic reranking."""

    technique_id: str
    name: str
    description: str
    tactics: List[str]
    url: Optional[str]
    bm25_score: float
    rerank_score: float
    original_rank: int


# ---------------------------------------------------------------------------
# Reranker
# ---------------------------------------------------------------------------


class Reranker:
    """Semantic reranker using sentence-transformer embeddings.

    Args:
        model_name: HuggingFace model identifier for sentence-transformers.
        device: Torch device string (``"cpu"`` or ``"cuda"``).
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        device: str = DEFAULT_DEVICE,
    ) -> None:
        self.model_name: str = model_name
        self.device: str = device

        logger.info(
            "Loading sentence-transformer model '%s' on device '%s' ...",
            model_name, device,
        )
        t_start: float = time.monotonic()
        try:
            self._model: SentenceTransformer = SentenceTransformer(
                model_name, device=device
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load sentence-transformer model '{model_name}': {exc}"
            ) from exc

        elapsed_ms: float = (time.monotonic() - t_start) * 1000.0
        logger.info(
            "Model loaded in %.0f ms -- embedding dim=%d",
            elapsed_ms, self._model.get_sentence_embedding_dimension(),
        )

    def rerank(
        self,
        query: str,
        candidates: List[Dict[str, Any]],
        top_k: int = DEFAULT_FINAL_K,
    ) -> List[Dict[str, Any]]:
        """Rerank candidates by cosine similarity to *query*."""
        if not candidates:
            return []
        if not query or not query.strip():
            logger.warning("Empty query passed to rerank -- returning candidates as-is")
            return candidates[:top_k]

        doc_texts: List[str] = [
            f"{c.get('name', '')} {c.get('description', '')}".strip()
            for c in candidates
        ]

        t_start: float = time.monotonic()
        query_embedding: np.ndarray = self._model.encode(
            query, convert_to_numpy=True, show_progress_bar=False
        )
        doc_embeddings: np.ndarray = self._model.encode(
            doc_texts, convert_to_numpy=True, show_progress_bar=False, batch_size=64
        )
        encode_ms: float = (time.monotonic() - t_start) * 1000.0
        logger.debug("Encoded query + %d docs in %.0f ms", len(doc_texts), encode_ms)

        similarities = util.cos_sim(query_embedding, doc_embeddings)[0]
        scores: np.ndarray = (
            similarities.cpu().numpy() if hasattr(similarities, "cpu")
            else np.array(similarities)
        )

        ranked_indices: List[int] = sorted(
            range(len(scores)), key=lambda i: float(scores[i]), reverse=True
        )[:top_k]

        results: List[Dict[str, Any]] = []
        for idx in ranked_indices:
            enriched: Dict[str, Any] = {**candidates[idx]}
            enriched["rerank_score"] = round(float(scores[idx]), 4)
            results.append(enriched)
        return results

    def model_info(self) -> Dict[str, Any]:
        """Return metadata about the loaded model."""
        return {
            "model_name": self.model_name,
            "device": self.device,
            "embedding_dim": self._model.get_sentence_embedding_dimension(),
        }


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def combine_retrieval_rerank(
    retriever: Any,
    reranker: Reranker,
    query: str,
    bm25_k: int = DEFAULT_BM25_K,
    final_k: int = DEFAULT_FINAL_K,
) -> Dict[str, Any]:
    """Run BM25 retrieval then semantic reranking in a single call."""
    t_start: float = time.monotonic()

    bm25_hits = retriever.search(query, top_k=bm25_k)
    logger.info("BM25 returned %d candidates for query: %r", len(bm25_hits), query)

    if not bm25_hits:
        return {
            "query": query,
            "results": [],
            "bm25_candidates": 0,
            "latency_ms": round((time.monotonic() - t_start) * 1000.0, 1),
            "model_info": reranker.model_info(),
        }

    candidates: List[Dict[str, Any]] = []
    for rank, hit in enumerate(bm25_hits, start=1):
        candidates.append(
            {
                "technique_id": hit.technique_id,
                "name": hit.name,
                "description": getattr(hit, "description", hit.name),
                "tactics": hit.tactics,
                "url": hit.url,
                "bm25_score": hit.bm25_score,
                "original_rank": rank,
            }
        )

    reranked: List[Dict[str, Any]] = reranker.rerank(query, candidates, top_k=final_k)
    elapsed_ms: float = round((time.monotonic() - t_start) * 1000.0, 1)
    logger.info("Pipeline complete in %.1f ms -- %d results", elapsed_ms, len(reranked))

    return {
        "query": query,
        "results": reranked,
        "bm25_candidates": len(bm25_hits),
        "latency_ms": elapsed_ms,
        "model_info": reranker.model_info(),
    }


# ---------------------------------------------------------------------------
# Demo candidates (for standalone testing without Sprint 3 data)
# ---------------------------------------------------------------------------

DEMO_CANDIDATES: List[Dict[str, Any]] = [
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "description": (
            "Adversaries may inject code into processes in order to evade"
            " process-based defenses as well as possibly elevate privileges."
        ),
        "tactics": ["defense-evasion", "privilege-escalation"],
        "url": "https://attack.mitre.org/techniques/T1055",
        "bm25_score": 12.34,
        "original_rank": 1,
    },
    {
        "technique_id": "T1021",
        "name": "Remote Services",
        "description": (
            "Adversaries may use valid accounts to log into a service"
            " specifically designed to accept remote connections."
        ),
        "tactics": ["lateral-movement"],
        "url": "https://attack.mitre.org/techniques/T1021",
        "bm25_score": 9.87,
        "original_rank": 2,
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": (
            "Adversaries may abuse command and script interpreters to"
            " execute commands, scripts, or binaries."
        ),
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1059",
        "bm25_score": 7.65,
        "original_rank": 3,
    },
]

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
    """CLI entry-point: test semantic reranking on ATT&CK techniques."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Semantic reranking of ATT&CK technique candidates.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--query", type=str, required=True, help="Search query string")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL_NAME, help="Sentence-transformer model name")
    parser.add_argument("--device", type=str, default=DEFAULT_DEVICE, help="Torch device (cpu or cuda)")
    parser.add_argument("--top-k", type=int, default=DEFAULT_FINAL_K, help="Number of results after reranking")
    parser.add_argument("--bm25-k", type=int, default=DEFAULT_BM25_K, help="Number of BM25 candidates (with --use-retriever)")
    parser.add_argument("--data-dir", type=Path, default=None, help="Data directory for retriever (with --use-retriever)")
    parser.add_argument("--use-retriever", action="store_true", help="Use the full BM25 + reranker pipeline with live data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args: argparse.Namespace = parser.parse_args()
    _configure_logging(args.verbose)

    sep: str = "=" * 55
    try:
        reranker: Reranker = Reranker(model_name=args.model, device=args.device)
        info: Dict[str, Any] = reranker.model_info()

        print(f"\n{sep}")
        print("  Semantic Reranking -- ATT&CK Techniques")
        print(sep)
        print(f"\n  Query     : {args.query}")
        print(f"  Model     : {info['model_name']}")
        print(f"  Device    : {info['device']}")
        print(f"  Embed dim : {info['embedding_dim']}")

        if args.use_retriever:
            _run_full_pipeline(args, reranker, sep)
        else:
            _run_demo_mode(args, reranker, sep)

    except RuntimeError as exc:
        logger.error("Model loading failed: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during reranking: %s", exc)
        sys.exit(1)


def _run_demo_mode(args: argparse.Namespace, reranker: Reranker, sep: str) -> None:
    """Run reranking on hardcoded demo candidates."""
    print(f"\n  Mode      : demo (hardcoded candidates)")
    print(f"  Candidates: {len(DEMO_CANDIDATES)}")
    print(f"\n  --- Before reranking ---\n")
    for i, c in enumerate(DEMO_CANDIDATES, start=1):
        print(f"  {i}) {c['technique_id']} - {c['name']} | bm25={c['bm25_score']:.2f}")

    t_start: float = time.monotonic()
    reranked: List[Dict[str, Any]] = reranker.rerank(
        args.query, DEMO_CANDIDATES, top_k=args.top_k
    )
    elapsed_ms: float = (time.monotonic() - t_start) * 1000.0

    print(f"\n  --- After reranking ({elapsed_ms:.0f} ms) ---\n")
    for i, c in enumerate(reranked, start=1):
        print(
            f"  {i}) {c['technique_id']} - {c['name']}"
            f" | rerank={c['rerank_score']:.4f}"
            f" | bm25={c['bm25_score']:.2f}"
            f" | was_rank={c['original_rank']}"
        )
    print(f"\n{sep}\n")


def _run_full_pipeline(args: argparse.Namespace, reranker: Reranker, sep: str) -> None:
    """Run the full BM25 + reranking pipeline with live data."""
    try:
        from gseg.retrieve import RetrieverBM25, DEFAULT_DATA_DIR
    except ImportError:
        logger.error("Could not import gseg.retrieve. Ensure Sprint 3 module is available.")
        sys.exit(1)

    data_dir: Path = args.data_dir if args.data_dir is not None else DEFAULT_DATA_DIR
    graph_path: Path = data_dir / "attack_graph.gpickle"
    text_index_path: Path = data_dir / "text_index.json"

    retriever: RetrieverBM25 = RetrieverBM25(
        graph_path=graph_path, text_index_path=text_index_path,
    )

    result: Dict[str, Any] = combine_retrieval_rerank(
        retriever=retriever, reranker=reranker,
        query=args.query, bm25_k=args.bm25_k, final_k=args.top_k,
    )

    print(f"\n  Mode      : full pipeline (BM25 + reranker)")
    print(f"  BM25 cands: {result['bm25_candidates']}")
    print(f"  Latency   : {result['latency_ms']:.1f} ms")
    print(f"\n  Results ({len(result['results'])}):\n")
    for i, c in enumerate(result["results"], start=1):
        tactics_str: str = ", ".join(c.get("tactics", [])) or "n/a"
        print(
            f"  {i}) {c['technique_id']} - {c['name']}"
            f" | rerank={c['rerank_score']:.4f}"
            f" | bm25={c['bm25_score']:.2f}"
            f" | was_rank={c['original_rank']}"
            f" | tactics=[{tactics_str}]"
        )
    print(f"\n{sep}\n")


if __name__ == "__main__":
    main()
