"""Tests for the semantic reranking module (gseg.rank).

Covers reranker logic, score ordering, combine pipeline,
and edge cases such as empty candidates.
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from gseg.rank import (
    DEFAULT_FINAL_K,
    DEFAULT_MODEL_NAME,
    Reranker,
    RerankHit,
    combine_retrieval_rerank,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def mock_reranker() -> Reranker:
      """Instantiate a real Reranker with the lightweight CPU model.

          Uses ``all-MiniLM-L6-v2`` which is small enough to run in CI on CPU.

              Returns:
                      Initialised ``Reranker`` instance.
                          """
      return Reranker(model_name=DEFAULT_MODEL_NAME, device="cpu")


@pytest.fixture()
def sample_candidates() -> List[Dict[str, Any]]:
      """Return a small list of candidate dicts for reranking tests.

          Returns:
                  Three candidate dictionaries with name and description fields.
                      """
      return [
          {
              "technique_id": "T1078",
              "name": "Login page authentication bypass",
              "description": "Adversaries use valid accounts to authenticate.",
              "tactics": ["initial-access"],
              "url": "https://attack.mitre.org/techniques/T1078",
              "bm25_score": 10.0,
              "original_rank": 1,
          },
          {
              "technique_id": "T9999",
              "name": "Apple fruit harvesting",
              "description": "Collecting apples from orchards in autumn.",
              "tactics": [],
              "url": None,
              "bm25_score": 8.0,
              "original_rank": 2,
          },
          {
              "technique_id": "T1021",
              "name": "Remote Services SSH",
              "description": "Adversaries may use SSH to log into remote systems.",
              "tactics": ["lateral-movement"],
              "url": "https://attack.mitre.org/techniques/T1021",
              "bm25_score": 6.0,
              "original_rank": 3,
          },
      ]


# ---------------------------------------------------------------------------
# Reranker tests
# ---------------------------------------------------------------------------
class TestReranker:
      """Tests for ``Reranker.rerank``."""

    def test_rerank_logic(
              self,
              mock_reranker: Reranker,
              sample_candidates: List[Dict[str, Any]],
    ) -> None:
              """Query 'authentication' should rank Login page above Apple fruit."""
              results: List[Dict[str, Any]] = mock_reranker.rerank(
                  query="authentication",
                  candidates=sample_candidates,
                  top_k=3,
              )

        assert len(results) >= 2
        # Find scores for authentication-related vs. fruit candidate
        scores_by_id: Dict[str, float] = {
                      r["technique_id"]: r["rerank_score"] for r in results
        }
        assert scores_by_id["T1078"] > scores_by_id["T9999"]

    def test_rerank_score_field(
              self,
              mock_reranker: Reranker,
              sample_candidates: List[Dict[str, Any]],
    ) -> None:
              """Each result dict should contain a 'rerank_score' float."""
              results: List[Dict[str, Any]] = mock_reranker.rerank(
                  query="SSH remote access",
                  candidates=sample_candidates,
                  top_k=3,
              )

        for result in results:
                      assert "rerank_score" in result
                      assert isinstance(result["rerank_score"], float)

    def test_rerank_top_k(
              self,
              mock_reranker: Reranker,
              sample_candidates: List[Dict[str, Any]],
    ) -> None:
              """Requesting top_k=1 should return exactly 1 result."""
              results: List[Dict[str, Any]] = mock_reranker.rerank(
                  query="lateral movement",
                  candidates=sample_candidates,
                  top_k=1,
              )
              assert len(results) == 1

    def test_rerank_empty_candidates(
              self, mock_reranker: Reranker
    ) -> None:
              """Empty candidates list returns an empty result."""
              results: List[Dict[str, Any]] = mock_reranker.rerank(
                  query="anything", candidates=[], top_k=5
              )
              assert results == []

    def test_rerank_empty_query(
              self,
              mock_reranker: Reranker,
              sample_candidates: List[Dict[str, Any]],
    ) -> None:
              """An empty query returns candidates as-is (up to top_k)."""
              results: List[Dict[str, Any]] = mock_reranker.rerank(
                  query="", candidates=sample_candidates, top_k=3
              )
              assert len(results) <= 3

    def test_model_info(self, mock_reranker: Reranker) -> None:
              """model_info returns expected keys."""
              info: Dict[str, Any] = mock_reranker.model_info()
              assert "model_name" in info
              assert "device" in info
              assert "embedding_dim" in info
              assert info["model_name"] == DEFAULT_MODEL_NAME
              assert isinstance(info["embedding_dim"], int)
              assert info["embedding_dim"] > 0


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------
class TestCombinePipeline:
      """Tests for ``combine_retrieval_rerank``."""

    def test_combine_pipeline(self) -> None:
              """Mocked retriever + reranker produces correct output structure."""
              # --- mock retriever ---
              mock_hit: MagicMock = MagicMock()
        mock_hit.technique_id = "T1055"
        mock_hit.name = "Process Injection"
        mock_hit.tactics = ["defense-evasion"]
        mock_hit.url = "https://attack.mitre.org/techniques/T1055"
        mock_hit.bm25_score = 12.0
        mock_hit.description = "Inject code into processes."

        mock_retriever: MagicMock = MagicMock()
        mock_retriever.search.return_value = [mock_hit]

        # --- mock reranker ---
        mock_reranker: MagicMock = MagicMock(spec=Reranker)
        mock_reranker.rerank.return_value = [
                      {
                                        "technique_id": "T1055",
                                        "name": "Process Injection",
                                        "description": "Inject code into processes.",
                                        "tactics": ["defense-evasion"],
                                        "url": "https://attack.mitre.org/techniques/T1055",
                                        "bm25_score": 12.0,
                                        "original_rank": 1,
                                        "rerank_score": 0.95,
                      }
        ]
        mock_reranker.model_info.return_value = {
                      "model_name": "test-model",
                      "device": "cpu",
                      "embedding_dim": 384,
        }

        # --- run pipeline ---
        result: Dict[str, Any] = combine_retrieval_rerank(
                      retriever=mock_retriever,
                      reranker=mock_reranker,
                      query="process injection",
                      bm25_k=10,
                      final_k=5,
        )

        # --- assertions ---
        assert result["query"] == "process injection"
        assert isinstance(result["results"], list)
        assert len(result["results"]) == 1
        assert result["results"][0]["technique_id"] == "T1055"
        assert result["results"][0]["rerank_score"] == 0.95
        assert result["bm25_candidates"] == 1
        assert isinstance(result["latency_ms"], float)
        assert "model_info" in result

        mock_retriever.search.assert_called_once_with("process injection", top_k=10)
        mock_reranker.rerank.assert_called_once()

    def test_combine_empty_retrieval(self) -> None:
              """Pipeline with no BM25 hits returns empty results."""
              mock_retriever: MagicMock = MagicMock()
              mock_retriever.search.return_value = []

        mock_reranker: MagicMock = MagicMock(spec=Reranker)
        mock_reranker.model_info.return_value = {
                      "model_name": "test-model",
                      "device": "cpu",
                      "embedding_dim": 384,
        }

        result: Dict[str, Any] = combine_retrieval_rerank(
                      retriever=mock_retriever,
                      reranker=mock_reranker,
                      query="nonexistent technique",
                      bm25_k=10,
                      final_k=5,
        )

        assert result["query"] == "nonexistent technique"
        assert result["results"] == []
        assert result["bm25_candidates"] == 0
        mock_reranker.rerank.assert_not_called()
