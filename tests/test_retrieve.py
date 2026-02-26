"""Tests for the BM25 retrieval module (gseg.retrieve).

Covers search, partial matching, mitigation lookup, and edge cases
using a small in-memory graph and text index.
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Any, Dict, List

import networkx as nx
import pytest

from gseg.retrieve import RetrieverBM25, TechniqueHit, tokenize


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def mock_graph_index(tmp_path: Path) -> Dict[str, Path]:
    """Create a small graph and text index for retrieval tests.

        Graph contains three techniques and two mitigations with edges:
            M1 -> T1  (mitigates)
                    M2 -> T2  (mitigates)

                        Returns:
                            Dictionary with ``graph_path`` and ``index_path`` keys.
                                """
    g: nx.DiGraph = nx.DiGraph()

    # --- techniques ---
    g.add_node(
        "T1566",
        type="technique",
        name="Phishing",
        description="Adversaries may send phishing messages to gain access.",
        tactics=["initial-access"],
        url="https://attack.mitre.org/techniques/T1566",
    )
    g.add_node(
        "T1110",
        type="technique",
        name="SSH Brute Force",
        description="Adversaries may use brute force to obtain SSH credentials.",
        tactics=["credential-access"],
        url="https://attack.mitre.org/techniques/T1110",
    )
    g.add_node(
        "T1059",
        type="technique",
        name="Malware Execution",
        description="Adversaries deploy malware to execute payloads on target.",
        tactics=["execution"],
        url="https://attack.mitre.org/techniques/T1059",
    )

    # --- mitigations ---
    g.add_node(
        "M1017",
        type="mitigation",
        name="User Training",
        description="Train users to identify phishing attempts.",
        url="https://attack.mitre.org/mitigations/M1017",
    )
    g.add_node(
        "M1032",
        type="mitigation",
        name="Multi-factor Authentication",
        description="Use MFA to limit brute force impact.",
        url="https://attack.mitre.org/mitigations/M1032",
    )

    # --- edges (mitigation -> technique) ---
    g.add_edge("M1017", "T1566", relation="mitigates")
    g.add_edge("M1032", "T1110", relation="mitigates")

    # --- serialize graph ---
    graph_path: Path = tmp_path / "attack_graph.gpickle"
    with open(graph_path, "wb") as fh:
        pickle.dump(g, fh)

    # --- text index ---
    text_index: Dict[str, str] = {
        "T1566": "Phishing adversaries may send phishing messages to gain access",
        "T1110": "SSH Brute Force adversaries may use brute force to obtain SSH credentials",
        "T1059": "Malware Execution adversaries deploy malware to execute payloads",
    }
    index_path: Path = tmp_path / "text_index.json"
    index_path.write_text(json.dumps(text_index), encoding="utf-8")

    return {"graph_path": graph_path, "index_path": index_path}


# ---------------------------------------------------------------------------
# Tokenizer tests
# ---------------------------------------------------------------------------
class TestTokenize:
    """Tests for the ``tokenize`` helper function."""

    def test_basic_tokenization(self) -> None:
        """Tokens are lowercased, stopwords removed, short tokens dropped."""
        tokens: List[str] = tokenize("The SSH Brute Force attack")
        assert "ssh" in tokens
        assert "brute" in tokens
        assert "force" in tokens
        assert "the" not in tokens

    def test_empty_string(self) -> None:
        """An empty string yields an empty token list."""
        assert tokenize("") == []

    def test_only_stopwords(self) -> None:
        """A query of only stopwords yields an empty list."""
        assert tokenize("the and of to a") == []


# ---------------------------------------------------------------------------
# Retriever search tests
# ---------------------------------------------------------------------------
class TestRetrieverSearch:
    """Tests for ``RetrieverBM25.search``."""

    def test_search_exact_match(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """Query 'phishing' must return the Phishing technique first."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        hits: List[TechniqueHit] = retriever.search("phishing", top_k=3)

        assert len(hits) >= 1
        assert hits[0].technique_id == "T1566"
        assert hits[0].name == "Phishing"
        assert hits[0].bm25_score > 0.0

    def test_search_partial_match(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """Query 'ssh' must find the SSH Brute Force technique."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        hits: List[TechniqueHit] = retriever.search("ssh", top_k=3)

        assert len(hits) >= 1
        found_ids: List[str] = [h.technique_id for h in hits]
        assert "T1110" in found_ids

    def test_empty_query(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """An empty query must return an empty list."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        hits: List[TechniqueHit] = retriever.search("", top_k=5)
        assert hits == []

    def test_stopword_only_query(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """A query with only stopwords returns an empty list."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        hits: List[TechniqueHit] = retriever.search("the and of", top_k=5)
        assert hits == []

    def test_hit_fields(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """Each TechniqueHit exposes the expected attributes."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        hits: List[TechniqueHit] = retriever.search("malware", top_k=1)

        assert len(hits) == 1
        hit: TechniqueHit = hits[0]
        assert hit.technique_id == "T1059"
        assert isinstance(hit.tactics, list)
        assert isinstance(hit.bm25_score, float)
        assert hit.url is not None


# ---------------------------------------------------------------------------
# Mitigation tests
# ---------------------------------------------------------------------------
class TestGetMitigations:
    """Tests for ``RetrieverBM25.get_mitigations``."""

    def test_get_mitigations(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """Mitigations linked to T1566 should include M1017."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        mitigations: List[Dict[str, Any]] = retriever.get_mitigations("T1566")

        assert len(mitigations) == 1
        assert mitigations[0]["mitigation_id"] == "M1017"
        assert mitigations[0]["name"] == "User Training"

    def test_get_mitigations_unknown_technique(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """An unknown technique ID returns an empty list."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        mitigations: List[Dict[str, Any]] = retriever.get_mitigations("T9999")
        assert mitigations == []

    def test_technique_without_mitigation(
            self, mock_graph_index: Dict[str, Path]
    ) -> None:
        """T1059 has no mitigation edges, so result is empty."""
        retriever: RetrieverBM25 = RetrieverBM25(
            graph_path=mock_graph_index["graph_path"],
            text_index_path=mock_graph_index["index_path"],
        )
        mitigations: List[Dict[str, Any]] = retriever.get_mitigations("T1059")
        assert mitigations == []


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------
class TestRetrieverErrors:
    """Tests for error conditions in ``RetrieverBM25``."""

    def test_missing_graph_file(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised when graph file does not exist."""
        index_path: Path = tmp_path / "text_index.json"
        index_path.write_text('{"T1": "test"}', encoding="utf-8")

        with pytest.raises(FileNotFoundError):
            RetrieverBM25(
                                        graph_path=tmp_path / "missing.gpickle",
                                        text_index_path=index_path,
            )

    def test_missing_index_file(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised when text index file does not exist."""
        g: nx.DiGraph = nx.DiGraph()
        g.add_node("T1", type="technique", name="Test")
        graph_path: Path = tmp_path / "graph.gpickle"
        with open(graph_path, "wb") as fh:
            pickle.dump(g, fh)

        with pytest.raises(FileNotFoundError):
            RetrieverBM25(
                    graph_path=graph_path,
                    text_index_path=tmp_path / "missing.json",
            )
