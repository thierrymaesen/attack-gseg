"""Tests for the graph construction module (gseg.build_graph).

Covers graph building, text index generation, and persistence
(save / load) using in-memory sample data and ``tmp_path``.
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Any, Dict, List

import networkx as nx
import pytest

from gseg.build_graph import (
    build_graph,
    build_text_index,
    compute_graph_stats,
    load_json,
    save_graph,
    save_text_index,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_techniques() -> List[Dict[str, Any]]:
    """Return a small list of technique dicts matching Sprint 1 format."""
    return [
        {
            "technique_id": "T1055",
            "name": "Process Injection",
            "description": "Inject code into processes for evasion.",
            "tactics": ["defense-evasion", "privilege-escalation"],
            "url": "https://attack.mitre.org/techniques/T1055",
        },
        {
            "technique_id": "T1021",
            "name": "Remote Services",
            "description": "Use remote services such as SSH for lateral movement.",
            "tactics": ["lateral-movement"],
            "url": "https://attack.mitre.org/techniques/T1021",
        },
    ]


@pytest.fixture()
def sample_mitigations() -> List[Dict[str, Any]]:
    """Return a small list of mitigation dicts matching Sprint 1 format."""
    return [
        {
            "mitigation_id": "M1026",
            "name": "Privileged Account Management",
            "description": "Manage the creation and use of privileged accounts.",
            "url": "https://attack.mitre.org/mitigations/M1026",
        },
        {
            "mitigation_id": "M1030",
            "name": "Network Segmentation",
            "description": "Segment networks to limit lateral movement.",
            "url": "https://attack.mitre.org/mitigations/M1030",
        },
    ]


@pytest.fixture()
def sample_relations() -> List[Dict[str, str]]:
    """Return mitigation-to-technique relations."""
    return [
        {"technique_id": "T1055", "mitigation_id": "M1026"},
        {"technique_id": "T1021", "mitigation_id": "M1030"},
        {"technique_id": "T1021", "mitigation_id": "M1026"},
    ]


@pytest.fixture()
def sample_graph(
        sample_techniques: List[Dict[str, Any]],
        sample_mitigations: List[Dict[str, Any]],
        sample_relations: List[Dict[str, str]],
) -> nx.DiGraph:
    """Build and return a graph from the sample data."""
    return build_graph(
    sample_techniques,
    sample_mitigations,
    sample_relations)


# ---------------------------------------------------------------------------
# Graph structure tests
# ---------------------------------------------------------------------------


class TestBuildGraph:
    """Tests for ``build_graph``."""

    def test_node_count(self, sample_graph: nx.DiGraph) -> None:
        """Graph contains the expected number of nodes (2 tech + 2 mit)."""
        assert sample_graph.number_of_nodes() == 4

    def test_edge_count(self, sample_graph: nx.DiGraph) -> None:
        """Graph contains the expected number of edges (3 relations)."""
        assert sample_graph.number_of_edges() == 3

    def test_technique_node_attributes(self, sample_graph: nx.DiGraph) -> None:
        """Technique nodes carry type, name, description, tactics, and url."""
        node: Dict[str, Any] = sample_graph.nodes["T1055"]
        assert node["type"] == "technique"
        assert node["name"] == "Process Injection"
        assert "defense-evasion" in node["tactics"]
        assert "privilege-escalation" in node["tactics"]
        assert node["url"] == "https://attack.mitre.org/techniques/T1055"

    def test_mitigation_node_attributes(self, sample_graph: nx.DiGraph) -> None:
        """Mitigation nodes carry type, name, description, and url."""
        node: Dict[str, Any] = sample_graph.nodes["M1026"]
        assert node["type"] == "mitigation"
        assert node["name"] == "Privileged Account Management"
        assert node["url"] == "https://attack.mitre.org/mitigations/M1026"

    def test_edge_direction(self, sample_graph: nx.DiGraph) -> None:
        """Edges run from mitigation to technique (mitigation -> technique)."""
        assert sample_graph.has_edge("M1026", "T1055")
        assert sample_graph.has_edge("M1030", "T1021")
        assert sample_graph.has_edge("M1026", "T1021")

        # Reverse direction should NOT exist
        assert not sample_graph.has_edge("T1055", "M1026")

    def test_edge_relationship_attribute(self, sample_graph: nx.DiGraph) -> None:
        """Each edge has a relationship='mitigates' attribute."""
        edge_data: Dict[str, Any] = sample_graph.edges["M1026", "T1055"]
        assert edge_data["relationship"] == "mitigates"

    def test_is_directed(self, sample_graph: nx.DiGraph) -> None:
        """The graph is a directed graph."""
        assert sample_graph.is_directed()

    def test_skips_missing_keys(self) -> None:
        """Technique entries missing required keys are skipped."""
        incomplete: List[Dict[str, Any]] = [
            {"technique_id": "T0001", "name": "Incomplete"}
            # missing description, tactics, url
        ]
        graph: nx.DiGraph = build_graph(incomplete, [], [])
        assert graph.number_of_nodes() == 0

    def test_skips_dangling_edges(
            self,
            sample_techniques: List[Dict[str, Any]],
            sample_mitigations: List[Dict[str, Any]],
    ) -> None:
        """Relations referencing non-existent nodes are skipped."""
        bad_relations: List[Dict[str, str]] = [
            {"technique_id": "T9999", "mitigation_id": "M1026"},
        ]
        graph: nx.DiGraph = build_graph(
            sample_techniques, sample_mitigations, bad_relations
        )
        assert graph.number_of_edges() == 0


# ---------------------------------------------------------------------------
# Text index tests
# ---------------------------------------------------------------------------


class TestBuildTextIndex:
    """Tests for ``build_text_index``."""

    def test_contains_all_nodes(self, sample_graph: nx.DiGraph) -> None:
        """Every node in the graph has an entry in the text index."""
        index: Dict[str, str] = build_text_index(sample_graph)
        assert len(index) == sample_graph.number_of_nodes()

    def test_technique_text_content(self, sample_graph: nx.DiGraph) -> None:
        """Technique index text contains name, description, and tactics."""
        index: Dict[str, str] = build_text_index(sample_graph)
        text: str = index["T1055"]
        assert "process injection" in text
        assert "inject code" in text
        assert "defense-evasion" in text

    def test_mitigation_text_content(self, sample_graph: nx.DiGraph) -> None:
        """Mitigation index text contains name and description."""
        index: Dict[str, str] = build_text_index(sample_graph)
        text: str = index["M1026"]
        assert "privileged account management" in text
        assert "privileged accounts" in text

    def test_text_is_lowercased(self, sample_graph: nx.DiGraph) -> None:
        """All index text is lowercased."""
        index: Dict[str, str] = build_text_index(sample_graph)
        for text in index.values():
                            assert text == text.lower()


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------


class TestSaveLoadGraph:
    """Tests for ``save_graph`` and graph loading."""

    def test_save_creates_file(
            self, sample_graph: nx.DiGraph, tmp_path: Path
    ) -> None:
        """``save_graph`` writes a file to disk."""
        output: Path = tmp_path / "graph.gpickle"
        save_graph(sample_graph, output)
        assert output.exists()
        assert output.stat().st_size > 0

    def test_roundtrip(
            self, sample_graph: nx.DiGraph, tmp_path: Path
    ) -> None:
        """A saved graph can be loaded back with identical structure."""
        output: Path = tmp_path / "graph.gpickle"
        save_graph(sample_graph, output)

        with open(output, "rb") as fh:
            loaded: nx.DiGraph = pickle.load(fh)

        assert loaded.number_of_nodes() == sample_graph.number_of_nodes()
        assert loaded.number_of_edges() == sample_graph.number_of_edges()
        assert loaded.nodes["T1055"]["type"] == "technique"
        assert loaded.has_edge("M1026", "T1055")


class TestSaveTextIndex:
    """Tests for ``save_text_index``."""

    def test_save_creates_json(
            self, sample_graph: nx.DiGraph, tmp_path: Path
    ) -> None:
        """``save_text_index`` writes a valid JSON file."""
        index: Dict[str, str] = build_text_index(sample_graph)
        output: Path = tmp_path / "text_index.json"
        save_text_index(index, output)

        assert output.exists()
        loaded: Dict[str, str] = json.loads(output.read_text(encoding="utf-8"))
        assert len(loaded) == len(index)
        assert loaded["T1055"] == index["T1055"]


# ---------------------------------------------------------------------------
# Statistics tests
# ---------------------------------------------------------------------------


class TestComputeGraphStats:
    """Tests for ``compute_graph_stats``."""

    def test_stats_structure(self, sample_graph: nx.DiGraph) -> None:
        """Statistics dict contains all expected keys."""
        stats: Dict[str, Any] = compute_graph_stats(sample_graph)

        assert stats["total_nodes"] == 4
        assert stats["technique_nodes"] == 2
        assert stats["mitigation_nodes"] == 2
        assert stats["total_edges"] == 3
        assert stats["is_directed"] is True

    def test_coverage(self, sample_graph: nx.DiGraph) -> None:
        """Mitigation coverage is 100% when all techniques have mitigations."""
        stats: Dict[str, Any] = compute_graph_stats(sample_graph)
        assert stats["mitigations_coverage"] == 100.0
        assert stats["techniques_without_mitigations"] == 0


# ---------------------------------------------------------------------------
# load_json tests
# ---------------------------------------------------------------------------


class TestLoadJson:
    """Tests for ``load_json``."""

    def test_loads_valid_array(self, tmp_path: Path) -> None:
        """A valid JSON array is loaded correctly."""
        data: List[Dict[str, str]] = [{"id": "1"}, {"id": "2"}]
        path: Path = tmp_path / "data.json"
        path.write_text(json.dumps(data), encoding="utf-8")

        result: List[Dict[str, Any]] = load_json(path)
        assert len(result) == 2

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Missing file raises ``FileNotFoundError``."""
        with pytest.raises(FileNotFoundError):
                            load_json(tmp_path / "nonexistent.json")

    def test_invalid_json(self, tmp_path: Path) -> None:
                    """Malformed JSON raises ``json.JSONDecodeError``."""
                    path: Path = tmp_path / "bad.json"
                    path.write_text("{not valid json", encoding="utf-8")

        with pytest.raises(Exception):
            load_json(path)

    def test_non_array_raises(self, tmp_path: Path) -> None:
        """A JSON object (not array) raises ``ValueError``."""
        path: Path = tmp_path / "obj.json"
        path.write_text('{"key": "value"}', encoding="utf-8")

        with pytest.raises(ValueError):
            load_json(path)
