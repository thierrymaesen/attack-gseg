"""Tests for the FastAPI REST endpoints (gseg.api).

Uses ``TestClient`` with mocked models so that tests run instantly
without loading heavy ML artefacts or graph files.
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from gseg.api import app, models


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def mock_models() -> None:
    """Inject mocked Retriever and Reranker into the global models dict.

        Uses ``autouse=True`` so every test in this module automatically gets
            lightweight mocks instead of real ML models.
                """
    # --- mock retriever ---
    mock_retriever: MagicMock = MagicMock()
    mock_retriever.search.return_value = []
    mock_retriever.graph = MagicMock()
    mock_retriever.graph.nodes.return_value = []
    mock_retriever.get_mitigations.return_value = []

    # --- mock reranker ---
    mock_reranker: MagicMock = MagicMock()
    mock_reranker.rerank.return_value = []
    mock_reranker.model_info.return_value = {
        "model_name": "test-model",
        "device": "cpu",
        "embedding_dim": 384,
    }

    models["retriever"] = mock_retriever
    models["reranker"] = mock_reranker

    yield

    models.clear()


@pytest.fixture()
def client() -> TestClient:
    """Return a FastAPI ``TestClient`` for the app.

        The lifespan is disabled (``raise_server_exceptions=True``) because
            models are injected by the ``mock_models`` fixture above.

                Returns:
                        Configured ``TestClient`` instance.
                            """
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Health endpoint tests
# ---------------------------------------------------------------------------
class TestHealthCheck:
    """Tests for ``GET /health``."""

    def test_health_check(self, client: TestClient) -> None:
        """GET /health returns 200 with status ok."""
        response = client.get("/health")

        assert response.status_code == 200
        data: Dict[str, Any] = response.json()
        assert data["status"] == "ok"
        assert data["models_loaded"] is True

    def test_health_check_no_models(self, client: TestClient) -> None:
        """GET /health reports models_loaded=False when models are absent."""
        models.clear()
        response = client.get("/health")

        assert response.status_code == 200
        data: Dict[str, Any] = response.json()
        assert data["models_loaded"] is False


# ---------------------------------------------------------------------------
# Map event endpoint tests
# ---------------------------------------------------------------------------
class TestMapEvent:
    """Tests for ``POST /map_event``."""

    def test_map_event_valid(self, client: TestClient) -> None:
        """POST /map_event with valid body returns 200 and correct structure."""
        # --- configure mock pipeline result ---
        mock_reranker: MagicMock = models["reranker"]
        mock_reranker.rerank.return_value = [
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "description": "Inject code into processes.",
                "tactics": ["defense-evasion"],
                "url": "https://attack.mitre.org/techniques/T1055",
                "bm25_score": 12.0,
                "original_rank": 1,
                "rerank_score": 0.92,
            }
        ]

        mock_retriever: MagicMock = models["retriever"]
        mock_hit: MagicMock = MagicMock()
        mock_hit.technique_id = "T1055"
        mock_hit.name = "Process Injection"
        mock_hit.tactics = ["defense-evasion"]
        mock_hit.url = "https://attack.mitre.org/techniques/T1055"
        mock_hit.bm25_score = 12.0
        mock_hit.description = "Inject code into processes."
        mock_retriever.search.return_value = [mock_hit]

        response = client.post(
                "/map_event",
                json={"text": "Detected process injection attempt", "top_k": 5},
        )

        assert response.status_code == 200
        data: Dict[str, Any] = response.json()
        assert "query" in data
        assert "results" in data
        assert "latency_ms" in data
        assert data["query"] == "Detected process injection attempt"
        assert isinstance(data["results"], list)
        assert isinstance(data["latency_ms"], float)

    def test_map_event_with_mitigations(self, client: TestClient) -> None:
        """POST /map_event with include_mitigations=True returns mitigations."""
        mock_reranker: MagicMock = models["reranker"]
        mock_reranker.rerank.return_value = [
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "description": "Inject code.",
                "tactics": ["defense-evasion"],
                "url": None,
                "bm25_score": 10.0,
                "original_rank": 1,
                "rerank_score": 0.88,
            }
        ]

        mock_retriever: MagicMock = models["retriever"]
        mock_hit: MagicMock = MagicMock()
        mock_hit.technique_id = "T1055"
        mock_hit.name = "Process Injection"
        mock_hit.tactics = ["defense-evasion"]
        mock_hit.url = None
        mock_hit.bm25_score = 10.0
        mock_hit.description = "Inject code."
        mock_retriever.search.return_value = [mock_hit]
        mock_retriever.get_mitigations.return_value = [
                {
                                        "mitigation_id": "M1040",
                                        "name": "Behavior Prevention",
                                        "description": "Prevent process injection behaviour.",
                                        "url": "https://attack.mitre.org/mitigations/M1040",
                }
        ]

        response = client.post(
                "/map_event",
                json={
                                        "text": "process injection detected",
                                        "top_k": 5,
                                        "include_mitigations": True,
                },
        )

        assert response.status_code == 200
        data: Dict[str, Any] = response.json()
        assert len(data["results"]) == 1
        result: Dict[str, Any] = data["results"][0]
        assert result["mitigations"] is not None
        assert len(result["mitigations"]) == 1
        assert result["mitigations"][0]["mitigation_id"] == "M1040"

    def test_map_event_empty_text(self, client: TestClient) -> None:
        """POST /map_event with empty text returns 422."""
        response = client.post("/map_event", json={"text": ""})
        assert response.status_code == 422

    def test_map_event_short_text(self, client: TestClient) -> None:
        """POST /map_event with text shorter than 3 chars returns 422."""
        response = client.post("/map_event", json={"text": "ab"})
        assert response.status_code == 422

    def test_map_event_missing_body(self, client: TestClient) -> None:
        """POST /map_event with no JSON body returns 422."""
        response = client.post("/map_event")
        assert response.status_code == 422

    def test_map_event_no_models(self, client: TestClient) -> None:
        """POST /map_event returns 503 when models are not loaded."""
        models.clear()
        response = client.post(
            "/map_event",
            json={"text": "test event for technique mapping"},
        )
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Techniques listing endpoint tests
# ---------------------------------------------------------------------------
class TestTechniquesListing:
    """Tests for ``GET /techniques``."""

    def test_techniques_default(self, client: TestClient) -> None:
        """GET /techniques returns 200 with a list."""
        mock_retriever: MagicMock = models["retriever"]
        mock_retriever.graph.nodes.return_value = [
            ("T1055", {"type": "technique", "name": "Process Injection",
                            "tactics": ["defense-evasion"], "url": None}),
            ("T1021", {"type": "technique", "name": "Remote Services",
                            "tactics": ["lateral-movement"], "url": None}),
        ]

        response = client.get("/techniques")

        assert response.status_code == 200
        data: List[Dict[str, Any]] = response.json()
        assert isinstance(data, list)

    def test_techniques_pagination(self, client: TestClient) -> None:
        """GET /techniques?limit=2&offset=0 returns at most 2 items."""
        # --- build 5 mock technique nodes ---
        nodes: list = []
        for i in range(5):
            nodes.append(
                                        (f"T{1000 + i}", {
                                                    "type": "technique",
                                                    "name": f"Technique {i}",
                                                    "tactics": ["execution"],
                                                    "url": None,
                                        })
            )
        mock_retriever: MagicMock = models["retriever"]
        mock_retriever.graph.nodes.return_value = nodes

        response = client.get("/techniques?limit=2&offset=0")

        assert response.status_code == 200
        data: List[Dict[str, Any]] = response.json()
        assert len(data) <= 2

    def test_techniques_no_models(self, client: TestClient) -> None:
        """GET /techniques returns 503 when models are not loaded."""
        models.clear()
        response = client.get("/techniques")
        assert response.status_code == 503
