"""FastAPI application for the ATT&CK Ground Segment Threat Graph.

This module exposes a REST API that combines BM25 retrieval (Sprint 3)
and semantic reranking (Sprint 4) into a single service.  Models are
loaded once at startup via the FastAPI lifespan mechanism.

Endpoints:
    GET  /health      -- Service health check.
    POST /map_event   -- Map a log line / event to ATT&CK techniques.
    GET  /techniques  -- Paginated list of all indexed techniques.

Usage:
    poetry run python -m gseg.api
    poetry run uvicorn gseg.api:app --reload
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from gseg.rank import Reranker, combine_retrieval_rerank
from gseg.retrieve import RetrieverBM25

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger: logging.Logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class SearchRequest(BaseModel):
    """Request body for the ``/map_event`` endpoint."""

    text: str = Field(
        ...,
        min_length=3,
        description="Log line or security event description to map",
        json_schema_extra={"example": "Detected SSH lateral movement to 10.0.0.5"},
    )
    top_k: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of top techniques to return",
    )
    include_mitigations: bool = Field(
        default=False,
        description="Include recommended mitigations for each technique",
    )


class MitigationResponse(BaseModel):
    """A single mitigation linked to a technique."""

    mitigation_id: str
    name: str
    description: str
    url: Optional[str] = None


class TechniqueResponse(BaseModel):
    """A single technique result returned by the API."""

    technique_id: str
    name: str
    tactics: List[str]
    bm25_score: float
    rerank_score: float
    mitigations: Optional[List[MitigationResponse]] = None
    url: Optional[str] = None


class SearchResponse(BaseModel):
    """Response body for the ``/map_event`` endpoint."""

    query: str
    results: List[TechniqueResponse]
    latency_ms: float


class HealthResponse(BaseModel):
    """Response body for the ``/health`` endpoint."""

    status: str
    models_loaded: bool


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------
models: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Load ML models at startup and release them on shutdown.

    The retriever (BM25 + knowledge graph) and the semantic reranker are
    both loaded into the global ``models`` dict so that every request
    handler can access them without re-loading.
    """
    logger.info("Loading models ...")
    t_start: float = time.monotonic()
    try:
        models["retriever"] = RetrieverBM25()
        models["reranker"] = Reranker()
    except Exception as exc:
        logger.error("Failed to load models: %s", exc)
        raise
    elapsed_ms: float = (time.monotonic() - t_start) * 1000.0
    logger.info("Models loaded successfully in %.0f ms", elapsed_ms)

    yield

    models.clear()
    logger.info("Models released")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app: FastAPI = FastAPI(
    title="ATT&CK Ground Segment Threat Graph API",
    description=(
        "Maps space ground segment logs and security events to MITRE "
        "ATT&CK techniques using BM25 retrieval and semantic reranking."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_models() -> tuple[RetrieverBM25, Reranker]:
    """Retrieve loaded models or raise HTTP 503.

    Returns:
        Tuple of ``(retriever, reranker)``.

    Raises:
        HTTPException: 503 if models are not yet loaded.
    """
    retriever: RetrieverBM25 | None = models.get("retriever")
    reranker: Reranker | None = models.get("reranker")
    if retriever is None or reranker is None:
        raise HTTPException(
            status_code=503,
            detail="Models are not loaded yet. Please try again shortly.",
        )
    return retriever, reranker


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
    summary="Service health check",
)
async def health() -> HealthResponse:
    """Return the health status of the API.

    Reports whether the retriever and reranker models have been
    loaded successfully.
    """
    loaded: bool = "retriever" in models and "reranker" in models
    return HealthResponse(status="ok", models_loaded=loaded)


@app.post(
    "/map_event",
    response_model=SearchResponse,
    tags=["search"],
    summary="Map a security event to ATT&CK techniques",
)
async def map_event(request: SearchRequest) -> SearchResponse:
    """Map a log line or event description to ranked ATT&CK techniques.

    The pipeline first retrieves a broad set of candidates using BM25,
    then reranks them with a sentence-transformer model for semantic
    relevance.  Optionally includes recommended mitigations for each
    returned technique.
    """
    retriever, reranker = _get_models()
    logger.info("POST /map_event -- query=%r top_k=%d", request.text, request.top_k)

    t_start: float = time.monotonic()

    pipeline_result: Dict[str, Any] = combine_retrieval_rerank(
        retriever=retriever,
        reranker=reranker,
        query=request.text,
        bm25_k=20,
        final_k=request.top_k,
    )

    # --- build response ---
    techniques: List[TechniqueResponse] = []
    for hit in pipeline_result["results"]:
        mitigations: Optional[List[MitigationResponse]] = None
        if request.include_mitigations:
            raw_mitigations: List[Dict[str, Any]] = retriever.get_mitigations(
                hit["technique_id"], limit=10
            )
            mitigations = [
                MitigationResponse(
                    mitigation_id=m["mitigation_id"],
                    name=m["name"],
                    description=m["description"],
                    url=m.get("url"),
                )
                for m in raw_mitigations
            ]

        techniques.append(
            TechniqueResponse(
                technique_id=hit["technique_id"],
                name=hit["name"],
                tactics=hit.get("tactics", []),
                bm25_score=hit.get("bm25_score", 0.0),
                rerank_score=hit.get("rerank_score", 0.0),
                mitigations=mitigations,
                url=hit.get("url"),
            )
        )

    elapsed_ms: float = round((time.monotonic() - t_start) * 1000.0, 1)
    logger.info("POST /map_event -- %d results in %.1f ms", len(techniques), elapsed_ms)

    return SearchResponse(
        query=request.text,
        results=techniques,
        latency_ms=elapsed_ms,
    )


@app.get(
    "/techniques",
    response_model=List[TechniqueResponse],
    tags=["browse"],
    summary="List all indexed ATT&CK techniques",
)
async def list_techniques(
    limit: int = Query(default=50, ge=1, le=500, description="Page size"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
) -> List[TechniqueResponse]:
    """Return a paginated list of all ATT&CK techniques in the graph.

    Techniques are returned in alphabetical order by name.  No ranking
    scores are applied (``bm25_score`` and ``rerank_score`` are 0.0).
    """
    retriever, _ = _get_models()
    logger.info("GET /techniques -- limit=%d offset=%d", limit, offset)

    technique_nodes: List[Dict[str, Any]] = []
    for node_id, attrs in retriever.graph.nodes(data=True):
        if attrs.get("type") != "technique":
            continue
        technique_nodes.append(
            {
                "technique_id": node_id,
                "name": attrs.get("name", ""),
                "tactics": attrs.get("tactics", []),
                "url": attrs.get("url"),
            }
        )

    technique_nodes.sort(key=lambda t: t["name"])
    page: List[Dict[str, Any]] = technique_nodes[offset : offset + limit]

    return [
        TechniqueResponse(
            technique_id=t["technique_id"],
            name=t["name"],
            tactics=t["tactics"],
            bm25_score=0.0,
            rerank_score=0.0,
            url=t["url"],
        )
        for t in page
    ]


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------
def main() -> None:
    """Start the API server via uvicorn."""
    uvicorn.run(
        "gseg.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
