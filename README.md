# 🛡️ ATT&CK Ground Segment Threat Graph

[![CI](https://github.com/thierrymaesen/attack-gseg/actions/workflows/ci.yml/badge.svg)](https://github.com/thierrymaesen/attack-gseg/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> An AI-powered security tool that maps ground segment logs to MITRE ATT&CK techniques using semantic search and knowledge graphs. Designed for space operations centers (SOC).

**Author:** [Thierry Maesen](https://github.com/thierrymaesen)
**Repository:** [github.com/thierrymaesen/attack-gseg](https://github.com/thierrymaesen/attack-gseg)

---

## ✨ Features

- 🧠 **Semantic Search** — Combines BM25 retrieval with `all-MiniLM-L6-v2` sentence embeddings for context-aware technique detection.
- 🕸️ **Knowledge Graph** — Navigates relationships between ATT&CK Techniques and Mitigations via a directed NetworkX graph.
- ⚡ **FastAPI Backend** — High-performance REST API with automatic Swagger/OpenAPI documentation.
- 🖥️ **Gradio UI** — Interactive web interface for security analysts to triage events in real time.
- 🏗️ **Production-Ready** — Fully tested (pytest + coverage), linted (Ruff), formatted (Black), and CI/CD integrated (GitHub Actions).

---

## 🚀 Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/thierrymaesen/attack-gseg.git
cd attack-gseg
poetry install
```

### 2. Ingest ATT&CK Data (first run only)

```bash
# Download MITRE ATT&CK STIX bundle and build the knowledge graph
poetry run python -m gseg.ingest_attack
poetry run python -m gseg.build_graph
```

### 3. Run the Application

```bash
# Terminal 1 — Start the API server
poetry run uvicorn gseg.api:app --reload

# Terminal 2 — Start the Gradio UI
poetry run python app/gradio_app.py
```

The API is available at **http://localhost:8000** and the Gradio UI at **http://localhost:7860**.

---

## 🏗️ Architecture

```text
                          ATT&CK Ground Segment Threat Graph
                          ==================================

  +-----------+     +-------------+     +---------------------+     +------------------+
  |  Security |     |   FastAPI   |     |   Retrieval Engine  |     |  Knowledge Graph |
  |   Logs    | --> |   /map_event| --> | BM25 + Reranker     | --> |   (NetworkX)     |
  |  (events) |     |   REST API  |     | (MiniLM embeddings) |     |                  |
  +-----------+     +-------------+     +---------------------+     +------------------+
                          |                                               |
                          v                                               v
                    +----------+                                  +----------------+
                    | Gradio UI|                                  | Techniques     |
                    | (analysts|                                  | Mitigations    |
                    |  triage) |                                  | Relationships  |
                    +----------+                                  +----------------+
```

**Data flow:**

1. **Ingest** — Downloads the MITRE ATT&CK STIX bundle and parses techniques, mitigations, and relationships ([src/gseg/ingest_attack.py](src/gseg/ingest_attack.py)).
2. **Build Graph** — Constructs a directed knowledge graph with technique and mitigation nodes ([src/gseg/build_graph.py](src/gseg/build_graph.py)).
3. **Retrieve** — BM25 keyword search over technique descriptions ([src/gseg/retrieve.py](src/gseg/retrieve.py)).
4. **Rerank** — Semantic reranking with sentence-transformer embeddings ([src/gseg/rank.py](src/gseg/rank.py)).
5. **Serve** — FastAPI exposes `/map_event`, `/techniques`, and `/health` endpoints ([src/gseg/api.py](src/gseg/api.py)).
6. **Visualise** — Gradio provides an interactive analyst interface ([app/gradio_app.py](app/gradio_app.py)).

---

## 📖 API Documentation

Once the API server is running, interactive documentation is available at:

| Docs | URL |
|------|-----|
| Swagger UI | [http://localhost:8000/docs](http://localhost:8000/docs) |
| ReDoc | [http://localhost:8000/redoc](http://localhost:8000/redoc) |

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `POST` | `/map_event` | Map a security event to ranked ATT&CK techniques |
| `GET` | `/techniques` | Paginated list of all indexed techniques |

### Example Request

```bash
curl -X POST http://localhost:8000/map_event \
  -H "Content-Type: application/json" \
  -d '{"text": "Detected SSH lateral movement to 10.0.0.5", "top_k": 5}'
```

---

## 🧪 Testing

```bash
# Run all tests with coverage report
poetry run pytest tests/ -v --cov=src --cov-report=term-missing

# Run linting
poetry run ruff check src/ tests/

# Check formatting
poetry run black --check src/ tests/
```

Tests cover data ingestion, graph building, BM25 retrieval, semantic reranking, and all FastAPI endpoints.

---

## 📁 Project Structure

```text
attack-gseg/
├── .github/workflows/ci.yml   # GitHub Actions CI pipeline
├── app/
│   └── gradio_app.py              # Gradio web interface
├── src/gseg/
│   ├── __init__.py                # Package metadata
│   ├── ingest_attack.py           # STIX data ingestion
│   ├── build_graph.py             # Knowledge graph construction
│   ├── retrieve.py                # BM25 retrieval engine
│   ├── rank.py                    # Semantic reranking
│   └── api.py                     # FastAPI REST API
├── tests/
│   ├── test_ingest.py             # Ingestion tests
│   ├── test_graph.py              # Graph building tests
│   ├── test_retrieve.py           # Retrieval tests
│   ├── test_rank.py               # Reranking tests
│   └── test_api.py                # API endpoint tests
├── pyproject.toml                 # Poetry project config
└── README.md                      # This file
```

---

## 📊 Development Status

**Sprint Progress:** 11/11 completed

- [x] Sprint 0 — Project setup
- [x] Sprint 1 — Data ingestion (ATT&CK STIX)
- [x] Sprint 2 — Graph building (NetworkX)
- [x] Sprint 3 — Retrieval engine (BM25)
- [x] Sprint 4 — Reranking (embeddings)
- [x] Sprint 5 — API (FastAPI)
- [x] Sprint 6 — UI (Gradio)
- [x] Sprint 7 — Tests (pytest)
- [x] Sprint 8 — Evaluation
- [x] Sprint 9 — CI/CD (GitHub Actions)
- [x] Sprint 10 — Documentation

---

## 🗺️ Roadmap

- [ ] Add graph embeddings (Node2Vec) for improved link prediction and technique similarity.
- [ ] Support streaming log ingestion via Kafka or NATS for real-time monitoring.
- [ ] Deploy to Hugging Face Spaces with a Docker-based runtime.
- [ ] Integrate MITRE ATT&CK sub-techniques for finer-grained mapping.
- [ ] Add STIX/TAXII feed support for automated threat intelligence updates.

---

## 🤝 Contributing

Pull requests are welcome. Please open an issue first to discuss what you would like to change.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit your changes (`git commit -m "Add my feature"`).
4. Push to the branch (`git push origin feature/my-feature`).
5. Open a pull request.

Please ensure all tests pass and code follows the project style (Black + Ruff) before submitting.

---

## 📜 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

ATT&CK data provided by [MITRE ATT&CK®](https://attack.mitre.org/). MITRE ATT&CK is a registered trademark of The MITRE Corporation.
