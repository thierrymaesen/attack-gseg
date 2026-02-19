# ATT&CK Ground Segment Threat Graph

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> MITRE ATT&CK threat intelligence mapper for space ground segment operations

**Author:** [Thierry Maesen](https://github.com/thierrymaesen)  
**Repository:** [github.com/thierrymaesen/attack-gseg](https://github.com/thierrymaesen/attack-gseg)

---

## 🎯 Project Goal

Map ground segment logs and security events to MITRE ATT&CK techniques using:
- BM25 retrieval + sentence embeddings
- Knowledge graph (techniques → mitigations)
- FastAPI backend + Gradio UI

---

## 🚧 Development Status

**Sprint Progress:** 3/11 completed

- [x] Sprint 0 — Project setup
- [x] Sprint 1 — Data ingestion (ATT&CK STIX)
- [x] Sprint 2 — Graph building (NetworkX)
- [ ] Sprint 3 — Retrieval engine (BM25)
- [ ] Sprint 4 — Reranking (embeddings)
- [ ] Sprint 5 — API (FastAPI)
- [ ] Sprint 6 — UI (Gradio)
- [ ] Sprint 7 — Tests (pytest)
- [ ] Sprint 8 — Evaluation
- [ ] Sprint 9 — CI/CD (GitHub Actions)
- [ ] Sprint 10 — Documentation

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/thierrymaesen/attack-gseg.git
cd attack-gseg

# Install dependencies
poetry install

# Verify installation
poetry run python -c "from gseg import __version__; print(__version__)"
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

**Data sources:**
- [MITRE ATT&CK®](https://attack.mitre.org/) (©2024 The MITRE Corporation) — Used under Terms of Use

---

## 🤝 Contributing

This is a portfolio project. Issues and PRs welcome!
