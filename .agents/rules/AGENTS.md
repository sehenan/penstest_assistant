# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

**SIATI** (Système Intelligent d'Assistance aux Tests d'Intrusion) is an AI-powered pentest assistant that ingests security scan files (Nmap, Nessus, OpenVAS), enriches vulnerabilities with NVD/CPE/Exploit-DB data, scores them with XGBoost ML, and generates exploitation playbooks via a RAG + Ollama LLM pipeline. The app exposes a FastAPI backend serving a static HTML dashboard.

## Commands

### Run the app
```bash
python main.py -web           # Start FastAPI UI on http://127.0.0.1:8505
python main.py -web --port 9000  # Custom port
```

### CLI pipeline commands
```bash
python main.py ingest scan.xml          # Phase 1: parse and store scan file
python main.py enrich                   # Phase 2: NVD/CPE/Exploit-DB enrichment
python main.py train                    # Phase 3a: train XGBoost model
python main.py score                    # Phase 3b: run ML inference, store scores
python main.py playbook <vuln_id>       # Phase 4: generate audit playbook via RAG+Ollama
python main.py playbook-v2 <vuln_id>    # Phase 4 PRO: strict RAG with source citations
python main.py auto scan.xml            # Full end-to-end pipeline
python main.py index-rag-v2             # Index knowledge base into FAISS
python main.py check                    # System diagnostics
python main.py setup-data               # Initialize CPE/Exploit enrichment DBs
```

### Tests
```bash
pytest tests/ -v
pytest tests/ --cov=app --cov-report=html
pytest tests/test_security.py -v        # Single file
pytest tests/ -k "test_name"            # Single test
```

### Code quality
```bash
black app/ tests/
flake8 app/ tests/
mypy app/
```

### Docker
```bash
docker-compose up -d
docker-compose --profile production up -d
docker-compose --profile monitoring up -d   # Includes Prometheus + Grafana
```

## Architecture

### Data flow
```
Scan file (XML/Nessus/OpenVAS)
  → app/core/parsers/          (detect format, parse to common structure)
  → app/core/normalizer/       (deduplicate, upsert into SQLite)
  → app/core/enrichment/       (NVD CVSS/EPSS/KEV, CPE→CVE mapping, Exploit-DB)
  → app/core/ml/               (XGBoost scoring + SHAP explanations)
  → app/core/llm/ or app/module_llm/  (RAG retrieval + Ollama playbook generation)
  → app/db/models.py           (SQLAlchemy: Host→Service→Vulnerability→ScoreML→Report)
```

### Key layers

**`app/db/`** — SQLAlchemy models + SQLite. Core entities: `Host → Service → Vulnerability → ScoreML`, `Exploit`, `Report`. The `ScoreML.reasoning` field stores XAI explanations.

**`app/core/parsers/`** — Format detection (`detect.py`) + dedicated parsers for Nmap XML, Nessus `.nessus`, OpenVAS XML, and plain-text. All parsers return the same normalized dict structure consumed by `normalizer.py`.

**`app/core/enrichment/`** — Offline-first enrichment against local SQLite caches (`data/cpe.db`, `data/exploits.db`) and NVD bulk JSON. No live internet calls during enrichment.

**`app/core/ml/`** — `DataManager` assembles training features from the DB; `train.py` fits XGBoost; `predict.py` runs inference and persists `ScoreML` rows. Model saved to `data/model_xgb.joblib`.

**`app/core/llm/`** — Lightweight RAG using FAISS (`rag.py`) + Ollama HTTP client (`ollama_client.py`) + `generator.py` that writes `Report` rows.

**`app/module_llm/`** — Upgraded V2 RAG/LLM stack: `rag/indexer.py` (Tiktoken chunking + metadata), `rag/retriever.py`, `module_llm/llm/generator.py` (strict source-citation prompting), accessed via `playbook-v2` and `index-rag-v2` CLI commands.

**`app/ui/server.py`** — FastAPI app. Serves `app/ui/index.html` as the SPA root. All REST routes are registered in `app/api/main_api.py` via `api_router`.

**`app/core/pipeline.py`** — `FullPipeline.run()` chains all phases sequentially for programmatic use (used by `auto` CLI command).

### Configuration
`config.yaml` is the single config file (DB path, RAG parameters, Ollama URL/model/timeout). Override with environment variables: `SIATI_DB_PATH`, `OLLAMA_HOST`, `OLLAMA_MODEL`, `SECRET_KEY`, `REDIS_HOST`.

### External dependencies
- **Ollama** must be running locally (`http://localhost:11434`) with the configured model (default: `mistral`) for playbook generation.
- **Redis** is optional; the cache layer falls back to in-memory if unavailable.
- Enrichment DBs (`data/cpe.db`, `data/exploits.db`) must exist; run `python main.py setup-data` to initialize them.

### Tests layout
`tests/` contains unit tests (`test_security.py`, `test_error_handler.py`, `test_ml.py`, `test_parsers.py`), integration tests (`test_ingest.py`, `test_nvd.py`), and E2E tests (`test_integration_e2e.py`, `test_e2e_empty_scan.py`). `config_test.yaml` provides test-specific config. `scratch/` holds throwaway debug scripts — not part of the test suite.
