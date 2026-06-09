# SIATI — Déploiement Docker

Stack conteneurisée : **SIATI (FastAPI)** + **Ollama (LLM)** + **Redis (cache)**.
Image Python 3.12, multi-stage, utilisateur non-root, runtime air-gap.

## Prérequis
- Docker Engine + Docker Compose v2 (`docker compose version`)
- ~8 Go d'espace disque (image ML + modèle Ollama ~4 Go)
- Les données (`./data`) présentes : `pentest.db`, `threat_intel.db`, `cpe.db`,
  `exploits.db`, `faiss_index/`, `knowledge_base/`, `model/`.

## Démarrage (une commande)
```bash
docker compose up -d --build
```
Au **premier** lancement, le service `ollama-init` télécharge le modèle
`mistral:7b-instruct-q4_K_M` (~4 Go) avant que `siati` ne démarre. C'est normal
que ce premier `up` soit long ; les suivants sont quasi instantanés (modèle mis
en cache dans le volume `ollama-data`).

Interface : http://localhost:8505

## Suivi / exploitation
```bash
docker compose ps                 # état + santé des services
docker compose logs -f siati      # logs applicatifs
docker compose logs -f ollama-init# progression du téléchargement du modèle
docker compose down               # arrêt (volumes conservés)
docker compose down -v            # arrêt + suppression des volumes
```

## Commandes CLI dans le conteneur
```bash
docker compose exec siati python main.py check
docker compose exec siati python main.py ingest /app/data/inputs/scan.xml
docker compose exec siati python main.py enrich
docker compose exec siati python main.py score
docker compose exec siati python main.py playbook <vuln_id>
```

## Choix d'architecture (best practices)
- **Multi-stage** : compilation isolée dans le builder, image finale sans
  toolchain (`gcc`, `g++`…), venv copié depuis `/opt/venv`.
- **Python 3.12-slim** : aligné sur l'environnement de développement validé.
- **PyTorch CPU** installé depuis l'index officiel CPU (évite ~2 Go de CUDA).
- **Modèle d'embedding RAG pré-téléchargé** à la construction → aucun appel
  réseau au runtime (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`).
- **Non-root** (`siati`, uid 1000), `HEALTHCHECK` sur `/api/stats`.
- **Écoute `0.0.0.0`** via `SIATI_HOST` (indispensable derrière un port publié).
- **Dépendances épinglées** (`requirements.txt`), test/qualité séparés
  (`requirements-dev.txt`). `bcrypt==4.0.1` pour compatibilité passlib 1.7.4.
- **Données persistantes** via volumes (`./data`, `./logs`, `ollama-data`,
  `redis-data`) — non incluses dans l'image.

## Variables d'environnement clés
| Variable | Défaut (conteneur) | Rôle |
|---|---|---|
| `SIATI_HOST` / `SIATI_PORT` | `0.0.0.0` / `8505` | Écoute du serveur |
| `PENTEST_DB_URL` | `sqlite:////app/data/pentest.db` | Base SQLite |
| `OLLAMA_HOST` | `http://ollama:11434` | Serveur LLM |
| `OLLAMA_MODEL` | `mistral:7b-instruct-q4_K_M` | Modèle de génération |
| `OLLAMA_TIMEOUT` | `1800` | Timeout génération (s) |
| `REDIS_HOST` / `REDIS_PORT` | `redis` / `6379` | Cache (fallback mémoire) |
