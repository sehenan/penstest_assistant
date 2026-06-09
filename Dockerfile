# syntax=docker/dockerfile:1
# ==============================================================================
# SIATI — Système Intelligent d'Assistance aux Tests d'Intrusion
# Image Docker multi-stage, air-gap au runtime, utilisateur non-root.
# Python 3.12 (aligné sur l'environnement de développement validé).
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1 : BUILDER — compile et installe les dépendances dans un venv isolé.
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dépendances système nécessaires à la COMPILATION de certaines roues.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        make \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Environnement virtuel dédié, copié tel quel dans l'image finale.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel

# PyTorch CPU d'abord (depuis l'index officiel CPU) pour éviter les paquets
# CUDA (~2 Go) tirés par sentence-transformers. Version alignée sur .venv.
RUN pip install torch==2.12.0 --index-url https://download.pytorch.org/whl/cpu

# Dépendances applicatives de production.
COPY requirements.txt .
RUN pip install -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 2 : RUNTIME — image légère, sans toolchain de compilation.
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Cache HuggingFace : modèle d'embedding pré-téléchargé à la construction.
    HF_HOME=/opt/hf_cache

# curl : requis uniquement par le HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie du venv complet depuis le builder.
COPY --from=builder /opt/venv /opt/venv

# Pré-téléchargement (build-time) du modèle d'embedding RAG afin que le
# runtime n'effectue AUCUN appel réseau (contrainte air-gap).
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# Code applicatif (les données volumineuses sont montées en volume, cf. compose).
COPY . .

# Répertoires de travail créés à vide (peuplés par les volumes au runtime).
RUN mkdir -p /app/data /app/logs

# Utilisateur non privilégié + appropriation des chemins inscriptibles.
RUN useradd --create-home --uid 1000 siati \
    && chown -R siati:siati /app /opt/hf_cache
USER siati

# --- Configuration runtime ---
ENV SIATI_HOST=0.0.0.0 \
    SIATI_PORT=8505 \
    PENTEST_DB_URL=sqlite:////app/data/pentest.db \
    OLLAMA_HOST=http://127.0.0.1:11434 \
    OLLAMA_MODEL=mistral:7b-instruct-q4_K_M \
    # Air-gap strict : interdit toute résolution réseau HuggingFace au runtime.
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    OMP_NUM_THREADS=1

EXPOSE 8505

# Sonde de santé sur un endpoint réel et léger.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8505/api/stats || exit 1

# `-web` est réécrit en commande `ui` par main.py ; l'écoute 0.0.0.0
# provient de SIATI_HOST (indispensable derrière un port publié Docker).
CMD ["python", "main.py", "-web"]
