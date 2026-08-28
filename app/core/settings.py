from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Configuration centralisée de l'application SIATI.

    Toutes les valeurs peuvent être surchargées via un fichier .env
    (copier .env.example -> .env) ou des variables d'environnement.
    Priorité : variable d'env > .env > valeur par défaut ci-dessous.
    """

    # ── Environnement ──────────────────────────────────────────────────────────
    # "development" : logs verbeux, rechargement automatique uvicorn.
    # "production"  : workers Gunicorn, auth obligatoire, CORS strict.
    SIATI_ENV: str = "development"

    # ── Serveur Web ────────────────────────────────────────────────────────────
    SIATI_HOST: str = "127.0.0.1"
    SIATI_PORT: int = 8505
    # Nombre de workers Gunicorn (production uniquement, ignoré en dev)
    SIATI_WORKERS: int = 2

    # ── Base de données ────────────────────────────────────────────────────────
    # Chemin relatif à la racine du projet ou absolu.
    SIATI_DB_PATH: str = "data/pentest.db"

    # ── Sécurité ───────────────────────────────────────────────────────────────
    SIATI_REQUIRE_AUTH: bool = False
    # Origines autorisées pour le CORS (séparées par des virgules).
    SIATI_CORS_ORIGINS: str = "http://localhost:8505"
    # OBLIGATOIRE en production : clé secrète JWT (min. 32 caractères).
    SECRET_KEY: Optional[str] = None
    # Durée de validité d'un token JWT (en minutes).
    JWT_EXPIRE_MINUTES: int = 1440  # 24 h

    # ── Authentification admin ─────────────────────────────────────────────────
    SIATI_ADMIN_USER: str = "admin"
    SIATI_ADMIN_PASSWORD: str = "admin"

    # ── LLM (Ollama) ───────────────────────────────────────────────────────────
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"       # mistral, llama3, phi3, etc.
    OLLAMA_TIMEOUT: int = 1800         # secondes
    OLLAMA_MAX_TOKENS: int = 2048
    OLLAMA_TEMPERATURE: float = 0.1    # Basse pour limiter les hallucinations

    # ── RAG (Recherche Vectorielle FAISS) ──────────────────────────────────────
    RAG_KNOWLEDGE_DIR: str = "data/knowledge_base"
    RAG_INDEX_PATH: str = "data/faiss_index/pentest.index"
    RAG_CHUNKS_PATH: str = "data/faiss_index/chunks.json"
    RAG_EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"
    RAG_CHUNK_SIZE: int = 500
    RAG_CHUNK_OVERLAP: int = 50
    RAG_TOP_K: int = 5
    RAG_TOP_N_VULNS: int = 10

    # ── Cache / Rate limiting ──────────────────────────────────────────────────
    # Redis est optionnel : le système bascule sur un cache en mémoire si indispo.
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    # ── Journalisation ─────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/siati.log"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Retourne le singleton Settings (chargé une seule fois)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
