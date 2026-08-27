from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    """Configuration centralisée de l'application SIATI."""
    
    # Mode d'environnement
    SIATI_ENV: str = "development"
    
    # Serveur web
    SIATI_HOST: str = "127.0.0.1"
    SIATI_PORT: int = 8505
    
    # Base de données
    SIATI_DB_PATH: str = "data/pentest.db"
    
    # Sécurité
    SIATI_REQUIRE_AUTH: bool = False
    SIATI_CORS_ORIGINS: str = "http://localhost:8505"
    SECRET_KEY: Optional[str] = None
    
    # LLM (Ollama)
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"
    OLLAMA_TIMEOUT: int = 1800
    
    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

_settings = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
