"""
VulnFix — FastAPI backend
Sert l'interface HTML statique et expose les endpoints REST
connectés à la base SQLite + ML (XGBoost) + LLM (Ollama/RAG).
"""
import sys
import os
from pathlib import Path

# ── path resolution ──────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT))

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import init_db
from app.utils.error_handler import app_error_handler
from app.api.main_api import api_router
from app.core.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Chemins importants ────────────────────────────────────────────────────────
TEMPLATES_DIR = ROOT / "app" / "templates"
STATIC_DIR = ROOT / "app" / "static"
ASSETS_DIR = ROOT / "app" / "ui" / "assets"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    # Préchargement du modèle d'embedding RAG pour éviter le blocage à la 1ère requête
    try:
        from app.core.llm.rag import _get_embed_model
        import asyncio
        await asyncio.get_event_loop().run_in_executor(None, _get_embed_model)
        logger.info("Modèle RAG (SentenceTransformer) préchargé.")
    except Exception as e:
        logger.warning("Préchargement RAG ignoré : %s", e)
    yield


# ── app setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulnFix API",
    description="Système Intelligent d'Assistance aux Tests d'Intrusion",
    version="1.0.0",
    lifespan=lifespan,
    # Désactiver la doc Swagger en production
    docs_url=None if settings.VULNFIX_ENV == "production" else "/docs",
    redoc_url=None if settings.VULNFIX_ENV == "production" else "/redoc",
)

# ── Gestionnaire d'erreurs global ─────────────────────────────────────────────
app.add_exception_handler(Exception, app_error_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Si VULNFIX_CORS_ORIGINS vaut "*", on ouvre tout (dev/air-gap).
# Sinon, liste d'origines stricte (prod).
_cors_raw = settings.VULNFIX_CORS_ORIGINS.strip()
_cors_wildcard = _cors_raw == "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _cors_wildcard else [o.strip() for o in _cors_raw.split(",")],
    allow_credentials=not _cors_wildcard,  # credentials incompatible avec wildcard
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Fichiers statiques ────────────────────────────────────────────────────────
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

DATA_DIR = ROOT / "data"
if DATA_DIR.exists():
    app.mount("/data", StaticFiles(directory=str(DATA_DIR)), name="evaluation-data")

# ── Routes HTML ───────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_ui(request: Request):
    """Redirige vers /login si le cookie d'authentification est absent."""
    token = request.cookies.get("vulnfix_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return RedirectResponse(url="/login", status_code=302)
    html_path = TEMPLATES_DIR / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    html_path = TEMPLATES_DIR / "login.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

# ── Routes API ────────────────────────────────────────────────────────────────
app.include_router(api_router)

# ── Point d'entrée direct (développement uniquement) ─────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.ui.server:app",
        host=settings.VULNFIX_HOST,
        port=settings.VULNFIX_PORT,
        reload=(settings.VULNFIX_ENV == "development"),
        log_level=settings.LOG_LEVEL.lower(),
    )
