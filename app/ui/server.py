"""
SIATI — FastAPI backend
Sert l'interface HTML statique et expose les endpoints REST
connectés à la base SQLite + ML (XGBoost) + LLM (Ollama/RAG).
"""
import sys
import os
from pathlib import Path

# ── path resolution ──────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT))

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import init_db
from app.core.error_handler import app_error_handler
from app.api.main_api import api_router

# ── app setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SIATI API",
    description="Système Intelligent d'Assistance aux Tests d'Intrusion",
    version="1.0.0",
)

# Add global error handler
app.add_exception_handler(Exception, app_error_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

UI_DIR = Path(__file__).parent

# ── serve static HTML ─────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_path = UI_DIR / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

# ── Include API Routes ────────────────────────────────────────────────────────
app.include_router(api_router)

# ── serve evaluation data static ──────────────────────────────────────────────
DATA_DIR = ROOT / "data"
if DATA_DIR.exists():
    app.mount("/data", StaticFiles(directory=str(DATA_DIR)), name="evaluation-data")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8505)
