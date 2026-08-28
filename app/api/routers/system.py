from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.db.database import get_session
from app.db.models import Host, Service, Vulnerability, ScoreML, Report
from app.core.security import require_auth

router = APIRouter(tags=["system"])

@router.get("/health")
def health_check():
    """Sonde de disponibilité (déploiement / monitoring)."""
    services = {}
    try:
        session = get_session()
        try:
            session.query(Vulnerability).count()
            services["database"] = "up"
        finally:
            session.close()
    except Exception:
        services["database"] = "down"

    try:
        from app.core.llm.ollama_client import check_ollama_status
        services["ollama"] = "up" if check_ollama_status() else "down"
    except Exception:
        services["ollama"] = "down"

    return {
        "status": "healthy",
        "services": services,
        "timestamp": datetime.utcnow().isoformat(),
    }

@router.delete("/api/clear-db")
def clear_database(_auth=Depends(require_auth)):
    """Vider complètement la base de données (hôtes, services, vulnérabilités, scores, rapports)."""
    session = get_session()
    try:
        session.query(Report).delete()
        session.query(ScoreML).delete()
        session.query(Vulnerability).delete()
        session.query(Service).delete()
        session.query(Host).delete()
        session.commit()
        return {"ok": True, "message": "Base de données entièrement vidée"}
    except Exception as e:
        session.rollback()
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()

@router.get("/api/audit")
def get_audit_log():
    return [
        {"ts": datetime.utcnow().isoformat(), "action": "Système", "details": "Plateforme démarrée en mode air-gap"}
    ]
