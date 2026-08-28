from typing import List
from fastapi import APIRouter
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from app.db.database import get_session
from app.db.models import Report

router = APIRouter(prefix="/api", tags=["playbooks"])

class PlaybookRequest(BaseModel):
    vuln_id: int
    mode: str = "audit"

class ChatRequest(BaseModel):
    vuln_id: int
    message: str
    history: List[dict] = []

@router.post("/generate")
def generate_playbook(req: PlaybookRequest):
    from app.core.llm.ollama_client import check_ollama_status
    if not check_ollama_status():
        return JSONResponse(
            status_code=503,
            content={"ok": False, "error": "Ollama inaccessible. Lancez Ollama avec : ollama serve"},
        )
    session = get_session()
    try:
        from app.core.llm.generator import generate_playbook_for_vulnerability
        report_id = generate_playbook_for_vulnerability(session, req.vuln_id, mode=req.mode)
        if report_id:
            r = session.query(Report).filter(Report.id == report_id).first()
            return {
                "ok": True,
                "report_id": report_id,
                "title": r.title if r else "",
                "content_md": r.content_md if r else "",
                "stage": req.mode,
            }
        return JSONResponse(status_code=500, content={"ok": False, "error": "Génération échouée — réponse LLM vide ou invalide"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()

@router.post("/chat")
def chat_endpoint(req: ChatRequest):
    from app.core.llm.ollama_client import check_ollama_status

    if not check_ollama_status():
        return JSONResponse(
            status_code=503,
            content={"ok": False, "error": "Ollama inaccessible. Lancez Ollama avec : ollama serve"},
        )

    session = get_session()
    try:
        from app.core.llm.generator import chat_with_vulnerability_stream
        messages = req.history + [{"role": "user", "content": req.message}]
        stream = chat_with_vulnerability_stream(session, req.vuln_id, messages)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()

    def gen():
        try:
            for chunk in stream:
                yield chunk
        except Exception as e:
            yield f"\n\n⚠️ Erreur de génération : {e}"

    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")
