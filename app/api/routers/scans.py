import os
import tempfile
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Depends
from fastapi.responses import JSONResponse
from app.db.database import get_session
from app.core.security import require_auth

router = APIRouter(prefix="/api/ingest", tags=["scans"])

@router.post("")
async def ingest_scan(file: UploadFile = File(...), auto_pilot: bool = True, _auth=Depends(require_auth)):
    suffix = Path(file.filename).suffix
    if not suffix:
        suffix = ".xml"
    
    content = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    session = get_session()
    try:
        if auto_pilot:
            from app.core.pipeline import FullPipeline
            pipeline = FullPipeline(session)
            result = pipeline.run(tmp_path)
            return {
                "ok": result.get("ok", False),
                "auto_pilot": True,
                "stats": result.get("stats"),
                "filename": file.filename,
                "error": result.get("error")
            }
        else:
            from app.core.ingest import ingest_scan_file
            counts = ingest_scan_file(tmp_path, session)
            return {"ok": True, "auto_pilot": False, "counts": counts, "filename": file.filename}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except:
            pass
