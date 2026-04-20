"""
SIATI — FastAPI backend
Sert l'interface HTML statique et expose les endpoints REST
connectés à la base SQLite + ML (XGBoost) + LLM (Ollama/RAG).
"""
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List

# ── path resolution ──────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT))

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.db.database import init_db, get_session
from app.db.models import Host, Service, Vulnerability, ScoreML, Report, Exploit

# ── app setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SIATI API",
    description="Système Intelligent d'Assistance aux Tests d'Intrusion",
    version="1.0.0",
)

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

# ═══════════════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1. STATS GLOBALES ─────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    session = get_session()
    try:
        total_vulns = session.query(Vulnerability).count()
        total_hosts = session.query(Host).count()

        label_counts = {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0}
        scores = session.query(ScoreML).all()
        for s in scores:
            lbl = (s.label or "").lower()
            if lbl in label_counts:
                label_counts[lbl] += 1

        total_reports = session.query(Report).count()
        total_scans = session.query(Host).count()

        avg_cvss = 0.0
        cvss_vals = [v.cvss_score for v in session.query(Vulnerability).all() if v.cvss_score]
        if cvss_vals:
            avg_cvss = round(sum(cvss_vals) / len(cvss_vals), 1)

        return {
            "total_vulns": total_vulns,
            "total_hosts": total_hosts,
            "total_reports": total_reports,
            "avg_cvss": avg_cvss,
            **label_counts,
        }
    finally:
        session.close()


# ── 2. HÔTES ─────────────────────────────────────────────────────────────────
@app.get("/api/hosts")
def get_hosts():
    session = get_session()
    try:
        hosts = session.query(Host).all()
        result = []
        for h in hosts:
            ports = [s.port for s in h.services]
            vuln_colors = []
            for svc in h.services:
                for v in svc.vulnerabilities:
                    latest = (
                        session.query(ScoreML)
                        .filter(ScoreML.vuln_id == v.id)
                        .order_by(ScoreML.timestamp.desc())
                        .first()
                    )
                    if latest:
                        vuln_colors.append(latest.label or "faible")
            result.append({
                "id": h.id,
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os,
                "ports": ports,
                "vuln_labels": vuln_colors,
            })
        return result
    finally:
        session.close()


# ── 3. VULNÉRABILITÉS ────────────────────────────────────────────────────────
@app.get("/api/vulns")
def get_vulns(severity: str = "", source: str = "", q: str = ""):
    session = get_session()
    try:
        query = session.query(Vulnerability)
        vulns = query.all()

        result = []
        for v in vulns:
            svc = v.service
            host = svc.host if svc else None

            latest_score = (
                session.query(ScoreML)
                .filter(ScoreML.vuln_id == v.id)
                .order_by(ScoreML.timestamp.desc())
                .first()
            )
            score_val = round(latest_score.score, 3) if latest_score and latest_score.score else None
            label = (latest_score.label or "faible") if latest_score else "faible"

            exploit = session.query(Exploit).filter(Exploit.cve == v.cve).first()
            exploit_info = None
            if exploit:
                if exploit.metasploit_module:
                    exploit_info = f"msf:{exploit.metasploit_module}"
                elif exploit.exploit_db_id:
                    exploit_info = f"edb:{exploit.exploit_db_id}"

            report = (
                session.query(Report)
                .filter(Report.vuln_id == v.id)
                .order_by(Report.timestamp.desc())
                .first()
            )

            item = {
                "id": v.id,
                "cve": v.cve,
                "description": v.description or "",
                "cvss": v.cvss_score,
                "cwe": v.cwe,
                "source": v.source,
                "ip": host.ip if host else "?",
                "port": svc.port if svc else None,
                "service": svc.service if svc else None,
                "protocol": svc.protocol if svc else None,
                "score_ml": score_val,
                "label": label,
                "exploit": exploit_info,
                "has_report": report is not None,
                "report_id": report.id if report else None,
            }

            # filtres
            if severity and label.lower() != severity.lower():
                continue
            if source and (v.source or "").lower() != source.lower():
                continue
            if q:
                needle = q.lower()
                if not any(needle in str(x).lower() for x in [v.cve, v.description, host.ip if host else "", svc.service if svc else ""]):
                    continue

            result.append(item)

        # tri par score ML décroissant
        result.sort(key=lambda x: x["score_ml"] or 0, reverse=True)
        return result
    finally:
        session.close()


# ── 4. DÉTAIL VULNÉRABILITÉ ───────────────────────────────────────────────────
@app.get("/api/vulns/{vuln_id}")
def get_vuln_detail(vuln_id: int):
    session = get_session()
    try:
        v = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not v:
            raise HTTPException(status_code=404, detail="Vulnérabilité introuvable")

        svc = v.service
        host = svc.host if svc else None

        scores_history = [
            {"score": s.score, "label": s.label, "ts": s.timestamp.isoformat()}
            for s in v.scores
        ]

        reports = [
            {
                "id": r.id,
                "title": r.title,
                "stage": r.stage,
                "ts": r.timestamp.isoformat(),
                "preview": (r.content_md or "")[:400],
            }
            for r in session.query(Report).filter(Report.vuln_id == v.id).order_by(Report.timestamp.desc()).all()
        ]

        exploit = session.query(Exploit).filter(Exploit.cve == v.cve).first()

        return {
            "id": v.id,
            "cve": v.cve,
            "description": v.description,
            "cvss": v.cvss_score,
            "cvss_vector": v.cvss_vector,
            "cwe": v.cwe,
            "source": v.source,
            "ip": host.ip if host else "?",
            "hostname": host.hostname if host else None,
            "port": svc.port if svc else None,
            "service": svc.service if svc else None,
            "version": svc.version if svc else None,
            "banner": svc.banner if svc else None,
            "scores_history": scores_history,
            "reports": reports,
            "exploit_msf": exploit.metasploit_module if exploit else None,
            "exploit_edb": exploit.exploit_db_id if exploit else None,
        }
    finally:
        session.close()


# ── 5. RAPPORTS ───────────────────────────────────────────────────────────────
@app.get("/api/reports")
def get_reports():
    session = get_session()
    try:
        reports = session.query(Report).order_by(Report.timestamp.desc()).all()
        result = []
        for r in reports:
            v = session.query(Vulnerability).filter(Vulnerability.id == r.vuln_id).first()
            result.append({
                "id": r.id,
                "title": r.title,
                "stage": r.stage,
                "cve": v.cve if v else None,
                "ts": r.timestamp.isoformat(),
                "size": len(r.content_md or ""),
            })
        return result
    finally:
        session.close()


@app.get("/api/reports/{report_id}")
def get_report_content(report_id: int):
    session = get_session()
    try:
        r = session.query(Report).filter(Report.id == report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Rapport introuvable")
        return {
            "id": r.id,
            "title": r.title,
            "stage": r.stage,
            "content_md": r.content_md,
            "ts": r.timestamp.isoformat(),
        }
    finally:
        session.close()


@app.delete("/api/reports/{report_id}")
def delete_report(report_id: int):
    """Supprime un rapport de la base de données."""
    session = get_session()
    try:
        r = session.query(Report).filter(Report.id == report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Rapport introuvable")
        session.delete(r)
        session.commit()
        return {"ok": True, "message": "Rapport supprimé"}
    except Exception as e:
        session.rollback()
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()


# ── 6. GÉNÉRATION PLAYBOOK ────────────────────────────────────────────────────
class PlaybookRequest(BaseModel):
    vuln_id: int
    mode: str = "audit"  # "audit" ou "payload"


@app.post("/api/generate")
def generate_playbook(req: PlaybookRequest):
    """Lance la génération LLM+RAG pour une vulnérabilité donnée."""
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
        return JSONResponse(status_code=500, content={"ok": False, "error": "Génération échouée"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()


# ── 7. INGESTION SCAN ─────────────────────────────────────────────────────────
@app.post("/api/ingest")
async def ingest_scan(file: UploadFile = File(...), auto_pilot: bool = True):
    """
    Upload et ingestion d'un fichier de scan (XML/nessus).
    Si auto_pilot est True, lance le pipeline complet (Enrichissement + ML).
    """
    import tempfile, shutil
    suffix = Path(file.filename).suffix
    if not suffix:
        suffix = ".xml"
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
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



# ── 8. PIPELINE AUTO (score ML) ───────────────────────────────────────────────
@app.post("/api/score")
def run_ml_score():
    """Relance l'inférence XGBoost sur toutes les vulnérabilités."""
    session = get_session()
    try:
        from app.core.ml.data_manager import DataManager
        from app.core.ml.predict import predict_and_store
        dm = DataManager()
        df = dm.extract_real_data(session)
        if df.empty:
            return {"ok": False, "error": "Aucune donnée en base"}
        stats = predict_and_store(session, df)
        return {"ok": True, "scored": stats}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()


# ── 9. AUDIT LOG ──────────────────────────────────────────────────────────────
@app.get("/api/audit")
def get_audit():
    """Retourne l'historique des rapports générés comme journal d'audit."""
    session = get_session()
    try:
        reports = session.query(Report).order_by(Report.timestamp.desc()).limit(100).all()
        entries = []
        for r in reports:
            v = session.query(Vulnerability).filter(Vulnerability.id == r.vuln_id).first()
            entries.append({
                "ts": r.timestamp.strftime("%d/%m/%Y %H:%M:%S"),
                "action": r.stage or "report",
                "details": r.title,
                "cve": v.cve if v else None,
                "status": "OK",
            })
        return entries
    finally:
        session.close()
