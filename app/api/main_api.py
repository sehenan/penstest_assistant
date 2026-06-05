import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.db.database import get_session
from app.db.models import Host, Service, Vulnerability, ScoreML, Report, Exploit
from app.core.security import rate_limit
from app.core.error_handler import DatabaseError

ROOT = Path(__file__).resolve().parents[2]

api_router = APIRouter()

# ── 1. STATS GLOBALES ─────────────────────────────────────────────────────────
@api_router.get("/api/stats")
@rate_limit(limit=60, window=60)
def get_stats(request: Request):
    session = get_session()
    try:
        total_vulns = session.query(Vulnerability).count()
        total_hosts = session.query(Host).count()

        label_counts = {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0, "info": 0}
        scores = session.query(ScoreML).all()
        for s in scores:
            lbl = (s.label or "").lower()
            if lbl == "moyen": lbl = "moyenne"
            if lbl == "haut": lbl = "haute"

            if lbl in label_counts:
                label_counts[lbl] += 1

        total_reports = session.query(Report).count()

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
    except Exception as e:
        raise DatabaseError(f"Failed to fetch stats: {str(e)}")
    finally:
        session.close()

# ── 2. HÔTES ─────────────────────────────────────────────────────────────────
@api_router.get("/api/hosts")
def get_hosts():
    session = get_session()
    try:
        hosts = session.query(Host).all()
        result = []
        for h in hosts:
            ports = [s.port for s in h.services]
            if not ports:
                continue
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
@api_router.get("/api/vulns")
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

            score_obj = session.query(ScoreML).filter(ScoreML.vuln_id == v.id).order_by(ScoreML.timestamp.desc()).first()
            score_val = score_obj.score if score_obj else 0
            label = score_obj.label if score_obj else "Info"
            reasoning = score_obj.reasoning if score_obj else ""

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
                "reasoning": reasoning,
                "exploit": exploit_info,
                "has_report": report is not None,
                "report_id": report.id if report else None,
                "timestamp": v.timestamp.isoformat() if v.timestamp else None,
            }

            if severity and label.lower() != severity.lower():
                continue
            if source and (v.source or "").lower() != source.lower():
                continue
            if q:
                needle = q.lower()
                if not any(needle in str(x).lower() for x in [v.cve, v.description, host.ip if host else "", svc.service if svc else ""]):
                    continue

            result.append(item)

        result.sort(key=lambda x: x["score_ml"] or 0, reverse=True)
        return result
    finally:
        session.close()

@api_router.delete("/api/vulns/{vuln_id}")
def delete_vuln(vuln_id: int):
    session = get_session()
    try:
        v = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not v:
            raise HTTPException(status_code=404, detail="Vulnérabilité introuvable")

        svc  = v.service
        host = svc.host if svc else None

        session.query(Report).filter(Report.vuln_id == vuln_id).delete()
        session.query(ScoreML).filter(ScoreML.vuln_id == vuln_id).delete()

        session.delete(v)
        session.flush()

        deleted_service = False
        deleted_host    = False

        if svc:
            remaining_vulns = (
                session.query(Vulnerability)
                .filter(Vulnerability.service_id == svc.id)
                .count()
            )
            if remaining_vulns == 0:
                session.delete(svc)
                session.flush()
                deleted_service = True

                if host:
                    remaining_services = (
                        session.query(Service)
                        .filter(Service.host_id == host.id)
                        .count()
                    )
                    if remaining_services == 0:
                        session.delete(host)
                        deleted_host = True

        session.commit()

        msg_parts = ["Vulnérabilité supprimée"]
        if deleted_service:
            msg_parts.append(f"port {svc.port} retiré")
        if deleted_host:
            msg_parts.append(f"hôte {host.ip} supprimé")

        return {
            "ok": True,
            "message": " · ".join(msg_parts),
            "deleted_service": deleted_service,
            "deleted_host": deleted_host,
        }

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()

# ── 4. DÉTAIL VULNÉRABILITÉ ───────────────────────────────────────────────────
@api_router.get("/api/vulns/{vuln_id}")
def get_vuln_detail(vuln_id: int):
    session = get_session()
    try:
        v = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not v:
            raise HTTPException(status_code=404, detail="Vulnérabilité introuvable")

        svc = v.service
        host = svc.host if svc else None

        scores_history = [
            {
                "score": s.score, 
                "label": s.label, 
                "reasoning": s.reasoning,
                "confidence": s.confidence,
                "ts": s.timestamp.isoformat()
            }
            for s in session.query(ScoreML).filter(ScoreML.vuln_id == v.id).order_by(ScoreML.timestamp.desc()).all()
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
@api_router.get("/api/reports")
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

@api_router.get("/api/reports/{report_id}")
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

@api_router.get("/api/reports/{report_id}/pdf")
def get_report_pdf(report_id: int):
    session = get_session()
    try:
        import markdown
        from xhtml2pdf import pisa
        from fastapi import Response
        from io import BytesIO

        r = session.query(Report).filter(Report.id == report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Rapport introuvable")
        
        md_content = r.content_md or ""
        md_content = md_content.replace("# RAPPORT DE AUDIT TECHNIQUE\n", "")
        md_content = md_content.replace("# RAPPORT DE PAYLOAD TECHNIQUE\n", "")
        import re
        md_content = re.sub(r'(?i)^#\s*Rapport technique.*?\n', '', md_content, flags=re.MULTILINE)
        html_content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
        
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        title = r.title or "Rapport d'Audit"

        full_html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
        <meta charset="UTF-8">
        <title>{title}</title>
        <style>
          @page {{
              size: A4;
              margin: 1.5cm;
              @frame footer {{
                  -pdf-frame-content: footerContent;
                  bottom: 1cm;
                  margin-left: 1.5cm;
                  margin-right: 1.5cm;
                  height: 1cm;
              }}
          }}
          body {{
              font-family: Helvetica, Arial, sans-serif;
              font-size: 10pt;
              color: #1f2937;
              line-height: 1.5;
          }}
          h1 {{ color: #f97316; font-size: 18pt; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; }}
          h2 {{ color: #374151; font-size: 14pt; margin-top: 15px; }}
          h3 {{ color: #4b5563; font-size: 12pt; }}
          table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
          th {{ background-color: #f3f4f6; color: #1f2937; font-weight: bold; padding: 6px; border: 1px solid #d1d5db; text-align: left; }}
          td {{ padding: 6px; border: 1px solid #e5e7eb; }}
          pre {{ background-color: #111827; color: #a6e3a1; padding: 10px; border-radius: 4px; font-size: 9pt; white-space: pre-wrap; }}
          code {{ font-family: Courier, monospace; background-color: #f3f4f6; padding: 2px 4px; border-radius: 3px; color: #e11d48; }}
          blockquote {{ border-left: 4px solid #f97316; margin-left: 0; padding-left: 10px; color: #6b7280; font-style: italic; background-color: #fff7ed; padding: 8px; }}
          .brand {{ color: #f97316; font-weight: bold; font-size: 20pt; }}
          .header {{ text-align: center; font-size: 10pt; color: #6b7280; margin-bottom: 25px; border-bottom: 1px solid #e5e7eb; padding-bottom: 15px; }}
          .alert {{ border-left: 4px solid #f97316; background-color: #fff7ed; padding: 10px; margin: 10px 0; }}
        </style>
        </head>
        <body>
          <div class="header">
             <span class="brand">SIATI</span><br>
             Système Intelligent d'Assistance aux Tests d'Intrusion<br>
             Généré le {date_str}
          </div>
          <div style="font-size: 16pt; font-weight: 700; color: #111827; margin-bottom: 18px; padding-bottom: 10px; border-bottom: 2px solid #f97316;">RAPPORT D'AUDIT TECHNIQUE</div>
          {html_content}
          
          <div id="footerContent" style="text-align: right; font-size: 8pt; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 5px;">
              SIATI — Pentest Intelligence Platform | Page <pdf:pagenumber> sur <pdf:pagecount>
          </div>
        </body>
        </html>
        """

        pdf_io = BytesIO()
        pisa_status = pisa.CreatePDF(
            full_html,
            dest=pdf_io,
            encoding='UTF-8'
        )

        if pisa_status.err:
            raise HTTPException(status_code=500, detail="Erreur lors de la génération du PDF")

        pdf_io.seek(0)
        
        headers = {
            'Content-Disposition': f'attachment; filename="report_{report_id}.pdf"'
        }
        return Response(content=pdf_io.read(), media_type="application/pdf", headers=headers)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@api_router.delete("/api/reports/{report_id}")
def delete_report(report_id: int):
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

# ── 6. GÉNÉRATION PLAYBOOK & CHAT ──────────────────────────────────────────────
class PlaybookRequest(BaseModel):
    vuln_id: int
    mode: str = "audit"

class ChatRequest(BaseModel):
    vuln_id: int
    message: str
    history: List[dict] = []

@api_router.post("/api/generate")
def generate_playbook(req: PlaybookRequest):
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

@api_router.post("/api/chat")
def chat_endpoint(req: ChatRequest):
    session = get_session()
    try:
        from app.core.llm.generator import chat_with_vulnerability
        messages = req.history + [{"role": "user", "content": req.message}]
        response = chat_with_vulnerability(session, req.vuln_id, messages)
        if response:
            return {"ok": True, "response": response}
        return JSONResponse(status_code=500, content={"ok": False, "error": "Pas de réponse LLM"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()

@api_router.get("/api/audit")
def get_audit_log():
    return [
        {"ts": datetime.utcnow().isoformat(), "action": "Système", "details": "Plateforme démarrée en mode air-gap"}
    ]

# ── 7. INGESTION SCAN ─────────────────────────────────────────────────────────
@api_router.post("/api/ingest")
async def ingest_scan(file: UploadFile = File(...), auto_pilot: bool = True):
    import tempfile, shutil
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

# ── 8. PIPELINE AUTO (score ML) ───────────────────────────────────────────────
@api_router.post("/api/score")
def run_ml_score():
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

# ── 10. PERFORMANCE DU MODÈLE ──────────────────────────────────────────────────
@api_router.get("/api/performance")
def get_model_performance():
    metrics_path = ROOT / "data" / "metrics_xgb.json"
    report_path = ROOT / "data" / "evaluation" / "performance_report.md"
    
    performance_data = {
        "metrics": None,
        "report_md": None,
        "plots": [
            {"id": "actual_vs_predicted", "path": "/data/evaluation/01_actual_vs_predicted.png"},
            {"id": "feature_importance", "path": "/data/evaluation/02_feature_importance.png"},
            {"id": "residuals", "path": "/data/evaluation/03_residuals.png"},
            {"id": "learning_curve", "path": "/data/evaluation/04_learning_curve.png"},
            {"id": "dataset_overview", "path": "/data/evaluation/05_dataset_overview.png"},
            {"id": "confusion_matrix", "path": "/data/evaluation/06_confusion_matrix.png"},
        ]
    }
    
    if metrics_path.exists():
        import json
        with open(metrics_path, "r") as f:
            performance_data["metrics"] = json.load(f)
            
    if report_path.exists():
        performance_data["report_md"] = report_path.read_text(encoding="utf-8")
        
    return performance_data
