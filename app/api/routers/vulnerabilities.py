from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from app.db.database import get_session
from app.db.models import Vulnerability, ScoreML, Exploit, Report, Service, Host
from app.core.security import require_auth

router = APIRouter(prefix="/api/vulns", tags=["vulnerabilities"])

@router.get("")
def get_vulns(severity: str = "", source: str = "", q: str = ""):
    session = get_session()
    try:
        query = session.query(Vulnerability)
        vulns = query.all()

        result = []
        for v in vulns:
            svc = v.service
            host = svc.host if svc else None

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

@router.delete("/{vuln_id}")
def delete_vuln(vuln_id: int, _auth=Depends(require_auth)):
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

@router.get("/{vuln_id}")
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
            "cvss_score": v.cvss_score,
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
