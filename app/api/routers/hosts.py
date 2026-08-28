from fastapi import APIRouter
from app.db.database import get_session
from app.db.models import Host, ScoreML

router = APIRouter(prefix="/api/hosts", tags=["hosts"])

@router.get("")
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
