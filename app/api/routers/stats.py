from fastapi import APIRouter, Request, Depends
from app.db.database import get_session
from app.db.models import Host, Vulnerability, ScoreML, Report
from app.core.security import rate_limit, verify_token_optional
from app.core.error_handler import DatabaseError

router = APIRouter(prefix="/api/stats", tags=["stats"])

@router.get("")
@rate_limit(limit=60, window=60)
def get_stats(request: Request, _auth=Depends(verify_token_optional)):
    session = get_session()
    try:
        total_vulns = session.query(Vulnerability).count()
        total_hosts = session.query(Host).count()

        label_counts = {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0, "info": 0}
        scores = session.query(ScoreML).join(Vulnerability).all()
        for s in scores:
            lbl = (s.label or "").lower()
            if lbl == "moyen": lbl = "moyenne"
            if lbl == "haut": lbl = "haute"

            if lbl in label_counts:
                label_counts[lbl] += 1

        total_reports = session.query(Report).join(Vulnerability).count()

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
