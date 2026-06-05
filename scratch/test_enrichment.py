"""
Script de validation du pipeline d'enrichissement CPE->CVE.
"""
import sys
import os
import logging
sys.path.insert(0, ".")
os.environ["PYTHONIOENCODING"] = "utf-8"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from app.db.database import get_session
from app.db.models import Vulnerability, Service, Host, ScoreML

session = get_session()

try:
    # Bilan APRES enrichissement (deja lance)
    total = session.query(Vulnerability).count()
    no_cve = session.query(Vulnerability).filter(Vulnerability.cve.is_(None)).count()
    with_cvss = session.query(Vulnerability).filter(Vulnerability.cvss_score.isnot(None)).count()
    with_cve = session.query(Vulnerability).filter(Vulnerability.cve.isnot(None)).count()
    print(f"\n=== BILAN FINAL ===")
    print(f"  Total vulns     : {total}")
    print(f"  Avec CVE        : {with_cve}")
    print(f"  Sans CVE        : {no_cve}")
    print(f"  Avec CVSS       : {with_cvss}")

    # NVD enrichissement sur les nouveaux CVEs
    from app.core.enrichment.nvd import enrich_vulnerabilities_from_local_intel
    nvd_stats = enrich_vulnerabilities_from_local_intel(session)
    print(f"\n=== RESULTATS NVD ===")
    for k, v in nvd_stats.items():
        print(f"  {k:20s}: {v}")

    # ML scoring
    from app.core.ml.data_manager import DataManager
    from app.core.ml.predict import predict_and_store
    dm = DataManager()
    df = dm.extract_real_data(session)
    if not df.empty:
        ml_stats = predict_and_store(session, df)
        print(f"\n=== SCORING ML ===")
        for k, v in ml_stats.items():
            print(f"  {k:20s}: {v}")
    else:
        print("\n=== SCORING ML === DataFrame vide, pas de scoring.")

    # Bilan FINAL
    total2 = session.query(Vulnerability).count()
    with_cvss2 = session.query(Vulnerability).filter(Vulnerability.cvss_score.isnot(None)).count()
    with_cve2 = session.query(Vulnerability).filter(Vulnerability.cve.isnot(None)).count()
    scored = session.query(ScoreML).count()
    print(f"\n=== BILAN FINAL APRES TOUT ===")
    print(f"  Total vulns     : {total2}")
    print(f"  Avec CVE        : {with_cve2}")
    print(f"  Avec CVSS       : {with_cvss2}")
    print(f"  Scores ML       : {scored}")

    # Apercu des vulns
    print(f"\n=== APERCU (15 premieres vulns par CVSS) ===")
    vulns = session.query(Vulnerability).order_by(Vulnerability.cvss_score.desc().nullslast()).limit(15).all()
    for v in vulns:
        svc = v.service
        score_ml = session.query(ScoreML).filter(ScoreML.vuln_id == v.id).first()
        ml_info = f"ML={score_ml.score}/{score_ml.label}" if score_ml else "ML=--"
        svc_name = svc.service if svc else "?"
        svc_port = svc.port if svc else "?"
        ip = svc.host.ip if svc and svc.host else "?"
        cve = v.cve or "NO-CVE"
        cvss = v.cvss_score if v.cvss_score else "--"
        print(f"  [{cve:20s}] CVSS={str(cvss):>5} {ml_info:25s} | {ip} {svc_name}:{svc_port}")

finally:
    session.close()
    print("\nDone.")
