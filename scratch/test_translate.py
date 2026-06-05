"""Test de traduction renforcee - dictionnaire seul puis apercu."""
import sys, logging
sys.path.insert(0, ".")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from app.db.database import get_session
from app.db.models import Vulnerability
from sqlalchemy import select

session = get_session()

try:
    # Reinitialiser les descriptions depuis le cache NVD (re-enrichir)
    # D'abord montrer l'etat actuel
    vulns = session.query(Vulnerability).filter(
        Vulnerability.cve.isnot(None)
    ).order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    print(f"\n=== DESCRIPTIONS ACTUELLES ({len(vulns)} vulns avec CVE) ===")
    for v in vulns[:3]:
        print(f"\n  [{v.cve}] CVSS={v.cvss_score}")
        print(f"    {(v.description or 'VIDE')[:150]}")

    # Lancer la traduction dictionnaire uniquement
    from app.core.enrichment.translate import translate_vulnerability_descriptions
    stats = translate_vulnerability_descriptions(session, use_llm=False)

    print(f"\n=== RESULTATS TRADUCTION DICTIONNAIRE ===")
    for k, val in stats.items():
        print(f"  {k:20s}: {val}")

    # Apercu APRES
    session.expire_all()
    vulns = session.query(Vulnerability).filter(
        Vulnerability.description.isnot(None)
    ).order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    print(f"\n=== APRES TRADUCTION ({len(vulns)} vulns) ===")
    for v in vulns[:10]:
        print(f"\n  [{v.cve or 'NO-CVE'}] CVSS={v.cvss_score}")
        desc = (v.description or '')[:250]
        print(f"    {desc}")

finally:
    session.close()
    print("\nDone.")
