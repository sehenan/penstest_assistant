"""
Enrichissement des Vulnérabilités via la base locale (Offline / Air-Gapped).
Remplace l'ancienne implémentation qui interrogeait l'API NVD en direct.
"""
from __future__ import annotations

import logging
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability
from app.db.threat_intel_db import get_intel_session, IntelCVE, IntelEPSS, IntelKEV

logger = logging.getLogger(__name__)

def enrich_vulnerabilities_from_local_intel(db_session: Session) -> dict[str, int]:
    """
    Met à jour les lignes Vulnerability depuis la base de Threat Intel locale.
    Récupère NVD (cvss, desc, cwe), EPSS (score) et KEV (bool).
    """
    stats = {"updated": 0, "skipped": 0, "failed": 0, "missing_intel_db": 0}
    
    intel_session = get_intel_session()
    if intel_session is None:
        logger.error("Threat Intel DB is missing! Run sync_manager to ingest a bundle.")
        stats["missing_intel_db"] = 1
        return stats

    rows = db_session.scalars(
        select(Vulnerability).where(Vulnerability.cve.isnot(None))
    ).all()
    
    try:
        for v in rows:
            if not v.cve or not v.cve.upper().startswith("CVE-"):
                stats["skipped"] += 1
                continue
                
            cve_id = v.cve.upper()
            updated_any = False
            
            # 1. Enrichissement NVD (Base)
            intel_cve = intel_session.query(IntelCVE).filter(IntelCVE.cve_id == cve_id).first()
            if intel_cve:
                if v.cvss_score is None and (intel_cve.cvss_v3_score or intel_cve.cvss_v2_score):
                    v.cvss_score = intel_cve.cvss_v3_score or intel_cve.cvss_v2_score
                    updated_any = True
                
                if not v.cvss_vector and intel_cve.cvss_v3_vector:
                    v.cvss_vector = intel_cve.cvss_v3_vector
                    updated_any = True
                    
                if not (v.description or "").strip() and intel_cve.description:
                    v.description = intel_cve.description
                    updated_any = True
                    
                if not v.cwe and intel_cve.cwe_id:
                    v.cwe = intel_cve.cwe_id
                    updated_any = True

            # 2. Enrichissement EPSS
            intel_epss = intel_session.query(IntelEPSS).filter(IntelEPSS.cve_id == cve_id).first()
            if intel_epss and v.epss_score is None:
                v.epss_score = intel_epss.epss_score
                updated_any = True
                
            # 3. Enrichissement KEV
            if not v.is_kev:
                intel_kev = intel_session.query(IntelKEV).filter(IntelKEV.cve_id == cve_id).first()
                if intel_kev:
                    v.is_kev = True
                    updated_any = True

            if updated_any:
                stats["updated"] += 1
            else:
                stats["skipped"] += 1

        db_session.commit()
    except Exception as e:
        logger.error(f"Error enriching from local intel: {e}")
        db_session.rollback()
        stats["failed"] += 1
    finally:
        intel_session.close()

    return stats
