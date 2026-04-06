"""
Enrichissement des services via une base locale CPE (mode air-gap).
Nécessite la présence d'une base de données SQLite (ex: data/cpe.db).
"""
import logging
import os
import sqlite3
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Service

logger = logging.getLogger(__name__)

CPE_DB_PATH = os.environ.get("CPE_DB_PATH", str(Path("data") / "cpe.db"))


def enrich_services_with_cpe(session: Session) -> dict[str, int]:
    """
    Tente de résoudre la version manquant de certains services
    en interrogeant une base CPE locale hors-ligne.
    """
    stats = {"updated": 0, "skipped": 0, "failed": 0}
    
    if not Path(CPE_DB_PATH).is_file():
        logger.warning("Base CPE introuvable (%s). Veillez à télécharger la l'index CPE localement.", CPE_DB_PATH)
        return stats

    rows = session.scalars(select(Service).where(Service.service.isnot(None))).all()
    
    try:
        with sqlite3.connect(CPE_DB_PATH) as conn:
            cursor = conn.cursor()
            for svc in rows:
                if svc.version:
                    stats["skipped"] += 1
                    continue
                
                # Exemple de requetage sur un schéma offline type 'cpe_entries'
                query = "SELECT version FROM cpe_entries WHERE title LIKE ? LIMIT 1"
                try:
                    cursor.execute(query, (f"%{svc.service}%",))
                    res = cursor.fetchone()
                    if res and res[0]:
                        svc.version = res[0]
                        stats["updated"] += 1
                    else:
                        stats["skipped"] += 1
                except sqlite3.OperationalError:
                    logger.debug("La structure de la table cpe_entries n'est pas standard.")
                    stats["failed"] += 1
                    break
        session.commit()
    except Exception as e:
        logger.error("Erreur lors de l'accès à la DB CPE: %s", e)
        session.rollback()
        stats["failed"] += 1

    return stats
