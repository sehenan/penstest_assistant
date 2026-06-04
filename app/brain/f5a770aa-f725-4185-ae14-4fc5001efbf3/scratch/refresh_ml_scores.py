import logging
import pandas as pd
from sqlalchemy import select
from app.db.database import get_session
from app.db.models import Vulnerability, Service, Exploit
from app.core.ml.predict import predict_and_store

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def refresh():
    session = get_session()
    try:
        # Extraire les features des vulnérabilités existantes
        query = (
            select(
                Vulnerability.id.label("vuln_id"),
                Vulnerability.cve,
                Vulnerability.cvss_score,
                Service.port,
                Service.service,
                Exploit.disponible.label("has_exploit"),
            )
            .join(Service, Vulnerability.service_id == Service.id)
            .outerjoin(Exploit, Vulnerability.cve == Exploit.cve)
        )
        
        rows = session.execute(query).fetchall()
        if not rows:
            logger.warning("Aucune vulnérabilité à rafraîchir.")
            return

        df = pd.DataFrame(rows)
        # S'assurer que les colonnes ont le bon nom pour le predict_and_store
        # Et calculer les features manquantes
        from app.core.ml.features import classify_service
        df["svc_type_num"] = df.apply(lambda r: classify_service(r["port"], r["service"]), axis=1)
        df["is_public"] = df["port"].isin([80, 443, 8080, 8443, 22, 445]).astype(int)
        df["has_exploit"] = df["has_exploit"].fillna(0).astype(int)
        
        # Pour les démo PFE, on peut simuler les flags NVD si non présents
        for col in ["in_cisa_kev", "in_exploitdb", "av_num", "ac_num", "pr_num", "ui_num"]:
            df[col] = 0
            
        logger.info("Lancement du scoring pour %d vulnérabilités...", len(df))
        stats = predict_and_store(session, df)
        logger.info("Scoring terminé : %s", stats)
        
    finally:
        session.close()

if __name__ == "__main__":
    refresh()
