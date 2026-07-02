"""
pipeline.py
===========
Orchestrateur du pipeline complet (Air-gap / Offline).
Enchaîne l'ingestion, l'enrichissement et le scoring ML.
"""
import logging
import time
from pathlib import Path
from sqlalchemy.orm import Session

from app.core.ingest import ingest_scan_file
from app.core.enrichment.nvd import enrich_vulnerabilities_from_local_intel
from app.core.enrichment.cpe import enrich_services_with_cpe
from app.core.enrichment.exploit_db import enrich_exploits
from app.core.enrichment.cpe_to_cve import enrich_service_vulns_from_cpe
from app.core.enrichment.translate import translate_vulnerability_descriptions
from app.core.ml.data_manager import DataManager
from app.core.ml.predict import predict_and_store

logger = logging.getLogger(__name__)

class FullPipeline:
    def __init__(self, session: Session):
        self.session = session
        self.stats = {
            "ingestion": {},
            "enrichment_cpe_to_cve": {},
            "enrichment_nvd": {},
            "enrichment_cpe": {},
            "enrichment_exploit": {},
            "translation": {},
            "scoring_ml": {},
            "duration": 0
        }

    def run(self, file_path: str) -> dict:
        """Exécute toutes les étapes de manière séquentielle."""
        start_time = time.time()
        
        try:
            # 1. Ingestion & Normalisation
            logger.info("Pipeline Step 1: Ingestion...")
            self.stats["ingestion"] = ingest_scan_file(file_path, self.session)

            # 1b. CPE → CVE (NVD cache local)
            # Enrichit les vulns sans CVE en cherchant des CVEs correspondant
            # au CPE du service dans le cache JSON NVD local.
            logger.info("Pipeline Step 1b: CPE→CVE Enrichment (NVD cache)...")
            self.stats["enrichment_cpe_to_cve"] = enrich_service_vulns_from_cpe(self.session)

            # 2. Enrichissement NVD (CVE Details)
            logger.info("Pipeline Step 2: NVD Enrichment...")
            self.stats["enrichment_nvd"] = enrich_vulnerabilities_from_local_intel(self.session)
            
            # 3. Enrichissement CPE (Versions)
            logger.info("Pipeline Step 3: CPE Enrichment...")
            self.stats["enrichment_cpe"] = enrich_services_with_cpe(self.session)
            
            # 4. Enrichissement Exploit-DB
            logger.info("Pipeline Step 4: Exploit-DB Enrichment...")
            self.stats["enrichment_exploit"] = enrich_exploits(self.session)
            
            # 5. Traduction des descriptions (EN → FR)
            # use_llm=False : la traduction par dictionnaire technique (200+ termes) est
            # instantanée et hors-ligne. La traduction LLM faisait un appel Ollama PAR vuln
            # (+ sleep 0.5s), ce qui rendait l'import extrêmement lent (plusieurs minutes).
            # La traduction fine LLM reste disponible via translate_vulnerability_descriptions
            # (use_llm=True) si on souhaite la lancer manuellement hors du chemin d'import.
            logger.info("Pipeline Step 5: Translation (EN→FR, dictionnaire)...")
            self.stats["translation"] = translate_vulnerability_descriptions(self.session, use_llm=False)

            # 6. Priorisation ML (XGBoost)
            logger.info("Pipeline Step 6: ML Scoring...")
            dm = DataManager()
            df = dm.extract_real_data(self.session)
            if not df.empty:
                self.stats["scoring_ml"] = predict_and_store(self.session, df)
            else:
                self.stats["scoring_ml"] = {"status": "skipped", "reason": "no_data"}
                
            self.stats["duration"] = round(time.time() - start_time, 2)
            logger.info("Full pipeline completed in %s seconds.", self.stats["duration"])
            
            return {"ok": True, "stats": self.stats}
            
        except Exception as e:
            logger.error("Pipeline failure: %s", e, exc_info=True)
            self.session.rollback()
            return {"ok": False, "error": str(e)}
