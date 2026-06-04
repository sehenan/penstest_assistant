# === FICHIER : app/module_llm/llm/orchestrator.py ===
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
import logging
logger = logging.getLogger(__name__)

from app.module_llm.rag.retriever import Retriever, get_retrieval_query
from app.module_llm.llm.generator import Generator

class Orchestrator:
    """
    Composant D : Orchestre le flux de données entre la DB, le Retriever et le Generator.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.db_path = config['database']['path']
        self.top_n = config['database'].get('top_n_vulns', 10)
        
        self.retriever = Retriever(config)
        self.generator = Generator(config)

    def _get_top_vulnerabilities(self, limit: int) -> List[Dict]:
        """Récupère les Top-N vulnérabilités classées par score ML."""
        logger.info(f"Récupération des {limit} meilleures vulnérabilités depuis la base...")
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT 
                v.id as vuln_id, v.cve, v.cvss_score, v.cvss_vector, v.description,
                s.service, s.port, s.version,
                e.metasploit_module, e.disponible as exploit_disponible,
                sm.score as ml_score
            FROM scores_ml sm
            JOIN vulnerabilites v ON sm.vuln_id = v.id
            JOIN services s ON v.service_id = s.id
            LEFT JOIN exploits e ON v.cve = e.cve
            ORDER BY sm.score DESC
            LIMIT ?
        """
        
        try:
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Erreur SQL : {e}")
            return []
        finally:
            conn.close()

    def _save_report(self, vuln_id: int, title: str, content: str):
        """Sauvegarde le playbook généré dans la table rapports."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "INSERT INTO rapports (titre, contenu_md, timestamp, vuln_id) VALUES (?, ?, ?, ?)"
        
        try:
            cursor.execute(query, (title, content, datetime.now().isoformat(), vuln_id))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du rapport : {e}")
            return None
        finally:
            conn.close()

    def run_llm_pipeline(self, top_n: int = None) -> Dict:
        """
        Exécute le pipeline complet pour le Top-N des vulnérabilités.
        """
        limit = top_n or self.top_n
        vulnerabilities = self._get_top_vulnerabilities(limit)
        
        results = {
            "total": len(vulnerabilities),
            "success": 0,
            "failed": 0,
            "rapports_ids": []
        }

        for vuln in vulnerabilities:
            cve = vuln.get('cve', 'Unknown-CVE')
            logger.info(f"Traitement de {cve} (Score ML: {vuln.get('ml_score')})...")
            
            start_time = datetime.now()
            
            # 1. Retrieval
            rag_query = get_retrieval_query(vuln)
            context_chunks = self.retriever.retrieve(rag_query)
            
            # 2. Generation
            playbook = self.generator.generate_playbook(vuln, context_chunks)
            
            if playbook:
                duration = (datetime.now() - start_time).total_seconds()
                title = f"Playbook {cve} - {vuln.get('service', 'Service')}"
                
                report_id = self._save_report(vuln['vuln_id'], title, playbook)
                if report_id:
                    results["success"] += 1
                    results["rapports_ids"].append(report_id)
                    logger.success(f"Playbook généré et sauvegardé pour {cve} en {duration:.1f}s (ID: {report_id})")
                else:
                    results["failed"] += 1
            else:
                results["failed"] += 1
                logger.error(f"Échec de la génération du playbook pour {cve}")

        return results

def run_llm_pipeline(db_path: str, top_n: int = 10) -> Dict:
    """Fonction d'exposition demandée par le cahier des charges."""
    import yaml
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    
    config['database']['path'] = db_path # Override if needed
    orch = Orchestrator(config)
    return orch.run_llm_pipeline(top_n=top_n)
