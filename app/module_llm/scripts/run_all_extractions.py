"""
Script principal d'orchestration pour le téléchargement et l'extraction de la knowledge base.
"""
import sys
import os
from pathlib import Path
from loguru import logger

# Ajouter le répertoire du script au sys.path pour permettre les imports locaux
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from download_sources import download_all
from extract_hacktricks import extract_hacktricks
from extract_patt import extract_patt
from extract_exploitdb import extract_exploitdb
from extract_mitre import extract_mitre
from extract_nvd import extract_nvd

def main() -> None:
    """
    Fonction principale orchestrant tout le pipeline de traitement de la knowledge base.
    """
    logger.info("=== Début de la consolidation de la Knowledge Base ===")
    
    # Étape 1 : Téléchargement
    logger.info("--- Étape 1: Téléchargement des sources ---")
    download_all("data/knowledge_base")
    
    # Étape 2 : Extraction et Nettoyage
    logger.info("--- Étape 2: Extraction des données ---")
    extract_hacktricks("data/knowledge_base/hacktricks/src", "data/knowledge_base/hacktricks_cleaned")
    extract_patt("data/knowledge_base/patt", "data/knowledge_base/payloadsallthethings")
    extract_exploitdb("data/knowledge_base/exploitdb", "data/knowledge_base/exploitdb_verified")
    extract_mitre("data/knowledge_base/mitre/enterprise-attack.json", "data/knowledge_base/mitre_attack")
    extract_nvd("data/knowledge_base/nvd", "data/knowledge_base/nvd_cache")
    
    # Étape 3 : Récapitulatif
    logger.info("--- Récapitulatif de la consolidation ---")
    kb_path = Path("data/knowledge_base")
    
    dirs_to_check = [
        "hacktricks_cleaned",
        "payloadsallthethings",
        "exploitdb_verified",
        "mitre_attack",
        "nvd_cache"
    ]
    
    total = 0
    for d in dirs_to_check:
        dir_path = kb_path / d
        if dir_path.exists():
            count = sum(1 for _ in dir_path.rglob("*.md"))
            logger.info(f"{d} : {count} fichiers .md")
            total += count
        else:
            logger.warning(f"{d} : 0 fichiers (dossier introuvable)")
            
    logger.success(f"=== Processus terminé. Total de fichiers dans la KB : {total} ===")

if __name__ == "__main__":
    main()
