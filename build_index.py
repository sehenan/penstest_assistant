# === FICHIER : build_index.py ===
import yaml
import argparse
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
from app.module_llm.rag.indexer import Indexer

def main():
    parser = argparse.ArgumentParser(description="SIATI - (Re)construction de l'index RAG")
    parser.add_argument("--config", default="config.yaml", help="Chemin du fichier config.yaml")
    parser.add_argument("--force", action="store_true", help="Force la ré-indexation")
    args = parser.parse_args()

    # Chargement de la config
    try:
        with open(args.config, "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Impossible de lire la configuration : {e}")
        return

    # Initialisation de l'indexer
    indexer = Indexer(config)
    
    knowledge_dir = config['rag']['knowledge_dir']
    output_dir = config['rag']['output_dir']

    logger.info("=== SIATI RAG INDEXER ===")
    indexer.build_index(knowledge_dir, output_dir)
    logger.info("Processus terminé.")

if __name__ == "__main__":
    main()
