import os
import sys
import logging
from pathlib import Path

# Résolution des chemins pour importer les modules de l'application
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT))

from app.core.llm.rag import build_index

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = ROOT / "data" / "knowledge"

def chunk_markdown_file(file_path: Path) -> list[dict]:
    """
    Découpe intelligemment un fichier Markdown en chunks.
    On utilise les séparateurs '---' ou '## ' pour garder un contexte cohérent.
    """
    content = file_path.read_text(encoding="utf-8")
    
    # Stratégie de découpage : d'abord par ---
    raw_chunks = content.split("\n---\n")
    
    documents = []
    source_name = file_path.name
    
    for chunk in raw_chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
            
        # Si un chunk est encore trop gros, on peut le diviser par "## "
        # Mais pour des cheat sheets ciblées, la division par --- est généralement suffisante.
        if len(chunk) > 2000:
            sub_chunks = chunk.split("\n## ")
            for i, sub in enumerate(sub_chunks):
                sub = sub.strip()
                if not sub: continue
                # Rajouter le "## " qui a été coupé, sauf pour le premier si ce n'était pas un H2
                if i > 0 or chunk.startswith("## "):
                    sub = "## " + sub
                documents.append({"content": sub, "source": source_name})
        else:
            documents.append({"content": chunk, "source": source_name})
            
    return documents

def main():
    logger.info("Démarrage de la construction de la base de connaissances (FAISS RAG)")
    
    if not KNOWLEDGE_DIR.exists():
        logger.error(f"Le dossier {KNOWLEDGE_DIR} n'existe pas.")
        return
        
    all_documents = []
    
    # Scanner les fichiers
    for filepath in KNOWLEDGE_DIR.glob("**/*.md"):
        logger.info(f"Lecture du fichier : {filepath.name}")
        chunks = chunk_markdown_file(filepath)
        all_documents.extend(chunks)
        logger.info(f" -> {len(chunks)} fragments extraits.")
        
    for filepath in KNOWLEDGE_DIR.glob("**/*.txt"):
        logger.info(f"Lecture du fichier : {filepath.name}")
        chunks = chunk_markdown_file(filepath)
        all_documents.extend(chunks)
        logger.info(f" -> {len(chunks)} fragments extraits.")
        
    if not all_documents:
        logger.warning("Aucun document trouvé dans data/knowledge/")
        return
        
    logger.info(f"Total de {len(all_documents)} fragments prêts pour l'indexation.")
    
    # Appel de la fonction de construction de FAISS
    try:
        build_index(all_documents)
        logger.info("Construction de l'index FAISS terminée avec succès !")
    except Exception as e:
        logger.error(f"Erreur lors de la construction de l'index : {e}", exc_info=True)

if __name__ == "__main__":
    main()
