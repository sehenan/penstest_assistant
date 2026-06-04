"""
Moteur de Recherche Vectoriel (RAG).
Utilise Sentence-Transformers (Local CPU) et FAISS pour indexer et rechercher
les playbooks/cheatsheets hors-ligne (air-gapped).
"""
import json
import logging
import os
from pathlib import Path
import numpy as np

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    HAS_RAG_DEPS = True
except ImportError:
    HAS_RAG_DEPS = False

logger = logging.getLogger(__name__)

FAISS_DB_DIR = Path("data") / "faiss_index"
INDEX_FILE = FAISS_DB_DIR / "pentest.index"
META_FILE = FAISS_DB_DIR / "metadata.json"

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
_embed_model = None


def _get_embed_model():
    global _embed_model
    if not HAS_RAG_DEPS:
        raise RuntimeError("Les dépendances faiss-cpu ou sentence-transformers sont manquantes.")
    if _embed_model is None:
        logger.info("Chargement du modèle d'embedding %s en mémoire (CPU)...", EMBED_MODEL_NAME)
        _embed_model = SentenceTransformer(EMBED_MODEL_NAME, device="cpu")
    return _embed_model


def build_index(documents: list[dict[str, str]]) -> None:
    """
    Moteur d'ingestion (Chunking/Embedding).
    Attend une liste de dict : [{'content': 'texte', 'source': 'fichier.md'}, ...]
    """
    if not HAS_RAG_DEPS:
        logger.error("RAG est désactivé faute de dépendances. Installez faiss-cpu.")
        return

    FAISS_DB_DIR.mkdir(parents=True, exist_ok=True)
    
    texts = [doc["content"] for doc in documents]
    metadata = [{"source": doc.get("source", "unknown")} for doc in documents]
    
    logger.info("Encodage de %d documents en cours...", len(texts))
    model = _get_embed_model()
    embeddings = model.encode(texts, convert_to_numpy=True)
    
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)
    
    faiss.write_index(index, str(INDEX_FILE))
    
    with open(META_FILE, 'w', encoding='utf-8') as f:
        json.dump({"texts": texts, "metadata": metadata}, f, ensure_ascii=False, indent=2)
        
    logger.info("Index FAISS sauvegardé avec succès dans %s", FAISS_DB_DIR)


def retrieve_context(query: str, top_k: int = 3) -> str:
    """
    Lance une similarité Vectorielle (L2) sur l'index pour extraire le texte RAG optimal.
    """
    if not HAS_RAG_DEPS:
        return "RAG local inactif : dépendances ou matériels non configurés."

    if not INDEX_FILE.is_file() or not META_FILE.is_file():
        return ""
        
    try:
        index = faiss.read_index(str(INDEX_FILE))
        with open(META_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            texts = data["texts"]
            
        model = _get_embed_model()
        q_emb = model.encode([query], convert_to_numpy=True)
        
        distances, indices = index.search(q_emb, k=top_k)
        
        results = []
        for rank, idx in enumerate(indices[0]):
            if idx == -1 or idx >= len(texts): 
                continue
            results.append(texts[idx])
            
        return "\n\n---\n\n".join(results)
    except Exception as e:
        logger.exception("Erreur critique durant la recherche vectorielle: %s", e)
        return ""
