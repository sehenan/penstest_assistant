# === FICHIER : app/module_llm/rag/retriever.py ===
from typing import List, Dict
import numpy as np
import faiss
import logging
logger = logging.getLogger(__name__)
from sentence_transformers import SentenceTransformer
from app.module_llm.rag.indexer import load_index

class Retriever:
    """
    Composant B : Responsable du chargement de l'index et de la recherche
    de similarité pour extraire les chunks pertinents.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.index_path = config['rag']['index_path']
        self.chunks_path = config['rag']['chunks_path']
        self.model_name = config['rag']['embedding_model']
        self.top_k = config['rag']['top_k']
        
        self._model = None
        self._index = None
        self._chunks = None

    @property
    def model(self):
        if self._chunks and self._chunks.get('mode') == 'TFIDF':
            return None # Pas besoin de SBERT en mode TFIDF
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                logger.info(f"Chargement du modèle d'embedding pour retriever : {self.model_name}")
                self._model = SentenceTransformer(self.model_name)
            except ImportError:
                return None
        return self._model

    def _ensure_loaded(self):
        """Charge l'index et les chunks en mémoire s'ils ne le sont pas."""
        if self._index is None or self._chunks is None:
            logger.info("Chargement de l'index FAISS et des chunks...")
            try:
                self._index, self._chunks = load_index(self.index_path, self.chunks_path)
                if self._chunks.get('mode') == 'TFIDF':
                    import joblib
                    self._tfidf = joblib.load(Path(self.index_path).parent / "tfidf.joblib")
            except Exception as e:
                logger.error(f"Échec du chargement de l'index : {e}")
                raise

    def retrieve(self, query: str, k: int = None) -> List[Dict]:
        """
        Prend une requête, l'encode et retourne les Top-K chunks les plus proches.
        """
        self._ensure_loaded()
        k = k or self.top_k

        logger.debug(f"Recherche RAG pour : '{query}'")
        
        # Encodage de la requête selon le mode
        if self._chunks.get('mode') == 'TFIDF' and self._tfidf:
            query_vec = self._tfidf.transform([query]).toarray().astype('float32')
        elif self.model:
            query_vec = self.model.encode([query], convert_to_numpy=True).astype('float32')
        else:
            logger.error("Aucun modèle disponible pour encoder la requête.")
            return []
        
        # Recherche FAISS
        distances, indices = self._index.search(query_vec, k)
        
        results = []
        chunks_list = self._chunks.get('chunks', self._chunks) # Support compatibilité
        for i, idx in enumerate(indices[0]):
            if idx == -1: continue # Aucun résultat
            
            chunk = chunks_list[idx].copy()
            chunk['score'] = float(distances[0][i])
            results.append(chunk)
            
        return results

def get_retrieval_query(vulnerability: Dict) -> str:
    """
    Construit la requête de recherche optimisée : CVE + Service + Version.
    """
    cve = vulnerability.get('cve', '')
    service = vulnerability.get('service', '')
    version = vulnerability.get('version', '')
    description = vulnerability.get('description', '')[:100] # Limiter la description
    
    return f"{cve} {service} {version} {description}".strip()
