# === FICHIER : app/module_llm/rag/indexer.py ===
import os
import json
import uuid
from pathlib import Path
from typing import List, Dict

import faiss
import numpy as np
# import tiktoken
import logging
logger = logging.getLogger(__name__)
# try:
#     from sentence_transformers import SentenceTransformer
#     HAS_SENTENCE_TRANSFORMERS = True
# except ImportError:
HAS_SENTENCE_TRANSFORMERS = False
from sklearn.feature_extraction.text import TfidfVectorizer

class Indexer:
    """
    Composant A : Responsable du parcours de la knowledge base, du chunking
    et de la construction de l'index FAISS.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.model_name = config['rag']['embedding_model']
        self.chunk_size = config['rag']['chunk_size']
        self.chunk_overlap = config['rag']['chunk_overlap']
        self._model = None
        self._tfidf = None

    @property
    def model(self):
        if not HAS_SENTENCE_TRANSFORMERS:
            return None
        if self._model is None:
            logger.info(f"Chargement du modèle d'embedding : {self.model_name}")
            try:
                self._model = SentenceTransformer(self.model_name)
            except Exception as e:
                logger.warning(f"Échec du chargement de sentence-transformers : {e}. Utilisation du fallback TF-IDF.")
                return None
        return self._model

    def _chunk_text(self, text: str) -> List[str]:
        """Découpe le texte en chunks de mots (fallback simple)."""
        words = text.split()
        chunks = []
        
        # On approxime 500 tokens par 400 mots
        step = 350 # 400 - 50 d'overlap approx
        for i in range(0, len(words), step):
            chunk_words = words[i : i + 400]
            chunks.append(" ".join(chunk_words))
            if i + 400 >= len(words):
                break
        return chunks

    def build_index(self, knowledge_dir: str, output_dir: str) -> None:
        """
        Parcourt récursivement le dossier knowledge_base, génère les embeddings
        et sauvegarde l'index FAISS ainsi que les métadonnées.
        """
        logger.info(f"Démarrage de l'indexation depuis : {knowledge_dir}")
        knowledge_path = Path(knowledge_dir)
        if not knowledge_path.exists():
            logger.error(f"Dossier source introuvable : {knowledge_dir}")
            return

        all_chunks = []
        all_texts = []

        # 1. Parcours récursif
        for ext in ['*.md']:
            for file_path in knowledge_path.rglob(ext):
                logger.debug(f"Traitement du fichier : {file_path}")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    file_chunks = self._chunk_text(content)
                    
                    # Métadonnées basiques (à enrichir selon le fichier)
                    for chunk in file_chunks:
                        chunk_metadata = {
                            "chunk_id": str(uuid.uuid4()),
                            "text": chunk,
                            "source_name": file_path.name,
                            "source_url": str(file_path), # En local, on met le chemin
                            "source_date": "2024-01-15", # Date par défaut ou extraite
                            "cve_tags": [] # À remplir si détecté dans le texte
                        }
                        all_chunks.append(chunk_metadata)
                        all_texts.append(chunk)
                except Exception as e:
                    logger.error(f"Erreur lors de la lecture de {file_path} : {e}")

        if not all_texts:
            logger.warning("Aucun document trouvé à indexer.")
            return

        # 2. Encodage
        logger.info(f"Encodage de {len(all_texts)} chunks...")
        
        if self.model:
            embeddings = self.model.encode(all_texts, convert_to_numpy=True)
            mode = "SBERT"
        else:
            logger.info("Utilisation du mode TF-IDF (fallback)")
            self._tfidf = TfidfVectorizer(max_features=384) # Aligné sur la dimension MiniLM
            embeddings = self._tfidf.fit_transform(all_texts).toarray()
            mode = "TFIDF"
            # On sauvegarde le vectoriseur pour le retriever
            import joblib
            joblib.dump(self._tfidf, Path(output_dir) / "tfidf.joblib")
        
        # 3. Construction FAISS
        dimension = embeddings.shape[1]
        index = faiss.IndexFlatL2(dimension)
        index.add(embeddings.astype('float32'))

        # 4. Sauvegarde
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        index_file = str(out_path / "pentest.index")
        chunks_file = str(out_path / "chunks.json")
        
        faiss.write_index(index, index_file)
        with open(chunks_file, 'w', encoding='utf-8') as f:
            # On ajoute le mode aux métadonnées
            meta_data = {
                "mode": mode,
                "chunks": all_chunks
            }
            json.dump(meta_data, f, ensure_ascii=False, indent=2)

        logger.info(f"Indexation terminée ({mode}). {len(all_texts)} chunks sauvegardés.")

def load_index(index_path: str, chunks_path: str) -> tuple:
    """Charge l'index et les chunks depuis le disque."""
    if not os.path.exists(index_path) or not os.path.exists(chunks_path):
        raise FileNotFoundError("Index ou fichier de chunks manquant.")
        
    index = faiss.read_index(index_path)
    with open(chunks_path, 'r', encoding='utf-8') as f:
        chunks = json.load(f)
    
    return index, chunks
