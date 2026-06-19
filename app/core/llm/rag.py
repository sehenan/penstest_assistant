"""
Moteur de Recherche Vectoriel (RAG).
Utilise Sentence-Transformers (Local CPU) et FAISS pour indexer et rechercher
les playbooks/cheatsheets hors-ligne (air-gapped).
"""
import json
import logging
import os
from pathlib import Path
# Évite le conflit OpenMP entre FAISS et PyTorch (segfault sinon sur macOS)
os.environ.setdefault("OMP_NUM_THREADS", "1")

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


def build_rag_context(service: str, version: str, cve_id: str, top_k: int = 3,
                      description: str = "") -> str:
    """
    Construit le contexte injecté dans le prompt Ollama.
    Ne contient QUE des données confirmées par la base locale intel.
    Si la CVE n'est pas confirmée pour ce service/version, retourne un avertissement
    qui instruira le modèle de ne pas décrire d'exploitation.
    `description` enrichit la requête vectorielle (mots-clés du mécanisme de la faille)
    pour une récupération FAISS nettement plus pertinente.
    """
    from app.db.intel_reader import IntelReader
    intel = IntelReader()

    # Requête vectorielle enrichie : CVE + service + version + mécanisme (description)
    faiss_query = f"{cve_id} {service} {version} {(description or '')[:300]}".strip()

    cve_entry = intel.get_cve(cve_id)
    confirmed_cves = intel.get_cves_for_service(service, version)
    cve_confirmed = any(c["cve_id"] == cve_id for c in confirmed_cves)

    if not cve_confirmed and cve_entry is None:
        # Pas de fiche dédiée dans l'intel base curée, MAIS la knowledge_base FAISS
        # contient des techniques génériques exploitables. On les remonte au lieu de
        # renvoyer un « exploitation impossible » sec. Le garde-fou anti-hallucination
        # reste : ne pas inventer le mapping version↔CVE ni des détails CVE absents.
        faiss_chunks = retrieve_context(faiss_query, top_k=top_k)
        note = (
            f"NOTE : {cve_id} n'a pas de fiche dédiée dans l'intel base locale pour "
            f"{service} {version}. N'invente NI mapping version↔CVE NI détail de la CVE "
            f"absent du prompt. Appuie-toi sur la description fournie et la documentation "
            f"technique ci-dessous."
        )
        if faiss_chunks:
            return note + "\n\n## Documentation technique (base locale FAISS)\n" + faiss_chunks
        return (
            f"NOTE : {cve_id} est absente de l'intel base locale et aucune documentation "
            f"FAISS ne correspond. Limite-toi strictement à la description fournie dans le "
            f"prompt ; n'invente aucune étape d'exploitation."
        )

    context_lines: list[str] = []
    if cve_entry:
        context_lines += [
            f"CVE-ID : {cve_entry['cve_id']}",
            f"Description : {cve_entry['description'] or 'N/A'}",
            f"CVSS v3 : {cve_entry.get('cvss_score', 'N/A')} — {cve_entry.get('cvss_vector', 'N/A')}",
            f"CWE : {cve_entry.get('cwe_id', 'N/A')}",
            f"Versions affectées : {json.dumps(cve_entry.get('affected_versions', []))}",
            f"Versions corrigées : {json.dumps(cve_entry.get('fixed_versions', []))}",
            f"PoC disponible : {'Oui' if cve_entry.get('poc_available') else 'Non'}",
            f"Mots-clés techniques : {', '.join(cve_entry.get('keywords', []))}",
        ]

    faiss_chunks = retrieve_context(faiss_query, top_k=top_k)
    if faiss_chunks:
        context_lines.append("\nDocumentation technique (base locale FAISS) :")
        context_lines.append(faiss_chunks)

    return "\n".join(context_lines) if context_lines else "Aucune donnée disponible dans la base locale."


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
