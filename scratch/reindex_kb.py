"""
Ré-indexation robuste de la knowledge_base vers le FAISS du chemin live
(core/llm/rag.py -> data/faiss_index/{pentest.index, metadata.json}).

Contourne le segfault OMP (faiss+torch) : torch importé AVANT faiss, threads=1,
encodage par batches avec progression visible. Format de sortie identique à
core.llm.rag.build_index : metadata.json = {"texts":[...], "metadata":[{source}]}.
"""
import os
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import json
import sys
from pathlib import Path

# 1) torch / sentence-transformers AVANT faiss
import torch
torch.set_num_threads(1)
from sentence_transformers import SentenceTransformer
import numpy as np

KB = Path("data/knowledge_base")
LEGACY = Path("data/knowledge")
OUT = Path("data/faiss_index")
OUT.mkdir(parents=True, exist_ok=True)
MODEL = "all-MiniLM-L6-v2"


def chunk(text, size=400, overlap=50):
    words = text.split()
    if not words:
        return []
    step = max(1, size - overlap)
    out = []
    for i in range(0, len(words), step):
        out.append(" ".join(words[i:i + size]))
        if i + size >= len(words):
            break
    return out


def collect():
    files = sorted(KB.rglob("*.md"))
    if LEGACY.is_dir() and LEGACY.resolve() != KB.resolve():
        files += sorted(LEGACY.glob("*.md"))
    texts, meta = [], []
    for f in files:
        try:
            content = f.read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if not content:
            continue
        try:
            src = str(f.relative_to(KB))
        except ValueError:
            src = f.name
        for c in chunk(content):
            c = c.strip()
            if c:
                # Garde-fou anti-crash : les fichiers exploitdb contiennent des blobs
                # sans espaces (base64/shellcode) -> un "mot" peut faire 200K chars et
                # faire planter le tokenizer. all-MiniLM ne lit que ~256 tokens de toute
                # façon ; on borne à 2000 chars.
                texts.append(c[:2000])
                meta.append({"source": src})
    return texts, meta, len(files)


def main():
    texts, meta, nfiles = collect()
    print(f"--> {nfiles} fichiers -> {len(texts)} chunks", flush=True)
    if not texts:
        print("Aucun chunk.", flush=True)
        return 1

    model = SentenceTransformer(MODEL, device="cpu")
    model.max_seq_length = 256
    bs = 256
    embs = []
    total = len(texts)
    for i in range(0, total, bs):
        batch = texts[i:i + bs]
        e = model.encode(batch, convert_to_numpy=True, batch_size=32,
                         show_progress_bar=False, normalize_embeddings=False)
        embs.append(e.astype("float32"))
        done = min(i + bs, total)
        if done % 2560 == 0 or done == total:
            print(f"    encodé {done}/{total}", flush=True)
    embeddings = np.vstack(embs)
    print(f"--> embeddings {embeddings.shape}", flush=True)

    # 2) faiss APRÈS l'encodage (évite le clash libomp pendant le calcul torch)
    import faiss
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)
    faiss.write_index(index, str(OUT / "pentest.index"))
    with open(OUT / "metadata.json", "w", encoding="utf-8") as fh:
        json.dump({"texts": texts, "metadata": meta}, fh, ensure_ascii=False)
    print(f"OK | {len(texts)} chunks indexés -> {OUT}/pentest.index", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
