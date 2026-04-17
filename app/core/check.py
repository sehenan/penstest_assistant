import os
from pathlib import Path
import requests
import logging
from app.db.database import get_engine
from sqlalchemy import text

logger = logging.getLogger(__name__)

def run_diagnostics():
    print("\n" + "="*50)
    print("      DIAGNOSTIC DU SYSTÈME PENTEST ASSISTANT")
    print("="*50 + "\n")

    # 1. Vérification Ollama
    print("[1] Vérification Ollama...")
    from app.core.llm.ollama_client import OLLAMA_HOST, OLLAMA_MODEL, check_ollama_status
    if check_ollama_status():
        print(f"  [OK] Serveur Ollama détecté sur {OLLAMA_HOST}")
        try:
            r = requests.get(f"{OLLAMA_HOST}/api/tags")
            models = [m['name'] for m in r.json().get('models', [])]
            if OLLAMA_MODEL in models or f"{OLLAMA_MODEL}:latest" in models:
                print(f"  [OK] Modèle '{OLLAMA_MODEL}' est disponible.")
            else:
                print(f"  [!] Modèle '{OLLAMA_MODEL}' non trouvé. Disponibles : {', '.join(models)}")
        except:
            print("  [?] Impossible de lister les modèles.")
    else:
        print(f"  [ERROR] Serveur Ollama inaccessible sur {OLLAMA_HOST}")

    # 2. Vérification des Bases de Données
    print("\n[2] Vérification des Bases de Données...")
    dbs = {
        "Base Principale (pentest.db)": "data/pentest.db",
        "Base CPE (cpe.db)": "data/cpe.db",
        "Base Exploits (exploits.db)": "data/exploits.db"
    }
    for name, path in dbs.items():
        if Path(path).exists():
            print(f"  [OK] {name} présente.")
        else:
            print(f"  [MISSING] {name} absente (lancez 'setup-data').")

    # 3. Vérification du Modèle ML
    print("\n[3] Vérification du Modèle ML...")
    if Path("data/model_xgb.joblib").exists():
        print("  [OK] Modèle XGBoost entraîné détecté.")
    else:
        print("  [MISSING] Modèle XGBoost absent (lancez 'train').")

    # 4. Vérification RAG
    print("\n[4] Vérification de l'Index RAG...")
    if Path("faiss_index").exists() or Path("data/faiss_index").exists():
        print("  [OK] Index FAISS détecté.")
    else:
        print("  [MISSING] Index RAG absent (lancez 'index-rag').")

    print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    run_diagnostics()
