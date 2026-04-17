"""
Connecteur sécurisé à l'API locale d'Ollama.
Invoque les LLM pré-configurés (Llama3, Mistral) depuis le socle air-gap local.
"""
import logging
import os
import requests

logger = logging.getLogger(__name__)

# Config Air-Gap : L'API réside sur le localhost par défaut.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

# Modèle par défaut : llama3 (8b). Mistral est souvent plus rapide sur CPU.
# Remplacement par tinyllama en raison des contraintes matérielles sévères
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "tinyllama")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "1800"))


def check_ollama_status() -> bool:
    """Vérifie si le serveur Ollama est joignable."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def generate_text(prompt: str, system_prompt: str = "") -> str | None:
    """
    Interagit avec l'API Ollama (generate endpoint) avec paramétrages conservateurs.
    (Température basse pour minimiser l'hallucination et maximiser le ciblage technique).
    """
    url = f"{OLLAMA_HOST}/api/generate"
    
    if not check_ollama_status():
        logger.error("Serveur Ollama inaccessible sur %s", OLLAMA_HOST)
        return None

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.2, # Bridage pour rigueur logicielle
            "num_predict": 1024 # Longueur suffisante pour élaborer un Playbook
        }
    }
    
    logger.info("Génération LLM via %s (Timeout: %ds)...", OLLAMA_MODEL, OLLAMA_TIMEOUT)
    try:
        r = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
        r.raise_for_status()
        return r.json().get("response", "")
    except requests.exceptions.Timeout:
        logger.error("Timeout d'Ollama : le modèle %s est trop lent pour votre matériel.", OLLAMA_MODEL)
        logger.error("Astuce : essayez un modèle plus léger comme 'mistral' ou 'phi3'.")
        return None
    except Exception as e:
        logger.error("Ollama LLM générique Erreur: %s", e)
        return None
