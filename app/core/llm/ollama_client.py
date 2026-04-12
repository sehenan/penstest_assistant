"""
Connecteur sécurisé à l'API locale d'Ollama.
Invoque les LLM pré-configurés (Llama3, Mistral) depuis le socle air-gap local.
"""
import logging
import os
import requests

logger = logging.getLogger(__name__)

# Config Air-Gap : L'API réside sur le localhost par défaut.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

# Llama3 est configuré par défaut comme LLM "Recommandé / Best-in-Class local"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")


def generate_text(prompt: str, system_prompt: str = "") -> str | None:
    """
    Interagit avec l'API Ollama (generate endpoint) avec paramétrages conservateurs.
    (Température basse pour minimiser l'hallucination et maximiser le ciblage technique).
    """
    url = f"{OLLAMA_HOST}/api/generate"
    
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
    
    logger.debug("Prompting de %s via %s...", OLLAMA_MODEL, url)
    try:
        r = requests.post(url, json=payload, timeout=300)
        r.raise_for_status()
        return r.json().get("response", "")
    except requests.exceptions.Timeout:
        logger.error("Timeout d'Ollama : le modèle LLM est pris dans une boucle ou matériel insuffisant.")
        return None
    except requests.exceptions.ConnectionError:
        logger.error("Impossible de joindre Ollama. Le démon tourne-t-il sur %s ?", OLLAMA_HOST)
        return None
    except Exception as e:
        logger.error("Ollama LLM générique Erreur: %s", e)
        return None
