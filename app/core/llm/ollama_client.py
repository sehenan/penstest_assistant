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

# Modèle par défaut : mistral. Mistral est souvent plus rapide sur CPU.
# Remplacement par mistral.
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:7b-instruct-q4_K_M")
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
    Standard generation (legacy wrapper for chat).
    """
    return chat([{"role": "user", "content": prompt}], system_prompt)

def chat(messages: list[dict], system_prompt: str = "") -> str | None:
    """
    Utilise l'endpoint /api/chat pour maintenir un contexte de conversation.
    messages: Liste de dict {"role": "user/assistant", "content": "..."}
    """
    url = f"{OLLAMA_HOST}/api/chat"
    
    if not check_ollama_status():
        logger.error("Serveur Ollama inaccessible.")
        return None

    # Injection du system prompt comme premier message si fourni
    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    payload = {
        "model": OLLAMA_MODEL,
        "messages": full_messages,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1024,
            "repeat_penalty": 1.25,
            "top_p": 0.6,
            "top_k": 20,
            "stop": ["Introduction:", "Overview:", "Bibliography:", "Conclusion:"]
        }
    }
    
    try:
        r = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")
    except Exception as e:
        logger.error("Erreur Chat Ollama: %s", e)
        return None
