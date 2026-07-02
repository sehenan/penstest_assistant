"""
Connecteur sécurisé à l'API locale d'Ollama.
Invoque les LLM pré-configurés (Llama3, Mistral) depuis le socle air-gap local.
"""
import json
import logging
import os
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

# Config Air-Gap : L'API réside sur le localhost par défaut.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

# Modèle par défaut : llama3 (mistral a été retiré du socle). Surcharge possible
# via l'env OLLAMA_MODEL (positionné par docker-compose / config de déploiement).
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")
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
    Génération longue (playbook, rapport).
    Température basse, num_predict élevé pour des rapports complets.
    """
    url = f"{OLLAMA_HOST}/api/chat"

    if not check_ollama_status():
        logger.error("Serveur Ollama inaccessible.")
        return None

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
            "num_predict": 4096,
            "repeat_penalty": 1.1,
            "top_p": 0.9,
            "top_k": 40,
            "stop": ["Introduction:", "Overview:", "Bibliography:"]
        }
    }

    try:
        r = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")
    except Exception as e:
        logger.error("Erreur Chat Ollama: %s", e)
        return None


def chat_completion(messages: list[dict], system_prompt: str = "") -> str | None:
    """
    Dialogue interactif (questions/réponses).
    Température plus élevée et num_predict limité pour éviter les boucles de répétition
    quand le contexte (historique + system prompt) est long.
    """
    url = f"{OLLAMA_HOST}/api/chat"

    if not check_ollama_status():
        logger.error("Serveur Ollama inaccessible.")
        return None

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    payload = {
        "model": OLLAMA_MODEL,
        "messages": full_messages,
        "stream": False,
        "options": {
            "temperature": 0.4,
            "num_predict": 1500,
            "repeat_penalty": 1.3,
            "top_p": 0.9,
            "top_k": 40,
        }
    }

    try:
        r = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")
    except Exception as e:
        logger.error("Erreur Chat Completion Ollama: %s", e)
        return None


def chat_completion_stream(messages: list[dict], system_prompt: str = "") -> Iterator[str]:
    """
    Variante STREAMING du dialogue interactif : identique à chat_completion
    (même modèle, mêmes options → qualité identique) mais émet la réponse token
    par token au fur et à mesure de la génération. Réduit drastiquement la latence
    perçue : le premier mot s'affiche en quelques secondes au lieu d'attendre la
    réponse complète (~1500 tokens).
    """
    url = f"{OLLAMA_HOST}/api/chat"

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    payload = {
        "model": OLLAMA_MODEL,
        "messages": full_messages,
        "stream": True,
        "options": {
            "temperature": 0.4,
            "num_predict": 1500,
            "repeat_penalty": 1.3,
            "top_p": 0.9,
            "top_k": 40,
        },
    }

    try:
        with requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (ValueError, TypeError):
                    continue
                chunk = obj.get("message", {}).get("content", "")
                if chunk:
                    yield chunk
                if obj.get("done"):
                    break
    except Exception as e:
        logger.error("Erreur Chat Completion Stream Ollama: %s", e)
        return
