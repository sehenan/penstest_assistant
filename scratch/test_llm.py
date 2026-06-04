import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.llm.ollama_client import generate_text

try:
    print("Testing LLM generation with Mistral...")
    system_prompt = "Tu es un expert cyber. Réponds uniquement en Français. Sois technique."
    user_prompt = "Génère une commande bash pour vérifier si le port 6200 d'un serveur (192.168.1.1) est ouvert, avec netcat."
    
    response = generate_text(prompt=user_prompt, system_prompt=system_prompt)
    print("=== RESPONSE FROM LLM ===")
    print(response)
    print("=== END RESPONSE ===")
except Exception as e:
    import traceback
    traceback.print_exc()
