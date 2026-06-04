# === FICHIER : app/module_llm/llm/generator.py ===
import json
import requests
from typing import List, Dict, Optional
from datetime import datetime
import logging
logger = logging.getLogger(__name__)

class Generator:
    """
    Composant C : Responsable de la génération de playbooks via Ollama
    en respectant strictement le contexte RAG fourni.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.url = f"{config['llm']['ollama_url']}/api/generate"
        self.model = config['llm']['model']
        self.timeout = config['llm']['timeout_seconds']
        self.max_tokens = config['llm']['max_tokens']

    def _build_system_prompt(self) -> str:
        return """Tu es un assistant spécialisé en tests d'intrusion (pentest).
Tu génères des playbooks d'exploitation UNIQUEMENT à partir des sources documentaires fournies dans le contexte ci-dessous.

RÈGLES ABSOLUES :
1. Tu ne dois JAMAIS inventer de commandes, payloads, techniques ou étapes qui ne sont pas présentes dans le contexte fourni.
2. Chaque affirmation doit être directement extraite d'un chunk du contexte et préfixée de sa source : [Source: nom].
3. Si le contexte est insuffisant pour une section, tu écris EXACTEMENT :
   [SOURCE INSUFFISANTE — vérification manuelle requise]
4. Tu ne dois pas reformuler librement une technique ; tu la reproduis fidèlement depuis la source.
5. Les blocs de code doivent être copiés tels quels depuis le contexte, sans modification.

FORMAT OBLIGATOIRE DU PLAYBOOK (Markdown) :

---
# Playbook — [CVE-XXXX-XXXX] — [Service] [Version]
**Score CVSS :** X.X | **Port :** XXXX | **Exploit dispo :** Oui/Non
**Généré le :** YYYY-MM-DD HH:MM

## 1. Résumé de la vulnérabilité
[Source: NVD] ...

## 2. Conditions préalables
[Source: HackTricks] ...

## 3. Étapes d'exploitation
[Source: HackTricks | PayloadsAllTheThings]
1. ...
2. ...

## 4. Commandes et Payloads
[Source: PayloadsAllTheThings]
```bash
# Commande exacte issue de la source
...
```

## 5. Module Metasploit associé
[Source: Exploit-DB] exploit/xxxx/xxxx
[SOURCE INSUFFISANTE — vérification manuelle requise]

## 6. Techniques MITRE ATT&CK
[Source: MITRE ATT&CK] T1190 — Exploit Public-Facing Application

## 7. Impact potentiel
[Source: NVD/CVSS] ...

## 8. Recommandations de remédiation
[Source: NVD] ...

## 9. Sources utilisées
- HackTricks : https://...
- PayloadsAllTheThings : https://...
---"""

    def _build_user_prompt(self, vulnerability: Dict, context_chunks: List[Dict]) -> str:
        # Métadonnées de la vulnérabilité
        vuln_info = (
            f"VULNÉRABILITÉ CIBLE :\n"
            f"- CVE : {vulnerability.get('cve', 'Inconnu')}\n"
            f"- CVSS : {vulnerability.get('cvss_score', 'N/A')}\n"
            f"- Vecteur : {vulnerability.get('cvss_vector', 'N/A')}\n"
            f"- Service : {vulnerability.get('service', 'Inconnu')}\n"
            f"- Port : {vulnerability.get('port', 'Inconnu')}\n"
            f"- Version : {vulnerability.get('version', 'Inconnu')}\n"
            f"- Exploit Disponible : {'Oui' if vulnerability.get('exploit_disponible') else 'Non'}\n"
            f"- Module Metasploit : {vulnerability.get('metasploit_module', 'N/A')}\n\n"
        )

        # Chunks RAG
        rag_context = "CONTEXTE DOCUMENTAIRE (SOURCES FIABLES) :\n"
        if not context_chunks:
            rag_context += "[AUCUN CONTEXTE TROUVÉ DANS LA BASE DE CONNAISSANCES]\n"
        else:
            for chunk in context_chunks:
                source_name = chunk.get('source_name', 'Inconnu')
                source_url = chunk.get('source_url', 'N/A')
                source_date = chunk.get('source_date', 'N/A')
                rag_context += f"[SOURCE: {source_name} | {source_url} | {source_date}]\n"
                rag_context += f"{chunk.get('text', '')}\n\n"

        instruction = (
            "Génère maintenant le playbook Markdown complet en respectant strictement "
            "le format demandé et en citant chaque source utilisée."
        )

        return f"{vuln_info}{rag_context}{instruction}"

    def generate_playbook(self, vulnerability: Dict, context_chunks: List[Dict]) -> Optional[str]:
        """
        Appelle l'API Ollama pour générer le playbook.
        """
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(vulnerability, context_chunks)

        payload = {
            "model": self.model,
            "prompt": user_prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "num_predict": self.max_tokens,
                "temperature": 0.1
            }
        }

        try:
            logger.info(f"Envoi de la requête de génération à Ollama ({self.model})...")
            response = requests.post(self.url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            result = response.json()
            generated_text = result.get('response', '')

            if not generated_text:
                logger.warning("Réponse vide d'Ollama.")
                return None

            # Vérification basique des sections obligatoires
            mandatory_sections = ["## 1.", "## 3.", "## 9."]
            if not all(sec in generated_text for sec in mandatory_sections):
                logger.warning("Le playbook généré semble incomplet (sections manquantes).")

            return generated_text

        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur de communication avec Ollama : {e}")
            return None
        except Exception as e:
            logger.error(f"Erreur inattendue lors de la génération : {e}")
            return None
