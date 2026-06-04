"""
Générateur de Playbook d'Attaque (Garde-Fous : Drafts uniquement).
Associe la Vulnérabilité métier, le contexte RAG, et le prompt expert
afin de solliciter le modèle Ollama.
"""
import logging
from sqlalchemy.orm import Session

from app.db.models import Vulnerability, Report
from app.core.llm.rag import retrieve_context
from app.core.llm.ollama_client import generate_text

logger = logging.getLogger(__name__)

from typing import Literal

# --- Prompts Spécifiques ---

SYSTEM_PROMPT_BASE = """Tu es SIATI, un expert technique senior en cybersécurité offensive et consultant en test d'intrusion.
TON STYLE : Professionnel, factuel, extrêmement technique. Pas de politesses.
LANGUE : FRANÇAIS UNIQUEMENT. Ne réponds jamais en anglais.

RÈGLES CRITIQUES DE SÉCURITÉ ET PRÉCISION :
1. CIBLE : Toutes les commandes doivent cibler l'IP et le Port fournis dans le contexte.
2. PAS D'HALLUCINATION LOCALE : Ne suggère JAMAIS de commandes qui affichent la version du client local (ex: PAS de `ssh -V`, PAS de `nmap -V`).
3. VÉRIFICATION RÉELLE : Pour vérifier une version, utilise le Banner Grabbing (nc, telnet) ou des scans de service Nmap (`-sV`).
4. PERTINENCE : N'utilise que des outils adaptés au protocole (ex: PAS de Burp Suite pour SSH, PAS de Hydra pour un service sans authentification).
5. FORMATAGE : Utilise un Markdown riche (Titres, Tableaux, Blocs de code).
"""

AUDIT_PROMPT_EXTENSION = """
OBJECTIF : AUDIT ET VÉRIFICATION TECHNIQUE.
- Étape 1 : Confirmation de l'accessibilité (Ping, Test de port).
- Étape 2 : Identification précise de la version (Banner Grabbing, Nmap NSE).
- Étape 3 : Corrélation avec les vulnérabilités connues (CVE).
L'audit doit permettre de confirmer SANS AMBIGUÏTÉ que la cible est vulnérable avant de tenter l'exploitation.
"""

PAYLOAD_PROMPT_EXTENSION = """
OBJECTIF : EXPLOITATION ET PROOF OF CONCEPT (POC).
- Étape 1 : Configuration de l'environnement d'attaque.
- Étape 2 : Commande d'exploitation spécifique (ex: Python script, Metasploit, Exploit-DB).
- Étape 3 : Payload (Reverse Shell, Exécution de commande).
Si un CVE est fourni, centre TOUTE l'explication sur l'exploitation de ce CVE précis. Évite les conseils génériques.
"""

def validate_playbook_content(text: str, mode: str) -> bool:
    """Vérifie la qualité et rejette les structures méta-anglaises génériques."""
    if not text or len(text) < 150:
        return False
    
    txt_lower = text.lower()
    # On autorise un peu de bruit anglais (car TinyLlama a tendance à en générer)
    # On se concentre surtout sur la présence de code (```) et de mots-clés.

    has_code = "```" in text
    if mode == "audit":
        valid = has_code and (any(kw in txt_lower for kw in ["nmap", "curl", "vérification", "scan", "msf"]))
    else:
        valid = has_code and (any(kw in txt_lower for kw in ["exploit", "payload", "msfconsole", "shell", "rce"]))
    
    return valid

def generate_playbook_for_vulnerability(
    db_session: Session, 
    vuln_id: int, 
    mode: Literal["audit", "payload"] = "audit"
) -> int | None:
    """
    Génère un playbook avec validation automatique de cohérence.
    """
    vuln = db_session.get(Vulnerability, vuln_id)
    if not vuln or not vuln.service:
        logger.error("Vuln introuvable impossible d'inférer un Playbook.")
        return None
        
    svc = vuln.service
    host = svc.host
    cve = vuln.cve or "INCONNU"
    
    # 1. Sélection du Prompt et Titre
    if mode == "audit":
        sys_prompt = SYSTEM_PROMPT_BASE + AUDIT_PROMPT_EXTENSION
        titre_prefix = "VÉRIFICATION"
    else:
        sys_prompt = SYSTEM_PROMPT_BASE + PAYLOAD_PROMPT_EXTENSION
        titre_prefix = "EXPLOITATION"

    # 2. Requête Vectorielle optimisée
    if cve and cve != "INCONNU":
        query = f"Exploitation technique détaillée pour {cve} sur {svc.service} {svc.version}"
    else:
        query = f"Vérification et exploitation du service {svc.service} version {svc.version} sur port {svc.port}"
    
    context = retrieve_context(query, top_k=3)
    
    # 3. Composition du Prompt Métier
    user_prompt = f"""
### INFORMATIONS CIBLE ###
- IP : {host.ip}
- SERVICE : {svc.service}
- VERSION : {svc.version or 'Inconnue'}
- PORT : {svc.port} ({svc.protocol})
- VULNÉRABILITÉ : {cve}

### CONTEXTE DE RÉFÉRENCE (RAG) ###
{context}

### INSTRUCTIONS POUR LE RAPPORT PROFESSIONNEL ###
1. Rédige un rapport technique de qualité consultant.
2. Utilise des tableaux Markdown pour résumer les infos si nécessaire.
3. Ne mentionne JAMAIS ton identité d'IA.
4. Pour SSH, concentre-toi sur l'énumération d'utilisateurs ou les failles de clé si applicables.
5. Sois extrêmement précis sur les syntaxes de commandes.
"""
    logger.info("Soumission du Prompt [%s] pour %s...", mode.upper(), cve)
    
    # 4. Appel du Modèle Local
    generated_md = generate_text(prompt=user_prompt, system_prompt=sys_prompt)
    
    if not generated_md:
        logger.error("Défaut de réponse de l'LLM.")
        return None
        
    # 5. Validation Automatique (Preuve de Performance LLM)
    is_valid = validate_playbook_content(generated_md, mode)
    if not is_valid:
        logger.warning("⚠️ Playbook généré semble incomplet ou mal formaté. Marquage comme 'DRAFT'")
        status_tag = " [VALIDATION ÉCHOUÉE]"
    else:
        status_tag = ""

    # 6. Gestion du Rapport (UPSERT)
    from datetime import datetime
    titre = f"[{titre_prefix}] {host.ip}:{svc.port} - {cve}{status_tag}"
    
    header = (
        f"| Attribut | Valeur |\n"
        f"| :--- | :--- |\n"
        f"| **Cible** | `{host.ip}` |\n"
        f"| **Service** | `{svc.service} {svc.version or ''}` |\n"
        f"| **Port** | `{svc.port}/{svc.protocol}` |\n"
        f"| **Vérification** | {cve} |\n"
        f"| **Date** | {datetime.now().strftime('%Y-%m-%d %H:%M')} |\n\n"
        f"---\n\n"
    )

    content_draft = (
        f"> [!IMPORTANT]\n"
        f"> **ÉTAPE: {mode.upper()}**\n"
        f"> Ce document est une suggestion générée par IA. État Validation: {'✅ OK' if is_valid else '❌ Incomplet'}\n\n"
        f"{header}"
        f"{generated_md}"
    )
    
    report = db_session.query(Report).filter(Report.vuln_id == vuln_id, Report.stage == mode).first()

    if report:
        report.title = titre
        report.content_md = content_draft
        report.timestamp = datetime.utcnow()
    else:
        report = Report(title=titre, content_md=content_draft, stage=mode, vuln_id=vuln_id)
        db_session.add(report)

    try:
        db_session.commit()
        logger.info("Playbook [%s] synchronisé -> Report ID %s (Valid: %s)", mode, report.id, is_valid)
        return report.id
    except Exception as e:
        logger.error("Erreur stockage (UPSERT) : %s", e)
        db_session.rollback()
        return None

def chat_with_vulnerability(
    db_session: Session,
    vuln_id: int,
    messages: list[dict]
) -> str | None:
    """
    Gère un dialogue continu sur une vulnérabilité spécifique avec contexte RAG.
    """
    vuln = db_session.get(Vulnerability, vuln_id)
    if not vuln or not vuln.service:
        return "Erreur: Vulnérabilité non trouvée."

    svc = vuln.service
    host = svc.host
    cve = vuln.cve or "INCONNU"

    # Récupération du contexte RAG (basé sur le dernier message utilisateur)
    last_user_msg = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
    context = retrieve_context(last_user_msg or cve, top_k=2)

    sys_prompt = SYSTEM_PROMPT_BASE + f"""
DÉTAILS TECHNIQUES : {cve} sur {host.ip} ({svc.service}).
CONTEXTE RAG : {context}

RÈGLES DE DIALOGUE :
1. RÉPONDS TOUJOURS EN FRANÇAIS. Ne bascule jamais en anglais.
2. Sois technique, direct et précis. Fournis des explications approfondies sur les étapes d'exploitation.
3. Utilise des blocs de code Markdown pour chaque commande suggérée.
4. Évite le bavardage ("Sure!", "I am on!"). Entre directement dans le vif du sujet.
5. Si l'utilisateur demande d'expliquer mieux, approfondis la technique d'attaque spécifique liée au service {svc.service}.
"""
    from app.core.llm.ollama_client import chat as ollama_chat
    return ollama_chat(messages, system_prompt=sys_prompt)
