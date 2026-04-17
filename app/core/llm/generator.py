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

SYSTEM_PROMPT_BASE = """Tu es un auditeur de cybersécurité offensive professionnel (Pentester).
Ton rôle exclusif est d'assister un opérateur humain.
Règles strictes :
1. Base-toi UNIQUEMENT sur les informations du "Contexte RAG".
2. Propose des commandes shell/terminal exactes (au formalisme Markdown).
3. Adapte tes charges utiles (payloads) à l'IP et au port de la cible.
4. N'hallucine jamais d'exploit. Si le RAG est vide, réponds formellement: "Contexte insuffisant".
"""

AUDIT_PROMPT_EXTENSION = """
OBJECTIF : VÉRIFICATION DES CONDITIONS D'EXPLOITATION.
- Propose des commandes d'énumération avancée (nmap scripts, curl, etc.) pour confirmer la version et la vulnérabilité.
- Vérifie les accès réseaux ou les dépendances nécessaires.
- Ne propose PAS encore l'exploit final, seulement la phase de reconnaissance/validation.
"""

PAYLOAD_PROMPT_EXTENSION = """
OBJECTIF : EXPLOITATION FINALE ET PAYLOAD.
- Développe le script d'exploitation complet ou la commande metasploit/POC.
- Fournis les instructions pour obtenir un accès (Reverse Shell, RCE, etc.).
- Structure la réponse : [1] Exploitation -> [2] Post-Exploitation.
"""

def generate_playbook_for_vulnerability(
    db_session: Session, 
    vuln_id: int, 
    mode: Literal["audit", "payload"] = "audit"
) -> int | None:
    """
    Génère un playbook en fonction du mode choisi : 
    - 'audit' : Pour vérifier les conditions d'exploitation.
    - 'payload' : Pour l'exécution de l'exploit final.
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
        titre_prefix = "VERIFICATION"
    else:
        sys_prompt = SYSTEM_PROMPT_BASE + PAYLOAD_PROMPT_EXTENSION
        titre_prefix = "EXPLOIT"

    # 2. Requête Vectorielle
    query = f"Technique d'exploitation et guide pour {cve} affectant {svc.service or 'service inconnu'} sur port {svc.port}."
    context = retrieve_context(query, top_k=3)
    
    # 3. Composition du Prompt Métier
    user_prompt = f"""
=== CONTEXTE TECHNIQUE EXTRAIT ===
{context}
==================================

Cible en cours d'Audit :
- Machine: {host.ip}
- Port d'entrée: {svc.port} ({svc.protocol})
- Service détecté: {svc.service} {svc.version or ''}
- Failles qualifiées: {cve}

Développe un guide de type {mode.upper()} structuré pour cette machine.
"""
    logger.info("Soumission du Prompt [%s] pour %s...", mode.upper(), cve)
    
    # 4. Appel du Modèle Local
    generated_md = generate_text(prompt=user_prompt, system_prompt=sys_prompt)
    
    if not generated_md:
        logger.error("Défaut de réponse de l'LLM.")
        return None
        
    # 5. Création du Rapport
    titre = f"[{titre_prefix}] {host.ip}:{svc.port} - {cve}"
    content_draft = (
        f"> [!IMPORTANT]\n"
        f"> **STAGE: {mode.upper()}**\n"
        f"> Ce document est une suggestion générée par IA pour la vulnérabilité {cve}.\n\n"
        f"{generated_md}"
    )
    
    report = Report(
        title=titre,
        content_md=content_draft,
        stage=mode,
        vuln_id=vuln_id
    )
    
    db_session.add(report)
    try:
        db_session.commit()
        logger.info("Playbook [%s] inséré -> Report ID %s", mode, report.id)
        return report.id
    except Exception as e:
        logger.error("Erreur stockage : %s", e)
        db_session.rollback()
        return None
