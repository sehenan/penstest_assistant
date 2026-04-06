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

# Personnage et consignes strictes (Anti-Hallucination)
SYSTEM_PROMPT = """Tu es un auditeur de cybersécurité offensive professionnel (Pentester).
Ton rôle exclusif est d'assister un opérateur humain.
Règles strictes :
1. Base-toi UNIQUEMENT sur les informations du "Contexte RAG".
2. Propose des commandes shell/terminal exactes (au formalisme Markdown).
3. Adapte tes charges utiles (payloads) à l'IP et au port de la cible.
4. N'hallucine jamais d'exploit. Si le RAG est vide, réponds formellement: "Contexte insuffisant pour fournir une routine d'exploitation fiable."
5. Structure la réponse : [1] Enumération -> [2] Exploitation -> [3] Post-Exploitation.
"""

def generate_playbook_for_vulnerability(db_session: Session, vuln_id: int) -> int | None:
    """
    Déploie la séquence de génération intégrale pour cibler une vulnérabilité précise.
    Les playbooks produits sont stockés et soumis à validation "DRAFT".
    """
    vuln = db_session.get(Vulnerability, vuln_id)
    if not vuln or not vuln.service:
        logger.error("Vuln introuvable impossible d'inférer un Playbook.")
        return None
        
    svc = vuln.service
    host = svc.host
    cve = vuln.cve or "INCONNU"
    
    # 1. Requête Vectorielle
    query = f"Technique d'exploitation et guide pour {cve} affectant {svc.service or 'service inconnu'} sur port {svc.port}."
    context = retrieve_context(query, top_k=3)
    
    # 2. Composition du Prompt Métier
    user_prompt = f"""
=== CONTEXTE TECHNIQUE EXTRAIT ===
{context}
==================================

Cible en cours d'Audit :
- Machine: {host.ip}
- Port d'entrée: {svc.port} (TCP/UDP: {svc.protocol})
- Service détecté: {svc.service} {svc.version or ''}
- Failles qualifiées: {cve}

Développe un Playbook d'exploitation structuré et concis ciblant cette machine.
"""
    logger.info("Soumission du Prompt à l'LLM local pour la vulnérabilité %s...", cve)
    
    # 3. Appel du Modèle Local
    generated_md = generate_text(prompt=user_prompt, system_prompt=SYSTEM_PROMPT)
    
    if not generated_md:
        logger.error("Défaut de réponse de l'LLM. Relance requise.")
        return None
        
    # 4. Garde-Fou Fonctionnel (DRAFT Status)
    titre = f"PLAYBOOK [DRAFT] - {host.ip}:{svc.port} - {cve}"
    content_draft = (
        "> [!CAUTION]\n"
        "> **BROUILLON (RELECTURE HUMAINE REQUISE)**\n"
        "> Ce playbook a été généré par IA. Validez systématiquement les adresses IPs et les "
        "> shells injectés avant d'exécuter l'arsenal offensif sur l'environnement client.\n\n"
        f"{generated_md}"
    )
    
    report = Report(
        title=titre,
        content_md=content_draft
    )
    
    db_session.add(report)
    try:
        db_session.commit()
        logger.info("Playbook inséré avec succès en base -> Report ID %s", report.id)
        return report.id
    except Exception as e:
        logger.error("Stockage du Playbook avorté: %s", e)
        db_session.rollback()
        return None
