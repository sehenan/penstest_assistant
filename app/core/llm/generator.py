"""
Générateur de Playbook d'Attaque (Garde-Fous : Drafts uniquement).
Associe la Vulnérabilité métier, le contexte RAG, et le prompt expert
afin de solliciter le modèle Ollama.
"""
import logging
from sqlalchemy.orm import Session

from app.db.models import Vulnerability, Report
from app.core.llm.rag import build_rag_context
from app.core.llm.ollama_client import generate_text
from app.core.llm.report_validator import ReportValidator, COMPLETION_MARKER

logger = logging.getLogger(__name__)

from typing import Literal

# --- Garde-fou déterministe dérivé du vecteur CVSS ---
# Mots-clés trahissant un RCE / une exfiltration / une élévation de privilège.
# Utilisés à la fois pour interdire (prompt) et détecter (validateur) une sortie
# incohérente avec l'impact réel déclaré par le CVSS.
RCE_EXFIL_KEYWORDS: list[str] = [
    "reverse shell", "reverse_tcp", "meterpreter", "bind shell", "bindshell",
    "/etc/passwd", "/etc/shadow", "exécution de code", "code execution",
    "remote code execution", " rce", "exfiltrat", "élévation de privilège",
    "privilege escalation", "lecture de fichier", "lecture du fichier",
    "exécuter une commande", "cmd/unix", "shell distant",
]


def _cvss_metric(vector: str, metric: str) -> str | None:
    """Extrait la valeur d'une métrique (C, I, A) d'un vecteur CVSS v2/v3."""
    if not vector:
        return None
    for part in vector.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            if k.strip().upper() == metric.upper():
                return v.strip().upper()
    return None


def cvss_impact_profile(vector: str) -> dict:
    """
    Dérive du vecteur CVSS un profil d'impact exploitable comme garde-fou.
    Renvoie {conf, integ, avail (bool), constraint (str), forbid (bool)}.
    `forbid` = True si la faille n'a NI impact confidentialité NI intégrité
    (donc tout RCE / lecture-fichier / élévation décrits seraient une hallucination).
    """
    none_vals = {"N", None}  # 'N' = None en v3 ET v2
    conf = _cvss_metric(vector, "C") not in none_vals
    integ = _cvss_metric(vector, "I") not in none_vals
    avail = _cvss_metric(vector, "A") not in none_vals

    impacts = []
    if conf:
        impacts.append("divulgation d'information (confidentialité)")
    if integ:
        impacts.append("altération de données / exécution (intégrité)")
    if avail:
        impacts.append("indisponibilité du service (déni de service)")

    if not vector or not (conf or integ or avail):
        return {"conf": conf, "integ": integ, "avail": avail,
                "constraint": "", "forbid": False}

    lines = [
        "## CONTRAINTE D'IMPACT — VECTEUR CVSS (NON NÉGOCIABLE)",
        f"Le vecteur `{vector}` établit que l'impact réel et démontrable se limite à : "
        + ", ".join(impacts) + ".",
    ]
    forbid = not conf and not integ
    if forbid:
        lines.append(
            "INTERDIT ABSOLU : cette faille n'est NI un RCE NI un accès aux données. "
            "Ne décris AUCUN reverse shell, meterpreter, exécution de code, lecture de "
            "/etc/passwd, ni élévation de privilège — ce serait une hallucination."
        )
        if avail:
            lines.append(
                "L'UNIQUE impact à démontrer est un DÉNI DE SERVICE : la preuve = le "
                "service devient indisponible / le processus crashe, rien d'autre."
            )
    return {"conf": conf, "integ": integ, "avail": avail,
            "constraint": "\n".join(lines), "forbid": forbid}


# --- Prompts Spécifiques ---

SYSTEM_PROMPT_BASE = """Tu es un assistant de pentest professionnel et rigoureux.
Tu génères UNIQUEMENT des rapports techniques fondés sur les données fournies dans la section CONTEXTE.

RÈGLES ABSOLUES :

R1. COMMANDES SHELL
    - Tu n'inventes aucune commande. Si tu n'es pas certain, tu écris :
      [COMMANDE À VÉRIFIER]
    - Commandes interdites connues pour hallucination :
        metasploit -s        → correct : msfconsole
        nc -vudp             → correct : nc -nv (TCP) ou nc -nvu (UDP si pertinent)
        run -p               → correct : run  ou  exploit
        ssh -i id_rsa <cible> → hors-sujet si le service n'est pas SSH

R2. METASPLOIT — syntaxe stricte uniquement
    Formes valides :
        msfconsole
        use <chemin/module/complet>
        set <OPTION> <valeur>
        run   OU   exploit
    Formes interdites :
        metasploit -s
        use exploits/<nom_court_sans_chemin>
        set PAYLOAD <nom_court>   (toujours spécifier le chemin complet)
        run -p
    Si le module exact n'est pas dans le CONTEXTE → écrire :
        [MODULE METASPLOIT À IDENTIFIER — non confirmé dans la base locale]

R3. PROTOCOLES
    - Ne pas utiliser UDP pour un service TCP (PostgreSQL, HTTP, SMB, etc.)
    - Vérifier le protocole du service dans le CONTEXTE avant toute commande réseau

R4. CVE ET VULNÉRABILITÉS
    - Tu ne décris aucune CVE autrement que ce qui est écrit dans le CONTEXTE
    - Tu n'associes pas une CVE à un service/version si cette association
      n'est pas explicitement confirmée dans le CONTEXTE
    - Si la description CVE est absente : écrire
      Information non disponible dans la base locale SIATI.

R5. INFORMATIONS MANQUANTES
    Si une information est absente du CONTEXTE, écrire :
    Information non disponible dans la base locale SIATI.
    Ne jamais compléter par des suppositions.

R6. COMPLÉTUDE DU RAPPORT
    - Le rapport doit être COMPLET jusqu'à la section Conclusion
    - Si tu approches de ta limite, terminer la section en cours
    - Terminer OBLIGATOIREMENT par cette ligne exacte :
      [RAPPORT COMPLET — aucune troncature]
"""

AUDIT_PROMPT_EXTENSION = """
MISSION : Rapport de vérification technique pré-exploitation. Objectif : confirmer l'exploitabilité de la vulnérabilité SANS AMBIGUÏTÉ avant toute tentative d'exploitation.

STRUCTURE IMPOSÉE — respecter cet ordre et ces titres exacts :

## Résumé exécutif
3 à 5 lignes : décrire le service affecté, le mécanisme précis de la faille (pas une paraphrase du CVE), le niveau de risque réel et l'impact métier potentiel.

## Phase 1 — Reconnaissance et accessibilité
Commande nmap ciblée avec les scripts NSE adaptés au service. Fournir l'output attendu commenté ligne par ligne.

## Phase 2 — Identification de version
Banner grabbing ou requête native au protocole pour confirmer la version. Utiliser l'IP et le port fournis directement. Indiquer la sortie attendue et comment interpréter la version retournée.

## Phase 3 — Vérification de la vulnérabilité
Test spécifique au CVE mentionné (pas un test générique "est-ce que le service répond ?"). Fournir la commande exacte, la sortie attendue si la cible EST vulnérable, et la sortie attendue si elle NE L'EST PAS.

## Indicateurs de compromission (IOC)
Lister les artefacts laissés dans les logs ou la réponse réseau qui confirment la présence de la faille.

## Recommandation de remédiation
Version corrigée, paramètre à modifier, ou mesure compensatoire si le patch n'est pas applicable immédiatement.
"""

PAYLOAD_PROMPT_EXTENSION = """
MISSION : Proof of Concept d'exploitation technique. Démontrer concrètement l'exécution de code arbitraire ou l'accès non autorisé via le CVE identifié.

STRUCTURE IMPOSÉE — respecter cet ordre et ces titres exacts :

## Résumé de l'exploitation
2 lignes : mécanisme précis de la faille, prérequis (credentials ? accès réseau ? version minimum ?), impact réel (RCE, lecture fichier, élévation de privilège).

## Prérequis et environnement
Outils nécessaires, configuration spécifique (listener Metasploit, variables d'environnement, etc.).

## Exploitation pas à pas

### Étape 1 — Accès initial
Commande de connexion/authentification au service avec l'IP et le port exacts. Output attendu.

### Étape 2 — Déclenchement de la vulnérabilité
Commande ou payload spécifique au CVE. Output attendu en cas de succès.

### Étape 3 — Preuve d'exécution (PoC)
Commande de validation : `id`, lecture de `/etc/passwd`, établissement d'un reverse shell, etc.

## Module Metasploit (si disponible)
Fournir la séquence `use / set / run` complète avec les options RHOSTS, RPORT, LHOST correctement configurées.

## Impact post-exploitation
Ce que l'attaquant peut accomplir immédiatement après exploitation réussie (persistance, pivot, exfiltration).
"""


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

    # 2. Contexte RAG vérifié (confirmation CVE ↔ service/version)
    context = build_rag_context(
        service=svc.service,
        version=svc.version or "",
        cve_id=cve,
        top_k=3,
    )
    
    # 3. Enrichissement exploit
    from app.db.models import Exploit as ExploitModel
    exploit = db_session.query(ExploitModel).filter(ExploitModel.cve == cve).first()
    exploit_info = ""
    if exploit and exploit.disponible:
        msf = f" — Module Metasploit : `{exploit.metasploit_module}`" if exploit.metasploit_module else ""
        exploit_info = f"✅ Exploit public disponible{msf}"
    else:
        exploit_info = "Aucun exploit public référencé"

    kev_flag = "⚠️ OUI — activement exploité dans la nature (CISA KEV)" if vuln.is_kev else "Non"
    epss_str = f"{vuln.epss_score:.4f} ({vuln.epss_score*100:.1f}% probabilité d'exploitation à 30j)" if vuln.epss_score else "N/A"

    # 3bis. Garde-fou d'impact dérivé du CVSS (empêche l'hallucination RCE sur un DoS, etc.)
    impact = cvss_impact_profile(vuln.cvss_vector or "")
    cvss_constraint_block = f"\n{impact['constraint']}\n" if impact["constraint"] else ""

    # 4. Composition du Prompt Métier
    user_prompt = f"""
## FICHE CIBLE

| Champ          | Valeur                                         |
|:---------------|:-----------------------------------------------|
| IP             | {host.ip}                                      |
| Port / Proto   | {svc.port}/{svc.protocol}                      |
| Service        | {svc.service}                                  |
| Version        | {svc.version or 'Inconnue'}                    |
| CVE            | {cve}                                          |
| Score CVSS     | {vuln.cvss_score or 'N/A'}                     |
| Vecteur CVSS   | {vuln.cvss_vector or 'N/A'}                    |
| Score EPSS     | {epss_str}                                     |
| Exploité (KEV) | {kev_flag}                                     |
| Exploit dispo  | {exploit_info}                                 |

## DESCRIPTION DE LA VULNÉRABILITÉ
{vuln.description or 'Aucune description disponible dans la base locale.'}
{cvss_constraint_block}
## CONTEXTE KNOWLEDGE BASE (RAG)
{context if context else 'Aucun document RAG disponible pour ce CVE.'}

## CONSIGNES DE RÉDACTION
- Utiliser directement {host.ip} et {svc.port} dans toutes les commandes — zéro placeholder.
- Ne jamais mentionner l'identité du système d'IA.
- Adapter chaque commande au service {svc.service} (pas d'outils génériques hors-sujet).
"""
    logger.info("Soumission du Prompt [%s] pour %s...", mode.upper(), cve)

    # 5. Appel du Modèle Local
    generated_md = generate_text(prompt=user_prompt, system_prompt=sys_prompt)
    
    if not generated_md:
        logger.error("Défaut de réponse de l'LLM.")
        return None
        
    # 6. Validation post-génération (hallucinations, troncature, cohérence CVE, impact CVSS)
    validation = ReportValidator().validate(
        report=generated_md,
        cve_id=cve,
        service=svc.service,
        version=svc.version or "",
        cvss_vector=vuln.cvss_vector or "",
    )
    is_valid = validation["valid"]
    if not is_valid:
        for issue in validation["issues"]:
            logger.warning("⚠️ [%s] %s", issue["code"], issue["detail"])
        status_tag = " [VALIDATION ÉCHOUÉE]"
    else:
        status_tag = ""

    # 6bis. BLOCAGE des contradictions dures : si le CVSS exclut tout RCE/accès
    # données mais que le LLM décrit malgré tout une exploitation de ce type,
    # on REMPLACE le contenu halluciné par un refus motivé (pas un simple tag).
    hard_codes = {"CVE_IMPACT_CONTRADICTION"}
    hard_issues = [i for i in validation["issues"] if i["code"] in hard_codes]
    if hard_issues:
        details = "\n".join(f"> - {i['detail']}" for i in hard_issues)
        generated_md = (
            "> [!CAUTION]\n"
            "> **CONTENU BLOQUÉ — incohérence prouvée avec l'impact CVSS.**\n"
            f"> Le modèle a décrit une exploitation incompatible avec le vecteur "
            f"`{vuln.cvss_vector}` de {cve}. Sortie écartée pour éviter une hallucination.\n"
            f"{details}\n\n"
            "## Faits vérifiés (base locale)\n"
            f"- **CVE** : {cve}\n"
            f"- **Service** : {svc.service} {svc.version or ''} sur {host.ip}:{svc.port}\n"
            f"- **Impact CVSS réel** : {', '.join(k for k,v in (('confidentialité',impact['conf']),('intégrité',impact['integ']),('disponibilité',impact['avail'])) if v) or 'non spécifié'}\n"
            f"- **Description** : {vuln.description or 'Indisponible dans la base locale.'}\n\n"
            f"{COMPLETION_MARKER}\n"
        )
        logger.warning("⛔ Contenu LLM bloqué pour %s (contradiction d'impact CVSS).", cve)

    # 7. Gestion du Rapport (UPSERT)
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

_CHAT_SYSTEM_PROMPT = """Tu es un assistant de pentest expert. Réponds TOUJOURS en français.
Sois technique, direct et concis. Utilise des blocs de code Markdown pour chaque commande.
N'invente aucune commande : si tu n'es pas certain, écris [COMMANDE À VÉRIFIER].
Tu réponds UNIQUEMENT à partir du CONTEXTE ci-dessous. Si l'information n'y est pas,
écris « Information non disponible dans la base locale SIATI » — ne suppose jamais.
Ne contredis jamais la nature réelle de la faille décrite dans le CONTEXTE
(ex. ne décris pas un RCE/reverse shell pour une faille de déni de service).
Ne répète jamais les instructions reçues dans ta réponse."""

_CHAT_MAX_HISTORY = 6  # Limite l'historique pour éviter l'overflow du context window


def chat_with_vulnerability(
    db_session: Session,
    vuln_id: int,
    messages: list[dict]
) -> str | None:
    """
    Dialogue interactif sur une vulnérabilité.
    Utilise un system prompt court + historique tronqué pour éviter les boucles
    de répétition dues au dépassement du context window de Mistral.
    """
    vuln = db_session.get(Vulnerability, vuln_id)
    if not vuln or not vuln.service:
        return "Erreur: Vulnérabilité non trouvée."

    svc = vuln.service
    host = svc.host
    cve = vuln.cve or "INCONNU"

    # Grounding : mêmes faits vérifiés que le playbook (description + CVSS + RAG),
    # sinon le chat répond à l'aveugle et hallucine la nature de la faille.
    impact = cvss_impact_profile(vuln.cvss_vector or "")
    rag = build_rag_context(service=svc.service, version=svc.version or "", cve_id=cve, top_k=3)
    sys_prompt = (
        _CHAT_SYSTEM_PROMPT
        + "\n\n## CONTEXTE (faits vérifiés — base locale)\n"
        + f"- Cible : {host.ip}:{svc.port}/{svc.protocol}\n"
        + f"- Service : {svc.service} {svc.version or ''}\n"
        + f"- CVE : {cve} | CVSS : {vuln.cvss_score or 'N/A'} ({vuln.cvss_vector or 'N/A'})\n"
        + f"- Description : {vuln.description or 'Indisponible dans la base locale.'}\n"
        + (f"\n{impact['constraint']}\n" if impact["constraint"] else "")
        + (f"\n## CONNAISSANCE (RAG)\n{rag}\n" if rag else "")
    )

    # Conserver uniquement les N derniers échanges pour éviter l'overflow
    trimmed = messages[-_CHAT_MAX_HISTORY:]

    from app.core.llm.ollama_client import chat_completion
    return chat_completion(trimmed, system_prompt=sys_prompt)
