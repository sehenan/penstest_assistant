"""
Générateur de Playbook d'Attaque (Garde-Fous : Drafts uniquement).
Associe la Vulnérabilité métier, le contexte RAG, et le prompt expert
afin de solliciter le modèle Ollama.
"""
import logging
from pathlib import Path
from sqlalchemy.orm import Session

from app.db.models import Vulnerability, Report
from app.core.llm.rag import build_rag_context
from app.core.llm.ollama_client import generate_text
from app.core.llm.report_validator import ReportValidator, COMPLETION_MARKER

logger = logging.getLogger(__name__)

from typing import Literal

_EXPLOITDB_KB = Path("data/knowledge_base/exploitdb_verified")


def _exploit_rag_hint(exploit) -> str:
    """Retourne le meilleur hint textuel pour la requête FAISS quand description=None.
    Priorité : titre H1 du fichier exploitdb local > décomposition nom MSF.
    """
    if exploit is None:
        return ""
    if exploit.exploit_db_id:
        kb_file = _EXPLOITDB_KB / f"{exploit.exploit_db_id}.md"
        if kb_file.is_file():
            for line in kb_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("# "):
                    return line[2:].strip()
    if exploit.metasploit_module:
        return exploit.metasploit_module.replace("/", " ").replace("_", " ")
    return ""


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

SYSTEM_PROMPT_BASE = """Tu es un consultant en sécurité offensive certifié (OSCP/CEH), rédigeant un rapport technique pour un client entreprise.
Ton rapport sera remis à un RSSI : chaque affirmation doit être vérifiable, chaque commande doit être exécutable telle quelle.
Tu génères UNIQUEMENT des rapports fondés sur les données fournies dans la section CONTEXTE.

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

R7. PAYLOADS ET MARQUEURS PoC
    - INTERDIT ABSOLU : toute chaîne de graffiti dans les payloads ou commandes.
      Exemples interdits : "hacked by X", "pwned", "l33t", pseudonymes, handles.
    - Le seul marqueur PoC acceptable pour prouver l'exécution de code est :
        Linux  : commande `id`  → sortie attendue : uid=0(root) gid=0(root) groups=0(root)
        Windows: commande `whoami` → sortie attendue : nt authority\\system
    - Tout payload DOIT être extrait du CONTEXTE (section KNOWLEDGE BASE RAG).
      Si aucun payload n'est fourni dans le CONTEXTE → écrire :
        [PAYLOAD NON DISPONIBLE DANS LA BASE LOCALE — voir advisory CVE officiel]
    - Ne jamais reconstituer un payload de mémoire si le CONTEXTE ne le contient pas.
    - Pour les payloads présents : remplacer toute démonstration fictive par
      `$(id)` (Linux) ou `$(whoami)` (Windows) en tant que PoC minimal.

R8. VERSIONS LOGICIELLES
    - Citer UNIQUEMENT les versions présentes dans le CONTEXTE ou la description CVE.
    - Si la version exacte n'est pas dans le CONTEXTE → écrire :
        [VERSION AFFECTÉE — se référer à l'advisory CVE officiel]
    - NE PAS inventer de numéros de version (ex: "2.4.49") absents du CONTEXTE.
    - Les versions corrigées doivent être sourcées depuis le CONTEXTE ou la description CVE.
"""

AUDIT_PROMPT_EXTENSION = """
MISSION : Rapport de vérification technique pré-exploitation. Objectif : confirmer l'exploitabilité de la vulnérabilité SANS AMBIGUÏTÉ avant toute tentative d'exploitation.
Ce rapport sera remis à un RSSI — chaque commande doit être copiable-collable et chaque section doit être sourcée.

STRUCTURE IMPOSÉE — respecter cet ordre et ces titres exacts :

## Résumé exécutif
4 à 6 lignes structurées :
- Service affecté et version détectée
- Mécanisme précis de la faille (vecteur d'attaque : réseau/local, authentification requise : oui/non)
- Impact réel (RCE / DoS / divulgation de données) — strictement conforme au vecteur CVSS fourni
- Criticité opérationnelle : exploitation publique connue, présence dans CISA KEV

## Phase 1 — Reconnaissance et fingerprinting
Commande nmap ciblée avec les scripts NSE adaptés au service et au CVE.
Format attendu :
```bash
nmap -sV -p <PORT> --script=<SCRIPT_NSE_ADAPTÉ> <IP>
```
Décrire les champs de sortie pertinents et leur interprétation (open/filtered, version string, CPE).

## Phase 2 — Confirmation de version
Banner grabbing ou requête native au protocole. Utiliser l'IP et le port fournis.
```bash
# commande exacte à copier-coller
```
Output attendu si la version est vulnérable vs. patchée (deux blocs distincts).

## Phase 3 — Vérification de l'exposition au CVE
Test unitaire spécifique à ce CVE (pas un test de connectivité générique).
- Fournir la commande exacte avec l'IP et le port réels
- Output attendu : cible VULNÉRABLE (avec critères de décision clairs)
- Output attendu : cible NON vulnérable ou patchée

## Indicateurs de compromission (IOC)
Artefacts observables dans les logs système, les logs applicatifs et le trafic réseau :
- Patterns de log (regex ou chaîne exacte à chercher)
- Champs de réponse HTTP/protocole discriminants
- Comportement réseau anormal (taille de paquets, timeouts, codes d'erreur inhabituels)

## Recommandation de remédiation

### Correctif prioritaire
- Version corrigée (depuis la description CVE ou le CONTEXTE) et lien advisory officiel
- Commande de mise à jour si disponible dans le CONTEXTE

### Mesures compensatoires immédiates (si patch impossible)
- Règle WAF ou filtre réseau spécifique au mécanisme de la faille
- Configuration à durcir ou fonctionnalité à désactiver
- Restriction d'accès réseau (VLAN, firewall rule)

### Détection continue
- Règle SIEM (pattern log à alerter)
- Commande de vérification post-patch pour confirmer la remédiation
"""

PAYLOAD_PROMPT_EXTENSION = """
MISSION : Proof of Concept d'exploitation technique à destination d'un auditeur certifié dans le cadre d'un test d'intrusion autorisé.
Chaque commande doit être opérationnelle et sourcée depuis le CONTEXTE. Aucun payload inventé.

⚠️ AVERTISSEMENT LÉGAL : Ce document est produit dans le cadre d'un test d'intrusion contractuel. Toute utilisation hors cadre légal est illicite.

RÈGLES SPÉCIFIQUES PAYLOAD :
- Utiliser EXCLUSIVEMENT les payloads et commandes fournis dans le CONTEXTE (section KNOWLEDGE BASE RAG)
- Si aucun payload n'est dans le CONTEXTE : écrire [PAYLOAD NON DISPONIBLE DANS LA BASE LOCALE]
- La preuve d'exécution (PoC) se limite à : commande `id` (Linux) ou `whoami` (Windows)
- INTERDIT : chaînes graffiti, pseudonymes, strings personnalisées dans les payloads
- INTERDIT : inventer un payload ou un vecteur d'attaque absent du CONTEXTE

STRUCTURE IMPOSÉE — respecter cet ordre et ces titres exacts :

## Résumé technique
3 lignes :
- Mécanisme précis de la faille (vecteur d'attaque : paramètre HTTP / header / protocole natif)
- Prérequis : authentification requise (oui/non), accès réseau, version cible
- Impact confirmé par le CVSS (strictement limité à ce que le vecteur autorise)

## Environnement de test
```
Attaquant : <IP_ATTAQUANT>
Cible     : <IP>:<PORT>/<PROTOCOLE>
Outils    : [lister uniquement les outils confirmés dans le CONTEXTE]
```

## Exploitation pas à pas

### Étape 1 — Préparation
Configuration du listener ou de l'environnement. Commandes exactes avec les valeurs réelles.

### Étape 2 — Déclenchement de la vulnérabilité
Commande ou payload extrait du CONTEXTE, avec l'IP et le port réels.
Expliquer quel composant est ciblé et pourquoi ce vecteur fonctionne.
Output HTTP/réseau attendu en cas de succès (code de réponse, headers, body).

### Étape 3 — Preuve d'exécution (PoC)
```bash
# Commande de validation — uniquement `id` ou `whoami`
# Sortie attendue : uid=0(root) gid=0(root) groups=0(root)
```

## Module Metasploit (si confirmé dans le CONTEXTE)
Fournir la séquence complète uniquement si le module figure dans le CONTEXTE :
```
msfconsole
use <chemin/complet/du/module>
set RHOSTS <IP>
set RPORT <PORT>
set LHOST <IP_ATTAQUANT>
set LPORT 4444
set PAYLOAD <chemin/complet/payload>
run
```

## Impact et périmètre post-exploitation
Limité à l'impact réel du vecteur CVSS :
- Ce que l'auditeur peut démontrer après exploitation réussie
- Données accessibles / commandes exécutables dans le contexte du processus vulnérable
- Actions à documenter pour le rapport final (captures d'écran, logs)

## Contre-mesures recommandées
Version corrigée et mesure d'urgence si patch impossible (depuis le CONTEXTE).
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

    # 2. Enrichissement exploit (avant RAG pour enrichir la requête vectorielle)
    from app.db.models import Exploit as ExploitModel
    exploit = db_session.query(ExploitModel).filter(ExploitModel.cve == cve).first()
    exploit_info = ""
    if exploit and exploit.disponible:
        msf = f" — Module Metasploit : `{exploit.metasploit_module}`" if exploit.metasploit_module else ""
        exploit_info = f"✅ Exploit public disponible{msf}"
    else:
        exploit_info = "Aucun exploit public référencé"

    # Requête RAG enrichie : description NVD > titre exploitdb > nom MSF décomposé
    _rag_desc = vuln.description or _exploit_rag_hint(exploit)

    # 3. Contexte RAG
    context = build_rag_context(
        service=svc.service,
        version=svc.version or "",
        cve_id=cve,
        top_k=3,
        description=_rag_desc,
    )

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

_CHAT_SYSTEM_PROMPT = """Tu es un consultant en sécurité offensive certifié répondant à un auditeur en mission.
Réponds TOUJOURS en français. Sois technique, précis, et structure ta réponse avec des sections courtes.
Utilise des blocs de code Markdown (```bash / ```python / etc.) pour chaque commande ou payload.

RÈGLES STRICTES :
1. SOURCING — Réponds UNIQUEMENT depuis le CONTEXTE fourni. Si l'information est absente :
   écrire « Information non disponible dans la base locale SIATI. »
   Ne jamais compléter par des suppositions ou la mémoire du modèle.

2. COMMANDES — N'invente aucune commande. Si non confirmée dans le CONTEXTE :
   écrire [COMMANDE À VÉRIFIER — non confirmée dans la base locale]

3. PAYLOADS — Utilise UNIQUEMENT les payloads présents dans le CONTEXTE (section KNOWLEDGE BASE).
   Si absent : écrire [PAYLOAD NON DISPONIBLE DANS LA BASE LOCALE]
   INTERDIT : chaînes graffiti ("hacked by X", pseudonymes), payloads inventés.
   PoC standard : commande `id` (Linux) ou `whoami` (Windows) uniquement.

4. VERSIONS — Ne cite que les versions issues du CONTEXTE ou de la description CVE fournie.
   Si absente : [VERSION — voir advisory CVE officiel]
   Ne jamais inventer un numéro de version.

5. IMPACT — Ne décris jamais un impact SUPÉRIEUR à celui du vecteur CVSS fourni.
   • CVSS DoS pur (C:N/I:N/A:H) → AUTORISÉ : expliquer comment déclencher le crash/DoS (commandes, payload forgé, module MSF)
                                  → INTERDIT : décrire un RCE, reverse shell, lecture de /etc/passwd ou élévation de privilège
   • Le blocage concerne le TYPE d'impact (RCE vs DoS), pas la question d'exploitation elle-même.
   • Pour un DoS : la preuve d'exploitation = le service devient indisponible (timeout, connexion refusée).

6. FORMAT — Réponse structurée en 3 à 5 blocs courts :
   → Réponse directe à la question (2-3 phrases)
   → Commande(s) ou payload(s) (bloc code)
   → Résultat attendu ou explication technique
   → Recommandation si pertinente (1-2 phrases)

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
    # Enrichir la requête RAG avec le module MSF si description absente
    from app.db.models import Exploit as ExploitModel
    _exploit_chat = db_session.query(ExploitModel).filter(ExploitModel.cve == cve).first()
    _chat_desc = vuln.description or _exploit_rag_hint(_exploit_chat)
    rag = build_rag_context(service=svc.service, version=svc.version or "", cve_id=cve, top_k=3,
                            description=_chat_desc)
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
