"""
Traduction automatique des descriptions de vulnérabilités (EN → FR).
===================================================================
Module complet de traduction pour SIATI — mode air-gap.

Stratégie en 3 couches :
  1. Détection langue : skip si déjà en français
  2. Dictionnaire technique étendu (200+ termes) — rapide, hors-ligne
  3. LLM local (Ollama) pour la traduction fine des phrases restantes

Le dictionnaire est appliqué EN PREMIER pour réduire la charge LLM
et garantir un vocabulaire technique cohérent.
"""
from __future__ import annotations

import logging
import re
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  DICTIONNAIRE DE TRADUCTION TECHNIQUE ÉTENDU
# ═══════════════════════════════════════════════════════════════════════════════
# Ordre important : les expressions longues AVANT les courtes pour éviter
# les remplacements partiels.

_TECH_DICT: list[tuple[str, str]] = [

    # ── Phrases d'introduction NVD ────────────────────────────────────────────
    ("A vulnerability was found in", "Une vulnérabilité a été trouvée dans"),
    ("A vulnerability has been found in", "Une vulnérabilité a été trouvée dans"),
    ("A vulnerability has been identified in", "Une vulnérabilité a été identifiée dans"),
    ("A vulnerability exists in", "Une vulnérabilité existe dans"),
    ("A vulnerability in the", "Une vulnérabilité dans le"),
    ("A vulnerability in", "Une vulnérabilité dans"),
    ("An issue was discovered in", "Un problème a été découvert dans"),
    ("An issue has been discovered in", "Un problème a été découvert dans"),
    ("A flaw was found in", "Une faille a été trouvée dans"),
    ("A flaw was discovered in", "Une faille a été découverte dans"),
    ("A security issue was discovered in", "Un problème de sécurité a été découvert dans"),
    ("A critical vulnerability in", "Une vulnérabilité critique dans"),
    ("Multiple vulnerabilities in", "Plusieurs vulnérabilités dans"),
    ("There is a vulnerability in", "Il existe une vulnérabilité dans"),
    ("was discovered in", "a été découvert(e) dans"),
    ("has been discovered in", "a été découvert(e) dans"),
    ("was found in", "a été trouvé(e) dans"),
    ("has been found in", "a été trouvé(e) dans"),
    ("were found in", "ont été trouvé(e)s dans"),
    ("were discovered in", "ont été découvert(e)s dans"),

    # ── Phrases d'impact ──────────────────────────────────────────────────────
    ("allows remote attackers to execute arbitrary code", "permet à des attaquants distants d'exécuter du code arbitraire"),
    ("allows remote attackers to cause a denial of service", "permet à des attaquants distants de provoquer un déni de service"),
    ("allows remote attackers to obtain sensitive information", "permet à des attaquants distants d'obtenir des informations sensibles"),
    ("allows remote attackers to bypass", "permet à des attaquants distants de contourner"),
    ("allows remote attackers to", "permet à des attaquants distants de"),
    ("allows remote authenticated users to", "permet à des utilisateurs authentifiés distants de"),
    ("allows local users to", "permet à des utilisateurs locaux de"),
    ("allows attackers to", "permet à des attaquants de"),
    ("allows an attacker to", "permet à un attaquant de"),
    ("could allow an unauthenticated, remote attacker to", "pourrait permettre à un attaquant distant non authentifié de"),
    ("could allow an authenticated, remote attacker to", "pourrait permettre à un attaquant distant authentifié de"),
    ("could allow a remote attacker to", "pourrait permettre à un attaquant distant de"),
    ("could allow an attacker to", "pourrait permettre à un attaquant de"),
    ("could allow a local attacker to", "pourrait permettre à un attaquant local de"),
    ("may allow an attacker to", "peut permettre à un attaquant de"),
    ("may allow remote attackers to", "peut permettre à des attaquants distants de"),
    ("enables an attacker to", "permet à un attaquant de"),
    ("enables remote attackers to", "permet à des attaquants distants de"),
    ("This makes it possible for authenticated attackers", "Cela rend possible pour des attaquants authentifiés"),
    ("This makes it possible for unauthenticated attackers", "Cela rend possible pour des attaquants non authentifiés"),
    ("This makes it possible for", "Cela rend possible pour"),
    ("This makes it possible", "Cela rend possible"),
    ("is vulnerable to", "est vulnérable à"),

    # ── Types d'attaques / vulnérabilités ─────────────────────────────────────
    ("execute arbitrary code in the context of", "exécuter du code arbitraire dans le contexte de"),
    ("execute arbitrary code", "exécuter du code arbitraire"),
    ("execute arbitrary commands", "exécuter des commandes arbitraires"),
    ("execute arbitrary operating system commands", "exécuter des commandes arbitraires du système d'exploitation"),
    ("execute arbitrary SQL commands", "exécuter des commandes SQL arbitraires"),
    ("arbitrary code execution", "exécution de code arbitraire"),
    ("remote code execution", "exécution de code à distance (RCE)"),
    ("denial of service (DoS)", "déni de service (DoS)"),
    ("denial-of-service (DoS)", "déni de service (DoS)"),
    ("denial of service", "déni de service"),
    ("denial-of-service", "déni de service"),
    ("Denial of Service", "Déni de Service"),
    ("Stored Cross-Site Scripting", "Cross-Site Scripting stocké (Stored XSS)"),
    ("Reflected Cross-Site Scripting", "Cross-Site Scripting réfléchi (Reflected XSS)"),
    ("Cross-Site Scripting (XSS)", "Cross-Site Scripting (XSS)"),
    ("cross-site scripting", "Cross-Site Scripting (XSS)"),
    ("Cross-Site Request Forgery", "Falsification de requête inter-sites (CSRF)"),
    ("Server-Side Request Forgery", "Falsification de requête côté serveur (SSRF)"),
    ("SQL Injection vulnerability", "vulnérabilité d'injection SQL"),
    ("SQL Injection", "injection SQL"),
    ("SQL injection", "injection SQL"),
    ("Command Injection", "injection de commandes"),
    ("command injection", "injection de commandes"),
    ("Code Injection", "injection de code"),
    ("code injection", "injection de code"),
    ("LDAP injection", "injection LDAP"),
    ("XML External Entity", "Entité externe XML (XXE)"),
    ("XML injection", "injection XML"),
    ("OS command injection", "injection de commandes OS"),
    ("heap-based buffer overflow", "dépassement de tampon basé sur le tas (heap overflow)"),
    ("stack-based buffer overflow", "dépassement de tampon basé sur la pile (stack overflow)"),
    ("buffer overflow vulnerability", "vulnérabilité de dépassement de tampon"),
    ("buffer overflow", "dépassement de tampon"),
    ("buffer over-read", "lecture au-delà du tampon"),
    ("integer overflow", "dépassement d'entier"),
    ("integer underflow", "sous-dépassement d'entier"),
    ("use-after-free vulnerability", "vulnérabilité d'utilisation après libération (use-after-free)"),
    ("use-after-free", "utilisation après libération (use-after-free)"),
    ("double free vulnerability", "vulnérabilité de double libération"),
    ("double free", "double libération"),
    ("null pointer dereference", "déréférencement de pointeur nul"),
    ("NULL pointer dereference", "déréférencement de pointeur NULL"),
    ("out-of-bounds read", "lecture hors limites"),
    ("out-of-bounds write", "écriture hors limites"),
    ("out of bounds read", "lecture hors limites"),
    ("out of bounds write", "écriture hors limites"),
    ("out-of-bounds memory", "mémoire hors limites"),
    ("memory corruption", "corruption de mémoire"),
    ("memory leak", "fuite de mémoire"),
    ("race condition", "condition de course"),
    ("time-of-check time-of-use", "vérification-puis-utilisation (TOCTOU)"),
    ("information disclosure vulnerability", "vulnérabilité de divulgation d'informations"),
    ("information disclosure", "divulgation d'informations"),
    ("information leak", "fuite d'informations"),
    ("sensitive information disclosure", "divulgation d'informations sensibles"),
    ("privilege escalation vulnerability", "vulnérabilité d'élévation de privilèges"),
    ("local privilege escalation", "élévation de privilèges locale"),
    ("privilege escalation", "élévation de privilèges"),
    ("elevation of privilege vulnerability", "vulnérabilité d'élévation de privilèges"),
    ("elevation of privilege", "élévation de privilèges"),
    ("directory traversal vulnerability", "vulnérabilité de traversée de répertoires"),
    ("directory traversal", "traversée de répertoires"),
    ("path traversal", "traversée de chemin"),
    ("Local File Inclusion", "Inclusion de fichier local (LFI)"),
    ("Remote File Inclusion", "Inclusion de fichier distant (RFI)"),
    ("Arbitrary File Upload", "Téléversement de fichier arbitraire"),
    ("arbitrary file upload", "téléversement de fichier arbitraire"),
    ("Arbitrary File Read", "Lecture de fichier arbitraire"),
    ("arbitrary file read", "lecture de fichier arbitraire"),
    ("Arbitrary File Deletion", "Suppression de fichier arbitraire"),
    ("Arbitrary File Download", "Téléchargement de fichier arbitraire"),
    ("unrestricted file upload", "téléversement de fichier non restreint"),
    ("insecure deserialization", "désérialisation non sécurisée"),
    ("insecure direct object reference", "référence directe non sécurisée à un objet (IDOR)"),
    ("open redirect", "redirection ouverte"),
    ("man-in-the-middle attack", "attaque de l'homme du milieu (MITM)"),
    ("man-in-the-middle", "homme du milieu (MITM)"),
    ("brute force attack", "attaque par force brute"),
    ("brute force", "force brute"),

    # ── Contexte et conditions ────────────────────────────────────────────────
    ("via a specially crafted request", "via une requête spécialement conçue"),
    ("via a specially crafted", "via un(e) spécialement conçu(e)"),
    ("via a crafted request", "via une requête spécialement conçue"),
    ("via a crafted HTTP request", "via une requête HTTP spécialement conçue"),
    ("via crafted input", "via une entrée spécialement conçue"),
    ("via a crafted packet", "via un paquet spécialement conçu"),
    ("via a crafted file", "via un fichier spécialement conçu"),
    ("via a crafted URL", "via une URL spécialement conçue"),
    ("via crafted", "via des données spécialement conçues"),
    ("via a crafted", "via un(e) spécialement conçu(e)"),
    ("specially crafted request", "requête spécialement conçue"),
    ("specially crafted input", "entrée spécialement conçue"),
    ("specially crafted packet", "paquet spécialement conçu"),
    ("specially crafted file", "fichier spécialement conçu"),
    ("specially crafted", "spécialement conçu(e)"),
    ("crafted request", "requête conçue"),
    ("crafted input", "entrée conçue"),
    ("crafted packet", "paquet conçu"),
    ("This functionality is enabled by default", "Cette fonctionnalité est activée par défaut"),
    ("enabled by default", "activé par défaut"),
    ("disabled by default", "désactivé par défaut"),
    ("without authentication", "sans authentification"),
    ("without prior authentication", "sans authentification préalable"),
    ("without any authentication", "sans aucune authentification"),
    ("with no authentication", "sans authentification"),
    ("requires authentication", "nécessite une authentification"),
    ("requires no authentication", "ne nécessite aucune authentification"),

    # ── Conséquences ──────────────────────────────────────────────────────────
    ("gain unauthorized access", "obtenir un accès non autorisé"),
    ("gain access to", "obtenir un accès à"),
    ("gain root access", "obtenir un accès root"),
    ("gain administrative access", "obtenir un accès administrateur"),
    ("unauthorized access", "accès non autorisé"),
    ("obtain sensitive information", "obtenir des informations sensibles"),
    ("read sensitive information", "lire des informations sensibles"),
    ("read arbitrary files", "lire des fichiers arbitraires"),
    ("write arbitrary files", "écrire des fichiers arbitraires"),
    ("delete arbitrary files", "supprimer des fichiers arbitraires"),
    ("modify arbitrary files", "modifier des fichiers arbitraires"),
    ("bypass authentication", "contourner l'authentification"),
    ("bypass authorization", "contourner l'autorisation"),
    ("bypass security restrictions", "contourner les restrictions de sécurité"),
    ("bypass security mechanisms", "contourner les mécanismes de sécurité"),
    ("bypass access controls", "contourner les contrôles d'accès"),
    ("bypass restrictions", "contourner les restrictions"),
    ("bypass security", "contourner la sécurité"),
    ("completely compromise", "compromettre entièrement"),
    ("full system compromise", "compromission totale du système"),
    ("take complete control", "prendre le contrôle total"),
    ("take control of", "prendre le contrôle de"),
    ("crash the application", "faire planter l'application"),
    ("crash the service", "faire planter le service"),
    ("crash the server", "faire planter le serveur"),
    ("application crash", "plantage de l'application"),
    ("process crash", "plantage du processus"),
    ("inject arbitrary web scripts", "injecter des scripts web arbitraires"),
    ("inject arbitrary", "injecter arbitrairement"),

    # ── Causalité et liens logiques ───────────────────────────────────────────
    ("due to insufficient input validation", "en raison d'une validation d'entrée insuffisante"),
    ("due to insufficient output escaping", "en raison d'un échappement de sortie insuffisant"),
    ("due to insufficient validation", "en raison d'une validation insuffisante"),
    ("due to improper input validation", "en raison d'une validation d'entrée incorrecte"),
    ("due to improper validation", "en raison d'une validation incorrecte"),
    ("due to improper access control", "en raison d'un contrôle d'accès incorrect"),
    ("due to improper authentication", "en raison d'une authentification incorrecte"),
    ("due to missing authentication", "en raison d'une authentification manquante"),
    ("due to insufficient authentication", "en raison d'une authentification insuffisante"),
    ("due to missing input sanitization", "en raison d'un assainissement d'entrée manquant"),
    ("due to a missing bounds check", "en raison d'une vérification de limites manquante"),
    ("due to", "en raison de"),
    ("caused by", "causé par"),
    ("resulting in", "entraînant"),
    ("leading to", "menant à"),
    ("which could lead to", "ce qui pourrait mener à"),
    ("which could result in", "ce qui pourrait entraîner"),
    ("which may lead to", "ce qui peut mener à"),
    ("which may result in", "ce qui peut entraîner"),
    ("which leads to", "ce qui mène à"),
    ("which results in", "ce qui entraîne"),
    ("This can be exploited to", "Ceci peut être exploité pour"),
    ("can be exploited by", "peut être exploité par"),
    ("can be abused to", "peut être utilisé de manière abusive pour"),
    ("could be exploited to", "pourrait être exploité pour"),
    ("could be abused to", "pourrait être utilisé de manière abusive pour"),

    # ── Versions et portée ────────────────────────────────────────────────────
    ("versions prior to", "les versions antérieures à"),
    ("versions before", "les versions antérieures à"),
    ("versions after", "les versions postérieures à"),
    ("versions up to, and including,", "les versions jusqu'à et y compris"),
    ("versions up to and including", "les versions jusqu'à et y compris"),
    ("up to, and including,", "jusqu'à et y compris"),
    ("up to and including", "jusqu'à et y compris"),
    ("before version", "avant la version"),
    ("prior to version", "antérieur à la version"),
    ("prior to", "antérieur à"),
    ("through version", "jusqu'à la version"),
    ("and earlier versions", "et les versions antérieures"),
    ("and earlier", "et antérieures"),
    ("and below", "et inférieures"),
    ("and later", "et ultérieures"),
    ("and above", "et supérieures"),
    ("in all versions", "dans toutes les versions"),

    # ── Acteurs et rôles ──────────────────────────────────────────────────────
    ("an unauthenticated, remote attacker", "un attaquant distant non authentifié"),
    ("an authenticated, remote attacker", "un attaquant distant authentifié"),
    ("a remote, unauthenticated attacker", "un attaquant distant non authentifié"),
    ("a remote authenticated attacker", "un attaquant distant authentifié"),
    ("a remote unauthenticated attacker", "un attaquant distant non authentifié"),
    ("remote authenticated attackers", "des attaquants distants authentifiés"),
    ("remote unauthenticated attackers", "des attaquants distants non authentifiés"),
    ("remote attackers", "des attaquants distants"),
    ("remote attacker", "un attaquant distant"),
    ("local attacker", "un attaquant local"),
    ("local attackers", "des attaquants locaux"),
    ("authenticated attacker", "un attaquant authentifié"),
    ("authenticated attackers", "des attaquants authentifiés"),
    ("unauthenticated attacker", "un attaquant non authentifié"),
    ("unauthenticated attackers", "des attaquants non authentifiés"),
    ("network-adjacent attacker", "un attaquant sur le réseau adjacent"),
    ("malicious user", "un utilisateur malveillant"),
    ("malicious users", "des utilisateurs malveillants"),
    ("superusers and users in the", "les super-utilisateurs et les utilisateurs du"),
    ("with contributor-level access and above", "avec un accès de niveau contributeur et supérieur"),
    ("with administrator-level access", "avec un accès de niveau administrateur"),

    # ── Termes techniques divers ──────────────────────────────────────────────
    ("insufficient input validation", "validation d'entrée insuffisante"),
    ("insufficient output escaping", "échappement de sortie insuffisant"),
    ("insufficient validation", "validation insuffisante"),
    ("improper input validation", "validation d'entrée incorrecte"),
    ("improper access control", "contrôle d'accès incorrect"),
    ("improper authentication", "authentification incorrecte"),
    ("improper authorization", "autorisation incorrecte"),
    ("improper neutralization", "neutralisation incorrecte"),
    ("missing authentication", "authentification manquante"),
    ("missing authorization", "autorisation manquante"),
    ("missing input sanitization", "assainissement d'entrée manquant"),
    ("weak authentication", "authentification faible"),
    ("weak encryption", "chiffrement faible"),
    ("sensitive information", "informations sensibles"),
    ("sensitive data", "données sensibles"),
    ("arbitrary web scripts in pages that will execute", "des scripts web arbitraires dans des pages qui s'exécuteront"),
    ("whenever a user accesses an injected page", "chaque fois qu'un utilisateur accède à une page infectée"),
    ("inject arbitrary web scripts", "injecter des scripts web arbitraires"),
    ("the affected system", "le système affecté"),
    ("the affected software", "le logiciel affecté"),
    ("the affected device", "l'appareil affecté"),
    ("affected versions", "les versions affectées"),
    ("affected systems", "les systèmes affectés"),
    ("unspecified vectors", "des vecteurs non spécifiés"),
    ("unspecified impact", "un impact non spécifié"),
    ("an unspecified", "un(e) non spécifié(e)"),

    # ── Notes et avertissements NVD ───────────────────────────────────────────
    ("NOTE: Third parties claim", "NOTE : Des tiers affirment"),
    ("NOTE: this is disputed", "NOTE : ceci est contesté"),
    ("NOTE:", "NOTE :"),
    ("References state that", "Les références indiquent que"),
    ("This vulnerability", "Cette vulnérabilité"),
    ("This issue", "Ce problème"),
    ("This flaw", "Cette faille"),
    ("This affects", "Cela affecte"),
    ("this issue", "ce problème"),
    ("this vulnerability", "cette vulnérabilité"),
    ("this flaw", "cette faille"),
    ("Exploitation requires", "L'exploitation nécessite"),
    ("the malicious post to be published", "que le billet malveillant soit publié"),
    ("a related issue to", "un problème lié à"),
    ("a separate vulnerability from", "une vulnérabilité distincte de"),
    ("when compiled with an experimental", "lorsqu'il est compilé avec un(e) expérimental(e)"),

    # ── Termes simples fréquents ──────────────────────────────────────────────
    ("An error in handling", "Une erreur dans le traitement de"),
    ("An error in", "Une erreur dans"),
    ("an assertion failure", "un échec d'assertion"),
    ("can cause", "peut provoquer"),
    ("could cause", "pourrait provoquer"),
    ("may cause", "peut provoquer"),
    ("might cause", "pourrait provoquer"),
    ("run arbitrary", "exécuter des"),
    ("read, modify, and delete database contents", "lire, modifier et supprimer le contenu de la base de données"),
    ("read and modify", "lire et modifier"),
    ("upload and execute", "téléverser et exécuter"),
    ("web shell backdoors", "portes dérobées web shell"),
    ("thereby enabling arbitrary code execution on the server", "permettant ainsi l'exécution de code arbitraire sur le serveur"),
    ("arbitrary code execution on the server", "exécution de code arbitraire sur le serveur"),
    ("on the server", "sur le serveur"),
    ("on the target system", "sur le système cible"),
    ("on Windows, Linux, and macOS", "sous Windows, Linux et macOS"),
]

# ═══════════════════════════════════════════════════════════════════════════════
#  DÉTECTION DE LANGUE
# ═══════════════════════════════════════════════════════════════════════════════

# Mots français courants qui n'apparaissent pas en anglais
_FR_WORDS = {
    "une", "des", "dans", "sur", "avec", "par", "pour", "cette", "est",
    "les", "aux", "peut", "permet", "attaquant", "vulnérabilité", "faille",
    "exécuter", "déni", "contourner", "mener", "entraîner", "serveur",
    "trouvée", "découvert", "enrichissement", "détecté", "heuristiquement",
    "arbitraire", "authentifié", "distant", "utilisateur", "malveillant",
    "informations", "sensibles", "élévation", "privilèges", "injection",
}

# Mots anglais courants qui n'apparaissent pas en français
_EN_WORDS = {
    "the", "allows", "could", "which", "through", "when", "before",
    "after", "vulnerability", "attacker", "attackers", "execute",
    "arbitrary", "remote", "local", "server", "system", "user",
    "authentication", "bypass", "crafted", "affected", "versions",
    "discovered", "found", "issue", "flaw", "resulting", "leading",
    "overflow", "injection", "disclosure", "escalation", "causes",
}


def _detect_language(text: str) -> str:
    """Retourne 'fr', 'en', ou 'mixed'."""
    words = set(re.findall(r'[a-zà-ÿ]+', text.lower()))
    fr_count = len(words & _FR_WORDS)
    en_count = len(words & _EN_WORDS)

    if fr_count >= 4 and en_count == 0:
        return "fr"
    return "en"  # par défaut, on traduit


# ═══════════════════════════════════════════════════════════════════════════════
#  TRADUCTION PAR DICTIONNAIRE
# ═══════════════════════════════════════════════════════════════════════════════

def _translate_with_dict(text: str) -> str:
    """Traduction par remplacement de termes techniques."""
    result = text
    for en_term, fr_term in _TECH_DICT:
        # Remplacement insensible à la casse mais en préservant la structure
        pattern = re.compile(re.escape(en_term), re.IGNORECASE)
        result = pattern.sub(fr_term, result)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  TRADUCTION VIA LLM (OLLAMA)
# ═══════════════════════════════════════════════════════════════════════════════

_LLM_SYSTEM_PROMPT = """Tu es un traducteur technique expert en cybersécurité.

RÈGLES STRICTES :
1. Traduis le texte de l'anglais vers le français technique.
2. CONSERVE tel quel : les CVE-ID (CVE-xxxx-xxxx), les noms de produits (OpenSSH, PostgreSQL, Apache, etc.), les chemins de fichiers, les noms de fonctions, les termes entre guillemets.
3. CONSERVE les termes techniques standards entre parenthèses : (XSS), (CSRF), (RCE), (DoS), etc.
4. Utilise un registre professionnel et factuel.
5. Réponds UNIQUEMENT avec la traduction, sans commentaire, sans guillemets autour.
6. Ne rajoute RIEN. Pas de "Voici la traduction", pas de note.
7. Si le texte est déjà en français, retourne-le tel quel."""


def _translate_with_llm(text: str) -> str | None:
    """Traduction via Ollama avec prompt optimisé."""
    try:
        from app.core.llm.ollama_client import generate_text, check_ollama_status

        if not check_ollama_status():
            logger.debug("Ollama indisponible, fallback dictionnaire.")
            return None

        prompt = f"Traduis cette description de vulnérabilité en français :\n\n{text}"
        result = generate_text(prompt, system_prompt=_LLM_SYSTEM_PROMPT)

        if not result:
            return None

        # Nettoyage de la réponse LLM
        cleaned = result.strip()
        # Supprimer les guillemets englobants si présents
        if cleaned.startswith('"') and cleaned.endswith('"'):
            cleaned = cleaned[1:-1]
        if cleaned.startswith("«") and cleaned.endswith("»"):
            cleaned = cleaned[1:-1].strip()

        # Vérification minimale de qualité
        if len(cleaned) < 30:
            logger.warning("Traduction LLM trop courte, rejet.")
            return None
        if cleaned.lower().startswith("voici") or cleaned.lower().startswith("here"):
            # Le LLM a mis un préambule — on prend après le premier saut de ligne
            lines = cleaned.split("\n", 1)
            if len(lines) > 1:
                cleaned = lines[1].strip()

        return cleaned

    except Exception as e:
        logger.debug("Erreur traduction LLM : %s", e)
        return None


def _translate_batch_with_llm(texts: list[tuple[int, str]]) -> dict[int, str]:
    """
    Traduit un batch de textes via Ollama (un par un avec throttle).
    Retourne {vuln_id: traduction}.
    """
    results = {}
    total = len(texts)

    for i, (vuln_id, text) in enumerate(texts):
        logger.info("Traduction LLM %d/%d (vuln #%d)...", i + 1, total, vuln_id)
        translated = _translate_with_llm(text)
        if translated:
            results[vuln_id] = translated
        # Petit délai pour ne pas surcharger Ollama
        if i < total - 1:
            time.sleep(0.5)

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  FONCTION PRINCIPALE
# ═══════════════════════════════════════════════════════════════════════════════

def translate_vulnerability_descriptions(
    session: Session,
    use_llm: bool = True,
) -> dict[str, int]:
    """
    Traduit toutes les descriptions de vulnérabilités anglaises en français.

    Pipeline de traduction :
      1. Détection de langue → skip si déjà en français
      2. Application du dictionnaire technique (200+ termes)
      3. Re-détection de langue après dictionnaire
      4. Si encore en anglais et use_llm=True → traduction LLM complète
      5. Sinon → garder la version dictionnaire

    Args:
        session: Session SQLAlchemy
        use_llm: Si True, utilise Ollama pour les descriptions encore en anglais
                 après le passage dictionnaire.
    """
    stats = {
        "translated_llm": 0,
        "translated_dict": 0,
        "already_french": 0,
        "skipped_empty": 0,
        "llm_failed": 0,
    }

    vulns = session.scalars(
        select(Vulnerability).where(Vulnerability.description.isnot(None))
    ).all()

    if not vulns:
        return stats

    # Phase 1 : Dictionnaire sur toutes les vulns
    need_llm: list[tuple[int, str]] = []

    for vuln in vulns:
        desc = (vuln.description or "").strip()
        if not desc:
            stats["skipped_empty"] += 1
            continue

        lang = _detect_language(desc)
        if lang == "fr":
            stats["already_french"] += 1
            continue

        # Appliquer le dictionnaire
        translated = _translate_with_dict(desc)
        vuln.description = translated

        # Vérifier si c'est suffisant
        lang_after = _detect_language(translated)
        if lang_after == "fr":
            stats["translated_dict"] += 1
        else:
            # Encore en anglais → besoin du LLM
            if use_llm:
                need_llm.append((vuln.id, desc))
            else:
                stats["translated_dict"] += 1  # on garde quand même la version dict

    # Phase 2 : LLM pour les descriptions encore en anglais
    if need_llm and use_llm:
        logger.info(
            "%d descriptions nécessitent la traduction LLM...", len(need_llm)
        )
        llm_results = _translate_batch_with_llm(need_llm)

        for vuln_id, translation in llm_results.items():
            vuln = session.get(Vulnerability, vuln_id)
            if vuln and translation:
                vuln.description = translation
                stats["translated_llm"] += 1

        stats["llm_failed"] = len(need_llm) - len(llm_results)

    # Commit
    try:
        session.commit()
        logger.info(
            "Traduction terminée : LLM=%d, Dict=%d, Déjà FR=%d, Vides=%d, Échecs LLM=%d",
            stats["translated_llm"],
            stats["translated_dict"],
            stats["already_french"],
            stats["skipped_empty"],
            stats["llm_failed"],
        )
    except Exception as e:
        logger.error("Erreur commit traduction : %s", e)
        session.rollback()

    return stats
