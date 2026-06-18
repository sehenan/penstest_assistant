"""
Validateur post-génération des rapports LLM.
Détecte les hallucinations prouvées (commandes invalides, troncature,
incohérence CVE) avant tout affichage ou stockage.
"""
import logging
import re

from app.db.intel_reader import IntelReader

logger = logging.getLogger(__name__)

COMPLETION_MARKER = "[RAPPORT COMPLET — aucune troncature]"

# Commandes hallucinées prouvées dans les rapports de test — (pattern, correction)
INVALID_COMMANDS: list[tuple[str, str]] = [
    ("metasploit -s",               "msfconsole"),
    ("metasploit --start",          "msfconsole"),
    ("nc -vudp",                    "nc -nv (TCP) ou nc -nvu (UDP si pertinent)"),
    ("nc -p",                       "nc -nv <ip> <port>"),
    ("use exploits/postgresql_8_x", "use exploit/multi/postgres/postgres_copy_from_program_cmd_exec"),
    ("use exploits/postgresql",     "chemin complet requis, ex: exploit/multi/postgres/..."),
    ("set PAYLOAD reverse_tcp",     "set PAYLOAD cmd/unix/reverse_bash (chemin complet)"),
    ("run -p",                      "run  ou  exploit"),
    ("ssh -i id_rsa",               "hors-sujet si le service cible n'est pas SSH"),
    ("ping <ip> <port>",            "nc -zv <ip> <port>  ou  nmap -p <port> <ip>"),
    ("ping -c 1",                   "nc -zv <ip> <port>  ou  nmap -p <port> <ip>  (ping n'accepte pas de port)"),
]

# Fins de rapport suspectes indiquant une troncature
_TRUNCATION_PATTERNS: list[str] = [
    r"nous avons explor\w*\s*$",
    r"\.\.\.\s*$",
    r"(ssh|nc|nmap) -[a-z]+ /path/to\s*$",
    r"dans ce rapport[^.]{0,60}\s*$",
    r"(nous allons|nous avons|il est)[^.]{0,80}\s*$",
]
_TRUNCATION_RE = re.compile(
    "|".join(_TRUNCATION_PATTERNS),
    re.IGNORECASE | re.MULTILINE,
)


class ReportValidator:
    """
    Vérifie la qualité d'un rapport généré par le LLM avant affichage.
    Utilise IntelReader pour la cohérence CVE (mots-clés de la base locale).
    """

    def __init__(self):
        self._intel = IntelReader()

    def validate(self, report: str, cve_id: str, service: str, version: str,
                 cvss_vector: str = "") -> dict:
        """
        Retourne un dict :
          - valid (bool)  : True si aucun problème détecté
          - issues (list) : liste de dicts {code, detail}
          - report (str)  : rapport original (non modifié)
        Si `cvss_vector` est fourni et exclut tout impact confidentialité/intégrité,
        toute description de RCE/exfiltration est signalée (CVE_IMPACT_CONTRADICTION).
        """
        issues: list[dict] = []

        if not report or len(report) < 150:
            issues.append({"code": "REPORT_TOO_SHORT", "detail": "Rapport trop court (< 150 caractères)"})
            return {"valid": False, "issues": issues, "report": report}

        # 1. Marqueur de complétude
        if COMPLETION_MARKER not in report:
            issues.append({
                "code": "COMPLETION_MARKER_MISSING",
                "detail": "Marqueur [RAPPORT COMPLET] absent — rapport peut-être tronqué",
            })

        # 2. Patterns de troncature sur la fin du rapport
        tail = report.rstrip()[-400:]
        if _TRUNCATION_RE.search(tail):
            issues.append({
                "code": "TRUNCATION_DETECTED",
                "detail": f"Fin suspecte détectée : ...{tail[-120:]!r}",
            })

        # 3. Commandes invalides
        for bad_cmd, correction in INVALID_COMMANDS:
            if bad_cmd in report:
                issues.append({
                    "code": "INVALID_COMMAND",
                    "detail": f"Commande invalide : {bad_cmd!r} → correction attendue : {correction}",
                })

        # 4. Cohérence CVE (mots-clés de la base locale)
        if not self._cve_consistent(cve_id, report):
            issues.append({
                "code": "CVE_DESCRIPTION_MISMATCH",
                "detail": (
                    f"{cve_id} : aucun mot-clé technique de la base locale retrouvé dans le rapport. "
                    "Possible hallucination de la description CVE."
                ),
            })

        # 5. Contradiction avec l'impact CVSS (RCE/exfil décrit sur une faille sans
        #    impact confidentialité ni intégrité — typiquement un DoS).
        found = self._impact_contradiction(cvss_vector, report)
        if found:
            issues.append({
                "code": "CVE_IMPACT_CONTRADICTION",
                "detail": (
                    f"Vecteur CVSS `{cvss_vector}` sans impact confidentialité/intégrité, "
                    f"mais le rapport décrit une exploitation de type RCE/accès : {found!r}. "
                    "Incohérence prouvée — contenu écarté."
                ),
            })

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "report": report,
        }

    @staticmethod
    def _impact_contradiction(cvss_vector: str, report: str) -> str | None:
        """
        Si le CVSS n'a NI impact confidentialité NI intégrité (C:N et I:N),
        toute mention de RCE / reverse shell / lecture de fichier / élévation
        est une hallucination. Renvoie le 1er mot-clé fautif trouvé, sinon None.
        """
        if not cvss_vector:
            return None
        from app.core.llm.generator import cvss_impact_profile, RCE_EXFIL_KEYWORDS
        profile = cvss_impact_profile(cvss_vector)
        if not profile["forbid"]:
            return None
        report_lower = report.lower()
        for kw in RCE_EXFIL_KEYWORDS:
            if kw in report_lower:
                return kw.strip()
        return None

    def _cve_consistent(self, cve_id: str, report: str) -> bool:
        """
        Vérifie que le rapport contient au moins un mot-clé issu de la base locale.
        Si la CVE est absente de la base, on ne bloque pas (on ne peut pas valider).
        """
        entry = self._intel.get_cve(cve_id)
        if not entry:
            return True
        keywords = entry.get("keywords", [])
        if not keywords:
            return True
        report_lower = report.lower()
        return any(kw.lower() in report_lower for kw in keywords)
