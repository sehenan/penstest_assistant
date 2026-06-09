"""
CPE → CVE Enrichment (NVD JSON Cache, format NVD 2.0).
=========================================================
- Pour chaque service ayant un CPE stocké (ou dans la description de sa vuln),
  interroge les fichiers JSON du cache NVD local.
- Crée de nouvelles entrées Vulnerability liées à des CVE réels.
- En l'absence de CVE, applique une heuristique CVSS basée sur le type de service.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Service, Vulnerability

logger = logging.getLogger(__name__)

NVD_CACHE_DIR = Path("data/nvd_cache")

# ─── CPE Parsing ─────────────────────────────────────────────────────────────

def _parse_cpe_vendor_product(cpe_str: str) -> Optional[tuple[str, str]]:
    """
    Extrait (vendor, product) depuis CPE 2.2 ou 2.3.
    Ex: cpe:/a:openbsd:openssh:4.7p1   → ('openbsd', 'openssh')
        cpe:2.3:a:openbsd:openssh:4.7p1:... → ('openbsd', 'openssh')
    """
    if not cpe_str:
        return None
    cpe_str = cpe_str.strip()
    if cpe_str.startswith("cpe:2.3:"):
        parts = cpe_str.split(":")
        # cpe:2.3:type:vendor:product:...
        if len(parts) >= 5:
            return parts[3].lower(), parts[4].lower()
    elif cpe_str.startswith("cpe:/"):
        # cpe:/a:vendor:product:version
        inner = cpe_str[5:]   # remove "cpe:/"
        parts = inner.split(":")
        if len(parts) >= 3:
            return parts[1].lower(), parts[2].lower()
    return None


def _extract_cpe_from_text(text: str) -> Optional[str]:
    """Extrait un CPE depuis un texte libre (description de vuln)."""
    if not text:
        return None
    m = re.search(r"(cpe:[^\s,;\]]+)", text, re.IGNORECASE)
    return m.group(1) if m else None


# ─── Version handling (ANTI-HALLUCINATION) ────────────────────────────────────
# Le rapprochement CVE n'est JAMAIS fait sur le seul nom de produit : la version
# détectée doit tomber dans la plage de versions vulnérables déclarée par le NVD.
# Si la version est inconnue ou la plage absente, AUCUNE CVE n'est associée.

_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _ver_tuple(value: Optional[str]) -> Optional[tuple[int, ...]]:
    """
    Convertit une chaîne de version en tuple d'entiers comparable.
    Tolérant aux suffixes/formats : '4.7p1'→(4,7), '5.0.96-0ubuntu3'→(5,0,96),
    '8.3.20 - 8.3.23'→(8,3,20), '9.4.2-P2.1'→(9,4,2), '2.2.8'→(2,2,8).
    Retourne None si aucune version numérique exploitable.
    """
    if not value:
        return None
    m = _VER_RE.search(str(value).strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _ver_cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare deux tuples de version (padding par zéros). -1 / 0 / 1."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _criteria_version(criteria: str) -> Optional[str]:
    """Extrait le champ version du CPE de critère (2.2 ou 2.3)."""
    if not criteria:
        return None
    if criteria.startswith("cpe:2.3:"):
        parts = criteria.split(":")
        # cpe:2.3:type:vendor:product:version:...
        if len(parts) >= 6:
            return parts[5]
    elif criteria.startswith("cpe:/"):
        parts = criteria[5:].split(":")
        # a:vendor:product:version
        if len(parts) >= 4:
            return parts[3]
    return None


def _version_confirmed(detected: tuple[int, ...], vc: dict) -> bool:
    """
    Confirme que la version détectée est explicitement couverte par la
    configuration NVD `vc` (champs versionStart*/versionEnd* + version du critère).

    Règle anti-hallucination : en l'absence totale de contrainte de version
    (critère '*'/'-' ET aucune borne), on REFUSE le rapprochement.
    """
    vsi = _ver_tuple(vc.get("vsi"))
    vse = _ver_tuple(vc.get("vse"))
    vei = _ver_tuple(vc.get("vei"))
    vee = _ver_tuple(vc.get("vee"))

    has_range = any(b is not None for b in (vsi, vse, vei, vee))
    if has_range:
        if vsi is not None and _ver_cmp(detected, vsi) < 0:
            return False
        if vse is not None and _ver_cmp(detected, vse) <= 0:
            return False
        if vei is not None and _ver_cmp(detected, vei) > 0:
            return False
        if vee is not None and _ver_cmp(detected, vee) >= 0:
            return False
        return True

    # Pas de plage : on s'appuie sur la version exacte du critère.
    crit = vc.get("crit_ver")
    if crit in (None, "", "*", "-"):
        # Aucune information de version → non confirmable → REFUS.
        return False
    crit_t = _ver_tuple(crit)
    if crit_t is None:
        return False
    # Correspondance par préfixe : critère '2.2' couvre '2.2.8' détecté,
    # mais '2.4.17' ne couvre PAS '2.2.8'.
    n = len(crit_t)
    det = detected + (0,) * (n - len(detected)) if len(detected) < n else detected
    return det[:n] == crit_t


# ─── CVE Data Extraction ──────────────────────────────────────────────────────

def _extract_cvss(cve_data: dict) -> tuple[Optional[float], Optional[str]]:
    """Retourne (score, vector_string) depuis le dict CVE NVD 2.0."""
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0]["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
    return None, None


def _extract_cwe(cve_data: dict) -> Optional[str]:
    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        descs = w.get("description", [])
        for d in descs:
            val = d.get("value", "")
            if val.startswith("CWE-"):
                return val
    return None


def _extract_description(cve_data: dict) -> Optional[str]:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


# ─── NVD Index ────────────────────────────────────────────────────────────────

_NVD_INDEX: Optional[dict[str, list[dict]]] = None


def _build_index() -> dict[str, list[dict]]:
    """
    Construit un index {vendor:product → [cve_entry, ...]} depuis les fichiers cache NVD.
    Chargé une seule fois en mémoire (singleton).
    """
    index: dict[str, list[dict]] = {}
    if not NVD_CACHE_DIR.exists():
        logger.warning("NVD cache introuvable (%s). CPE→CVE enrichissement désactivé.", NVD_CACHE_DIR)
        return index

    json_files = sorted(NVD_CACHE_DIR.glob("*.json"))
    logger.info("Construction de l'index NVD CPE→CVE depuis %d fichiers cache...", len(json_files))

    for fpath in json_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                items = json.load(f)
            for item in items:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                configs = cve_data.get("configurations", [])
                for cfg in configs:
                    for node in cfg.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            if not cpe_match.get("vulnerable", False):
                                continue
                            criteria = cpe_match.get("criteria", "")
                            parsed = _parse_cpe_vendor_product(criteria)
                            if not parsed:
                                continue
                            vendor, product = parsed
                            key = f"{vendor}:{product}"
                            entries = index.setdefault(key, [])
                            # Limiter à 30 CVEs par produit pour la mémoire
                            if len(entries) < 30:
                                score, vector = _extract_cvss(cve_data)
                                entries.append({
                                    "cve_id": cve_id,
                                    "score": score,
                                    "vector": vector,
                                    "cwe": _extract_cwe(cve_data),
                                    "description": _extract_description(cve_data),
                                    # Contraintes de version (anti-hallucination).
                                    "crit_ver": _criteria_version(criteria),
                                    "vsi": cpe_match.get("versionStartIncluding"),
                                    "vse": cpe_match.get("versionStartExcluding"),
                                    "vei": cpe_match.get("versionEndIncluding"),
                                    "vee": cpe_match.get("versionEndExcluding"),
                                })
        except Exception as e:
            logger.warning("Erreur lors du parsing de %s : %s", fpath.name, e)

    logger.info("Index NVD construit : %d produits référencés.", len(index))
    return index


def _get_index() -> dict[str, list[dict]]:
    global _NVD_INDEX
    if _NVD_INDEX is None:
        _NVD_INDEX = _build_index()
    return _NVD_INDEX


# ─── Service heuristic CVSS fallback ─────────────────────────────────────────

_HIGH_RISK_SVC   = {"ssh", "telnet", "rdp", "vnc", "ftp", "rsh", "rlogin", "rexec"}
_MEDIUM_RISK_SVC = {"http", "https", "smtp", "pop3", "imap", "snmp", "nfs", "smb", "msrpc"}
_DB_SVC          = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "cassandra"}

_HIGH_RISK_PORTS   = {22, 23, 3389, 5900, 21, 512, 513, 514}
_MEDIUM_RISK_PORTS = {80, 443, 8080, 8443, 25, 110, 143, 161, 2049, 445, 139}
_DB_PORTS          = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 7474}


def _service_heuristic_cvss(svc: Service) -> tuple[float, str]:
    """Retourne (cvss_score, cvss_vector) heuristique basé sur le service/port."""
    port = int(svc.port or 0)
    name = (svc.service or "").lower()

    if name in _HIGH_RISK_SVC or port in _HIGH_RISK_PORTS:
        return 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if name in _DB_SVC or port in _DB_PORTS:
        return 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    if name in _MEDIUM_RISK_SVC or port in _MEDIUM_RISK_PORTS:
        return 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    return 4.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"


# ─── Main enrichment function ─────────────────────────────────────────────────

def enrich_service_vulns_from_cpe(session: Session) -> dict[str, int]:
    """
    Pour chaque vulnérabilité sans CVE :
      1. Extrait le CPE depuis Service.cpe ou depuis la description
      2. Cherche des CVEs correspondants dans l'index NVD
      3. Crée de nouvelles Vulnerability liées à ces CVEs
      4. Si aucun CVE trouvé, applique CVSS heuristique sur la vuln existante
    """
    stats = {"found_cpe": 0, "cves_created": 0, "heuristic_applied": 0, "skipped": 0}

    no_cve_vulns = session.scalars(
        select(Vulnerability).where(Vulnerability.cve.is_(None))
    ).all()

    if not no_cve_vulns:
        logger.info("Aucune vulnérabilité sans CVE — CPE enrichissement ignoré.")
        return stats

    index = _get_index()

    for vuln in no_cve_vulns:
        svc = vuln.service
        if not svc:
            stats["skipped"] += 1
            continue

        # 1. Déterminer le CPE à utiliser
        cpe_str = svc.cpe or _extract_cpe_from_text(vuln.description or "")
        parsed = _parse_cpe_vendor_product(cpe_str) if cpe_str else None

        if parsed:
            stats["found_cpe"] += 1
            vendor, product = parsed
            key = f"{vendor}:{product}"
            candidates = index.get(key, [])
        else:
            candidates = []

        # 1bis. FILTRE ANTI-HALLUCINATION : ne garder que les CVE dont la plage
        # de versions vulnérables couvre EXPLICITEMENT la version détectée.
        # Sans version détectée, aucune CVE n'est associée (refus strict).
        detected_ver = _ver_tuple(svc.version)
        if detected_ver is None:
            matches = []
        else:
            matches = [e for e in candidates if _version_confirmed(detected_ver, e)]

        if matches:
            # 2. Créer des CVE-linked vulns pour ce service
            created = 0
            for entry in matches[:5]:   # Max 5 CVE créés par service
                cve_id = entry["cve_id"]
                # Déduplique par (service_id, cve)
                exists = session.scalar(
                    select(Vulnerability).where(
                        Vulnerability.service_id == svc.id,
                        Vulnerability.cve == cve_id
                    )
                )
                if exists:
                    continue

                new_vuln = Vulnerability(
                    service_id=svc.id,
                    cve=cve_id,
                    description=entry["description"],
                    cvss_score=entry["score"],
                    cvss_vector=entry["vector"],
                    cwe=entry["cwe"],
                    source=vuln.source or "nvd_cache",
                )
                session.add(new_vuln)
                created += 1

            if created > 0:
                stats["cves_created"] += created
                # Mettre à jour la description de la vuln de service
                vuln.description = (
                    f"[CPE: {cpe_str}] Service {svc.service} {svc.version or ''} détecté. "
                    f"{created} CVE(s) associé(s) créé(s) depuis la base NVD locale."
                )
        else:
            # 3. Aucun CVE trouvé — heuristique CVSS sur la vuln existante
            if vuln.cvss_score is None:
                score, vector = _service_heuristic_cvss(svc)
                vuln.cvss_score = score
                vuln.cvss_vector = vector
                vuln.description = (
                    f"[Service détecté] {svc.service} {svc.version or ''} "
                    f"sur le port {svc.port}/{svc.protocol}. "
                    f"Aucun CVE trouvé dans la base NVD locale. "
                    f"Score CVSS estimé heuristiquement : {score}."
                )
                stats["heuristic_applied"] += 1

    try:
        session.commit()
        logger.info(
            "CPE→CVE enrichissement : found_cpe=%d, cves_created=%d, heuristic=%d",
            stats["found_cpe"], stats["cves_created"], stats["heuristic_applied"],
        )
    except Exception as e:
        logger.error("Erreur commit CPE→CVE : %s", e)
        session.rollback()

    return stats
