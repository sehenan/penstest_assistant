"""
fetch_training_data.py
======================
Pipeline de collecte de données réelles depuis 3 sources officielles :

  1. NVD  (NIST)  – Scores CVSS, métriques d'exploitabilité
  2. CISA KEV     – Known Exploited Vulnerabilities (~1 200 CVE activement exploitées)
  3. ExploitDB    – PoC publics (~24 000 CVE avec exploit confirmé)

Logique de labellisation (has_exploit / label) :
  label = 1  si :  CVE dans CISA KEV  OU  CVE dans ExploitDB  OU  (CVSS >= 9.0 ET exploitabilité NVD haute)
  label = 0  sinon

Résultat → data/nvd_training_data.csv
  Colonnes : cve, cvss_score, severity, severity_num, port, service,
             is_public, has_exploit, label, attackVector, attackComplexity,
             privilegesRequired, userInteraction, gold_risk_score, source

Usage :
    python -m app.core.ml.fetch_training_data
    python -m app.core.ml.fetch_training_data --max-cves 2000 --severities CRITICAL HIGH MEDIUM LOW
    python -m app.core.ml.fetch_training_data --max-cves 5000 --api-key <NVD_KEY>
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import time
from pathlib import Path
from typing import Optional

import requests

# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Constantes
# ─────────────────────────────────────────────────────────────────────────────
NVD_BASE_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV   = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
OUTPUT_PATH     = Path("data") / "nvd_training_data.csv"

SEVERITY_NUM:  dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0,
}
PUBLIC_PORTS: set[int] = {21, 22, 25, 53, 80, 443, 445, 8080, 8443}

# Mapping partiel produit/vendor → port (depuis CPE)
SERVICE_PORT_MAP: dict[str, int] = {
    "http": 80, "apache": 80, "nginx": 80, "iis": 80, "tomcat": 8080,
    "https": 443, "ssl": 443, "tls": 443,
    "ssh": 22, "openssh": 22,
    "ftp": 21, "vsftpd": 21, "proftpd": 21,
    "smtp": 25, "postfix": 25, "sendmail": 25,
    "smb": 445, "samba": 445, "cifs": 445,
    "rdp": 3389, "mstsc": 3389,
    "mysql": 3306, "mariadb": 3306,
    "postgresql": 5432, "postgres": 5432,
    "mssql": 1433, "sqlserver": 1433,
    "oracle": 1521,
    "ldap": 389, "activedirectory": 389,
    "dns": 53, "bind": 53,
    "telnet": 23,
    "vnc": 5900,
    "imap": 143, "pop3": 110,
    "snmp": 161,
    "docker": 2375, "kubernetes": 6443,
    "redis": 6379, "mongodb": 27017, "elasticsearch": 9200,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Source 1 : NVD API v2
# ─────────────────────────────────────────────────────────────────────────────
def fetch_nvd_cves(
    severities: list[str],
    max_cves: int,
    api_key: Optional[str] = None,
) -> list[dict]:
    """
    Télécharge max_cves CVEs depuis l'API NVD v2 en couvrant les sévérités demandées.
    Rate-limit : 5 req/30 s sans clé (6,5 s entre requêtes) | 50 req/30 s avec clé (0,6 s).
    """
    all_cves: list[dict] = []
    headers = {"apiKey": api_key} if api_key else {}
    delay   = 0.6 if api_key else 6.5

    per_severity = max(1, max_cves // len(severities))

    for severity in severities:
        if len(all_cves) >= max_cves:
            break

        quota       = min(per_severity, max_cves - len(all_cves))
        start_index = 0
        fetched_sev = 0
        page_size   = min(200, quota)

        logger.info("⬇  NVD — sévérité: %-8s  (quota: %d)", severity, quota)

        while fetched_sev < quota:
            params = {
                "cvssV3Severity": severity,
                "resultsPerPage": min(page_size, quota - fetched_sev),
                "startIndex":     start_index,
            }
            try:
                resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
                resp.raise_for_status()
            except requests.RequestException as exc:
                logger.warning("Erreur NVD (%s). Attente 30 s…", exc)
                time.sleep(30)
                continue

            data  = resp.json()
            items = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            if not items:
                break

            all_cves.extend(items)
            fetched_sev += len(items)
            start_index += len(items)

            logger.info("   %d/%d  CVEs (%s)", fetched_sev, min(quota, total), severity)

            if start_index >= total:
                break

            time.sleep(delay)

    logger.info("✅ NVD — Total brut récupéré : %d", len(all_cves))
    return all_cves[:max_cves]


def fetch_nvd_by_cve_ids(
    cve_ids: list[str],
    api_key: Optional[str] = None,
) -> list[dict]:
    """
    Récupère les fiches NVD pour une liste spécifique de CVE IDs.
    Utilisé pour garantir que tous les CVEs CISA KEV sont dans le dataset.
    Pause entre chaque requête pour respecter le rate-limit.
    """
    results: list[dict] = []
    headers = {"apiKey": api_key} if api_key else {}
    delay   = 0.6 if api_key else 6.5

    logger.info("⬇  NVD (par CVE ID) — %d CVEs KEV manquants à récupérer…", len(cve_ids))

    for i, cve_id in enumerate(cve_ids):
        try:
            resp = requests.get(
                NVD_BASE_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            if items:
                results.extend(items)
        except requests.RequestException as exc:
            logger.warning("Erreur NVD pour %s : %s", cve_id, exc)

        if (i + 1) % 10 == 0:
            logger.info("   %d/%d KEV récupérés…", i + 1, len(cve_ids))

        time.sleep(delay)

    logger.info("✅ NVD par ID — %d/%d CVEs KEV récupérés.", len(results), len(cve_ids))
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  Source 2 : CISA KEV (Known Exploited Vulnerabilities)
# ─────────────────────────────────────────────────────────────────────────────
def fetch_cisa_kev() -> set[str]:
    """
    Télécharge le catalogue CISA KEV (JSON).
    Retourne l'ensemble des CVE IDs activement exploitées en production.
    ~1 200 entrées — toutes labellisées 1 (exploitées confirmées).
    """
    logger.info("⬇  CISA KEV — téléchargement…")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("CISA KEV indisponible : %s — label KEV sera ignoré.", exc)
        return set()

    cves = {vuln.get("cveID", "").upper() for vuln in data.get("vulnerabilities", [])}
    logger.info("✅ CISA KEV — %d CVE activement exploitées.", len(cves))
    return cves


# ─────────────────────────────────────────────────────────────────────────────
#  Source 3 : ExploitDB
# ─────────────────────────────────────────────────────────────────────────────
def fetch_exploitdb() -> set[str]:
    """
    Télécharge le CSV ExploitDB et en extrait les CVE IDs avec PoC public.
    ~24 000 exploits, ~20 000 CVEs uniques.
    """
    logger.info("⬇  ExploitDB — téléchargement CSV…")
    try:
        resp = requests.get(EXPLOITDB_CSV, timeout=60)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("ExploitDB indisponible : %s — label ExploitDB ignoré.", exc)
        return set()

    cves: set[str] = set()
    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        codes = row.get("codes", "") or row.get("cve", "") or ""
        for part in codes.split(";"):
            part = part.strip().upper()
            if part.startswith("CVE-"):
                cves.add(part)

    logger.info("✅ ExploitDB — %d CVEs uniques avec exploit PoC.", len(cves))
    return cves


# ─────────────────────────────────────────────────────────────────────────────
#  Parsing NVD → tableau de features
# ─────────────────────────────────────────────────────────────────────────────
def _infer_port(cpe: str) -> tuple[int, str]:
    """Déduit le port et le service depuis une chaîne CPE."""
    cpe_lower = cpe.lower()
    for keyword, port in SERVICE_PORT_MAP.items():
        if keyword in cpe_lower:
            parts   = cpe.split(":")
            service = parts[4] if len(parts) > 4 else keyword
            return port, service
    return 0, "unknown"


def _extract_cvss(metrics: dict) -> tuple[Optional[float], str, dict]:
    """
    Extrait le score CVSS, la sévérité et les métriques exploitabilité
    (attackVector, attackComplexity, privilegesRequired, userInteraction).
    Priorité : CVSSv3.1 > CVSSv3.0 > CVSSv2.
    """
    extra: dict[str, str] = {
        "attackVector":        "UNKNOWN",
        "attackComplexity":    "UNKNOWN",
        "privilegesRequired":  "UNKNOWN",
        "userInteraction":     "UNKNOWN",
    }

    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m        = metrics[key][0].get("cvssData", {})
            score    = m.get("baseScore")
            severity = m.get("baseSeverity", "UNKNOWN").upper()
            extra.update({
                "attackVector":       m.get("attackVector",       "UNKNOWN"),
                "attackComplexity":   m.get("attackComplexity",   "UNKNOWN"),
                "privilegesRequired": m.get("privilegesRequired", "UNKNOWN"),
                "userInteraction":    m.get("userInteraction",    "UNKNOWN"),
            })
            return score, severity, extra

    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m        = metrics["cvssMetricV2"][0].get("cvssData", {})
        score    = m.get("baseScore")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN").upper()
        extra["attackVector"] = m.get("accessVector", "UNKNOWN")
        extra["attackComplexity"] = m.get("accessComplexity", "UNKNOWN")
        return score, severity, extra

    return None, "UNKNOWN", extra


def parse_nvd(
    raw_cves: list[dict],
    cisa_cves: set[str],
    exploitdb_cves: set[str],
) -> list[dict]:
    """
    Transforme les CVEs bruts NVD en lignes featuisées + labellisées.

    Règle de labellisation (has_exploit / label) :
      1. CVE dans cisa_cves          → label = 1  (exploitée en production)
      2. CVE dans exploitdb_cves     → label = 1  (PoC public confirmé)
      3. CVSS >= 9.0 + AV=NETWORK + AC=LOW + PR=NONE → label = 1 (très probable)
      4. Sinon                       → label = 0
    """
    rows: list[dict] = []

    for item in raw_cves:
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "UNKNOWN").upper()
        metrics  = cve_data.get("metrics", {})

        cvss_score, severity, extra = _extract_cvss(metrics)
        if cvss_score is None:
            continue

        cvss_score = float(cvss_score)

        # ── Port / Service depuis CPE ──
        port, service = 0, "unknown"
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    p, s = _infer_port(cpe_match.get("criteria", ""))
                    if p != 0:
                        port, service = p, s
                        break
                if port:
                    break
            if port:
                break

        is_public = int(port in PUBLIC_PORTS)

        # ── Labellisation (3 règles) ──
        in_kev       = cve_id in cisa_cves
        in_exploitdb = cve_id in exploitdb_cves
        high_risk_nvd = (
            cvss_score >= 9.0
            and extra["attackVector"]      in ("NETWORK",    "N")
            and extra["attackComplexity"]  in ("LOW",        "L")
            and extra["privilegesRequired"] in ("NONE",      "N")
        )
        has_exploit = int(in_kev or in_exploitdb or high_risk_nvd)

        # ── Gold Risk Score (cible de régression continue) ──
        bonus = (1.5 if has_exploit else 0.0) + (0.5 if is_public else 0.0)
        gold_risk = round(min(cvss_score + bonus, 10.0), 2)

        # ── Colonne source lisible ──
        src_parts = ["NVD"]
        if in_kev:
            src_parts.append("CISA_KEV")
        if in_exploitdb:
            src_parts.append("ExploitDB")
        source_label = "+".join(src_parts)

        rows.append({
            "cve":                cve_id,
            "cvss_score":         round(cvss_score, 2),
            "severity":           severity,
            "severity_num":       SEVERITY_NUM.get(severity, 0),
            "port":               port,
            "service":            service,
            "is_public":          is_public,
            "has_exploit":        has_exploit,
            "in_cisa_kev":        int(in_kev),
            "in_exploitdb":       int(in_exploitdb),
            "attackVector":       extra["attackVector"],
            "attackComplexity":   extra["attackComplexity"],
            "privilegesRequired": extra["privilegesRequired"],
            "userInteraction":    extra["userInteraction"],
            "gold_risk_score":    gold_risk,
            "source":             source_label,
        })

    return rows


# ─────────────────────────────────────────────────────────────────────────────
#  Sauvegarde CSV
# ─────────────────────────────────────────────────────────────────────────────
def save_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        logger.error("Aucune donnée à sauvegarder.")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    logger.info("💾 CSV sauvegardé : %s  (%d lignes)", path, len(rows))


# ─────────────────────────────────────────────────────────────────────────────
#  Pipeline principal
# ─────────────────────────────────────────────────────────────────────────────
def fetch_and_save(
    severities: Optional[list[str]] = None,
    max_cves:   int                 = 2000,
    api_key:    Optional[str]       = None,
    output:     Path                = OUTPUT_PATH,
) -> Path:
    if severities is None:
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    sep = "═" * 55
    logger.info(sep)
    logger.info(" PIPELINE DONNÉES OFFICIELLES — PFE Pentest Assistant")
    logger.info("  Sources  : NVD (NIST)  + CISA KEV + ExploitDB")
    logger.info("  Sévérités: %s", ", ".join(severities))
    logger.info("  Max CVEs : %d", max_cves)
    logger.info(sep)

    # ── Étape 1 : NVD (par sévérité) ──
    raw = fetch_nvd_cves(severities, max_cves, api_key)
    already_fetched = {item["cve"]["id"].upper() for item in raw if "cve" in item}

    # ── Étape 2 : CISA KEV (télécharge la liste complète) ──
    cisa = fetch_cisa_kev()

    # ── Étape 3 : ExploitDB (télécharge la liste complète) ──
    edb = fetch_exploitdb()

    # ── Étape 4 : Récupérer depuis NVD les CVEs KEV manquants ──
    missing_kev = [cid for cid in cisa if cid not in already_fetched]
    if missing_kev:
        logger.info(
            "🔍 %d CVEs CISA KEV absents du quota NVD initial — récupération ciblée…",
            len(missing_kev),
        )
        # Limiter pour éviter des temps de téléchargement excessifs
        # (prendre les 300 premiers suffit pour couvrir les plus critiques)
        kev_extra = fetch_nvd_by_cve_ids(missing_kev[:300], api_key)
        raw.extend(kev_extra)
        logger.info("  → %d CVEs KEV ajoutés au dataset.", len(kev_extra))
    else:
        logger.info("✅ Tous les CVEs CISA KEV sont déjà couverts par le quota NVD.")

    # ── Étape 5 : Parsing + labellisation ──
    logger.info("🔄 Parsing NVD + fusion des labels KEV / ExploitDB…")
    rows = parse_nvd(raw, cisa, edb)
    # Dédoublonnage sur CVE ID
    seen: set[str] = set()
    unique_rows = []
    for r in rows:
        if r["cve"] not in seen:
            seen.add(r["cve"])
            unique_rows.append(r)
    rows = unique_rows
    logger.info("  %d lignes uniques après dédoublonnage.", len(rows))

    # ── Étape 5 : Sauvegarde ──
    save_csv(rows, output)

    # ── Statistiques ──
    n          = len(rows)
    n_exploit  = sum(r["has_exploit"]  for r in rows)
    n_kev      = sum(r["in_cisa_kev"]  for r in rows)
    n_edb      = sum(r["in_exploitdb"] for r in rows)
    n_port     = sum(1 for r in rows if r["port"] != 0)

    sev_dist: dict[str, int] = {}
    for r in rows:
        sev_dist[r["severity"]] = sev_dist.get(r["severity"], 0) + 1

    logger.info("─" * 55)
    logger.info("📊 STATISTIQUES DU DATASET FINAL")
    logger.info("  Total lignes              : %d",  n)
    logger.info("  has_exploit = 1 (positifs): %d  (%.1f%%)", n_exploit, 100 * n_exploit / max(n, 1))
    logger.info("  └─ via CISA KEV           : %d", n_kev)
    logger.info("  └─ via ExploitDB          : %d", n_edb)
    logger.info("  └─ via règle CVSS NVD     : %d", n_exploit - n_kev - n_edb + sum(
        1 for r in rows if r["in_cisa_kev"] == 0 and r["in_exploitdb"] == 0 and r["has_exploit"] == 1
    ))
    logger.info("  Avec port identifié       : %d  (%.1f%%)", n_port,    100 * n_port    / max(n, 1))
    logger.info("  Distribution sévérité     : %s",     json.dumps(sev_dist))
    logger.info("  Ratio positifs/négatifs   : %.2f / %.2f",
                100 * n_exploit / max(n, 1), 100 * (n - n_exploit) / max(n, 1))
    logger.info("─" * 55)
    logger.info("✅ Dataset prêt pour l'entraînement XGBoost — %s", output)

    return output


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(
        description="Télécharge les données d'entraînement depuis NVD, CISA KEV et ExploitDB."
    )
    p.add_argument("--max-cves",    type=int,   default=2000,
                   help="Nombre total de CVEs à récupérer depuis NVD (défaut: 2000).")
    p.add_argument("--severities",  nargs="+",  default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="Sévérités CVSS à cibler.")
    p.add_argument("--api-key",     type=str,   default=None,
                   help="Clé API NVD optionnelle (lève le rate-limit à 50 req/30 s).")
    p.add_argument("--output",      type=str,   default=str(OUTPUT_PATH),
                   help=f"Chemin CSV de sortie (défaut: {OUTPUT_PATH}).")
    args = p.parse_args()

    fetch_and_save(
        severities=args.severities,
        max_cves=args.max_cves,
        api_key=args.api_key,
        output=Path(args.output),
    )


if __name__ == "__main__":
    main()
