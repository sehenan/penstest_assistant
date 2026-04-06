"""
Enrichissement CVE via l'API NVD 2.0 (JSON).
Hors-ligne : définir NVD_OFFLINE=1 et fournir un cache JSON (voir fetch_cve_from_nvd).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _rate_delay() -> None:
    """Délai minimal entre requêtes (NVD limite les clients sans clé API)."""
    if os.environ.get("NVD_OFFLINE") == "1":
        return
    key = os.environ.get("NVD_API_KEY")
    delay = float(os.environ.get("NVD_DELAY", "0.6" if key else "6.0"))
    time.sleep(delay)


def _parse_nvd_vulnerability(blob: dict[str, Any]) -> dict[str, Any] | None:
    vulns = blob.get("vulnerabilities") or []
    if not vulns:
        return None
    cve_block = vulns[0].get("cve") or {}
    cve_id = cve_block.get("id")
    desc = None
    for d in cve_block.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value")
            break
    if not desc and (cve_block.get("descriptions") or []):
        desc = cve_block["descriptions"][0].get("value")

    cwe = None
    for w in cve_block.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value") or ""
            if val.startswith("CWE-"):
                cwe = val.split(":")[0].strip()
                break
        if cwe:
            break

    score = None
    vector = None
    metrics = cve_block.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString")
            break
    if score is None:
        arr = metrics.get("cvssMetricV2") or []
        if arr:
            data = arr[0].get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString")

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": float(score) if score is not None else None,
        "cvss_vector": vector,
        "cwe": cwe,
    }


def fetch_cve_from_nvd(cve_id: str, session: requests.Session | None = None) -> dict[str, Any] | None:
    """
    Récupère les métadonnées NVD pour un CVE.
    Mode air-gap : placer un fichier JSON par CVE dans le dossier NVD_CACHE_DIR
    (nom : CVE-xxxx-xxxxx.json) avec le corps brut de l'API.
    """
    cve_id = cve_id.strip().upper()
    cache_dir = os.environ.get("NVD_CACHE_DIR")
    if cache_dir:
        p = Path(cache_dir) / f"{cve_id}.json"
        if p.is_file():
            with open(p, encoding="utf-8") as f:
                return _parse_nvd_vulnerability(json.load(f))

    if os.environ.get("NVD_OFFLINE") == "1":
        return None

    sess = session or requests.Session()
    params = {"cveId": cve_id}
    headers = {}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    r = sess.get(NVD_URL, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    return _parse_nvd_vulnerability(r.json())


def enrich_vulnerabilities_from_nvd(
    db_session: Session,
    http_session: requests.Session | None = None,
) -> dict[str, int]:
    """
    Met à jour les lignes Vulnerability (cvss_*, description, cwe) depuis la NVD
    lorsque cvss_score est encore vide.
    """
    rows = db_session.scalars(
        select(Vulnerability).where(Vulnerability.cve.isnot(None))
    ).all()
    stats = {"updated": 0, "skipped": 0, "failed": 0}
    http = http_session or requests.Session()

    for v in rows:
        if not v.cve or not v.cve.upper().startswith("CVE-"):
            stats["skipped"] += 1
            continue
        if v.cvss_score is not None:
            stats["skipped"] += 1
            continue
        try:
            _rate_delay()
            data = fetch_cve_from_nvd(v.cve, session=http)
            if not data:
                stats["failed"] += 1
                continue
            if data.get("cvss_score") is not None:
                v.cvss_score = data["cvss_score"]
            if data.get("cvss_vector"):
                v.cvss_vector = data["cvss_vector"]
            if data.get("description") and not (v.description or "").strip():
                v.description = data["description"]
            if data.get("cwe"):
                v.cwe = data["cwe"]
            stats["updated"] += 1
        except (requests.RequestException, OSError, ValueError, KeyError):
            stats["failed"] += 1
            continue

    try:
        db_session.commit()
    except Exception:
        db_session.rollback()
        raise
    return stats
