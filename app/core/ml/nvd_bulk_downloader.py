"""
nvd_bulk_downloader.py
======================
Script pour télécharger massivement des CVE depuis le NVD (ex: 2019 à 2026).
Gère la limite de 120 jours par requête et le rate-limiting NVD.
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

import requests

from app.core.ml.fetch_training_data import (
    fetch_cisa_kev,
    fetch_exploitdb,
    fetch_nvd_by_cve_ids,
    parse_nvd,
    save_csv,
    NVD_BASE_URL
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

OUTPUT_PATH = Path("data") / "nvd_full_data.csv"
RAW_CACHE_DIR = Path("data") / "nvd_cache"

def generate_date_intervals(start_year: int, end_year: int) -> List[tuple[datetime.datetime, datetime.datetime]]:
    """Génère des intervalles de 90 jours max (NVD limite à 120 consécutifs)."""
    intervals = []
    current_start = datetime.datetime(start_year, 1, 1, tzinfo=datetime.timezone.utc)
    # Jusqu'à la fin de end_year
    end_date = datetime.datetime(end_year, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
    delta = datetime.timedelta(days=90)
    
    # On gère le fait de ne pas aller trop dans le futur (au delà de la date actuelle)
    now = datetime.datetime.now(datetime.timezone.utc)
    if end_date > now:
        end_date = now

    while current_start < end_date:
        current_end = min(current_start + delta, end_date)
        intervals.append((current_start, current_end))
        current_start = current_end + datetime.timedelta(seconds=1)
    
    return intervals

def format_nvd_date(dt: datetime.datetime) -> str:
    """Formate la date pour l'API NVD (YYYY-MM-DDTHH:MM:SS.000)."""
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000')

def fetch_cves_for_interval(
    start_dt: datetime.datetime, 
    end_dt: datetime.datetime, 
    api_key: Optional[str] = None
) -> List[Dict]:
    """Récupère les CVE pour un intervalle donné, gérant la pagination."""
    all_cves = []
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.6 if api_key else 6.5
    
    start_str = format_nvd_date(start_dt)
    end_str = format_nvd_date(end_dt)
    
    start_index = 0
    total_results = 1 # Sera mis à jour
    
    logger.info(f"⬇ NVD — Période {start_str[:10]} à {end_str[:10]}...")
    
    while start_index < total_results:
        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "resultsPerPage": 2000,
            "startIndex": start_index
        }
        
        success = False
        retries = 0
        while not success and retries < 5:
            try:
                resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=60)
                if resp.status_code in (403, 503):
                    logger.warning(f"Rate limit NVD atteint (HTTP {resp.status_code}). Attente 30 s...")
                    time.sleep(30)
                    retries += 1
                    continue
                resp.raise_for_status()
                data = resp.json()
                items = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)
                
                all_cves.extend(items)
                start_index += len(items)
                success = True
                
                if total_results > 0:
                    logger.info(f"   Récupération: {start_index}/{total_results} CVEs...")
                
            except requests.RequestException as exc:
                logger.warning(f"Erreur NVD ({exc}). Attente 30 s... (Essai {retries+1}/5)")
                time.sleep(30)
                retries += 1
                if retries == 5:
                    logger.error("❌ Échec de la requête après 5 essais, passage à la suite.")
                    break
        
        # S'il n'y a plus de résultats, on quitte la boucle de pagination
        if not success or len(data.get("vulnerabilities", [])) == 0:
            break
            
        time.sleep(delay)
        
    return all_cves

def fetch_and_save_full_dataset(
    start_year: int,
    end_year: int,
    api_key: Optional[str] = None,
    output: Path = OUTPUT_PATH
) -> Path:
    
    sep = "═" * 55
    logger.info(sep)
    logger.info(f" PIPELINE BULK DATA NVD — {start_year} à {end_year}")
    logger.info("  Téléchargement séquentiel avec gestion des limites d'API")
    logger.info(sep)
    
    # ── Étape 1 : Téléchargement progressif NVD ──
    intervals = generate_date_intervals(start_year, end_year)
    raw_cves = []
    
    # On sauvegarde temporairement pour éviter la perte en cas de crash
    RAW_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    for i, (s_dt, e_dt) in enumerate(intervals):
        cache_file = RAW_CACHE_DIR / f"nvd_{s_dt.strftime('%Y%m%d')}_{e_dt.strftime('%Y%m%d')}.json"
        
        if cache_file.exists():
            logger.info(f"♻️ Utilisation du cache pour {cache_file.name}")
            with open(cache_file, "r", encoding="utf-8") as f:
                interval_cves = json.load(f)
        else:
            interval_cves = fetch_cves_for_interval(s_dt, e_dt, api_key)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(interval_cves, f)
                
        raw_cves.extend(interval_cves)
        logger.info(f"  Total cumulé : {len(raw_cves)} CVEs")

    already_fetched = {item.get("cve", {}).get("id", "").upper(): True for item in raw_cves}
    
    # ── Étape 2 : CISA KEV (télécharge la liste complète) ──
    cisa = fetch_cisa_kev()

    # ── Étape 3 : ExploitDB (télécharge la liste complète) ──
    edb = fetch_exploitdb()

    # ── Étape 4 : Récupérer depuis NVD les CVEs KEV manquants ──
    missing_kev = [cid for cid in cisa if cid not in already_fetched and cid]
    if missing_kev:
        logger.info(
            f"🔍 {len(missing_kev)} CVEs CISA KEV absents (probablement hors de la plage {start_year}-{end_year}) — récupération ciblée…",
        )
        # Limiter pour éviter des temps excessifs
        kev_extra = fetch_nvd_by_cve_ids(missing_kev[:500], api_key)
        raw_cves.extend(kev_extra)
        logger.info(f"  → {len(kev_extra)} CVEs KEV ajoutés au dataset.")

    # ── Étape 5 : Parsing + labellisation ──
    logger.info("🔄 Parsing NVD + fusion des labels KEV / ExploitDB…")
    rows = parse_nvd(raw_cves, cisa, edb)
    
    # Dédoublonnage sur CVE ID
    seen = set()
    unique_rows = []
    for r in rows:
        if r["cve"] not in seen:
            seen.add(r["cve"])
            unique_rows.append(r)
    rows = unique_rows
    logger.info(f"  {len(rows)} lignes uniques après dédoublonnage.")

    # ── Étape 6 : Sauvegarde CSV ──
    save_csv(rows, output)
    
    logger.info("✅ Pipeline de téléchargement massif terminé !")
    return output

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Télécharge massivement l'API NVD sur plusieurs années.")
    p.add_argument("--start", type=int, default=2019, help="Année de début (ex: 2019)")
    p.add_argument("--end", type=int, default=2026, help="Année de fin (ex: 2026)")
    p.add_argument("--api-key", type=str, default=None, help="Clé API NVD")
    p.add_argument("--output", type=str, default=str(OUTPUT_PATH), help="Chemin de sauvegarde du CSV")
    
    args = p.parse_args()
    
    key = args.api_key or os.environ.get("NVD_API_KEY")
    
    fetch_and_save_full_dataset(args.start, args.end, key, Path(args.output))
