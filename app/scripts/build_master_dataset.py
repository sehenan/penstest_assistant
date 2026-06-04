import os
import zipfile
import json
import gzip
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION ET CHARGEMENT
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR = Path("data/Dataset")
OUTPUT_FILE = Path("data/entrainement_dataset.csv")
CURRENT_YEAR = 2026

# Mappings catégoriels pour encodage numérique (Modèle XGBoost)
AV_MAP = {"NETWORK": 4, "ADJACENT": 3, "LOCAL": 2, "PHYSICAL": 1, "UNKNOWN": 0}
AC_MAP = {"LOW": 2, "MEDIUM": 1, "HIGH": 0, "UNKNOWN": 0}
PR_MAP = {"NONE": 2, "LOW": 1, "HIGH": 0, "UNKNOWN": 0}
UI_MAP = {"NONE": 1, "REQUIRED": 0, "UNKNOWN": 0}
SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

def get_nvd_data():
    """Charge et parse les fichiers JSON NVD (V2.0) depuis les archives ZIP."""
    nvd_records = []
    zip_files = list(DATA_DIR.glob("nvdcve-2.0-*.json.zip"))
    
    print(f"[*] Analyse de {len(zip_files)} archives NVD...")
    
    for zip_path in zip_files:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for file_info in zf.infolist():
                if file_info.filename.endswith(".json"):
                    with zf.open(file_info.filename) as f:
                        data = json.load(f)
                        for item in data.get("vulnerabilities", []):
                            cve = item.get("cve", {})
                            cve_id = cve.get("id")
                            
                            # Extraction CVSS v3.1 (prioritaire) ou v3.0
                            metrics = cve.get("metrics", {})
                            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
                            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0]
                            
                            m = cvss_v31 if cvss_v31 else cvss_v30
                            cvss_data = m.get("cvssData", {})
                            
                            if not cvss_data: continue # On ne garde que les CVE avec score
                            
                            nvd_records.append({
                                "cve_id": cve_id,
                                "cvss_score": cvss_data.get("baseScore", 0.0),
                                "baseSeverity": cvss_data.get("baseSeverity", "UNKNOWN"),
                                "attackVector": cvss_data.get("attackVector", "UNKNOWN"),
                                "attackComplexity": cvss_data.get("attackComplexity", "UNKNOWN"),
                                "privilegesRequired": cvss_data.get("privilegesRequired", "UNKNOWN"),
                                "userInteraction": cvss_data.get("userInteraction", "UNKNOWN")
                            })
    
    return pd.DataFrame(nvd_records)

def get_epss_data():
    """Charge les scores EPSS depuis le fichier GZ (le plus rcent)."""
    epss_files = sorted(list(DATA_DIR.glob("epss_scores-*.csv.gz")))
    if not epss_files:
        raise FileNotFoundError("Aucun fichier EPSS trouvé dans " + str(DATA_DIR))
    
    epss_path = epss_files[-1] # On prend le plus récent par ordre alphabétique
    print(f"[*] Chargement des scores EPSS : {epss_path.name}")
    
    # On saute les lignes de commentaire (#) au début du fichier EPSS
    return pd.read_csv(epss_path, compression='gzip', comment='#')

def get_kev_data():
    """Charge la liste CISA KEV."""
    kev_path = DATA_DIR / "known_exploited_vulnerabilities.csv"
    print(f"[*] Chargement de CISA KEV : {kev_path.name}")
    df_kev = pd.read_csv(kev_path)
    # On ne garde que l'ID pour la jointure
    df_kev = df_kev[['cveID']].copy()
    df_kev['is_exploited'] = 1
    return df_kev.rename(columns={'cveID': 'cve_id'})

# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE PRINCIPAL (LOGIQUE DATA ENGINEER)
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=== Construction du Master Dataset Priorisation ===")
    
    # 1. Extraction
    df_nvd = get_nvd_data()
    df_epss = get_epss_data().rename(columns={'cve': 'cve_id'})
    df_kev = get_kev_data()
    
    # 2. Jointure (Clé Primaire : CVE-ID)
    print("[*] Fusion des sources de données...")
    master_df = pd.merge(df_nvd, df_epss, on='cve_id', how='left')
    master_df = pd.merge(master_df, df_kev, on='cve_id', how='left')
    
    # Nettoyage des valeurs manquantes (EPSS/KEV)
    master_df['epss'] = master_df['epss'].fillna(0.0)
    master_df['percentile'] = master_df['percentile'].fillna(0.0)
    master_df['is_exploited'] = master_df['is_exploited'].fillna(0).astype(int)
    
    # 3. Feature Engineering
    print("[*] Génération des features calculées...")
    
    # Risk Factor (CVSS x EPSS)
    master_df['risk_factor'] = master_df['cvss_score'] * master_df['epss']
    
    # Age CVE (Différence d'année)
    # Format CVE id : CVE-YYYY-NNNN
    master_df['age_cve'] = master_df['cve_id'].apply(
        lambda x: CURRENT_YEAR - int(x.split('-')[1]) if '-' in x else 0
    )
    
    # 4. Encodage Numérique (Mapping professionnel)
    print("[*] Encodage catégoriel (Conversion en nombres)...")
    master_df['av_num'] = master_df['attackVector'].str.upper().map(AV_MAP).fillna(0).astype(int)
    master_df['ac_num'] = master_df['attackComplexity'].str.upper().map(AC_MAP).fillna(0).astype(int)
    master_df['pr_num'] = master_df['privilegesRequired'].str.upper().map(PR_MAP).fillna(0).astype(int)
    master_df['ui_num'] = master_df['userInteraction'].str.upper().map(UI_MAP).fillna(0).astype(int)
    master_df['severity_num'] = master_df['baseSeverity'].str.upper().map(SEVERITY_MAP).fillna(0).astype(int)
    
    # 5. Finalisation et Export
    print("[*] Nettoyage final et export...")
    
    # On ne garde que les colonnes utiles au ML ou à l'interprétation
    final_cols = [
        'cve_id', 'cvss_score', 'severity_num', 'epss', 'percentile', 
        'is_exploited', 'risk_factor', 'age_cve',
        'av_num', 'ac_num', 'pr_num', 'ui_num'
    ]
    
    master_df = master_df[final_cols].drop_duplicates(subset=['cve_id'])
    
    master_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[SUCCESS] Dataset généré avec succès : {OUTPUT_FILE}")
    print(f"Total des vulnérabilités traitées : {len(master_df)}")
    print(f"Vulnerabilités exploitées (CISA) : {master_df['is_exploited'].sum()}")

if __name__ == "__main__":
    main()
