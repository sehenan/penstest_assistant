import pandas as pd
import numpy as np
from pathlib import Path

# Paths
NVD_PATH = Path("data/nvd_training_data.csv")
EPSS_1_PATH = Path("data/Dataset/entrainement_dataset_1.csv")
ENRICHED_PATH = Path("data/Dataset/cve_cisa_epss_enriched_dataset.csv")
KEV_PATH = Path("data/Dataset/known_exploited_vulnerabilities.csv")
OUTPUT_PATH = Path("data/entrainement_dataset.csv")
CURRENT_YEAR = 2026


# ─────────────────────────────────────────────────────────────────────────────
#  Professional Encoding Tables (Aligned with features.py)
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
AV_MAP = {"NETWORK": 4, "N": 4, "ADJACENT": 3, "A": 3, "LOCAL": 2, "L": 2, "PHYSICAL": 1, "P": 1, "UNKNOWN": 0}
AC_MAP = {"LOW": 2, "L": 2, "MEDIUM": 1, "M": 1, "HIGH": 0, "H": 0, "UNKNOWN": 0}
PR_MAP = {"NONE": 2, "N": 2, "LOW": 1, "L": 1, "HIGH": 0, "H": 0, "UNKNOWN": 0}
UI_MAP = {"NONE": 1, "N": 1, "REQUIRED": 0, "R": 0, "UNKNOWN": 0}

def encode_val(val, map_dict):
    if pd.isna(val): return 0
    s_val = str(val).upper().strip()
    return map_dict.get(s_val, 0)

def consolidate():
    print("--- Professional Data Consolidation (Technical Constitution Phase) ---")

    # 1. Load Data
    print(f"Loading sources...")
    df_nvd = pd.read_csv(NVD_PATH)
    df_u1 = pd.read_csv(EPSS_1_PATH).rename(columns={'cve_id': 'cve'})
    df_master = pd.read_csv(ENRICHED_PATH).rename(columns={'cve_id': 'cve'})

    # 2. Sequential Merging (Priority Hierarchy)
    print("Merging and enriching...")
    df = df_nvd.copy()
    
    # Enrichment: EPSS and Age from User Dataset and Master Dataset
    df = pd.merge(df, df_u1[['cve', 'epss_score', 'age_cve']], on='cve', how='left')
    df = pd.merge(df, df_master[['cve', 'epss_score', 'epss_perc']], on='cve', how='left', suffixes=('', '_m'))
    df['epss_score'] = df['epss_score'].fillna(df['epss_score_m']).fillna(0)
    
    # KEV Status
    if KEV_PATH.exists():
        df_kev = pd.read_csv(KEV_PATH).rename(columns={'cveID': 'cve'})
        df_kev['is_kev'] = 1
        df = pd.merge(df, df_kev[['cve', 'is_kev']], on='cve', how='left')
        df['in_cisa_kev'] = df['is_kev'].fillna(df.get('in_cisa_kev', 0)).fillna(0).astype(int)

    # 3. TECHNICAL CONSTITUTION: Cleaning & Encoding
    print("Finalizing Technical Constitution (Encoding & Cleanup)...")
    
    # Map qualitative vectors to numeric features used by XGBoost
    df['av_num'] = df['attackVector'].apply(lambda x: encode_val(x, AV_MAP))
    df['ac_num'] = df['attackComplexity'].apply(lambda x: encode_val(x, AC_MAP))
    df['pr_num'] = df['privilegesRequired'].apply(lambda x: encode_val(x, PR_MAP))
    df['ui_num'] = df['userInteraction'].apply(lambda x: encode_val(x, UI_MAP))
    df['severity_num'] = df['severity'].apply(lambda x: encode_val(x, SEVERITY_MAP))
    
    # Contextual Cleanups
    # Dynamic Age Calculation
    def get_age(cve_id):
        try:
            if pd.isna(cve_id) or not isinstance(cve_id, str): return 6
            parts = cve_id.split('-')
            if len(parts) > 1:
                return CURRENT_YEAR - int(parts[1])
        except (ValueError, IndexError):
            pass
        return 6

    df['age_cve'] = df['cve'].apply(get_age)
    
    df['port'] = pd.to_numeric(df['port'], errors='coerce').fillna(0).astype(int)
    df['service'] = df['service'].fillna('unknown').str.lower()
    df['is_public'] = df['is_public'].fillna(0).astype(int)
    df['has_exploit'] = df[['has_exploit', 'in_cisa_kev']].max(axis=1).fillna(0).astype(int)

    # Classification Contextuelle (re-calc inline for portability)
    def svc_context(p):
        if p in [80, 443, 8080, 8443]: return 4 # WEB
        if p in [22, 3389, 23, 5900]: return 3 # REMOTE
        if p in [3306, 5432, 1521, 1433, 27017]: return 2 # DB
        if p in [21, 445, 139, 2049]: return 2 # FILE
        return 1
    df['svc_type_num'] = df['port'].apply(svc_context)

    # 4. COMPOSITE RISK SCORING (Non-CVSS redundant)
    print("Recalculating Multi-Factor Gold Risk Score...")
    
    # Formula: Risk = Impact(CVSS) + Likelihood(EPSS) + Proven Threat(KEV/ExploitDB) + Context(Svc)
    # Balanced weighting for professional accuracy
    df['gold_risk_score'] = (
        (df['cvss_score'] * 0.45) + # Theoretical Impact
        (df['epss_score'] * 6.5) +  # High likelihood boost
        (df['in_cisa_kev'] * 2.0) + # Real world proof boost
        (df.get('in_exploitdb',0) * 0.5) + # Public PoC boost
        (df['svc_type_num'] * 0.1) # Business context boost
    )
    df['gold_risk_score'] = df['gold_risk_score'].clip(0, 10).round(2)

    # 5. Export Final Constitution
    # Ensure all columns required by features.py are present in numeric format
    df = df.drop_duplicates(subset=['cve'])
    
    # Columns to include: The 'Truth' plus numeric features
    cols_to_save = [
        'cve', 'cvss_score', 'gold_risk_score', 'epss_score', 'age_cve',
        'port', 'is_public', 'has_exploit', 'in_cisa_kev', 'in_exploitdb',
        'av_num', 'ac_num', 'pr_num', 'ui_num', 'severity_num', 'svc_type_num'
    ]
    df = df[cols_to_save]
    
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"SUCCESS: Exported {len(df)} technically finalized entries to {OUTPUT_PATH}")
    
    # Verify diversity
    diff = (df['gold_risk_score'] != df['cvss_score']).sum()
    print(f"Verification: {diff}/{len(df)} rows have a different Risk score from CVSS (Good).")

if __name__ == "__main__":
    consolidate()
