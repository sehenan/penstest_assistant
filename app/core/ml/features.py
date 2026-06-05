"""
Feature Engineering & Data Alignment.
Version 7 - Alignée sur les nouveaux modèles classificateur_xgb.joblib / regresseur_xgb.joblib.

Les modèles réentraînés utilisent désormais 11 features sans data leakage.
"""
import logging

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Tables d'encodage des métriques CVSS
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_NUM: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
# av_num : 1=Physical, 2=Local, 3=Adjacent, 4=Network
AV_NUM: dict[str, int] = {
    "NETWORK": 4, "N": 4, "ADJACENT": 3, "A": 3,
    "LOCAL": 2, "L": 2, "PHYSICAL": 1, "P": 1, "UNKNOWN": 0
}
# ac_num : 1=High, 2=Low
AC_NUM: dict[str, int] = {"LOW": 2, "L": 2, "HIGH": 1, "H": 1, "MEDIUM": 1, "M": 1, "UNKNOWN": 1}
# pr_num : 0=None, 1=Low, 2=High
PR_NUM: dict[str, int] = {"NONE": 0, "N": 0, "LOW": 1, "L": 1, "HIGH": 2, "H": 2, "UNKNOWN": 0}
# ui_num : 0=Required, 1=None
UI_NUM: dict[str, int] = {"NONE": 1, "N": 1, "REQUIRED": 0, "R": 0, "UNKNOWN": 0}

# ─────────────────────────────────────────────────────────────────────────────
#  Ports à risque élevé / critique / DB / web
# ─────────────────────────────────────────────────────────────────────────────
PORTS_HIGHRISK  = {21, 22, 23, 25, 110, 143, 445, 3389, 5900}
PORTS_CRITICAL  = {22, 23, 3389, 5900}               # accès distant direct
PORTS_DB        = {3306, 5432, 1521, 1433, 27017, 6379, 9200}
PORTS_WEB       = {80, 443, 8080, 8443, 8000, 8888}

# Classification contextuelle des services (svc_type_num)
SVC_TYPE_NUM: dict[str, int] = {
    "WEB":           4,   # HTTP/HTTPS, API
    "REMOTE_ACCESS": 3,   # SSH, RDP, VNC, Telnet
    "DATABASE":      2,   # SQL, NoSQL
    "FILE_TRANSFER": 2,   # FTP, SMB, NFS
    "OTHER":         1,
    "UNKNOWN":       0,
}


def classify_service(port: int, service_name: str = "") -> int:
    """Classe un service selon son importance stratégique."""
    name = str(service_name).upper()
    p = int(port) if port else 0

    if p in PORTS_WEB or "HTTP" in name:
        return SVC_TYPE_NUM["WEB"]
    if p in PORTS_CRITICAL or any(kw in name for kw in ["SSH", "RDP", "TELNET", "VNC"]):
        return SVC_TYPE_NUM["REMOTE_ACCESS"]
    if p in PORTS_DB or any(kw in name for kw in ["SQL", "MONGO", "ORACLE", "REDIS", "ELASTIC"]):
        return SVC_TYPE_NUM["DATABASE"]
    if p in {21, 445, 139, 2049} or any(kw in name for kw in ["FTP", "SMB", "NFS"]):
        return SVC_TYPE_NUM["FILE_TRANSFER"]

    return SVC_TYPE_NUM["OTHER"]


# ─────────────────────────────────────────────────────────────────────────────
#  Ordre STRICT des features — extrait du booster XGBoost (feature_names)
# ─────────────────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    'epss',
    'epss_log',
    'age_cve',
    'age_bucket',
    'ac_num',
    'pr_num',
    'ui_num',
    'host_type',
    'port',
    'svc_type_num',
    'port_is_web',
]

# Colonnes brutes minimales attendues dans le DataFrame en entrée
RAW_COLS_NEEDED = [
    'epss', 'age_cve', 'ac_num', 'pr_num', 'ui_num', 'host_type', 'port'
]


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Reproduit le feature engineering des nouveaux modèles classificateur_xgb.joblib
    et regresseur_xgb.joblib (11 features sans fuite de données).

    Toutes les colonnes manquantes sont imputées à 0.
    """
    out = df.copy()

    # Imputation des colonnes manquantes
    for col in RAW_COLS_NEEDED:
        if col not in out.columns:
            out[col] = 0.0
        out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0.0)

    # ── Features exploitabilité ───────────────────────────────────────────────
    # Log EPSS (distribution longue queue)
    out['epss_log']        = np.log1p(out['epss'])

    # ── Features temporelles ──────────────────────────────────────────────────
    # Tranche d'âge semestrielle (0–8)
    out['age_bucket']      = (out['age_cve'].clip(0, 9999) // 6).clip(0, 8).astype(int)

    # ── Features hôte / port ─────────────────────────────────────────────────
    port = out['port'].fillna(0).astype(int)

    # Type de service (0–4)
    out['svc_type_num']    = port.apply(lambda p: classify_service(p))

    # Flags booléens du port
    out['port_is_web']      = port.isin(PORTS_WEB).astype(int)

    return out[FEATURE_COLS]


def get_training_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Prépare X et y pour l'entraînement."""
    X = engineer_features(df)
    y = df['ops_risk_score'].copy() if 'ops_risk_score' in df.columns else df['risk_score'].copy()
    return X, y
