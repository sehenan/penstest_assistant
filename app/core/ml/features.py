"""
Feature Engineering & Data Alignment.
Version 6 - Alignée sur les modèles classificateur_xgb.joblib / regresseur_xgb.joblib.

Les 31 features exactes ont été extraites du message d'erreur XGBoost
(feature_names mismatch) lors du chargement des modèles.

Features CVE (17) :
    cvss_score, severity_num, av_num, ac_num, pr_num, ui_num,
    cvss_sq, severity_x_av, attack_surface, network_no_auth, ui_penalty,
    is_exploited, epss, epss_log, epss_kev, age_cve, age_bucket

Features Hôte/Port (14) :
    port, svc_type_num, is_public, host_type, host_criticality,
    port_is_highrisk, port_is_critical, port_is_db, port_is_web,
    public_and_network, public_and_exploit, public_critical_port,
    db_exposed, host_x_cvss
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
    # CVE / CVSS
    'cvss_score', 'severity_num', 'av_num', 'ac_num', 'pr_num', 'ui_num',
    # Features CVE construites
    'cvss_sq', 'severity_x_av', 'attack_surface', 'network_no_auth', 'ui_penalty',
    # Exploitabilité
    'is_exploited', 'epss', 'epss_log', 'epss_kev',
    # Temporel
    'age_cve', 'age_bucket',
    # Hôte / Port
    'port', 'svc_type_num', 'is_public', 'host_type', 'host_criticality',
    # Flags port
    'port_is_highrisk', 'port_is_critical', 'port_is_db', 'port_is_web',
    # Features croisées hôte × CVE
    'public_and_network', 'public_and_exploit', 'public_critical_port',
    'db_exposed', 'host_x_cvss',
]

# Colonnes brutes minimales attendues dans le DataFrame en entrée
RAW_COLS_NEEDED = [
    'cvss_score', 'severity_num', 'av_num', 'ac_num', 'pr_num', 'ui_num',
    'is_exploited', 'age_cve', 'epss',
    'port', 'is_public', 'host_type', 'host_criticality',
]


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Reproduit le feature engineering des modèles classificateur_xgb.joblib
    et regresseur_xgb.joblib (31 features).

    Colonnes brutes attendues :
        cvss_score, severity_num, av_num, ac_num, pr_num, ui_num,
        is_exploited, age_cve, epss,
        port, is_public, host_type, host_criticality

    Toutes les colonnes manquantes sont imputées à 0.

    Encodages CVSS :
        av_num  : Physical=1, Local=2, Adjacent=3, Network=4
        ac_num  : High=1, Low=2
        pr_num  : None=0, Low=1, High=2
        ui_num  : Required=0, None=1
    """
    out = df.copy()

    # Imputation des colonnes manquantes
    for col in RAW_COLS_NEEDED:
        if col not in out.columns:
            out[col] = 0.0
        out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0.0)

    # ── Features CVE construites ──────────────────────────────────────────────

    # Non-linéarité sévérité CVSS
    out['cvss_sq']         = (out['cvss_score'] / 10.0) ** 2

    # Interaction sévérité × vecteur d'attaque
    out['severity_x_av']   = out['severity_num'] * out['av_num']

    # Surface d'attaque normalisée [0,1]
    av_norm  = (out['av_num'] - 1) / 3.0             # [0,1]
    ac_ease  = (out['ac_num'] - 1) / 1.0             # ac_num ∈ {1,2}
    pr_ease  = 1.0 - out['pr_num'] / 2.0             # pr_num ∈ {0,1,2}
    out['attack_surface']  = (av_norm * 0.5 + ac_ease * 0.3 + pr_ease * 0.2).clip(0, 1)

    # Réseau sans authentification : av=4 (Network) & pr=0 (None)
    out['network_no_auth'] = ((out['av_num'] == 4) & (out['pr_num'] == 0)).astype(int)

    # Pénalité interaction utilisateur requise (ui_num=0 → requise)
    out['ui_penalty']      = (out['ui_num'] == 0).astype(int)

    # ── Features exploitabilité ───────────────────────────────────────────────

    # Log EPSS (distribution longue queue)
    out['epss_log']        = np.log1p(out['epss'])

    # EPSS pondéré KEV
    out['epss_kev']        = out['epss'] * (1.0 + out['is_exploited'])

    # ── Features temporelles ──────────────────────────────────────────────────

    # Tranche d'âge semestrielle (0–8)
    out['age_bucket']      = (out['age_cve'].clip(0, 9999) // 6).clip(0, 8).astype(int)

    # ── Features hôte / port ─────────────────────────────────────────────────

    port = out['port'].fillna(0).astype(int)

    # Type de service (0–4)
    out['svc_type_num']    = port.apply(lambda p: classify_service(p))

    # Flags booléens du port
    out['port_is_highrisk'] = port.isin(PORTS_HIGHRISK).astype(int)
    out['port_is_critical'] = port.isin(PORTS_CRITICAL).astype(int)
    out['port_is_db']       = port.isin(PORTS_DB).astype(int)
    out['port_is_web']      = port.isin(PORTS_WEB).astype(int)

    # ── Features croisées hôte × CVE ─────────────────────────────────────────

    is_public  = out['is_public'].clip(0, 1)
    is_network = (out['av_num'] == 4).astype(int)

    # IP publique + vecteur réseau
    out['public_and_network']   = (is_public * is_network)

    # IP publique + CVE exploitée
    out['public_and_exploit']   = (is_public * out['is_exploited'])

    # IP publique + port critique
    out['public_critical_port'] = (is_public * out['port_is_critical'])

    # BD exposée (port DB + pas d'authentification requise)
    out['db_exposed']           = (out['port_is_db'] * (out['pr_num'] == 0).astype(int))

    # Criticité hôte × CVSS normalisé
    out['host_x_cvss']          = out['host_criticality'] * (out['cvss_score'] / 10.0)

    return out[FEATURE_COLS]


def get_training_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Prépare X et y pour l'entraînement."""
    X = engineer_features(df)
    y = df['ops_risk_score'].copy() if 'ops_risk_score' in df.columns else df['risk_score'].copy()
    return X, y
