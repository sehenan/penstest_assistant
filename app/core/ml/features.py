"""
Feature Engineering & Data Augmentation.

Stratégie 'Officielle + Hybride' :
1. Chargement prioritaire depuis data/nvd_training_data.csv
   (données NVD/NIST + CISA KEV + ExploitDB via fetch_training_data.py).
2. Fallback : extraction des données SQL locales (scans ingérés).
3. Augmentation contrôlée KS-test uniquement si dataset < seuil minimal.

Features utilisées pour l'entraînement XGBoost :
  cvss_score, severity_num, port, is_public, has_exploit,
  in_cisa_kev, in_exploitdb,
  av_num (attackVector encodé), ac_num (attackComplexity encodé),
  pr_num (privilegesRequired encodé), ui_num (userInteraction encodé)
"""
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Exploit, Service, Vulnerability

logger = logging.getLogger(__name__)

NVD_CSV_PATH = Path("data") / "nvd_training_data.csv"

# ─────────────────────────────────────────────────────────────────────────────
#  Tables d'encodage des métriques CVSS
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_NUM: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0,
}

# attackVector : réseau = plus risqué
AV_NUM: dict[str, int] = {
    "NETWORK":          4,   # N
    "N":                4,
    "ADJACENT":         3,   # A
    "ADJACENT_NETWORK": 3,
    "A":                3,
    "LOCAL":            2,   # L
    "L":                2,
    "PHYSICAL":         1,   # P
    "P":                1,
    "UNKNOWN":          0,
}

# attackComplexity : LOW = plus facile à exploiter
AC_NUM: dict[str, int] = {
    "LOW":     2, "L": 2,
    "MEDIUM":  1, "M": 1,   # CVSSv2
    "HIGH":    0, "H": 0,
    "UNKNOWN": 0,
}

# privilegesRequired : NONE = pas besoin d'auth
PR_NUM: dict[str, int] = {
    "NONE":    2, "N": 2,
    "LOW":     1, "L": 1,
    "HIGH":    0, "H": 0,
    "UNKNOWN": 0,
}

# userInteraction : NONE = pas besoin de l'utilisateur
UI_NUM: dict[str, int] = {
    "NONE":     1, "N": 1,
    "REQUIRED": 0, "R": 0,
    "UNKNOWN":  0,
}

# Features exportées vers XGBoost
FEATURE_COLS = [
    "cvss_score",
    "severity_num",
    "port",
    "is_public",
    "has_exploit",
    "in_cisa_kev",
    "in_exploitdb",
    "av_num",
    "ac_num",
    "pr_num",
    "ui_num",
]


# ─────────────────────────────────────────────────────────────────────────────
#  Source officielle (CSV NVD + CISA KEV + ExploitDB)
# ─────────────────────────────────────────────────────────────────────────────
def load_official_data() -> pd.DataFrame:
    """
    Charge les données officielles depuis data/nvd_training_data.csv
    généré par fetch_training_data.py.

    Encode les colonnes catégorielles CVSS en valeurs numériques et
    ajoute les colonnes manquantes avec 0 pour la rétrocompatibilité.

    Returns:
        DataFrame enrichi prêt pour get_training_features(),
        ou DataFrame vide si le CSV est absent.
    """
    if not NVD_CSV_PATH.exists():
        logger.warning(
            "CSV NVD introuvable (%s). "
            "Lancez : python -m app.core.ml.fetch_training_data",
            NVD_CSV_PATH,
        )
        return pd.DataFrame()

    df = pd.read_csv(NVD_CSV_PATH)

    required = {"cvss_score", "port", "has_exploit", "gold_risk_score"}
    missing  = required - set(df.columns)
    if missing:
        logger.error("Colonnes manquantes dans le CSV NVD : %s", missing)
        return pd.DataFrame()

    # ── Nettoyage numérique de base ──
    df["cvss_score"]  = pd.to_numeric(df["cvss_score"],  errors="coerce").fillna(5.0)
    df["port"]        = pd.to_numeric(df["port"],        errors="coerce").fillna(0).astype(int)
    df["has_exploit"] = df["has_exploit"].fillna(0).astype(int)
    df["is_public"]   = df["is_public"].fillna(0).astype(int) if "is_public" in df.columns else 0

    # ── Sévérité ──
    df["severity"]     = df["severity"].fillna("UNKNOWN").str.upper() if "severity" in df.columns else "UNKNOWN"
    df["severity_num"] = df["severity"].map(SEVERITY_NUM).fillna(0).astype(int)

    # ── Colonnes KEV / ExploitDB (rétrocompatibilité) ──
    df["in_cisa_kev"]  = df["in_cisa_kev"].fillna(0).astype(int)  if "in_cisa_kev"  in df.columns else 0
    df["in_exploitdb"] = df["in_exploitdb"].fillna(0).astype(int) if "in_exploitdb" in df.columns else 0

    # ── Encodage des métriques CVSS en numériques ──
    for col, table in [
        ("attackVector",       AV_NUM),
        ("attackComplexity",   AC_NUM),
        ("privilegesRequired", PR_NUM),
        ("userInteraction",    UI_NUM),
    ]:
        target = col.replace("attack", "a").replace("Vector", "v").replace(
            "Complexity", "c").replace("privileges", "p").replace(
            "Required", "r").replace("user", "u").replace("Interaction", "i") + "_num"
        # Noms attendus : av_num, ac_num, pr_num, ui_num
        target = {
            "attackVector":       "av_num",
            "attackComplexity":   "ac_num",
            "privilegesRequired": "pr_num",
            "userInteraction":    "ui_num",
        }[col]
        if col in df.columns:
            df[target] = df[col].fillna("UNKNOWN").str.upper().map(table).fillna(0).astype(int)
        else:
            df[target] = 0

    df["is_synth"] = 0  # données officielles = non synthétiques

    n_positive = (df["has_exploit"] == 1).sum()
    n_kev      = (df.get("in_cisa_kev",  pd.Series(dtype=int)) == 1).sum()
    n_edb      = (df.get("in_exploitdb", pd.Series(dtype=int)) == 1).sum()

    logger.info(
        "✅ %d CVEs NVD chargés — positifs: %d  (KEV: %d | ExploitDB: %d)",
        len(df), n_positive, n_kev, n_edb,
    )
    return df


# ─────────────────────────────────────────────────────────────────────────────
#  Source locale (DB SQLite — scans ingérés)
# ─────────────────────────────────────────────────────────────────────────────
def extract_real_data(session: Session) -> pd.DataFrame:
    """Consolide la vérité terrain depuis les scans ingérés (DB locale)."""
    query = (
        select(
            Vulnerability.id.label("vuln_id"),
            Vulnerability.cve,
            Vulnerability.cvss_score,
            Service.port,
            Service.service,
            Exploit.disponible.label("has_exploit"),
        )
        .join(Service, Vulnerability.service_id == Service.id)
        .outerjoin(Exploit, Vulnerability.cve == Exploit.cve)
    )

    rows = session.execute(query).fetchall()
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    df["cvss_score"]  = df["cvss_score"].fillna(
        df["cvss_score"].median() if not df["cvss_score"].isna().all() else 5.0
    )
    df["has_exploit"] = df["has_exploit"].fillna(False).astype(int)

    public_ports      = {80, 443, 8080, 8443, 22, 445}
    df["is_public"]   = df["port"].isin(public_ports).astype(int)

    # Gold risk score
    df["gold_risk_score"] = np.clip(
        df["cvss_score"] + df["has_exploit"] * 1.5 + df["is_public"] * 0.5,
        0.0, 10.0
    )

    # Colonnes absentes depuis la DB locale → remplir avec 0
    for col in ["severity_num", "in_cisa_kev", "in_exploitdb", "av_num", "ac_num", "pr_num", "ui_num"]:
        df[col] = 0

    return df


# ─────────────────────────────────────────────────────────────────────────────
#  Augmentation (uniquement si dataset insuffisant)
# ─────────────────────────────────────────────────────────────────────────────
def augment_data(real_df: pd.DataFrame, target_size: int = 500) -> pd.DataFrame:
    """
    Augmentation par re-échantillonnage + bruit gaussien sur cvss_score.
    N'est activée que si len(real_df) < target_size (pas utile avec NVD).
    Inclut une validation KS-test proxy pour détecter les dérives.
    """
    if real_df.empty:
        return real_df

    n_real = len(real_df)
    if n_real >= target_size:
        logger.info("Augmentation désactivée — %d échantillons suffisants.", n_real)
        return real_df.copy()

    n_synth  = target_size - n_real
    synth_df = real_df.sample(n=n_synth, replace=True, random_state=42).copy()

    noise = np.random.default_rng(42).normal(0, 0.5, size=n_synth)
    synth_df["cvss_score"] = np.clip(synth_df["cvss_score"] + noise, 0.0, 10.0)
    synth_df["gold_risk_score"] = np.clip(
        synth_df["cvss_score"]
        + synth_df["has_exploit"] * 1.5
        + synth_df["is_public"]   * 0.5,
        0.0, 10.0,
    )

    # KS-test proxy (sans scipy)
    sorted_real  = np.sort(real_df["cvss_score"].values)
    sorted_synth = np.sort(synth_df["cvss_score"].values)
    all_vals     = np.concatenate([sorted_real, sorted_synth])
    cdf1 = np.searchsorted(sorted_real,  all_vals, side="right") / len(sorted_real)
    cdf2 = np.searchsorted(sorted_synth, all_vals, side="right") / len(sorted_synth)
    ks_stat = float(np.max(np.abs(cdf1 - cdf2)))

    logger.info("Augmentation KS-stat: %.3f (%d→%d échantillons)", ks_stat, n_real, target_size)
    if ks_stat > 0.3:
        logger.warning("Distribution synthétique déviée (KS=%.3f > 0.3).", ks_stat)

    real_df  = real_df.copy()
    real_df["is_synth"]  = 0
    synth_df["is_synth"] = 1

    return pd.concat([real_df, synth_df], ignore_index=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Préparation des features pour XGBoost
# ─────────────────────────────────────────────────────────────────────────────
def get_training_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """
    Retourne (X, y) prêts pour l'entraînement XGBoost.

    Features sélectionnées (ordre stable) :
      cvss_score   – Score CVSS réel (0–10)
      severity_num – Sévérité encodée (CRITICAL=4 … UNKNOWN=0)
      port         – Port réseau (0 = inconnu)
      is_public    – 1 si port exposé publiquement
      has_exploit  – 1 si exploit confirmé (KEV ou ExploitDB ou règle NVD)
      in_cisa_kev  – 1 si CVE dans CISA KEV (exploitée en prod)
      in_exploitdb – 1 si CVE avec PoC public ExploitDB
      av_num       – attackVector encodé (NETWORK=4 … PHYSICAL=1)
      ac_num       – attackComplexity encodé (LOW=2, HIGH=0)
      pr_num       – privilegesRequired encodé (NONE=2, HIGH=0)
      ui_num       – userInteraction encodé (NONE=1, REQUIRED=0)

    Cible (y) :
      gold_risk_score – Score de risque continu [0–10]
    """
    available = [col for col in FEATURE_COLS if col in df.columns]
    missing   = set(FEATURE_COLS) - set(available)
    if missing:
        logger.debug("Features absentes (remplies à 0) : %s", missing)
        for col in missing:
            df[col] = 0

    X = df[FEATURE_COLS].copy().fillna(0)
    y = df["gold_risk_score"].copy()
    return X, y
