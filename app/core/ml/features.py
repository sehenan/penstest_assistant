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
