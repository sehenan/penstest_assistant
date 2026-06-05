"""
predict.py
==========
Inférence avec les modèles XGBoost v2.
Modèles : classificateur_xgb.joblib (CalibratedClassifierCV) + regresseur_xgb.joblib (XGBRegressor)
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.db.models import ScoreML
from app.core.ml.features import FEATURE_COLS, engineer_features

logger = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────────
# CHEMINS DES MODÈLES
# ───────────────────────────────────────────────────────────────
MODEL_REG_PATH = Path("data") / "model" / "regresseur_xgb.joblib"
MODEL_CLF_PATH = Path("data") / "model" / "classificateur_xgb.joblib"

# ───────────────────────────────────────────────────────────────
# MAPPING LABELS
# Train.py v2 : 0=Low, 1=Medium, 2=High, 3=Critical
# (quantiles adaptatifs  q25/q60/q88 de ops_risk_score)
# ───────────────────────────────────────────────────────────────
LABEL_MAP = {0: "Faible", 1: "Moyenne", 2: "Haute", 3: "Critique"}

def _score_to_label(score: float) -> str:
    """Convertit un ops_risk_score [0–1] en label métier (fallback régresseur)."""
    if score >= 0.75:
        return "Critique"
    if score >= 0.50:
        return "Haute"
    if score >= 0.25:
        return "Moyenne"
    return "Faible"


def _generate_reasoning(row: pd.Series, score: float, label: str) -> str:
    """Génère une explication textuelle basée sur les features critiques."""
    reasons = []

    if row.get("is_exploited", 0) == 1:
        reasons.append("Exploitation active détectée (KEV)")
    if row.get("cvss_score", 0) >= 9.0:
        reasons.append(f"CVSS critique ({row.get('cvss_score', 0):.1f})")
    elif row.get("cvss_score", 0) >= 7.0:
        reasons.append(f"CVSS élevé ({row.get('cvss_score', 0):.1f})")
    if row.get("epss", 0) > 0.5:
        reasons.append(f"EPSS très élevé ({row.get('epss', 0):.2f})")
    elif row.get("epss", 0) > 0.1:
        reasons.append(f"Probabilité d'exploitation significative (EPSS={row.get('epss', 0):.2f})")
    # pr_num=0 → None (aucun privilège requis) dans l'encodage v2
    if row.get("av_num", 0) == 4 and row.get("pr_num", 0) == 0:
        reasons.append("Accessible à distance sans authentification")
    if row.get("age_cve", 999) <= 6:
        reasons.append("CVE récente (< 6 mois)")

    if not reasons:
        return f"Priorité {label}. Score ops_risk={score:.3f} basé sur les métriques standards."

    return f"Priorité {label}. Facteurs clés : {', '.join(reasons)}. Score ops_risk={score:.3f}."

def predict_and_store(session: Session, df: pd.DataFrame) -> dict[str, int]:
    """
    Exécute l'inférence et stocke les résultats.
    """
    stats = {"scored": 0, "failed": 0}

    if df.empty:
        return stats

    if not MODEL_REG_PATH.exists() or not MODEL_CLF_PATH.exists():
        logger.error(f"Modèles manquants dans {MODEL_REG_PATH.parent}")
        return stats

    try:
        model_reg = joblib.load(MODEL_REG_PATH)
        model_clf = joblib.load(MODEL_CLF_PATH)

        # 1. Feature Engineering (Logique v4)
        X = engineer_features(df)

        # 2. Prédictions
        raw_scores = model_reg.predict(X)
        raw_labels = model_clf.predict(X)
        clf_probas = model_clf.predict_proba(X)

        # 3. Stockage
        for idx, (_, row) in enumerate(df.iterrows()):
            score_v4 = float(raw_scores[idx])
            label_num = int(raw_labels[idx])
            label_str = LABEL_MAP.get(label_num, "Moyenne")
            confidence = float(np.max(clf_probas[idx]))
            
            # Le nouveau modèle prédit directement un score sur 10 (cvss_score)
            display_score = round(score_v4, 1)
            
            vuln_id = int(row["vuln_id"])
            s_ml = session.query(ScoreML).filter(ScoreML.vuln_id == vuln_id).first()

            reasoning = _generate_reasoning(row, score_v4, label_str)

            if s_ml:
                s_ml.score = display_score
                s_ml.label = label_str
                s_ml.reasoning = reasoning
                s_ml.confidence = round(confidence, 4)
                s_ml.timestamp = datetime.utcnow()
            else:
                s_ml = ScoreML(
                    vuln_id=vuln_id,
                    score=display_score,
                    label=label_str,
                    reasoning=reasoning,
                    confidence=round(confidence, 4)
                )
                session.add(s_ml)
            
            stats["scored"] += 1

        session.commit()
        logger.info(f"Scoring ML terminé : {stats['scored']} vulns traitées.")

    except Exception as e:
        logger.error(f"Erreur pendant l'inférence ML : {e}", exc_info=True)
        session.rollback()
        stats["failed"] += 1

    return stats
