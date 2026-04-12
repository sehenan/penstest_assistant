"""
predict.py
==========
Inférence et discrétisation hybride : Score brut (régression) → Classe label.

Le modèle XGBoost entraîné sur NVD + CISA KEV + ExploitDB produit un
gold_risk_score continu [0–10] qui est ensuite converti en label métier.

Seuils de discrétisation (alignés CVSS v3) :
  ≥ 9.0  → Critique   (CRITICAL)
  ≥ 7.0  → Haut       (HIGH)
  ≥ 4.0  → Moyen      (MEDIUM)
  > 0.0  → Faible     (LOW)
  = 0.0  → Info
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd
from sqlalchemy.orm import Session

from app.db.models import ScoreML
from app.core.ml.features import FEATURE_COLS

logger = logging.getLogger(__name__)

MODEL_PATH = Path("data") / "model_xgb.joblib"


# ─────────────────────────────────────────────────────────────────────────────
#  Discrétisation du score continu
# ─────────────────────────────────────────────────────────────────────────────
def _score_to_label(score: float) -> str:
    """Convertit un gold_risk_score [0–10] en label métier."""
    if score >= 9.0:
        return "Critique"
    if score >= 7.0:
        return "Haut"
    if score >= 4.0:
        return "Moyen"
    if score > 0.0:
        return "Faible"
    return "Info"


# ─────────────────────────────────────────────────────────────────────────────
#  Préparation des features pour l'inférence
# ─────────────────────────────────────────────────────────────────────────────
def _prepare_inference_features(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """
    Aligne le DataFrame d'entrée sur les features attendues par le modèle.

    Colonnes requises (issues de features.FEATURE_COLS) :
        cvss_score, severity_num, port, is_public, has_exploit,
        in_cisa_kev, in_exploitdb, av_num, ac_num, pr_num, ui_num

    Les colonnes manquantes sont remplies avec 0 (valeur neutre/inconnue).
    """
    X = pd.DataFrame(index=df.index)
    for col in FEATURE_COLS:
        if col in df.columns:
            X[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        else:
            X[col] = 0
            logger.debug("Feature absente pour l'inférence, remplie à 0 : %s", col)
    return X[FEATURE_COLS]


# ─────────────────────────────────────────────────────────────────────────────
#  Inférence + écriture en base
# ─────────────────────────────────────────────────────────────────────────────
def predict_and_store(session: Session, df: pd.DataFrame) -> dict[str, int]:
    """
    Prédit le gold_risk_score pour chaque vulnérabilité et stocke le résultat
    dans la table ScoreML.

    Args:
        session: Session SQLAlchemy active.
        df:      DataFrame contenant au minimum les colonnes FEATURE_COLS
                 ET une colonne 'vuln_id'.

    Returns:
        dict {"scored": int, "failed": int}
    """
    stats: dict[str, int] = {"scored": 0, "failed": 0}

    if df is None or df.empty:
        logger.warning("predict_and_store : DataFrame vide, rien à scorer.")
        return stats

    if not MODEL_PATH.is_file():
        logger.error(
            "Modèle introuvable : %s\n"
            "Lancez d'abord : python -m app.core.ml.fetch_training_data",
            MODEL_PATH,
        )
        return stats

    try:
        pipeline = joblib.load(MODEL_PATH)
        logger.info("Modèle chargé : %s", MODEL_PATH)

        X = _prepare_inference_features(df)
        raw_scores = pipeline.predict(X)

        for idx, (_, row) in enumerate(df.iterrows()):
            score = float(raw_scores[idx])
            label = _score_to_label(score)

            vuln_id = int(row["vuln_id"])
            
            # Recherche d'un score existant pour cette vulnérabilité
            s_ml = session.query(ScoreML).filter(ScoreML.vuln_id == vuln_id).first()
            
            if s_ml:
                s_ml.score = round(score, 4)
                s_ml.label = label
                s_ml.timestamp = datetime.utcnow()
                logger.debug("Mise à jour du score pour vuln_id %d", vuln_id)
            else:
                s_ml = ScoreML(
                    vuln_id=vuln_id,
                    score=round(score, 4),
                    label=label,
                )
                session.add(s_ml)
                logger.debug("Nouveau score pour vuln_id %d", vuln_id)
            stats["scored"] += 1

        session.commit()
        logger.info("Scoring terminé — %d vulnérabilités scorées.", stats["scored"])

    except Exception as exc:
        logger.error("Erreur inférence ML : %s", exc, exc_info=True)
        session.rollback()
        stats["failed"] += 1

    return stats
