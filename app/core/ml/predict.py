"""
Inférence et discretisation hybride (Score Brut -> Classe Label).
"""
import logging
from pathlib import Path

import joblib
import pandas as pd
from sqlalchemy.orm import Session

from app.db.models import ScoreML

logger = logging.getLogger(__name__)

MODEL_PATH = Path("data") / "model_xgb.joblib"


def _score_to_label(score: float) -> str:
    """Discretisation hybride ancrée avec seuils métiers."""
    if score >= 9.0: return "Critique"
    if score >= 7.0: return "Haut"
    if score >= 4.0: return "Moyen"
    if score > 0.0:  return "Faible"
    return "Info"


def predict_and_store(session: Session, df: pd.DataFrame) -> dict[str, int]:
    """Score les nouvelles vulnérabilités et les enregistre en base."""
    stats = {"scored": 0, "failed": 0}
    if df.empty:
        return stats
        
    if not MODEL_PATH.is_file():
        logger.error("Modèle introuvable : %s. Impossible de scorer la BDD.", MODEL_PATH)
        return stats
        
    try:
        pipeline = joblib.load(MODEL_PATH)
        
        # Préparation des X pour prédiction
        features = ['cvss_score', 'port', 'is_public', 'has_exploit']
        X = df[features].copy()
        raw_scores = pipeline.predict(X)
        
        for idx, (_, row) in enumerate(df.iterrows()):
            score = float(raw_scores[idx])
            label = _score_to_label(score)
            
            s_ml = ScoreML(
                vuln_id=row['vuln_id'],
                score=score,
                label=label
            )
            session.add(s_ml)
            stats["scored"] += 1
            
        session.commit()
    except Exception as e:
        logger.error("Erreur lors de l'inférence ML : %s", e)
        session.rollback()
        stats["failed"] += 1
        
    return stats
