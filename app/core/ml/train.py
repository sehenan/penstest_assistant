"""
Entraînement du modèle hybride (XGBoost + Scaler).
Le modèle produit un score brut (régression continue).
"""
import logging
from pathlib import Path

import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor

logger = logging.getLogger(__name__)

MODEL_PATH = Path("data") / "model_xgb.joblib"


def train_and_save_model(X, y) -> None:
    """Entraîne et sauvegarde le pipeline."""
    if X.empty:
        logger.warning("Aucune donnée d'entraînement disponible.")
        return
        
    logger.info("Entraînement XGBoost sur %d exemples...", len(X))
    
    # Validation basique
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('xgb', XGBRegressor(
            n_estimators=100, 
            learning_rate=0.1, 
            max_depth=4, 
            objective='reg:squarederror'
        ))
    ])
    
    pipeline.fit(X, y)
    
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    logger.info("Modèle sauvegardé dans %s", MODEL_PATH)
