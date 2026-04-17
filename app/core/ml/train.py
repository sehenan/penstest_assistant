import logging
from pathlib import Path
from typing import Optional, Tuple

import joblib
import pandas as pd
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.model_selection import train_test_split, RandomizedSearchCV, KFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor
import numpy as np

logger = logging.getLogger(__name__)

MODEL_PATH = Path("data") / "model_xgb.joblib"
METRICS_PATH = Path("data") / "metrics_xgb.joblib"
IMPORTANCE_PATH = Path("data") / "feature_importance.csv"

def train_and_save_model(
    X: pd.DataFrame, 
    y: pd.Series, 
    optimize: bool = False,
    validation_data: Optional[Tuple[pd.DataFrame, pd.Series]] = None
) -> dict:
    """
    Entraîne le pipeline XGBoost avec support Early Stopping et HPO.
    """
    if X is None or (hasattr(X, "empty") and X.empty):
        logger.warning("Aucune donnée d'entraînement disponible.")
        return {}

    logger.info("Entraînement XGBoost — %d échantillons, %d features", len(X), X.shape[1])

    # 1. Split interne si non fourni (Cross-Validation interne)
    if validation_data:
        X_train, y_train = X, y
        X_val, y_val = validation_data
    else:
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.15, random_state=42
        )

    # 2. Pipeline de base
    # Note: On laisse le scaler dans le pipeline pour l'inférence facile
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("xgb", XGBRegressor(
            objective="reg:squarederror",
            random_state=42,
            verbosity=0,
            n_estimators=1000,  # Augmenté car Early Stopping va interrompre
            early_stopping_rounds=20,  # Arrêt si pas de progrès sur 20 rounds
        )),
    ])

    if optimize:
        logger.info("🚀 Lancement de l'optimisation HPO (RandomizedSearchCV)...")
        param_dist = {
            "xgb__n_estimators": [500, 1000],
            "xgb__learning_rate": [0.01, 0.05, 0.1],
            "xgb__max_depth": [4, 6, 8],
            "xgb__subsample": [0.8, 0.9, 1.0],
            "xgb__colsample_bytree": [0.8, 0.9, 1.0],
        }
        
        cv = KFold(n_splits=3, shuffle=True, random_state=42)
        search = RandomizedSearchCV(
            pipeline, 
            param_distributions=param_dist,
            n_iter=15,
            cv=cv,
            scoring="neg_mean_squared_error",
            verbose=1,
            random_state=42,
            n_jobs=-1
        )
        
        # Le fit du search ne supporte pas bien l'eval_set global pour chaque fold
        # donc on le fait sans early stopping pour la recherche pure
        search.fit(X_train, y_train)
        pipeline = search.best_estimator_
        logger.info("✅ Meilleurs paramètres : %s", search.best_params_)
    else:
        # Hyperparamètres "Pro" par défaut
        pipeline.set_params(
            xgb__learning_rate=0.05,
            xgb__max_depth=6,
            xgb__subsample=0.9,
            xgb__colsample_bytree=0.9,
        )

    # 3. Fit final avec Early Stopping sur le set de validation
    # On transforme X_val avec le scaler du pipeline manuellement pour eval_set
    scaler = pipeline.named_steps["scaler"]
    scaler.fit(X_train) # On scale sur le train complet
    X_train_scaled = scaler.transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    xgb_model = pipeline.named_steps["xgb"]
    xgb_model.fit(
        X_train_scaled, y_train,
        eval_set=[(X_val_scaled, y_val)],
        verbose=False
    )

    # 4. Évaluation sur le set de validation
    y_pred = xgb_model.predict(X_val_scaled)
    rmse = float(np.sqrt(mean_squared_error(y_val, y_pred)))
    r2 = float(r2_score(y_val, y_pred))

    logger.info("─" * 40)
    logger.info("RMSE Validation : %.4f", rmse)
    logger.info("R² Validation   : %.4f", r2)
    logger.info("Meilleure Iteration : %d", xgb_model.best_iteration)
    logger.info("─" * 40)

    # 5. Sauvegarde
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    
    # Feature Importance
    importances = pd.DataFrame({
        "feature": X.columns,
        "importance": xgb_model.feature_importances_
    }).sort_values(by="importance", ascending=False)
    importances.to_csv(IMPORTANCE_PATH, index=False)
    
    results = {
        "rmse": rmse, 
        "r2": r2, 
        "best_iteration": xgb_model.best_iteration,
        "params": xgb_model.get_params()
    }
    joblib.dump(results, METRICS_PATH)
    
    return results
