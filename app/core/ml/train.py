import logging
from pathlib import Path
from typing import Optional, Tuple, Dict

import joblib
import pandas as pd
from sklearn.metrics import mean_squared_error, r2_score, accuracy_score, f1_score
from sklearn.model_selection import train_test_split, RandomizedSearchCV, KFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor
import numpy as np

logger = logging.getLogger(__name__)

MODEL_DIR = Path("data") / "model"
MODEL_REG_PATH = MODEL_DIR / "xgb_regression.joblib"
MODEL_CLF_PATH = MODEL_DIR / "xgb_classification.joblib"
METRICS_PATH = Path("data") / "metrics_xgb.json"
IMPORTANCE_PATH = Path("data") / "feature_importance.csv"

def _get_categorical_labels(y: pd.Series) -> pd.Series:
    """Discrétisation pour risk_score [0-1] en classes."""
    bins = [-0.01, 0.0, 0.35, 0.55, 0.8, 1.01]
    labels = ["Info", "Faible", "Moyen", "Haut", "Critique"]
    return pd.cut(y, bins=bins, labels=labels)

def train_and_save_model(
    X: pd.DataFrame, 
    y: pd.Series, 
    optimize: bool = False,
    validation_data: Optional[Tuple[pd.DataFrame, pd.Series]] = None
) -> dict:
    """
    Entraîne le pipeline XGBoost avec support Early Stopping, HPO et Cross-Validation.
    """
    if X is None or (hasattr(X, "empty") and X.empty):
        logger.warning("Aucune donnée d'entraînement disponible.")
        return {}

    logger.info("Entraînement XGBoost — %d échantillons, %d features", len(X), X.shape[1])
    logger.info("Features utilisées : %s", list(X.columns))

    # 1. Split Training / Internal Validation
    if validation_data:
        X_train, y_train = X, y
        X_val, y_val = validation_data
    else:
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.15, random_state=42
        )

    # 2. Pipeline de base
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("xgb", XGBRegressor(
            objective="reg:squarederror",
            random_state=42,
            verbosity=0,
            n_estimators=1000,
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
        search.fit(X_train, y_train)
        pipeline = search.best_estimator_
        logger.info("✅ Meilleurs paramètres : %s", search.best_params_)
    else:
        pipeline.set_params(
            xgb__learning_rate=0.05,
            xgb__max_depth=6,
            xgb__subsample=0.9,
            xgb__colsample_bytree=0.9,
        )

    # 3. Cross-Validation (Preuve de robustesse)
    logger.info("📊 Calcul de la Cross-Validation (3-Fold)...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=3, scoring="neg_mean_squared_error")
    cv_rmse = np.sqrt(-cv_scores).mean()

    # 4. Fit final avec Early Stopping
    scaler = pipeline.named_steps["scaler"]
    scaler.fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    xgb_model = pipeline.named_steps["xgb"]
    xgb_model.set_params(early_stopping_rounds=20)
    xgb_model.fit(
        X_train_scaled, y_train,
        eval_set=[(X_val_scaled, y_val)],
        verbose=False
    )

    # 5. Évaluation multi-métriques
    y_pred = xgb_model.predict(X_val_scaled)
    rmse = float(np.sqrt(mean_squared_error(y_val, y_pred)))
    r2 = float(r2_score(y_val, y_pred))

    # Métriques catégorielles (Preuve PFE)
    y_val_cat = _get_categorical_labels(y_val)
    y_pred_cat = _get_categorical_labels(pd.Series(y_pred))
    acc = accuracy_score(y_val_cat, y_pred_cat)
    f1 = f1_score(y_val_cat, y_pred_cat, average="weighted")

    logger.info("─" * 45)
    logger.info("RÉSULTATS DE L'ENTRAÎNEMENT")
    logger.info("RMSE (Validation)      : %.4f", rmse)
    logger.info("RMSE (Cross-Val mean)  : %.4f", cv_rmse)
    logger.info("R²   (Validation)      : %.4f", r2)
    logger.info("Accuracy (Classes)     : %.4f (Précision de classification)", acc)
    logger.info("F1-Score (Weighted)    : %.4f", f1)
    logger.info("─" * 45)

    # 6. Sauvegarde
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_REG_PATH)
    
    importances = pd.DataFrame({
        "feature": X.columns,
        "importance": xgb_model.feature_importances_
    }).sort_values(by="importance", ascending=False)
    importances.to_csv(IMPORTANCE_PATH, index=False)
    
    results = {
        "rmse": rmse, 
        "cv_rmse": cv_rmse,
        "r2": r2, 
        "accuracy": acc,
        "f1_score": f1,
        "best_iteration": int(xgb_model.best_iteration),
        "timestamp": pd.Timestamp.now().isoformat(),
        "n_samples": len(X)
    }
    
    # On sauvegarde aussi en JSON pour le frontend
    import json
    with open(METRICS_PATH, "w") as f:
        json.dump(results, f, indent=4)
    
    return results

if __name__ == "__main__":
    import logging
    from app.core.ml.data_manager import TRAIN_SET_PATH, get_prepared_features
    
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    if not TRAIN_SET_PATH.exists():
        print(f"Dataset non trouvé : {TRAIN_SET_PATH}. Lancez data_manager.py d'abord.")
    else:
        X, y = get_prepared_features(TRAIN_SET_PATH)
        train_and_save_model(X, y, optimize=False)
