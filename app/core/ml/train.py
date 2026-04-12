import logging
from pathlib import Path

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

def train_and_save_model(X: pd.DataFrame, y: pd.Series, optimize: bool = False) -> dict:
    """
    Entraîne le pipeline XGBoost (avec option d'optimisation HPO) et le sauvegarde.

    Args:
        X: DataFrame de features.
        y: Series gold_risk_score.
        optimize: Si True, lance une recherche d'hyperparamètres (RandomizedSearchCV).

    Returns:
        dict avec les métriques et meilleurs paramètres.
    """
    if X is None or (hasattr(X, "empty") and X.empty):
        logger.warning("Aucune donnée d'entraînement disponible.")
        return {}

    n_samples = len(X)
    logger.info("Entraînement XGBoost — %d échantillons, %d features", n_samples, X.shape[1])
    logger.info("Features : %s", list(X.columns))

    # Split 80/20 pour évaluation finale
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Pipeline de base
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("xgb", XGBRegressor(
            objective="reg:squarederror",
            random_state=42,
            verbosity=0,
        )),
    ])

    if optimize:
        logger.info("🚀 Lancement de l'optimisation HPO (RandomizedSearchCV)...")
        # Grille de recherche étendue pour un modèle "puissant"
        param_dist = {
            "xgb__n_estimators": [100, 200, 500, 1000],
            "xgb__learning_rate": [0.01, 0.05, 0.1, 0.2],
            "xgb__max_depth": [3, 4, 5, 6, 8],
            "xgb__subsample": [0.7, 0.8, 0.9, 1.0],
            "xgb__colsample_bytree": [0.7, 0.8, 0.9, 1.0],
            "xgb__gamma": [0, 0.1, 0.2],
        }
        
        # Validation croisée 5-folds pour la robustesse
        cv = KFold(n_splits=5, shuffle=True, random_state=42)
        
        search = RandomizedSearchCV(
            pipeline, 
            param_distributions=param_dist,
            n_iter=20,  # 20 itérations pour un bon compromis temps/qualité
            cv=cv,
            scoring="neg_mean_squared_error",
            verbose=1,
            random_state=42,
            n_jobs=-1
        )
        search.fit(X_train, y_train)
        
        logger.info("✅ Meilleurs paramètres trouvés : %s", search.best_params_)
        pipeline = search.best_estimator_
    else:
        # Paramètres par défaut "solides"
        pipeline.set_params(
            xgb__n_estimators=200,
            xgb__learning_rate=0.08,
            xgb__max_depth=5,
            xgb__subsample=0.85,
            xgb__colsample_bytree=0.85,
        )
        pipeline.fit(X_train, y_train)

    # Évaluation sur le set de test
    y_pred = pipeline.predict(X_test)
    rmse   = float(np.sqrt(mean_squared_error(y_test, y_pred)))
    r2     = float(r2_score(y_test, y_pred))

    logger.info("─" * 40)
    logger.info("RMSE  : %.4f", rmse)
    logger.info("R²    : %.4f", r2)
    logger.info("Train : %d   Test : %d", len(X_train), len(X_test))
    logger.info("─" * 40)

    # Sauvegarde du modèle
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    
    # Export de l'importance des caractéristiques (utile pour le Dashboard)
    xgb_model = pipeline.named_steps["xgb"]
    importances = pd.DataFrame({
        "feature": X.columns,
        "importance": xgb_model.feature_importances_
    }).sort_values(by="importance", ascending=False)
    importances.to_csv(IMPORTANCE_PATH, index=False)
    
    logger.info("💾 Modèle sauvegardé → %s", MODEL_PATH)
    logger.info("📊 Importance des features → %s", IMPORTANCE_PATH)

    results = {
        "rmse": rmse, 
        "r2": r2, 
        "n_train": len(X_train), 
        "n_test": len(X_test),
        "params": pipeline.named_steps["xgb"].get_params()
    }
    # Sauvegarde des métriques pour référence rapide
    joblib.dump(results, METRICS_PATH)
    
    return results
