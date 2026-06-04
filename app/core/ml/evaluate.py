"""
evaluate.py
===========
Script autonome d'évaluation du modèle XGBoost.
Génère 6 graphiques de performance pour le mémoire PFE.

Graphiques produits dans data/evaluation/ :
  01_actual_vs_predicted.png   — Scatter prédictions vs vérité terrain
  02_feature_importance.png    — Importance des features XGBoost
  03_residuals.png             — Distribution des résidus
  04_learning_curve.png        — Courbe d'apprentissage
  05_dataset_overview.png      — Distribution CVSS + ratio positifs/négatifs
  06_confusion_matrix.png      — Performance par classe (Critique, Haut, etc.)
"""
import logging
from pathlib import Path

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import (
    mean_squared_error, 
    r2_score, 
    confusion_matrix, 
    ConfusionMatrixDisplay,
    classification_report
)
from sklearn.model_selection import learning_curve, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor

from app.db.database import get_session, init_db
from app.core.ml.data_manager import DataManager
from app.core.ml.features import get_training_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EVAL_DIR = Path("data") / "evaluation"

# Labels lisibles pour les features
FEATURE_LABELS = {
    "cvss_score":    "CVSS Score",
    "severity_num":  "Sévérité (encodée)",
    "port":          "Port réseau",
    "is_public":     "Port exposé (public)",
    "has_exploit":   "Exploit confirmé",
    "in_cisa_kev":   "CISA KEV",
    "in_exploitdb":  "ExploitDB PoC",
    "av_num":        "Attack Vector",
    "ac_num":        "Attack Complexity",
    "pr_num":        "Privileges Required",
    "ui_num":        "User Interaction",
}

def _get_categorical_labels(y: pd.Series) -> pd.Series:
    """Discrétisation (0-1 -> Catégories)."""
    bins = [-0.01, 0.0, 0.35, 0.55, 0.8, 1.01]
    labels = ["Info", "Faible", "Moyen", "Haut", "Critique"]
    return pd.cut(y, bins=bins, labels=labels)

# ─────────────────────────────────────────────────────────────────────────────
#  Chargement des données
# ─────────────────────────────────────────────────────────────────────────────
def _load_data() -> tuple[pd.DataFrame, str]:
    init_db()
    session = get_session()
    dm = DataManager()
    try:
        df = dm.prepare_unified_dataset(session)
        if df.empty:
            raise RuntimeError("Aucune donnée disponible pour l'évaluation.")
        return df, "Dataset Unifié (NVD + Local)"
    finally:
        session.close()

# ─────────────────────────────────────────────────────────────────────────────
#  Graphiques
# ─────────────────────────────────────────────────────────────────────────────
def _plot_actual_vs_predicted(y_test, y_pred, r2, rmse, source: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 7))
    ax.scatter(y_test, y_pred, alpha=0.55, color="#3B82F6", edgecolor="k", linewidths=0.4, s=40)
    ax.plot([0, 10], [0, 10], "r--", lw=2, label="Idéal (y = x)")
    ax.set_title(f"XGBoost — Prédictions vs. Vérité Terrain\n{source}", fontsize=12, pad=12)
    ax.set_xlabel("Score de Risque Réel (Gold)")
    ax.set_ylabel("Score de Risque Prédit")
    ax.set_xlim(0, 10.5)
    ax.set_ylim(0, 10.5)
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend()
    ax.text(0.05, 0.92, f"R² = {r2:.3f}\nRMSE = {rmse:.3f}", transform=ax.transAxes, fontsize=11,
            bbox=dict(facecolor="white", alpha=0.85, boxstyle="round,pad=0.4"))
    fig.tight_layout()
    fig.savefig(EVAL_DIR / "01_actual_vs_predicted.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 01_actual_vs_predicted.png")

def _plot_feature_importance(pipeline: Pipeline, feature_names: list[str]) -> None:
    xgb_model   = pipeline.named_steps["xgb"]
    importances = xgb_model.feature_importances_
    labels      = [FEATURE_LABELS.get(f, f) for f in feature_names]
    idx = np.argsort(importances)
    fig, ax = plt.subplots(figsize=(9, max(5, len(labels) * 0.5 + 1)))
    colors = plt.cm.viridis(np.linspace(0.2, 0.85, len(idx)))
    bars = ax.barh(range(len(idx)), importances[idx], color=colors[idx], align="center", height=0.65)
    ax.set_yticks(range(len(idx)))
    ax.set_yticklabels([labels[i] for i in idx], fontsize=10)
    ax.set_xlabel("Importance Relative (gain)")
    ax.set_title("Importance des Features")
    for bar, imp in zip(bars, importances[idx]):
        ax.text(imp + 0.001, bar.get_y() + bar.get_height() / 2, f"{imp:.3f}", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(EVAL_DIR / "02_feature_importance.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 02_feature_importance.png")

def _plot_residuals(y_test, y_pred) -> None:
    residuals = y_test - y_pred
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    axes[0].scatter(y_pred, residuals, alpha=0.5, color="#10B981")
    axes[0].axhline(0, color="r", linestyle="--")
    axes[0].set_title("Résidus vs. Prédictions")
    axes[1].hist(residuals, bins=30, color="#6366F1", alpha=0.8)
    axes[1].set_title(f"Distribution des Résidus (σ={residuals.std():.3f})")
    fig.savefig(EVAL_DIR / "03_residuals.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 03_residuals.png")

def _plot_confusion_matrix(y_test, y_pred) -> None:
    """Preuve de performance catégorielle (CRUCIAL POUR PFE)."""
    y_test_cat = _get_categorical_labels(y_test)
    y_pred_cat = _get_categorical_labels(pd.Series(y_pred))
    
    classes = ["Info", "Faible", "Moyen", "Haut", "Critique"]
    present_classes = [c for c in classes if c in y_test_cat.unique() or c in y_pred_cat.unique()]
    
    cm = confusion_matrix(y_test_cat, y_pred_cat, labels=present_classes)
    fig, ax = plt.subplots(figsize=(8, 7))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=present_classes)
    disp.plot(cmap="Blues", ax=ax, colorbar=False)
    ax.set_title("Matrice de Confusion (Classes de Sévérité)")
    fig.tight_layout()
    fig.savefig(EVAL_DIR / "06_confusion_matrix.png", dpi=300)
    plt.close(fig)
    
    # Rapport texte
    report = classification_report(y_test_cat, y_pred_cat, labels=present_classes)
    with open(EVAL_DIR / "classification_report.txt", "w") as f:
        f.write(report)
    logger.info("✔ 06_confusion_matrix.png & classification_report.txt")

def _plot_learning_curve(pipeline: Pipeline, X: pd.DataFrame, y: pd.Series) -> None:
    train_sizes, train_scores, test_scores = learning_curve(
        pipeline, X, y, cv=3, train_sizes=np.linspace(0.1, 1.0, 10),
        scoring="neg_mean_squared_error", random_state=42
    )
    tr_mean = np.sqrt(-np.mean(train_scores, axis=1))
    te_mean = np.sqrt(-np.mean(test_scores, axis=1))
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(train_sizes, tr_mean, "o-", label="Train")
    ax.plot(train_sizes, te_mean, "o-", label="Cross-Val")
    ax.set_title("Courbe d'Apprentissage (Learning Curve)")
    ax.set_xlabel("Taille Dataset")
    ax.set_ylabel("RMSE")
    ax.legend()
    fig.savefig(EVAL_DIR / "04_learning_curve.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 04_learning_curve.png")

def _plot_dataset_overview(df: pd.DataFrame, source: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    axes[0].hist(df["cvss_score"], bins=25, color="#8B5CF6")
    axes[0].set_title("Distribution CVSS")
    
    expl_col = "is_exploited" if "is_exploited" in df.columns else "has_exploit"
    n_pos = int((df[expl_col] == 1).sum())
    n_neg = int((df[expl_col] == 0).sum())
    axes[1].pie([n_pos, n_neg], labels=["Exploités", "Non-expl."], autopct="%1.1f%%")
    axes[1].set_title("Ratio Exploits")
    fig.savefig(EVAL_DIR / "05_dataset_overview.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 05_dataset_overview.png")

# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────
def generate_evaluation_plots() -> None:
    logger.info("🚀 Début de la génération du rapport de performance...")
    df, source = _load_data()
    X, y = get_training_features(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("xgb", XGBRegressor(n_estimators=300, learning_rate=0.05, max_depth=6, random_state=42))
    ])
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))
    r2 = r2_score(y_test, y_pred)

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    _plot_actual_vs_predicted(y_test, y_pred, r2, rmse, source)
    _plot_feature_importance(pipeline, list(X.columns))
    _plot_residuals(y_test, y_pred)
    _plot_confusion_matrix(y_test, y_pred)
    _plot_learning_curve(pipeline, X, y)
    _plot_dataset_overview(df, source)

    logger.info("✅ Évaluation terminée. Rapports disponibles dans : %s", EVAL_DIR.absolute())

if __name__ == "__main__":
    generate_evaluation_plots()
