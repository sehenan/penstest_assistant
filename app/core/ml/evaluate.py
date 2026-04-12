"""
evaluate.py
===========
Script autonome d'évaluation du modèle XGBoost.
Génère 5 graphiques de performance pour le mémoire PFE.

Sources de données (priorité décroissante) :
  1. data/nvd_training_data.csv  — NVD + CISA KEV + ExploitDB (officiel)
  2. DB SQLite locale            — scans ingérés via pipeline

Graphiques produits dans data/evaluation/ :
  01_actual_vs_predicted.png   — Scatter prédictions vs vérité terrain
  02_feature_importance.png    — Importance des 11 features XGBoost
  03_residuals.png             — Distribution des résidus
  04_learning_curve.png        — Courbe d'apprentissage (RMSE vs taille)
  05_cvss_distribution.png     — Distribution CVSS + ratio positifs/négatifs
"""
import logging
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.model_selection import learning_curve, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor

from app.db.database import get_session, init_db
from app.core.ml.features import (
    augment_data,
    extract_real_data,
    get_training_features,
    load_official_data,
)

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


# ─────────────────────────────────────────────────────────────────────────────
#  Chargement des données
# ─────────────────────────────────────────────────────────────────────────────
def _load_data() -> tuple[pd.DataFrame, str]:
    """
    Charge les données d'entraînement depuis la meilleure source disponible.
    Returns (df, data_source_label).
    """
    # Priorité 1 : CSV NVD officiel
    df = load_official_data()
    if not df.empty:
        n_pos = int((df["has_exploit"] == 1).sum())
        return df, f"NVD Officiel — NIST + CISA KEV + ExploitDB ({len(df)} CVEs, {n_pos} positifs)"

    # Fallback : DB SQLite locale
    logger.warning("CSV NVD absent — fallback sur la base de données locale.")
    init_db()
    session = get_session()
    try:
        df_real = extract_real_data(session)
    finally:
        session.close()

    if df_real.empty:
        raise RuntimeError(
            "Aucune donnée disponible.\n"
            "Lancez : python -m app.core.ml.fetch_training_data"
        )

    df = augment_data(df_real, target_size=500)
    return df, f"DB locale augmentée ({len(df)} échantillons)"


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
    ax.text(
        0.05, 0.92,
        f"R² = {r2:.3f}\nRMSE = {rmse:.3f}",
        transform=ax.transAxes, fontsize=11,
        bbox=dict(facecolor="white", alpha=0.85, boxstyle="round,pad=0.4"),
    )
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
    ax.set_xlabel("Importance Relative (gain)", fontsize=10)
    ax.set_title(
        f"Importance des Features — XGBoost\n({len(labels)} variables)",
        fontsize=12, pad=10
    )
    ax.grid(axis="x", linestyle="--", alpha=0.5)

    # Annotations valeurs
    for bar, imp in zip(bars, importances[idx]):
        ax.text(imp + 0.001, bar.get_y() + bar.get_height() / 2,
                f"{imp:.3f}", va="center", fontsize=8)

    fig.tight_layout()
    fig.savefig(EVAL_DIR / "02_feature_importance.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 02_feature_importance.png")


def _plot_residuals(y_test, y_pred) -> None:
    residuals = y_test - y_pred

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Scatter résidus vs prédictions
    axes[0].scatter(y_pred, residuals, alpha=0.5, color="#10B981", edgecolor="k",
                    linewidths=0.3, s=35)
    axes[0].axhline(0, color="r", linestyle="--", lw=2)
    axes[0].set_xlabel("Score Prédit")
    axes[0].set_ylabel("Résidu (Réel − Prédit)")
    axes[0].set_title("Résidus vs. Prédictions")
    axes[0].grid(True, linestyle="--", alpha=0.4)

    # Histogramme des résidus
    axes[1].hist(residuals, bins=30, color="#6366F1", edgecolor="k", linewidth=0.5, alpha=0.8)
    axes[1].axvline(0, color="r", linestyle="--", lw=2)
    axes[1].set_xlabel("Résidu")
    axes[1].set_ylabel("Fréquence")
    axes[1].set_title(f"Distribution des Résidus\nMoyenne={residuals.mean():.3f}, σ={residuals.std():.3f}")
    axes[1].grid(True, linestyle="--", alpha=0.4)

    fig.suptitle("Analyse des Erreurs de Prédiction (Résidus)", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(EVAL_DIR / "03_residuals.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 03_residuals.png")


def _plot_learning_curve(pipeline: Pipeline, X: pd.DataFrame, y: pd.Series) -> None:
    train_sizes, train_scores, test_scores = learning_curve(
        pipeline, X, y,
        cv=5, n_jobs=1,
        train_sizes=np.linspace(0.1, 1.0, 10),
        scoring="neg_mean_squared_error",
        random_state=42,
    )
    tr_mean = np.sqrt(-np.mean(train_scores, axis=1))
    tr_std  = np.sqrt(np.std(-train_scores,  axis=1))
    te_mean = np.sqrt(-np.mean(test_scores,  axis=1))
    te_std  = np.sqrt(np.std(-test_scores,   axis=1))

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(train_sizes, tr_mean, "o-", color="#EF4444", label="Erreur Entraînement")
    ax.fill_between(train_sizes, tr_mean - tr_std, tr_mean + tr_std, alpha=0.15, color="#EF4444")
    ax.plot(train_sizes, te_mean, "o-", color="#22C55E", label="Erreur Validation Croisée")
    ax.fill_between(train_sizes, te_mean - te_std, te_mean + te_std, alpha=0.15, color="#22C55E")
    ax.set_title("Courbe d'Apprentissage (Learning Curve)", fontsize=12)
    ax.set_xlabel("Taille du Dataset")
    ax.set_ylabel("RMSE (↓ = mieux)")
    ax.legend(loc="upper right")
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()
    fig.savefig(EVAL_DIR / "04_learning_curve.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 04_learning_curve.png")


def _plot_dataset_overview(df: pd.DataFrame, source: str) -> None:
    """Graphique bonus : distribution CVSS + ratio positifs/négatifs (label)."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Distribution CVSS
    axes[0].hist(df["cvss_score"], bins=25, color="#8B5CF6", edgecolor="k",
                 linewidth=0.4, alpha=0.85)
    axes[0].axvline(df["cvss_score"].mean(), color="r", linestyle="--",
                    label=f"Moyenne = {df['cvss_score'].mean():.2f}")
    axes[0].set_xlabel("Score CVSS")
    axes[0].set_ylabel("Nombre de CVEs")
    axes[0].set_title("Distribution des Scores CVSS")
    axes[0].legend()
    axes[0].grid(True, linestyle="--", alpha=0.4)

    # Ratio positifs / négatifs
    n_pos = int((df["has_exploit"] == 1).sum())
    n_neg = int((df["has_exploit"] == 0).sum())
    labels_pie = [f"Exploités\n(label=1)\n{n_pos}", f"Non exploités\n(label=0)\n{n_neg}"]
    colors_pie  = ["#EF4444", "#3B82F6"]
    axes[1].pie(
        [n_pos, n_neg], labels=labels_pie, colors=colors_pie,
        autopct="%1.1f%%", startangle=90, textprops={"fontsize": 10},
        wedgeprops={"edgecolor": "white", "linewidth": 1.5},
    )
    axes[1].set_title("Ratio Positifs / Négatifs\n(has_exploit)")

    fig.suptitle(f"Aperçu du Dataset — {source}", fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(EVAL_DIR / "05_dataset_overview.png", dpi=300)
    plt.close(fig)
    logger.info("✔ 05_dataset_overview.png")


# ─────────────────────────────────────────────────────────────────────────────
#  Pipeline principal
# ─────────────────────────────────────────────────────────────────────────────
def generate_evaluation_plots() -> None:
    """Génère tous les graphiques d'évaluation dans data/evaluation/."""
    logger.info("═" * 55)
    logger.info(" ÉVALUATION DU MODÈLE XGBOOST — PFE Pentest Assistant")
    logger.info("═" * 55)

    # 1. Chargement
    df, data_source = _load_data()
    logger.info("Source utilisée : %s", data_source)
    logger.info("Dataset shape   : %s", df.shape)

    # 2. Features
    X, y = get_training_features(df)
    feature_names = list(X.columns)
    logger.info("Features        : %s", feature_names)

    # 3. Split 80/20
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    logger.info("Train: %d  |  Test: %d", len(X_train), len(X_test))

    # 4. Entraînement
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("xgb", XGBRegressor(
            n_estimators=200,
            learning_rate=0.08,
            max_depth=5,
            subsample=0.85,
            colsample_bytree=0.85,
            objective="reg:squarederror",
            random_state=42,
        )),
    ])
    pipeline.fit(X_train, y_train)

    # 5. Métriques
    y_pred = pipeline.predict(X_test)
    mse    = mean_squared_error(y_test, y_pred)
    rmse   = float(np.sqrt(mse))
    r2     = float(r2_score(y_test, y_pred))
    logger.info("─" * 40)
    logger.info("RMSE : %.4f", rmse)
    logger.info("R²   : %.4f", r2)
    logger.info("─" * 40)

    # 6. Graphiques
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    _plot_actual_vs_predicted(y_test, y_pred, r2, rmse, data_source)
    _plot_feature_importance(pipeline, feature_names)
    _plot_residuals(y_test, y_pred)
    _plot_learning_curve(pipeline, X, y)
    _plot_dataset_overview(df, data_source)

    logger.info("═" * 55)
    logger.info("✅ 5 graphiques sauvegardés dans : %s", EVAL_DIR.absolute())
    logger.info("═" * 55)


if __name__ == "__main__":
    generate_evaluation_plots()
