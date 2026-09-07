"""
predict.py
==========
Inférence avec les modèles XGBoost v2 + explications SHAP.
Modèles : classificateur_xgb.joblib (CalibratedClassifierCV) + regresseur_xgb.joblib (XGBRegressor)
Les explications sont générées dynamiquement par SHAP TreeExplainer
(contribution réelle de chaque feature à la décision du modèle).
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


# ───────────────────────────────────────────────────────────────
# SHAP — Explications dynamiques basées sur le modèle
# ───────────────────────────────────────────────────────────────

# Traduction des noms de features en français lisible
_FEATURE_LABELS: dict[str, str] = {
    "epss":         "Probabilité d'exploitation (EPSS)",
    "epss_log":     "EPSS (échelle log)",
    "age_cve":      "Ancienneté de la CVE",
    "age_bucket":   "Tranche d'ancienneté CVE",
    "ac_num":       "Complexité d'attaque",
    "pr_num":       "Privilèges requis",
    "ui_num":       "Interaction utilisateur",
    "host_type":    "Type d'hôte (infra/serveur/client)",
    "port":         "Port du service",
    "svc_type_num": "Type de service (web/accès distant/DB)",
    "port_is_web":  "Service web exposé",
}

# Interprétation contextuelle des valeurs de features
def _interpret_feature(feat_name: str, feat_value: float, shap_val: float) -> str:
    """Traduit une contribution SHAP en explication métier lisible."""
    direction = "↑" if shap_val > 0 else "↓"
    impact = abs(shap_val)
    label = _FEATURE_LABELS.get(feat_name, feat_name)

    # Interprétations spécifiques par feature
    if feat_name == "epss":
        if feat_value > 0.5:
            detail = f"très élevée ({feat_value:.1%})"
        elif feat_value > 0.1:
            detail = f"significative ({feat_value:.1%})"
        elif feat_value > 0.01:
            detail = f"non négligeable ({feat_value:.2%})"
        elif feat_value > 0:
            detail = f"faible ({feat_value:.3%})"
        else:
            detail = "non disponible"
        return f"{label} {detail} {direction} ({impact:+.2f})"

    if feat_name == "age_cve":
        v = int(feat_value)
        if v <= 1:
            detail = f"très récente (<1 an)"
        elif v <= 3:
            detail = f"récente ({v} ans)"
        elif v <= 10:
            detail = f"modérée ({v} ans)"
        else:
            detail = f"ancienne ({v} ans)"
        return f"Ancienneté CVE {detail} {direction} ({impact:+.2f})"

    if feat_name == "pr_num":
        pr_labels = {0: "aucun (N)", 1: "faible (L)", 2: "élevé (H)"}
        detail = pr_labels.get(int(feat_value), str(int(feat_value)))
        return f"Privilèges requis : {detail} {direction} ({impact:+.2f})"

    if feat_name == "ac_num":
        ac_labels = {1: "élevée (H)", 2: "faible (L)"}
        detail = ac_labels.get(int(feat_value), str(int(feat_value)))
        return f"Complexité d'attaque : {detail} {direction} ({impact:+.2f})"

    if feat_name == "ui_num":
        ui_labels = {0: "requise", 1: "aucune"}
        detail = ui_labels.get(int(feat_value), str(int(feat_value)))
        return f"Interaction utilisateur : {detail} {direction} ({impact:+.2f})"

    if feat_name == "host_type":
        ht_labels = {0: "inconnu", 1: "client", 2: "serveur", 3: "infrastructure critique"}
        detail = ht_labels.get(int(feat_value), str(int(feat_value)))
        return f"Type d'hôte : {detail} {direction} ({impact:+.2f})"

    if feat_name == "port":
        return f"Port {int(feat_value)} {direction} ({impact:+.2f})"

    if feat_name == "svc_type_num":
        svc_labels = {0: "inconnu", 1: "autre", 2: "base de données/transfert", 3: "accès distant", 4: "web"}
        detail = svc_labels.get(int(feat_value), str(int(feat_value)))
        return f"Type de service : {detail} {direction} ({impact:+.2f})"

    if feat_name == "port_is_web":
        detail = "oui" if feat_value else "non"
        return f"Port web : {detail} {direction} ({impact:+.2f})"

    # Fallback générique
    return f"{label}={feat_value:.2f} {direction} ({impact:+.2f})"


def _shap_reasoning(shap_values_row: np.ndarray, feature_values: pd.Series,
                    feature_names: list[str], score: float, label: str,
                    top_k: int = 5) -> str:
    """
    Génère une explication textuelle basée sur les valeurs SHAP réelles.
    Sélectionne les top_k features les plus influentes (par magnitude SHAP)
    et les traduit en phrases lisibles.
    """
    # Trier les features par impact absolu décroissant
    indices = np.argsort(-np.abs(shap_values_row))
    
    explanations = []
    for i in indices[:top_k]:
        sv = float(shap_values_row[i])
        if abs(sv) < 0.01:  # ignorer les contributions négligeables
            continue
        fv = float(feature_values.iloc[i])
        fn = feature_names[i]
        explanations.append(_interpret_feature(fn, fv, sv))

    if not explanations:
        return f"Priorité {label}. Score ops_risk={score:.3f} — aucune feature dominante."

    return f"Priorité {label}. {'; '.join(explanations)}. Score ops_risk={score:.3f}."


def _extract_xgb_booster(model):
    """Extrait le booster XGBoost depuis un modèle potentiellement wrappé (CalibratedClassifierCV)."""
    # CalibratedClassifierCV wraps the estimator
    if hasattr(model, "calibrated_classifiers_"):
        base = model.calibrated_classifiers_[0].estimator
        if hasattr(base, "get_booster"):
            return base
    if hasattr(model, "estimator") and hasattr(model.estimator, "get_booster"):
        return model.estimator
    if hasattr(model, "get_booster"):
        return model
    return None


def predict_and_store(session: Session, df: pd.DataFrame) -> dict[str, int]:
    """
    Exécute l'inférence et stocke les résultats avec explications SHAP.
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

        # 3. Explications SHAP (basées sur le régresseur pour un score continu)
        shap_values = None
        try:
            import shap
            xgb_model = _extract_xgb_booster(model_reg)
            if xgb_model is not None:
                explainer = shap.TreeExplainer(xgb_model)
                shap_values = explainer.shap_values(X)
                logger.info("Explications SHAP calculées pour %d vulnérabilités.", len(X))
            else:
                logger.warning("Impossible d'extraire le booster XGBoost — SHAP désactivé.")
        except ImportError:
            logger.warning("SHAP non installé — explications basées sur les features brutes.")
        except Exception as e:
            logger.warning("Erreur SHAP (fallback features brutes) : %s", e)

        # 4. Stockage
        feature_names = list(X.columns)
        for idx, (_, row) in enumerate(df.iterrows()):
            score_v4 = float(raw_scores[idx])
            label_num = int(raw_labels[idx])
            label_str = LABEL_MAP.get(label_num, "Moyenne")
            confidence = float(np.max(clf_probas[idx]))
            
            # Le nouveau modèle prédit directement un score sur 10 (cvss_score)
            display_score = round(score_v4, 1)
            
            vuln_id = int(row["vuln_id"])
            s_ml = session.query(ScoreML).filter(ScoreML.vuln_id == vuln_id).first()

            # Raisonnement SHAP ou fallback
            if shap_values is not None:
                reasoning = _shap_reasoning(
                    shap_values[idx], X.iloc[idx], feature_names,
                    score_v4, label_str,
                )
            else:
                reasoning = f"Priorité {label_str}. Score ops_risk={score_v4:.3f} basé sur les métriques standards."

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

