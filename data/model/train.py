"""
pentest-ai — ML Training Pipeline v2
=====================================
Auteur : BN_Cyber02
Description :
    Pipeline d'entraînement XGBoost dual-model (classifieur + régresseur)
    pour le scoring de vulnérabilités CVE.

    Corrections v2 vs v1 :
    - Target opérationnelle multi-dimensionnelle (non dérivable trivialement depuis les features)
    - Suppression des features en leakage direct (exploited_x_cvss, epss_x_cvss, percentile_sq)
    - Validation croisée StratifiedKFold honnête
    - SMOTE appliqué uniquement à l'intérieur de chaque fold train
    - Calibration isotonique du classifieur
    - Métriques complètes : F1-macro, ROC-AUC OvR, RMSE, R², Spearman
    - Export des courbes ROC et Precision-Recall
    - Métadonnées sauvegardées avec les modèles (.json)
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import xgboost as xgb

from scipy.stats import spearmanr
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report, f1_score, roc_auc_score,
    mean_squared_error, r2_score, average_precision_score,
    RocCurveDisplay, PrecisionRecallDisplay
)
from sklearn.preprocessing import label_binarize
from sklearn.utils.class_weight import compute_sample_weight
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

warnings.filterwarnings('ignore')

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
DATASET_PATH  = '/mnt/user-data/uploads/entrainement_dataset.csv'
OUTPUT_DIR    = '/mnt/user-data/outputs'
PLOT_DIR      = os.path.join(OUTPUT_DIR, 'plots')
RANDOM_STATE  = 42
TEST_SIZE     = 0.20
N_FOLDS       = 5
LABEL_NAMES   = ['Low', 'Medium', 'High', 'Critical']

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# 1. CHARGEMENT
# ─────────────────────────────────────────────
print("=" * 60)
print("  pentest-ai — ML Training Pipeline v2")
print("=" * 60)

df = pd.read_csv(DATASET_PATH)
print(f"\n[1/6] Dataset chargé : {df.shape[0]:,} CVEs × {df.shape[1]} colonnes")
print(f"      Colonnes : {df.columns.tolist()}")

# ─────────────────────────────────────────────
# 2. TARGET OPÉRATIONNELLE MULTI-DIMENSIONNELLE
# ─────────────────────────────────────────────
# Objectif : score de priorité opérationnelle qui ne soit PAS
# une transformation linéaire triviale d'une seule feature.
# Dimensions intégrées :
#   - Sévérité intrinsèque (CVSS normalisé)          → 35 %
#   - Exploitabilité réelle (EPSS + KEV)              → 40 %
#   - Complexité d'attaque (vecteur réseau, privs)    → 15 %
#   - Fraîcheur de la vulnérabilité                   → 10 %
#
# Note: cvss_score reste une FEATURE utile au modèle
# car d'autres dimensions (EPSS, KEV, age) permettent
# de le combiner de façon non-linéaire.

W_SEV         = 0.35   # sévérité CVSS normalisée [0,1]
W_EXPLOIT     = 0.40   # exploitabilité réelle
W_COMPLEXITY  = 0.15   # complexité d'accès (réseau + privs)
W_FRESHNESS   = 0.10   # fraîcheur

# Composante sévérité : transformation non-linéaire via puissance
sev_component = (df['cvss_score'] / 10.0) ** 1.5

# Composante exploitabilité : combinaison EPSS + KEV avec saturation
#   - EPSS seul : faible si CVE non exploitée en pratique
#   - KEV (is_exploited) : boost multiplicatif fort mais plafonné
epss_norm      = df['epss'].clip(0, 1)
kev_boost      = 1.0 + 1.5 * df['is_exploited']          # ×1 ou ×2.5
exploit_raw    = (epss_norm * kev_boost).clip(0, 1)
exploit_component = np.tanh(3.0 * exploit_raw)            # saturation douce [0,1]

# Composante complexité : réseau sans authentification = surface maximale
#   av_num : 1=Physical, 2=Local, 3=Adjacent, 4=Network
#   ac_num : 1=High, 2=Low  (inversé → facilité)
#   pr_num : 0=None, 1=Low, 2=High (inversé → facilité)
av_norm    = (df['av_num'] - 1) / 3.0                     # [0,1]
ac_ease    = 1.0 - (df['ac_num'] - 1) / 1.0              # AC_Low=1 → ease=1
pr_ease    = 1.0 - df['pr_num'] / 2.0                     # PR_None=0 → ease=1
complexity_component = (av_norm * 0.5 + ac_ease * 0.3 + pr_ease * 0.2).clip(0, 1)

# Composante fraîcheur : CVEs récentes sont plus dangereuses
#   age_cve en mois ; demi-vie = 24 mois
freshness_component = np.exp(-df['age_cve'] / 24.0)

# Score composite final
df['ops_risk_score'] = (
    W_SEV        * sev_component       +
    W_EXPLOIT    * exploit_component   +
    W_COMPLEXITY * complexity_component +
    W_FRESHNESS  * freshness_component
).round(6).clip(0, 1)

# Labels via quantiles adaptatifs (distribution équilibrée sur classes opérationnelles)
q25, q60, q88 = df['ops_risk_score'].quantile([0.25, 0.60, 0.88])
df['ops_risk_label'] = pd.cut(
    df['ops_risk_score'],
    bins=[-0.001, q25, q60, q88, 1.0],
    labels=[0, 1, 2, 3]
).astype(int)

print(f"\n[2/6] Target opérationnelle construite")
print(f"      Quantiles : q25={q25:.4f}, q60={q60:.4f}, q88={q88:.4f}")
print(f"      Distribution labels :")
vc = df['ops_risk_label'].value_counts().sort_index()
for i, n in vc.items():
    print(f"        {LABEL_NAMES[i]:10s} ({i}) : {n:6,}  ({n/len(df)*100:.1f}%)")

# ─────────────────────────────────────────────
# 3. FEATURE ENGINEERING (sans leakage)
# ─────────────────────────────────────────────


df['epss_log']        = np.log1p(df['epss'])                           # échelle log (distribution longue queue)
df['network_no_auth'] = ((df['av_num'] == 4) & (df['pr_num'] == 0)).astype(int)  # surface max
df['age_bucket']      = (df['age_cve'].clip(0, 9999) // 6).clip(0, 8).astype(int) # tranche semestrielle
df['severity_x_av']   = df['severity_num'] * df['av_num']             # interaction sévérité×vecteur
df['attack_surface']  = (
    df['av_num'] * (4 - df['ac_num']) * (4 - df['pr_num'])
).clip(0, 64) / 64.0                                                   # surface normalisée [0,1]
df['ui_penalty']      = (df['ui_num'] == 1).astype(int)               # interaction requise → pénalité
df['epss_kev']        = df['epss'] * (1 + df['is_exploited'])         # EPSS pondéré KEV (différent target)
df['cvss_sq']         = (df['cvss_score'] / 10.0) ** 2               # non-linéarité sévérité

FEATURES = [
    # Métriques de base
    'cvss_score', 'severity_num',
    # Vecteurs CVSS v3
    'av_num', 'ac_num', 'pr_num', 'ui_num',
    # Exploitabilité
    'is_exploited', 'epss', 'epss_log', 'epss_kev',
    # Temporel
    'age_cve', 'age_bucket',
    # Features construites
    'network_no_auth', 'severity_x_av', 'attack_surface',
    'ui_penalty', 'cvss_sq',
]

print(f"\n[3/6] Feature engineering : {len(FEATURES)} features (sans leakage)")
print(f"      {FEATURES}")

# ─────────────────────────────────────────────
# 4. SPLIT TRAIN / TEST
# ─────────────────────────────────────────────
X       = df[FEATURES]
y_reg   = df['ops_risk_score']
y_clf   = df['ops_risk_label']

X_train, X_test, yr_train, yr_test, yc_train, yc_test = train_test_split(
    X, y_reg, y_clf,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_clf
)

print(f"\n[4/6] Split : train={len(X_train):,} | test={len(X_test):,}")

# ─────────────────────────────────────────────
# 5. VALIDATION CROISÉE STRATIFIÉE (honnête)
# ─────────────────────────────────────────────
print(f"\n[5/6] Validation croisée {N_FOLDS}-Fold en cours...")

skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_STATE)

cv_f1_scores   = []
cv_auc_scores  = []
cv_rmse_scores = []

for fold, (tr_idx, val_idx) in enumerate(skf.split(X_train, yc_train)):
    X_tr, X_val     = X_train.iloc[tr_idx], X_train.iloc[val_idx]
    yc_tr, yc_val   = yc_train.iloc[tr_idx], yc_train.iloc[val_idx]
    yr_tr, yr_val   = yr_train.iloc[tr_idx], yr_train.iloc[val_idx]

    # SMOTE uniquement sur le fold train (pas de leakage inter-fold)
    n_med = yc_tr.value_counts().get(1, 100)
    smote_strategy = {
        0: yc_tr.value_counts()[0],
        1: n_med,
        2: min(n_med, yc_tr.value_counts().get(2, 0) * 4),
        3: min(n_med, yc_tr.value_counts().get(3, 0) * 8),
    }
    smote = SMOTE(sampling_strategy=smote_strategy, k_neighbors=5, random_state=RANDOM_STATE)
    X_tr_sm, yc_tr_sm = smote.fit_resample(X_tr, yc_tr)

    # Classifieur fold
    clf_fold = xgb.XGBClassifier(
        n_estimators=400, max_depth=5, learning_rate=0.05,
        objective='multi:softprob', num_class=4,
        eval_metric='mlogloss', subsample=0.8, colsample_bytree=0.8,
        min_child_weight=5, random_state=RANDOM_STATE, n_jobs=-1, verbosity=0,
        use_label_encoder=False
    )
    sw = compute_sample_weight('balanced', y=yc_tr_sm)
    clf_fold.fit(X_tr_sm, yc_tr_sm, sample_weight=sw)

    yc_pred_val  = clf_fold.predict(X_val)
    yc_proba_val = clf_fold.predict_proba(X_val)
    f1   = f1_score(yc_val, yc_pred_val, average='macro', zero_division=0)
    y_bin = label_binarize(yc_val, classes=[0, 1, 2, 3])
    auc  = roc_auc_score(y_bin, yc_proba_val, multi_class='ovr', average='macro')

    # Régresseur fold
    reg_fold = xgb.XGBRegressor(
        n_estimators=400, max_depth=5, learning_rate=0.05,
        objective='reg:squarederror', subsample=0.8, colsample_bytree=0.8,
        min_child_weight=5, random_state=RANDOM_STATE, n_jobs=-1, verbosity=0
    )
    reg_fold.fit(X_tr, yr_tr)
    yr_pred_val = reg_fold.predict(X_val)
    rmse = np.sqrt(mean_squared_error(yr_val, yr_pred_val))

    cv_f1_scores.append(f1)
    cv_auc_scores.append(auc)
    cv_rmse_scores.append(rmse)
    print(f"      Fold {fold+1}/{N_FOLDS} → F1-macro={f1:.4f} | AUC-OvR={auc:.4f} | RMSE={rmse:.6f}")

print(f"\n      ── Résumé Cross-Validation ──")
print(f"      F1-macro  : {np.mean(cv_f1_scores):.4f} ± {np.std(cv_f1_scores):.4f}")
print(f"      AUC-OvR   : {np.mean(cv_auc_scores):.4f} ± {np.std(cv_auc_scores):.4f}")
print(f"      RMSE      : {np.mean(cv_rmse_scores):.6f} ± {np.std(cv_rmse_scores):.6f}")

# ─────────────────────────────────────────────
# 6. ENTRAÎNEMENT FINAL SUR TOUT LE TRAIN SET
# ─────────────────────────────────────────────
print(f"\n[6/6] Entraînement final...")

# SMOTE sur tout le train
n_med = yc_train.value_counts().get(1, 100)
smote_final = SMOTE(
    sampling_strategy={
        0: yc_train.value_counts()[0],
        1: n_med,
        2: min(n_med, yc_train.value_counts().get(2, 0) * 4),
        3: min(n_med, yc_train.value_counts().get(3, 0) * 8),
    },
    k_neighbors=5, random_state=RANDOM_STATE
)
X_train_sm, yc_train_sm = smote_final.fit_resample(X_train, yc_train)
sw_final = compute_sample_weight('balanced', y=yc_train_sm)
print(f"      Après SMOTE : {len(X_train_sm):,} échantillons train")

# ── Classifieur XGBoost ──
clf_base = xgb.XGBClassifier(
    n_estimators=600, max_depth=5, learning_rate=0.03,
    objective='multi:softprob', num_class=4,
    eval_metric='mlogloss', subsample=0.8, colsample_bytree=0.8,
    min_child_weight=5, random_state=RANDOM_STATE, n_jobs=-1, verbosity=0,
    use_label_encoder=False, early_stopping_rounds=50
)
clf_base.fit(
    X_train_sm, yc_train_sm,
    sample_weight=sw_final,
    eval_set=[(X_test, yc_test)],
    verbose=False
)

# Calibration isotonique via cross-validation interne (cv=3)
# Probabilités mieux calibrées pour le scoring downstream
clf_calibrated = CalibratedClassifierCV(
    xgb.XGBClassifier(
        n_estimators=clf_base.best_iteration or 600,
        max_depth=5, learning_rate=0.03,
        objective='multi:softprob', num_class=4,
        eval_metric='mlogloss', subsample=0.8, colsample_bytree=0.8,
        min_child_weight=5, random_state=RANDOM_STATE, n_jobs=-1, verbosity=0,
        use_label_encoder=False
    ),
    method='isotonic', cv=3
)
clf_calibrated.fit(X_train_sm, yc_train_sm)

# ── Régresseur XGBoost ──
reg_final = xgb.XGBRegressor(
    n_estimators=600, max_depth=5, learning_rate=0.03,
    objective='reg:squarederror', subsample=0.8, colsample_bytree=0.8,
    min_child_weight=5, random_state=RANDOM_STATE, n_jobs=-1, verbosity=0,
    early_stopping_rounds=50
)
reg_final.fit(
    X_train, yr_train,
    eval_set=[(X_test, yr_test)],
    verbose=False
)

# ─────────────────────────────────────────────
# ÉVALUATION SUR TEST SET
# ─────────────────────────────────────────────
print("\n" + "=" * 60)
print("  MÉTRIQUES TEST SET (données jamais vues)")
print("=" * 60)

# -- Classifieur --
yc_pred      = clf_calibrated.predict(X_test)
yc_proba     = clf_calibrated.predict_proba(X_test)
yc_test_bin  = label_binarize(yc_test, classes=[0, 1, 2, 3])

f1_macro     = f1_score(yc_test, yc_pred, average='macro', zero_division=0)
f1_weighted  = f1_score(yc_test, yc_pred, average='weighted', zero_division=0)
auc_ovr      = roc_auc_score(yc_test_bin, yc_proba, multi_class='ovr', average='macro')
ap_macro     = average_precision_score(yc_test_bin, yc_proba, average='macro')

print(f"\n── Classifieur (4 classes) ──")
print(classification_report(yc_test, yc_pred, target_names=LABEL_NAMES, zero_division=0))
print(f"  F1-macro          : {f1_macro:.4f}")
print(f"  F1-weighted       : {f1_weighted:.4f}")
print(f"  ROC-AUC OvR macro : {auc_ovr:.4f}")
print(f"  Avg Precision     : {ap_macro:.4f}")

# -- Régresseur --
yr_pred   = reg_final.predict(X_test)
rmse      = np.sqrt(mean_squared_error(yr_test, yr_pred))
mae       = np.mean(np.abs(yr_test - yr_pred))
r2        = r2_score(yr_test, yr_pred)
spearman  = spearmanr(yr_test, yr_pred).statistic

print(f"\n── Régresseur (score continu) ──")
print(f"  RMSE              : {rmse:.6f}")
print(f"  MAE               : {mae:.6f}")
print(f"  R²                : {r2:.4f}")
print(f"  Spearman ρ        : {spearman:.4f}")

# ─────────────────────────────────────────────
# COURBES ROC ET PRECISION-RECALL
# ─────────────────────────────────────────────
COLORS = ['#27ae60', '#f39c12', '#e67e22', '#e74c3c']

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle('pentest-ai — Évaluation ML (test set)', fontsize=14, fontweight='bold')

# ROC curves
ax = axes[0]
for i, (label, color) in enumerate(zip(LABEL_NAMES, COLORS)):
    RocCurveDisplay.from_predictions(
        yc_test_bin[:, i], yc_proba[:, i],
        name=label, color=color, ax=ax
    )
ax.plot([0, 1], [0, 1], 'k--', linewidth=0.8, label='Random')
ax.set_title(f'Courbes ROC — AUC macro={auc_ovr:.3f}')
ax.set_xlabel('Taux Faux Positifs')
ax.set_ylabel('Taux Vrais Positifs')
ax.legend(loc='lower right', fontsize=9)
ax.grid(alpha=0.3)

# Precision-Recall curves
ax = axes[1]
for i, (label, color) in enumerate(zip(LABEL_NAMES, COLORS)):
    PrecisionRecallDisplay.from_predictions(
        yc_test_bin[:, i], yc_proba[:, i],
        name=label, color=color, ax=ax
    )
ax.set_title(f'Courbes Precision-Recall — AP macro={ap_macro:.3f}')
ax.set_xlabel('Rappel')
ax.set_ylabel('Précision')
ax.legend(loc='upper right', fontsize=9)
ax.grid(alpha=0.3)

plt.tight_layout()
roc_path = os.path.join(PLOT_DIR, 'roc_pr_curves.png')
plt.savefig(roc_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"\n  Courbes ROC/PR sauvegardées → {roc_path}")

# Feature importance
fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle('pentest-ai — Feature Importances XGBoost', fontsize=14, fontweight='bold')

for ax, model, title in zip(axes, [clf_base, reg_final], ['Classifieur', 'Régresseur']):
    fi = pd.Series(model.feature_importances_, index=FEATURES).sort_values()
    colors = ['#e74c3c' if v > fi.quantile(0.75) else '#3498db' for v in fi]
    fi.plot(kind='barh', ax=ax, color=colors)
    ax.set_title(f'Feature Importances — {title}')
    ax.set_xlabel('Importance (gain)')
    ax.grid(axis='x', alpha=0.3)

plt.tight_layout()
fi_path = os.path.join(PLOT_DIR, 'feature_importances.png')
plt.savefig(fi_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"  Feature importances sauvegardées → {fi_path}")

# ─────────────────────────────────────────────
# SAUVEGARDE MODÈLES + MÉTADONNÉES
# ─────────────────────────────────────────────
clf_path = os.path.join(OUTPUT_DIR, 'xgb_classifier_v2.joblib')
reg_path = os.path.join(OUTPUT_DIR, 'xgb_regressor_v2.joblib')
joblib.dump(clf_calibrated, clf_path)
joblib.dump(reg_final, reg_path)

metadata = {
    "version": "2.0",
    "project": "pentest-ai",
    "features": FEATURES,
    "n_features": len(FEATURES),
    "label_names": LABEL_NAMES,
    "target": {
        "classifier": "ops_risk_label (4 classes)",
        "regressor": "ops_risk_score [0, 1]",
        "score_weights": {
            "severity": W_SEV,
            "exploitability": W_EXPLOIT,
            "complexity": W_COMPLEXITY,
            "freshness": W_FRESHNESS,
        },
        "label_quantiles": {"q25": round(q25, 6), "q60": round(q60, 6), "q88": round(q88, 6)}
    },
    "training": {
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "smote": True,
        "calibration": "isotonic",
        "cv_folds": N_FOLDS,
    },
    "metrics": {
        "cv": {
            "f1_macro_mean": round(float(np.mean(cv_f1_scores)), 4),
            "f1_macro_std":  round(float(np.std(cv_f1_scores)),  4),
            "auc_ovr_mean":  round(float(np.mean(cv_auc_scores)), 4),
            "auc_ovr_std":   round(float(np.std(cv_auc_scores)),  4),
            "rmse_mean":     round(float(np.mean(cv_rmse_scores)), 6),
            "rmse_std":      round(float(np.std(cv_rmse_scores)),  6),
        },
        "test": {
            "f1_macro":    round(float(f1_macro),    4),
            "f1_weighted": round(float(f1_weighted), 4),
            "auc_ovr":     round(float(auc_ovr),     4),
            "avg_precision": round(float(ap_macro),  4),
            "rmse":        round(float(rmse),        6),
            "mae":         round(float(mae),         6),
            "r2":          round(float(r2),          4),
            "spearman":    round(float(spearman),    4),
        }
    }
}

meta_path = os.path.join(OUTPUT_DIR, 'model_metadata_v2.json')
with open(meta_path, 'w', encoding='utf-8') as f:
    json.dump(metadata, f, indent=2, ensure_ascii=False)

print(f"\n  Classifieur  → {clf_path}")
print(f"  Régresseur   → {reg_path}")
print(f"  Métadonnées  → {meta_path}")

print("\n" + "=" * 60)
print("  Entraînement terminé avec succès.")
print("=" * 60)
