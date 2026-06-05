import warnings; warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import os
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    ConfusionMatrixDisplay, classification_report,
    roc_curve, auc, precision_recall_curve,
    average_precision_score, mean_squared_error
)
from sklearn.preprocessing import LabelBinarizer
from sklearn.utils.class_weight import compute_sample_weight
from imblearn.over_sampling import SMOTE

os.makedirs('data/model',     exist_ok=True)
os.makedirs('data/graphiques', exist_ok=True)

plt.rcParams.update({
    'figure.facecolor': '#FFFFFF', 'axes.facecolor': '#F0F0F0',
    'axes.edgecolor':   '#CCCCCC', 'axes.labelcolor': '#333333',
    'xtick.color':      '#333333', 'ytick.color':     '#333333',
    'text.color':       '#333333', 'grid.color':      '#DDDDDD',
    'grid.alpha': 0.8,  'axes.grid': True,
    'legend.facecolor': '#F0F0F0', 'legend.edgecolor': '#CCCCCC',
    'font.family': 'DejaVu Sans'
})

LABEL_NAMES  = ['Low', 'Medium', 'High', 'Critical']
RANDOM_STATE = 42

# ════════════════════════════════════════════════════════════════
# CORRECTION PRINCIPALE — FEATURES PROPRES SANS DATA LEAKAGE
#
# Règle simple : une feature ne doit PAS apparaître dans
# la fonction assign_pentest_label qui construit les labels.
#
# SUPPRIMÉES (utilisées dans assign_pentest_label) :
#   cvss_score, severity_num, is_exploited, is_public,
#   host_criticality, port_is_critical, db_exposed,
#   network_no_auth, public_and_exploit, public_and_network,
#   public_critical_port, attack_surface
#
# GARDÉES (indépendantes des règles de labels) :
#   epss, epss_log, age_cve, age_bucket,
#   ac_num, pr_num, ui_num,
#   host_type, port, svc_type_num, port_is_web
# ════════════════════════════════════════════════════════════════

FEATURES = [
    'epss',          # Probabilité d'exploitation (source NVD externe)
    'epss_log',      # Version logarithmique du EPSS
    'age_cve',       # Ancienneté de la CVE en jours
    'age_bucket',    # Tranche d'âge de la CVE
    'ac_num',        # Complexité d'attaque (CVSS vector)
    'pr_num',        # Privilèges requis (CVSS vector)
    'ui_num',        # Interaction utilisateur requise (CVSS vector)
    'host_type',     # Type de machine (serveur, workstation...)
    'port',          # Numéro de port du service vulnérable
    'svc_type_num',  # Type de service
    'port_is_web',   # Le service est-il un port web ?
]

# ════════════════════════════════════════════════════════════════
# ÉTAPE 1 — Chargement
# ════════════════════════════════════════════════════════════════
DATASET_PATH = '/content/dataset_corrige.csv'
df = pd.read_csv(DATASET_PATH)
print(f"Dataset chargé : {len(df):,} lignes × {len(df.columns)} colonnes")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 2 — Construction des labels (inchangée)
# ════════════════════════════════════════════════════════════════
print("\nConstruction des labels métier...")
np.random.seed(RANDOM_STATE)

def assign_pentest_label(row):
    score   = row['cvss_score']
    epss    = row['epss_kev']
    exploit = row['is_exploited']
    public  = row['is_public']
    crit    = row['host_criticality']
    pcrit   = row['port_is_critical']
    dbe     = row['db_exposed']
    pexp    = row['public_and_exploit']
    nav     = row['network_no_auth']
    av      = row['av_num']

    if exploit == 1 and public == 1 and score >= 7.0:  return 3
    if pexp == 1 and score >= 8.0:                      return 3
    if epss >= 0.15 and av == 4 and score >= 7.5:       return 3
    if dbe == 1 and nav == 1 and score >= 8.0:          return 3
    if crit == 4 and score >= 9.0:                      return 3
    if score >= 8.5 and public == 1:                    return 2
    if score >= 7.5 and (pcrit == 1 or dbe == 1):       return 2
    if epss >= 0.05 and av == 4:                        return 2
    if exploit == 1 and score >= 6.0:                   return 2
    if crit >= 3 and score >= 7.0 and public == 1:      return 2
    if score >= 6.0 and av == 4:                        return 1
    if score >= 5.0 and public == 1:                    return 1
    if score >= 7.0 and crit >= 2:                      return 1
    if epss >= 0.01 and score >= 5.0:                   return 1
    return 0

print("  Application des règles (peut prendre 30-60s)...")
df['pentest_label'] = df.apply(assign_pentest_label, axis=1)

label_counts = df['pentest_label'].value_counts().sort_index()
print(f"\n  Distribution des labels :")
for lbl, name in enumerate(LABEL_NAMES):
    n = label_counts.get(lbl, 0)
    print(f"    {name:8s} ({lbl}) : {n:6,}  ({100*n/len(df):.1f}%)")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 3 — Target régression (cvss_score — inchangée)
# ════════════════════════════════════════════════════════════════
print(f"\nTarget régression : cvss_score")
print(f"  Min: {df['cvss_score'].min():.1f} | Max: {df['cvss_score'].max():.1f} | "
      f"Mean: {df['cvss_score'].mean():.2f}")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 4 — Split 70 / 15 / 15
# ════════════════════════════════════════════════════════════════
X     = df[FEATURES]
y_clf = df['pentest_label']
y_reg = df['cvss_score']

X_tmp, X_test, yc_tmp, yc_test, yr_tmp, yr_test = train_test_split(
    X, y_clf, y_reg,
    test_size=0.15, random_state=RANDOM_STATE, stratify=y_clf
)
X_train, X_val, yc_train, yc_val, yr_train, yr_val = train_test_split(
    X_tmp, yc_tmp, yr_tmp,
    test_size=0.176, random_state=RANDOM_STATE, stratify=yc_tmp
)
print(f"\nSplit — Train: {len(X_train):,} | Val: {len(X_val):,} | Test: {len(X_test):,}")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 5 — SMOTE sur train uniquement
# ════════════════════════════════════════════════════════════════
n_per_class = {lbl: yc_train.value_counts().get(lbl, 0) for lbl in range(4)}
print(f"\nDistribution train avant SMOTE: {dict(sorted(n_per_class.items()))}")

minority_threshold = max(n_per_class.values()) * 0.5
smote_strat = {
    lbl: max(n, int(minority_threshold))
    for lbl, n in n_per_class.items()
    if n < minority_threshold
}

if smote_strat:
    sm = SMOTE(sampling_strategy=smote_strat, k_neighbors=5, random_state=RANDOM_STATE)
    X_sm, yc_sm = sm.fit_resample(X_train, yc_train)
else:
    X_sm, yc_sm = X_train.copy(), yc_train.copy()

sw = compute_sample_weight('balanced', y=yc_sm)
print(f"Après SMOTE — Train: {len(X_sm):,} échantillons")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 6 — Classificateur XGBoost (inchangé)
# ════════════════════════════════════════════════════════════════
print("\nEntraînement du classificateur XGBoost...")
n_classes = len(df['pentest_label'].unique())

clf_base = xgb.XGBClassifier(
    n_estimators=500, max_depth=6, learning_rate=0.02,   # 1000 → 500
    objective='multi:softprob', num_class=n_classes,
    eval_metric='mlogloss',
    subsample=0.8, colsample_bytree=0.8,
    min_child_weight=5, gamma=0.1,
    reg_alpha=0.1, reg_lambda=1.5,
    random_state=RANDOM_STATE, n_jobs=-1, verbosity=0,
    early_stopping_rounds=30                              # 50 → 30
)
clf_base.fit(
    X_sm, yc_sm,
    sample_weight=sw,
    eval_set=[(X_sm, yc_sm), (X_val, yc_val)],
    verbose=False
)
best_iter = clf_base.best_iteration + 1
ml_best   = clf_base.evals_result()['validation_1']['mlogloss'][clf_base.best_iteration]
print(f"  Meilleure itération : {best_iter}")
print(f"  MLogLoss val (best) : {ml_best:.4f}")

print("  Calibration sur val set...")
clf_calibrated = CalibratedClassifierCV(
    xgb.XGBClassifier(
        n_estimators=best_iter, max_depth=6, learning_rate=0.02,
        objective='multi:softprob', num_class=n_classes,
        subsample=0.8, colsample_bytree=0.8,
        min_child_weight=5, gamma=0.1,
        reg_alpha=0.1, reg_lambda=1.5,
        random_state=RANDOM_STATE, n_jobs=-1, verbosity=0
    ),
    cv=3, method='isotonic'
)
clf_calibrated.fit(X_val, yc_val)
clf_calibrated.feature_names_in_ = np.array(FEATURES)

# ════════════════════════════════════════════════════════════════
# ÉTAPE 7 — Régresseur XGBoost (cvss_score)
# ════════════════════════════════════════════════════════════════
print("\nEntraînement du régresseur XGBoost...")

REG_FEATURES = [f for f in FEATURES if f not in
                ['cvss_score', 'severity_num', 'cvss_sq', 'severity_x_av',
                 'host_x_cvss', 'attack_surface']]
print(f"  Features régresseur : {len(REG_FEATURES)}")

reg = xgb.XGBRegressor(
    n_estimators=500, max_depth=5, learning_rate=0.02,   # 1000 → 500
    objective='reg:squarederror',
    subsample=0.8, colsample_bytree=0.8,
    min_child_weight=5, gamma=0.1,
    reg_alpha=0.1, reg_lambda=1.5,
    random_state=RANDOM_STATE, n_jobs=-1, verbosity=0,
    early_stopping_rounds=30                              # 50 → 30
)
reg.fit(
    X_train[REG_FEATURES], yr_train,
    eval_set=[(X_train[REG_FEATURES], yr_train),
              (X_val[REG_FEATURES], yr_val)],
    verbose=False
)
rm_best = reg.evals_result()['validation_1']['rmse'][reg.best_iteration]
print(f"  Meilleure itération : {reg.best_iteration + 1}")
print(f"  RMSE val (best)     : {rm_best:.4f}")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 8 — Évaluation sur test set
# ════════════════════════════════════════════════════════════════
yc_pred = clf_calibrated.predict(X_test)
y_prob  = clf_calibrated.predict_proba(X_test)
yr_pred = reg.predict(X_test[REG_FEATURES])
yr_test_vals = yr_test.values

rmse = np.sqrt(mean_squared_error(yr_test_vals, yr_pred))
mae  = np.mean(np.abs(yr_test_vals - yr_pred))

print(f"\n═══════════════════════════════════════════════════════════")
print(f"  Classificateur")
print(f"  MLogLoss (val best)  : {ml_best:.4f}")
print(f"  Accuracy (test)      : {(yc_pred == yc_test.values).mean():.4f}")
print(f"\n  Régresseur (cvss_score)")
print(f"  RMSE (test)          : {rmse:.4f}")
print(f"  MAE  (test)          : {mae:.4f}")
print(f"═══════════════════════════════════════════════════════════")
print(classification_report(yc_test, yc_pred, target_names=LABEL_NAMES))

# MAP@K et NDCG@K
def map_at_k(y_true, y_scores, k, relevant_class=3):
    order   = np.argsort(y_scores)[::-1][:k]
    hits    = (y_true[order] == relevant_class).astype(int)
    n_rel   = (y_true == relevant_class).sum()
    if n_rel == 0: return 0.0
    ap, n_hits = 0.0, 0
    for i, h in enumerate(hits):
        if h:
            n_hits += 1
            ap += n_hits / (i + 1)
    return ap / min(n_rel, k)

def ndcg_at_k(y_true, y_scores, k, relevant_class=3):
    order  = np.argsort(y_scores)[::-1][:k]
    gains  = (y_true[order] == relevant_class).astype(float)
    dcg    = np.sum(gains / np.log2(np.arange(2, k + 2)))
    ideal  = np.sort((y_true == relevant_class).astype(float))[::-1][:k]
    idcg   = np.sum(ideal / np.log2(np.arange(2, k + 2)))
    return dcg / idcg if idcg > 0 else 0.0

yc_test_arr = yc_test.values
rank_score  = y_prob[:, 3]

k_values = [5, 10, 15, 20, 30, 50]
maps  = [map_at_k(yc_test_arr, rank_score, k=k)  for k in k_values]
ndcgs = [ndcg_at_k(yc_test_arr, rank_score, k=k) for k in k_values]

print("\n  Métriques de ranking :")
print(f"  {'K':>4}  {'MAP@K':>8}  {'NDCG@K':>8}")
for k, m, n in zip(k_values, maps, ndcgs):
    print(f"  {k:>4}  {m:>8.4f}  {n:>8.4f}")

# ════════════════════════════════════════════════════════════════
# ÉTAPE 9 — Graphiques (identiques à avant)
# ════════════════════════════════════════════════════════════════

# 1. Distribution labels
fig, ax = plt.subplots(figsize=(10, 5))
colors_bar = ['#2ecc71','#f1c40f','#e67e22','#e74c3c']
counts = [label_counts.get(i,0) for i in range(4)]
bars = ax.bar(LABEL_NAMES, counts, color=colors_bar, edgecolor='white', linewidth=1.5)
for bar, cnt in zip(bars, counts):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 800,
            f'{100*cnt/len(df):.1f}%', ha='center', fontsize=11, fontweight='bold')
ax.set_title('Distribution des labels pentest (règles métier)', fontsize=13)
ax.set_ylabel('Nombre de vulnérabilités')
plt.tight_layout()
plt.savefig('data/graphiques/label_distribution.png', bbox_inches='tight', dpi=300)
plt.show()

# 2. Matrice de confusion
plt.figure(figsize=(8, 6))
ConfusionMatrixDisplay.from_predictions(
    yc_test, yc_pred, display_labels=LABEL_NAMES, cmap='Blues')
plt.title('Matrice de confusion (Test Set)')
plt.savefig('data/graphiques/confusion_matrix.png', bbox_inches='tight', dpi=300)
plt.show()

# 3. Courbes d'apprentissage
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 6))
ml_tr = clf_base.evals_result()['validation_0']['mlogloss']
ml_va = clf_base.evals_result()['validation_1']['mlogloss']
ax1.plot(ml_tr, label='Train', alpha=0.8, color='steelblue')
ax1.plot(ml_va, label='Val',   alpha=0.8, color='coral')
ax1.axvline(clf_base.best_iteration, color='red', linestyle='--',
            alpha=0.7, label=f'Best iter={best_iter}')
ax1.set_title('Classifieur — MLogLoss')
ax1.set_xlabel('Itération'); ax1.set_ylabel('MLogLoss'); ax1.legend()

rm_tr = reg.evals_result()['validation_0']['rmse']
rm_va = reg.evals_result()['validation_1']['rmse']
ax2.plot(rm_tr, label='Train', alpha=0.8, color='steelblue')
ax2.plot(rm_va, label='Val',   alpha=0.8, color='coral')
ax2.axvline(reg.best_iteration, color='red', linestyle='--',
            alpha=0.7, label=f'Best iter={reg.best_iteration+1}')
ax2.set_title('Régresseur — RMSE')
ax2.set_xlabel('Itération'); ax2.set_ylabel('RMSE'); ax2.legend()
plt.suptitle("Courbes d'apprentissage", fontsize=14)
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig('data/graphiques/training_curves.png', bbox_inches='tight', dpi=300)
plt.show()

# 4. Métriques par classe
report = classification_report(yc_test, yc_pred, target_names=LABEL_NAMES, output_dict=True)
df_rep = pd.DataFrame(report).transpose().drop(columns=['support'])
fig, ax = plt.subplots(figsize=(11, 6))
df_rep[['precision','recall','f1-score']].plot(
    kind='bar', ax=ax, color=['#3498db','#e67e22','#2ecc71'], edgecolor='white')
ax.set_title('Métriques par classe (Test Set)')
ax.set_ylabel('Score'); ax.set_ylim(0, 1.1)
ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')
plt.tight_layout()
plt.savefig('data/graphiques/metrics_by_class.png', bbox_inches='tight', dpi=300)
plt.show()

# 5. ROC et PR
lb = LabelBinarizer()
y_test_bin = lb.fit_transform(yc_test)
colors_roc = ['#3498db','#f1c40f','#e67e22','#e74c3c']
fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(18, 6))
for i, (name, col) in enumerate(zip(LABEL_NAMES, colors_roc)):
    fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_prob[:, i])
    ax_roc.plot(fpr, tpr, label=f'{name} (AUC={auc(fpr,tpr):.3f})', color=col)
    prec, rec, _ = precision_recall_curve(y_test_bin[:, i], y_prob[:, i])
    ap = average_precision_score(y_test_bin[:, i], y_prob[:, i])
    ax_pr.plot(rec, prec, label=f'{name} (AP={ap:.3f})', color=col)
ax_roc.plot([0,1],[0,1],'k--', alpha=0.4, label='Aléatoire')
ax_roc.set_title('Courbes ROC'); ax_roc.legend(loc='lower right')
ax_pr.set_title('Précision-Rappel'); ax_pr.legend(loc='upper right')
plt.suptitle('ROC & Précision-Rappel (Test Set)', fontsize=14)
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig('data/graphiques/roc_pr_curves.png', bbox_inches='tight', dpi=300)
plt.show()

# 6. Feature importance
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 8))
xgb.plot_importance(clf_base, max_num_features=15, importance_type='gain', ax=ax1)
ax1.set_title('Importance — Classifieur (gain)')
xgb.plot_importance(reg, max_num_features=15, importance_type='gain', ax=ax2)
ax2.set_title('Importance — Régresseur (gain)')
plt.suptitle('Importance des Caractéristiques', fontsize=14)
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig('data/graphiques/feature_importances.png', bbox_inches='tight', dpi=300)
plt.show()

# 7. Régresseur réel vs prédit
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 6))
ax1.hist(yr_pred,      bins=50, alpha=0.7, label='Prédictions', color='steelblue')
ax1.hist(yr_test_vals, bins=50, alpha=0.7, label='Réel',        color='coral')
ax1.legend(); ax1.set_title('CVSS Score — Réel vs Prédit')
idx = np.random.choice(len(yr_test_vals), min(5000, len(yr_test_vals)), replace=False)
ax2.scatter(yr_test_vals[idx], yr_pred[idx], alpha=0.15, s=5, color='steelblue')
ax2.plot([0,10],[0,10], 'r--', lw=2, label='Parfait')
ax2.set_title(f'CVSS Réel vs Prédit — RMSE={rmse:.3f}')
ax2.legend()
plt.suptitle('Analyse du Régresseur', fontsize=14)
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig('data/graphiques/regressor_analysis.png', bbox_inches='tight', dpi=300)
plt.show()

# 8. MAP@K et NDCG@K
fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(k_values, maps,  marker='o', label='MAP@K',  color='steelblue', linewidth=2)
ax.plot(k_values, ndcgs, marker='s', label='NDCG@K', color='coral',     linewidth=2)
for k, m, n in zip(k_values, maps, ndcgs):
    ax.annotate(f'{m:.2f}', (k, m), textcoords='offset points',
                xytext=(0,8), ha='center', fontsize=9, color='steelblue')
    ax.annotate(f'{n:.2f}', (k, n), textcoords='offset points',
                xytext=(0,-14), ha='center', fontsize=9, color='coral')
ax.set_title('MAP@K & NDCG@K — Qualité du Ranking')
ax.set_xlabel('K'); ax.set_ylabel('Score'); ax.set_ylim(0, 1.1)
ax.legend(); ax.grid(True)
plt.tight_layout()
plt.savefig('data/graphiques/ranking_metrics.png', bbox_inches='tight', dpi=300)
plt.show()

# ════════════════════════════════════════════════════════════════
# RÉSUMÉ FINAL
# ════════════════════════════════════════════════════════════════
print("\n╔══════════════════════════════════════════════════════════╗")
print("║              RÉSUMÉ FINAL — TEST SET                    ║")
print("╠══════════════════════════════════════════════════════════╣")
print(f"║  CLASSIFICATEUR                                         ║")
print(f"║    MLogLoss (val best) : {ml_best:.4f}                        ║")
print(f"║    Accuracy            : {(yc_pred==yc_test.values).mean():.4f}                        ║")
print(f"║    F1 macro            : {pd.DataFrame(report)['macro avg']['f1-score']:.4f}                        ║")
print("╠══════════════════════════════════════════════════════════╣")
print(f"║  RÉGRESSEUR (cvss_score)                                ║")
print(f"║    RMSE                : {rmse:.4f}                        ║")
print(f"║    MAE                 : {mae:.4f}                        ║")
print("╠══════════════════════════════════════════════════════════╣")
print(f"║  RANKING                                                ║")
print(f"║    MAP@10              : {maps[1]:.4f}                        ║")
print(f"║    NDCG@10             : {ndcgs[1]:.4f}                        ║")
print(f"║    MAP@20              : {maps[3]:.4f}                        ║")
print(f"║    NDCG@20             : {ndcgs[3]:.4f}                        ║")
print("╚══════════════════════════════════════════════════════════╝")

# Sauvegarde
joblib.dump(clf_calibrated, 'data/model/classificateur_xgb.joblib')
joblib.dump(reg,            'data/model/regresseur_xgb.joblib')
joblib.dump(np.array(REG_FEATURES), 'data/model/reg_features.joblib')

print("\n✅ Modèles sauvegardés dans data/model/")
print("✅ Graphiques dans data/graphiques/")
