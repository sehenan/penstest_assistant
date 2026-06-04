"""
report_generator.py
===================
Génère un rapport de performance consolidé (Markdown) pour le modèle ML.
Utile pour le mémoire PFE et l'affichage dans le Dashboard.
"""
import json
from pathlib import Path

METRICS_PATH = Path("data") / "metrics_xgb.json"
REPORT_PATH = Path("data") / "evaluation" / "performance_report.md"
EVAL_DIR = Path("data") / "evaluation"

def generate_performance_report():
    if not METRICS_PATH.exists():
        return "Erreur : Aucune métrique trouvée. Lancez l'entraînement d'abord."

    with open(METRICS_PATH, "r") as f:
        m = json.load(f)

    # Lecture du rapport de classification si existant
    class_report = ""
    cr_path = EVAL_DIR / "classification_report.txt"
    if cr_path.exists():
        class_report = cr_path.read_text()

    report = f"""# Rapport de Performance - Modèle XGBoost SIATI

## 1. Résumé Exécutif
Ce modèle de régression XGBoost a été entraîné pour prédire le score de risque des vulnérabilités. 
Les performances ont été mesurées via une validation croisée (K-Fold) et un test set indépendant.

**Métriques Clés :**
- **RMSE (Root Mean Square Error) :** {m.get('rmse', 0):.4f}
- **R² (Coefficient de Détermination) :** {m.get('r2', 0):.4f}
- **Précision de Classification (Accuracy) :** {m.get('accuracy', 0):.2%}
- **F1-Score (Weighted) :** {m.get('f1_score', 0):.4f}
- **Validations Croisée (RMSE moyen) :** {m.get('cv_rmse', 0):.4f}

---

## 2. Analyse de Classification
Le modèle convertit son score continu [0-10] en catégories de sévérité. 
Voici les performances par classe :

```text
{class_report}
```

---

## 3. Visualisations de Performance

### Matrice de Confusion
Affiche la capacité du modèle à classer correctement les niveaux de risque (Critique vs Haut vs Moyen).
![Matrice de Confusion](data/evaluation/06_confusion_matrix.png)

### Importance des Features
Quels critères influencent le plus le score de risque ?
![Importance des Features](data/evaluation/02_feature_importance.png)

### Courbe d'Apprentissage
Vérification que le modèle ne sur-apprend pas (Overfitting) et profite de nouvelles données.
![Learning Curve](data/evaluation/04_learning_curve.png)

### Résidus
Distribution des erreurs de prédiction.
![Résidus](data/evaluation/03_residuals.png)

---
*Généré automatiquement par SIATI Pentest Assistant le {m.get('timestamp')}*
"""
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    return REPORT_PATH

if __name__ == "__main__":
    path = generate_performance_report()
    print(f"Rapport généré : {path}")
