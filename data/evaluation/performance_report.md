# Rapport de Performance - Modèle XGBoost SIATI

## 1. Résumé Exécutif
Ce modèle de régression XGBoost a été entraîné pour prédire le score de risque des vulnérabilités. 
Les performances ont été mesurées via une validation croisée (K-Fold) et un test set indépendant.

**Métriques Clés :**
- **RMSE (Root Mean Square Error) :** 1.2565
- **R² (Coefficient de Détermination) :** 0.6602
- **Précision de Classification (Accuracy) :** 62.49%
- **F1-Score (Weighted) :** 0.6104
- **Validations Croisée (RMSE moyen) :** 1.2546

---

## 2. Analyse de Classification
Le modèle convertit son score continu [0-10] en catégories de sévérité. 
Voici les performances par classe :

```text
              precision    recall  f1-score   support

      Faible       0.53      0.07      0.12       596
       Moyen       0.45      0.51      0.47      2598
        Haut       0.48      0.53      0.50      2382
    Critique       0.97      0.94      0.96      2648

    accuracy                           0.62      8224
   macro avg       0.61      0.51      0.51      8224
weighted avg       0.63      0.62      0.61      8224

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
*Généré automatiquement par SIATI Pentest Assistant le 2026-04-20T21:25:54.008753*
