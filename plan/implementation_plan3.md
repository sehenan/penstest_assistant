# Plan d'implémentation — PFE | Module 3 : Priorisation ML

Ce plan détaille l'implémentation du **Module 3 : Priorisation par Machine Learning** avec XGBoost, permettant de scorer les vulnérabilités de manière contextuelle (bien au-delà d'un simple CVSS).

## User Review Required

> [!NOTE]
> Nous abordons la pierre angulaire de votre PFE. Le code sera décomposé en 3 fichiers clairs (`features.py`, `train.py` et `predict.py`) pour séparer l'extraction de données, l'entraînement et l'inférence.
> **Merci de valider si les hypothèses sur les *features* (voir Open Questions) correspondent à votre vision de Pentester.**

## Proposed Changes

### [NEW] [app/core/ml/features.py](file:///d:/Aptitudes/PFE/penstest_assistant/app/core/ml/features.py)
Création d'un module de **Feature Engineering**. Il va lire la base de données (Tables `Host`, `Service`, `Vulnerability`, `Exploit`) et construire un `pandas.DataFrame` propre.
- **Features extraites** : `cvss_score`, `port`, `service_name` (encodé), `has_exploit` (bool).
- **Features dérivées** : `is_public_facing` (ex: ports 80/443 = 1, sinon 0), et `is_eol` (mocké ou loggué).

### [NEW] [app/core/ml/train.py](file:///d:/Aptitudes/PFE/penstest_assistant/app/core/ml/train.py)
Création d'un script d'entraînement (permettant au modèle d'apprendre sur d'anciens rapports).
- **Baseline** : `LogisticRegression`.
- **Primary Model** : `XGBoostRegressor` ou `XGBoostClassifier` (selon qu'on préfère un score continu ou de la classification binaire).
- **Pipeline** : Un objet `Scikit-Learn Pipeline` incluant un encodeur `OneHot` et un `StandardScaler` qui sera sauvegardé dans `data/model_xgb.joblib` ou `data/model_xgb.pkl`.

### [NEW] [app/core/ml/predict.py](file:///d:/Aptitudes/PFE/penstest_assistant/app/core/ml/predict.py)
Création du module d'inférence (utilisé en phase post-scan).
- Récupère le dataframe des nouvelles vulnérabilités, load le modèle `.pkl`, infère le score de risque Contextuel (0 à 1) et injecte le résultat dans la table `scores_ml`.

### [NEW] [tests/test_ml.py](file:///d:/Aptitudes/PFE/penstest_assistant/tests/test_ml.py)
Ajout d'un test pipeline unitaire (création d'un mini-dataset de vulnérabilités, génération des features, train/predict rapide).

## Open Questions

> [!IMPORTANT]
> 1. **Classification vs Régression** : Voulez-vous que le modèle prédise un score continu de Risque (de 0.0 à 1.0 ou 0.0 à 10.0), ou plutôt une classe de sévérité (ex: "Critique", "Haut", "Moyen") ? Un score continu (Régression logistique / XGBRegressor) permet souvent un tri "Top-N" plus précis.
> 2. **L'entraînement des données (Training Data)** : En tant que Pentester, n'ayant pas nativement des milliers de rapports "labellisés", nous allons concevoir une fonction qui permet de générer des **données synthétiques (Mock)** pour tester l'entraînement (ex : `cvss > 7` + `exploit=True` = Risque extrême). Cela vous va-t-il pour la soutenance ?
> 3. **Bibliothèques manquantes** : `xgboost`, `scikit-learn` et `joblib` ne sont techniquement pas encore dans votre `requirements.txt`. Puis-je les installer et populer le `requirements.txt` ?

## Verification Plan

### Automated Tests
- Exécution de pytest ciblant le pipeline ML : simulation d'extraction de données depuis un test SQLite, entrainement à la volée du modèle et prédiction pour s'assurer que les dimensions des matrices (shapes) sont valides.

### Manual Verification
- Appel explicite à la fonction `prioritize_vulnerabilities()` via via un script, puis inspection de la base SQLite (`scores_ml`) pour valider la logique de scoring.
