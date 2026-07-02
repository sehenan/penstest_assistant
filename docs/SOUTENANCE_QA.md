# SIATI — Préparation à la soutenance : questions du jury & réponses

> Document de préparation. Pour chaque zone sensible : la **question probable**, une
> **réponse solide et honnête**, et le **piège à éviter**. Les points ont été
> renforcés par les corrections apportées (tests verts, sécurité câblée, cohérence
> config, alignement des modèles).

---

## 1. Machine Learning / IA — la zone la plus attaquée

### Q1.1 — « Votre "vérité terrain" (`gold_risk_score`) est une formule que vous avez inventée. Qu'apprend réellement le modèle ? »
**Réponse.** Le `gold_risk_score` est un **score métier de priorisation**, pas une vérité empirique — je l'assume comme tel. Il combine impact (CVSS), probabilité d'exploitation (EPSS), preuve d'exploitation réelle (CISA KEV, Exploit-DB) et contexte de service. Le rôle du modèle n'est **pas** de redécouvrir cette formule : les features d'entrée (`epss`, âge de la CVE, complexité d'attaque, privilèges requis, interaction utilisateur, type de service/port) **ne contiennent NI le CVSS NI le flag KEV** — les deux termes les plus lourds de la cible. Le modèle apprend donc à **estimer une priorité de risque à partir de signaux d'exploitabilité et de contexte**, y compris quand le CVSS est absent du scan (cas fréquent en pentest réel : un service détecté sans CVE mappée).

**Piège à éviter.** Ne dites jamais « mon modèle découvre le risque ». Dites : « c'est un système de scoring expert dont j'ai appris une **approximation généralisable** à partir de features disjointes de la cible ». C'est défendable ; l'inverse ne l'est pas.

### Q1.2 — « EPSS est à la fois une feature ET le terme dominant de la cible (×6.5). N'est-ce pas de la fuite de données ? »
**Réponse.** C'est le point le plus subtil et je le connais. Oui, EPSS pèse dans la cible et est aussi une feature : sur ce terme, le modèle a effectivement une tâche facile. Mais (1) c'est **légitime** — EPSS est LE signal probabiliste de référence, l'ignorer serait absurde ; (2) les autres termes lourds (CVSS, KEV) sont **volontairement retirés des features** (`FEATURE_COLS` dans `features.py`), ce qui crée un vrai plafond d'erreur irréductible et empêche la tautologie complète ; (3) le fichier `features.py` documente explicitement « sans fuite de données » pour ces choix.

### Q1.3 — « Classification ou régression ? »
**Réponse.** Les deux, complémentaires : un **régresseur XGBoost** produit un score continu (0–10) pour le tri fin, et un **classificateur calibré** (`CalibratedClassifierCV`) produit un label métier (Faible/Moyenne/Haute/Critique) + une **probabilité de confiance** affichée dans l'UI. La calibration est essentielle : elle donne des probabilités interprétables, pas juste un argmax.

### Q1.4 — « Comment garantissez-vous la reproductibilité du modèle ? »
**Réponse.** Les artefacts (`data/model/*.joblib`) ont été sérialisés avec **scikit-learn 1.6.1** ; `requirements.txt` est désormais **épinglé sur cette même version** pour éviter tout `InconsistentVersionWarning` au dépicklage (un écart de version peut fausser l'inférence). `random_state=42` est fixé dans les splits et l'entraînement.

### Q1.5 — « Métriques d'évaluation ? »
**Réponse.** Régression : MSE / RMSE + courbe prédictions-vs-vérité et courbes d'apprentissage (`app/core/ml/evaluate.py`, sorties dans `data/evaluation/`). Classification : matrice de confusion + importance des features (SHAP/feature\_importance). L'endpoint `/api/performance` expose ces métriques et graphiques dans le dashboard.

---

## 2. Sécurité

### Q2.1 — « Un outil de pentest… et l'API n'a aucune authentification ? »
**Réponse.** L'infrastructure JWT (hachage bcrypt, tokens signés, rôles) existe dans `app/core/security.py`, et elle est désormais **câblée** :
- Les routes **destructives** (`DELETE /api/clear-db`, `DELETE /api/vulns/{id}`, `DELETE /api/reports/{id}`, `POST /api/ingest`, `POST /api/score`) passent par la garde `require_auth`.
- Les routes de lecture valident le token **s'il est fourni** (`verify_token_optional`) : un jeton falsifié est rejeté (401), au lieu d'être silencieusement accepté.
- Le mode est piloté par `SIATI_REQUIRE_AUTH` : **OFF par défaut** (usage local / air-gap, API liée à 127.0.0.1, mono-utilisateur — auth obligatoire inutile et contre-productive) ; **ON** pour un déploiement réseau, où un token valide devient obligatoire.

**Piège à éviter.** N'affirmez pas « c'est 100 % sécurisé ». Dites : « la sécurité est **proportionnée au modèle de menace** : air-gap local par défaut, durcissement activable par configuration ».

### Q2.2 — « Votre clé secrète JWT était en dur dans le code. »
**Réponse.** Corrigé : `SECRET_KEY` est lu depuis l'environnement (`os.environ`), avec un repli de développement explicitement marqué comme non-production. Le `.env` a par ailleurs été **retiré du suivi Git** (il y figurait par erreur alors qu'il est dans `.gitignore`).

### Q2.3 — « Injection / XSS ? »
**Réponse.** Les entrées passent par `sanitize_input` (`error_handler.py`), réécrit pour retirer les blocs `<script>…</script>` **avec leur contenu**, les balises HTML résiduelles et les fragments partiels — récursivement sur dicts et listes. Côté base, l'ORM SQLAlchemy paramètre toutes les requêtes (pas de concaténation SQL). Des tests dédiés couvrent l'injection SQL et le XSS (`test_integration_e2e.py::TestSecurity`).

### Q2.4 — « Rate limiting ? »
**Réponse.** Décorateur `@rate_limit` (Redis avec repli mémoire) appliqué p.ex. sur `/api/stats` (60 req/min). Testé unitairement, isolé par instance pour éviter la contamination d'état.

---

## 3. Architecture & Ingénierie

### Q3.1 — « Pourquoi deux piles LLM/RAG (`app/core/llm` et `app/module_llm`) ? »
**Réponse.** Choix assumé de séparation :
- `app/core/llm` : pile **runtime** légère, servie par l'API (chat streaming + playbook standard), configurée par variables d'environnement, optimisée pour la latence (index FAISS mis en cache mémoire, streaming token-par-token).
- `app/module_llm` : pile **V2 "PRO"** en CLI (`playbook-v2`, `index-rag-v2`), RAG strict avec **citations de sources** et chunking Tiktoken, configurée par `config.yaml`.
La première privilégie l'expérience temps réel ; la seconde, la traçabilité documentaire. `config.yaml` documente désormais explicitement qui lit quoi.

### Q3.2 — « Air-gap : prouvez qu'il n'y a aucun appel réseau sortant. »
**Réponse.** L'enrichissement interroge des **bases locales** (`enrich_vulnerabilities_from_local_intel` lit la Threat Intel SQLite locale — NVD/EPSS/KEV pré-ingérés, plus d'appel à l'API NVD en direct). Le RAG (FAISS + SentenceTransformers) et le LLM (Ollama) tournent en local. Seul `localhost:11434` (Ollama) et éventuellement Redis local sont contactés.

### Q3.3 — « Isolation des tests / pollution de la base ? »
**Réponse.** Corrigé à la racine : la résolution de l'URL de base est **dynamique** (`PENTEST_DB_URL` / `SIATI_DB_PATH`), ce qui permet aux tests d'intégration d'utiliser une **base temporaire** partagée avec les routes de l'API — plus aucune écriture de test dans `data/pentest.db`. Cette base runtime a d'ailleurs été retirée du suivi Git.

### Q3.4 — « Robustesse face à un scan corrompu ? »
**Réponse.** Les parsers utilisent `XMLParser(recover=True)` : un export Nmap tronqué (crash réseau, export incomplet) ne fait **pas** planter l'ingestion — les hôtes déjà exploitables sont récupérés. C'est un choix volontaire de résilience, couvert par `test_robustness.py`.

---

## 4. RAG & LLM

### Q4.1 — « Comment évitez-vous les hallucinations du LLM ? »
**Réponse.** Plusieurs garde-fous : (1) `build_rag_context` distingue une CVE **confirmée** par l'intel base d'une CVE non confirmée, et instruit explicitement le modèle de **ne pas inventer** le mapping version↔CVE ; (2) température basse ; (3) un **garde-fou d'impact CVSS** filtre les playbooks incohérents ; (4) la voie V2 impose la **citation des sources** récupérées. Le contexte injecté ne contient que des données confirmées localement.

### Q4.2 — « Pourquoi `all-MiniLM-L6-v2` et FAISS ? »
**Réponse.** MiniLM : excellent compromis qualité/latence sur CPU (384 dims), compatible air-gap (poids locaux). FAISS `IndexFlatL2` : recherche exacte, suffisante à l'échelle de la base (~23K chunks), sans dépendance serveur. L'index est **chargé une fois en cache mémoire** pour éviter de relire le disque à chaque message.

### Q4.3 — « Le chat était lent — qu'avez-vous fait ? »
**Réponse.** Trois causes traitées sans dégrader la qualité (même modèle, même prompt, mêmes options) : cache mémoire de l'index FAISS (relecture disque supprimée), **streaming** de la réponse (premier token en quelques secondes au lieu d'attendre ~1500 tokens), et suppression des vérifications d'état Ollama redondantes.

---

## 5. Qualité, tests, CI

### Q5.1 — « Quelle est la couverture de tests ? »
**Réponse.** **124 tests passants**, couvrant parsers, ingestion, ML (feature engineering + inférence), enrichissement offline, sécurité (JWT, rate-limit, sanitization), gestion d'erreurs, et intégration E2E de l'API. Les tests obsolètes (ancienne API v1) ont été **réécrits** pour cibler l'API réelle, pas supprimés.

### Q5.2 — « La CI est-elle verte ? »
**Réponse.** Le workflow `.github/workflows/ci-cd.yml` lance `pytest` avec couverture. Point d'attention à mentionner : il cible Python 3.10 alors que l'environnement de dev est 3.12 — à aligner. (Si la question vient : « oui, je l'aligne sur 3.12. »)

### Q5.3 — « Import PDF ? »
**Réponse.** Ajout d'un parser `pdf_parser.py` (pypdf, pur-Python, offline) : extraction texte page par page + heuristique de reconstruction hôte/port/service/CVE, branché dans la détection de format et l'UI (`accept=".pdf"`). L'ingestion a par ailleurs été accélérée (traduction des descriptions sans appel LLM par vulnérabilité).

---

## 6. Questions « méta » fréquentes

- **« Qu'est-ce qui est vraiment à vous vs. bibliothèques ? »** → À moi : le pipeline d'orchestration, le feature engineering sans fuite, le scoring métier, les garde-fous anti-hallucination, l'intégration RAG↔intel base, l'UI. Bibliothèques : XGBoost, FAISS, SentenceTransformers, Ollama, FastAPI.
- **« Limite principale ? »** → La cible ML est un score expert, pas une vérité empirique issue d'incidents réels ; l'amélioration future serait un jeu de données d'exploitations avérées pour un vrai apprentissage supervisé de l'exploitabilité.
- **« Prochaine étape ? »** → Auth réseau complète avec store utilisateurs + endpoint `/api/auth/login`, alignement CI Python 3.12, et enrichissement du dataset d'entraînement.

---

### Rappel de posture
Assumez les choix. Un jury valorise « voici pourquoi j'ai fait ce compromis, en voici les limites » bien plus que « c'est parfait ». Vos points fragiles connus (cible ML, air-gap vs auth) deviennent des forces dès que vous montrez que **vous les avez identifiés et raisonnés**.
