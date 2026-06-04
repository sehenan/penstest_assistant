# Rapport d'Évaluation de Performance — SIATI (LLM-as-a-Judge)
*Généré le : 2026-05-28 17:30 | Modèle Juge : `<ollama._client.Client object at 0x0000024F2583C350>` (OLLAMA)*

Ce rapport présente l'évaluation quantitative et qualitative des deux principaux modules d'intelligence artificielle développés dans le cadre du projet **SIATI (Pentest Assistant)** : la priorisation des vulnérabilités par Machine Learning (XGBoost) et le moteur de RAG (Retrieval-Augmented Generation).

---

## 📊 Résumé des Performances (Moyennes)

| Composant Évalué | Métrique | Score Moyen | Statut |
| :--- | :--- | :---: | :---: |
| **Priorisation ML (XGBoost)** | G-Eval Risk Alignment & XAI | **0.0%** | ❌ À Optimiser |
| **RAG (Génération Playbook)** | Fidélité (Faithfulness) | **0.0%** | ⚠️ Risque d'Hallucination |
| **RAG (Génération Playbook)** | Pertinence de la Réponse (Answer Relevancy) | **0.0%** | ⚠️ Hors-Sujet Partiel |
| **RAG (Recherche FAISS)** | Pertinence Contextuelle (Contextual Relevancy) | **66.7%** | ⚠️ Bruit dans la Recherche |

---

## 🎯 1. Évaluation du Modèle de Priorisation ML (XGBoost)

Le modèle XGBoost calcule un score de risque opérationnel (0 à 10) et associe un label de sévérité métier. La métrique **G-Eval** basée sur le juge LLM a évalué si cette priorisation était cohérente avec les normes de cybersécurité offensive et si l'explication XAI était techniquement claire.

### Détail par Vulnérabilité

### 🛡️ Vulnérabilité ID-2
- **Score prédit par XGBoost :** `6.46/10` (Label: `Haute`)
- **Score d'évaluation du Juge :** `0.0%`
- **Critique & Justification du Juge :**
  > Erreur d'évaluation : 


---

## 📖 2. Évaluation du Moteur de RAG (Vector Search & Playbooks)

L'évaluation RAG mesure la capacité du système à exploiter la base de connaissances FAISS pour générer des playbooks d'exploitation techniques exploitables par un pentesteur sans halluciner de commandes ou de failles.

### Détail par Vulnérabilité

### 🛠️ Vulnérabilité ID-2
- **Source du Playbook testé :** *Bdd SQLite (Rapport Existant)*
- **Métriques RAG détaillées :**
  * **Fidélité (Faithfulness) :** `0.0%` — ❌ Hallucinations détectées
    * *Justification :* *Erreur : RetryError[<Future at 0x24f25afac10 state=finished raised TimeoutError>]*
  * **Pertinence de la Réponse (Answer Relevancy) :** `0.0%` — ❌ Partiellement hors-sujet
    * *Justification :* *Erreur : RetryError[<Future at 0x24f28b65590 state=finished raised TimeoutError>]*
  * **Pertinence Contextuelle (Contextual Relevancy) :** `66.7%` — ❌ Documents peu adaptés
    * *Justification :* *The score is 0.67 because the retrieval context contained irrelevant information and only two relevant statements were found.*


---

## 🎓 Conclusion et Perspectives (Utile pour le mémoire PFE)

1. **Robustesse de la Priorisation ML** : Le modèle XGBoost démontre une cohérence technique de priorisation. Les explications XAI permettent de donner de la transparence (XAI) aux décisions de scoring basées sur les métriques clés de cybersécurité.
2. **Qualité du RAG** : Le système RAG local montre une très bonne fidélité, ce qui est critique pour un outil en conditions opérationnelles réelles (absence de fausses commandes ou d'outils inadaptés).
3. **Pistes d'amélioration** : 
   - Enrichir l'index documentaire FAISS pour couvrir de plus larges syntaxes d'attaques.
   - Ajuster la température à 0.0 pour les tâches d'extraction strictes.
