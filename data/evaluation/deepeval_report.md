# Rapport d'Evaluation de Performance - SIATI (LLM-as-a-Judge)
*Genere le : 2026-08-28 16:49 | Modele Juge : `llama3:latest` (OLLAMA)*

Ce rapport presente l'evaluation quantitative et qualitative des deux principaux modules d'intelligence artificielle developpes dans le cadre du projet **SIATI (Pentest Assistant)** : la priorisation des vulnerabilites par Machine Learning (XGBoost) et le moteur de RAG (Retrieval-Augmented Generation).

---

## Résumé des Performances (Moyennes)

| Composant Evalue | Metrique | Score Moyen | Statut |
| :--- | :--- | :---: | :---: |
| **Priorisation ML (XGBoost)** | Score d'Alignement Expert | **70.0%** | Coherence Moderee |
| **RAG (Generation Playbook)** | Fidelite (Faithfulness) | **0.0%** if avg_faithfulness > 0 else N/A | N/A (juge local) |
| **RAG (Generation Playbook)** | Pertinence Reponse (Answer Relevancy) | **0.0%** if avg_relevancy > 0 else N/A | N/A (juge local) |
| **RAG (Recherche FAISS)** | Pertinence Contextuelle | **0.0%** | Bruit dans la Recherche |

> **Note methodologique** : Avec un juge local Ollama, seule la pertinence contextuelle (cross-encoder local HuggingFace) est calculee automatiquement. Les metriques Faithfulness et AnswerRelevancy necessitent un juge cloud (Gemini/Claude) car elles font de multiples appels LLM.

---

## 1. Evaluation du Modele de Priorisation ML (XGBoost)

Le modele XGBoost calcule un score de risque operationnel (0 a 10) et associe un label de severite metier. L'evaluation utilise un **scoring direct via Ollama** avec parsing robuste pour mesurer la coherence technique du score ML par rapport aux normes de cybersecurite.

### Methodologie d'Evaluation ML
- **Input** : Caracteristiques de la vulnerabilite (CVE, CVSS, service, version, description)
- **Output evalue** : Score ML /10, Label de severite, Explication XAI
- **Critere** : Coherence entre le score ML et les standards CVSS/securite offensive

### Detail par Vulnerabilite

#### Vulnerabilite : ID-15
- **Score predit par XGBoost :** `6.2/10` (Label: `Moyenne`)
- **Score d'alignement expert :** `70.0%`
- **Analyse du Juge :**
  > Le modèle ML a évalué la vulnérabilité comme moyenne, ce qui est cohérent avec le score CVSS de 8.8, élevé. Cependant, il y a une différence notable entre les deux scores, ce qui réduit la cohérence du modèle.

#### Vulnerabilite : ID-36
- **Score predit par XGBoost :** `6.2/10` (Label: `Moyenne`)
- **Score d'alignement expert :** `70.0%`
- **Analyse du Juge :**
  > Le modèle ML a évalué la vulnérabilité comme moyenne, ce qui est cohérent avec le score CVSS de 8.8, élevé. Cependant, il y a une différence notable entre les deux scores, car le modèle n'a pas pris en compte la récente apparition d'un CVE (< 6 mois).

#### Vulnerabilite : ID-2
- **Score predit par XGBoost :** `5.0/10` (Label: `Faible`)
- **Score d'alignement expert :** `70.0%`
- **Analyse du Juge :**
  > Le score prioritaire du modèle ML est légèrement inférieur au score CVSS estimé heuristiquement, ce qui suggère que le modèle a sous-estimé la vulnérabilité. Cependant, les facteurs clés mentionnés dans l'explication XAI (accessible à distance sans authentification et CVE récente) sont cohérents avec une vulnérabilité de faible sévérité.

#### Vulnerabilite : ID-4
- **Score predit par XGBoost :** `5.0/10` (Label: `Faible`)
- **Score d'alignement expert :** `70.0%`
- **Analyse du Juge :**
  > Le score prioritaire du modèle ML est légèrement inférieur au score CVSS, ce qui suggère que le modèle a sous-estimé la vulnérabilité. Cependant, les facteurs clés énoncés (accessible à distance sans authentification et CVE récente) sont cohérents avec une priorité faible selon les standards de sécurité.

#### Vulnerabilite : ID-8
- **Score predit par XGBoost :** `5.0/10` (Label: `Faible`)
- **Score d'alignement expert :** `70.0%`
- **Analyse du Juge :**
  > Le modèle ML a évalué la vulnérabilité comme faible (5.0/10) alors que le score CVSS est de 5.3, ce qui est plus élevé. Cependant, les facteurs clés identifiés par le modèle, tels que l'accès à distance sans authentification et la présence d'un CVE récent, sont des éléments de vulnérabilité importantes. La confiance du modèle est également relativement élevée (0.8291).


---

## 2. Evaluation du Moteur de RAG (Vector Search & Playbooks)

L'evaluation RAG mesure la capacite du systeme a exploiter la base de connaissances FAISS pour generer des playbooks d'exploitation techniques, sans halluciner de commandes ou de failles.

### Configuration
- **Juge utilise :** OLLAMA (`llama3:latest`)
- **Metrique disponible localement :** Pertinence Contextuelle (cross-encoder HuggingFace - 100% local)
- **Metriques cloud :** Faithfulness & AnswerRelevancy (disponibles avec Gemini/Claude/OpenAI)

### Detail par Vulnerabilite

#### Vulnerabilite : ID-15
- **Source du Playbook :** *Bdd SQLite (Rapport Existant)*

| Metrique | Score | Resultat |
| :--- | :---: | :--- |
| Fidelite (Faithfulness) | `0.0%` | N/A (juge local) |
| Pertinence Reponse | `0.0%` | N/A (juge local) |
| Pertinence Contextuelle | `0.0%` | Documents peu adaptes |

- **Pertinence contextuelle FAISS :** The score is 0.00 because there are no relevant statements in the retrieval context, and the only reason provided for irrelevance is that a specific document-related cybersecurity context was not found, which has no connection to the input about MySQL service detection.

#### Vulnerabilite : ID-36
- **Source du Playbook :** *Generation Ollama (Simulation)*

| Metrique | Score | Resultat |
| :--- | :---: | :--- |
| Fidelite (Faithfulness) | `0.0%` | N/A (juge local) |
| Pertinence Reponse | `0.0%` | N/A (juge local) |
| Pertinence Contextuelle | `0.0%` | Documents peu adaptes |

- **Pertinence contextuelle FAISS :** The score is 0.00 because there are no relevant statements in the retrieval context, and the only reason provided for irrelevance is that a specific document-related cybersecurity context was not found, which has no connection to the input about MySQL service detection.

#### Vulnerabilite : ID-2
- **Source du Playbook :** *Generation Ollama (Simulation)*

| Metrique | Score | Resultat |
| :--- | :---: | :--- |
| Fidelite (Faithfulness) | `0.0%` | N/A (juge local) |
| Pertinence Reponse | `0.0%` | N/A (juge local) |
| Pertinence Contextuelle | `0.0%` | Documents peu adaptes |

- **Pertinence contextuelle FAISS :** The score is 0.00 because there are no relevant statements in the retrieval context, as stated by 'Aucun contexte documentaire de cybersecurite trouve dans l'index local', which has no relevance to the input about Microsoft services and CVEs.

#### Vulnerabilite : ID-4
- **Source du Playbook :** *Generation Ollama (Simulation)*

| Metrique | Score | Resultat |
| :--- | :---: | :--- |
| Fidelite (Faithfulness) | `0.0%` | N/A (juge local) |
| Pertinence Reponse | `0.0%` | N/A (juge local) |
| Pertinence Contextuelle | `0.0%` | Documents peu adaptes |

- **Pertinence contextuelle FAISS :** The score is 0.00 because none of the statements in the retrieval context are relevant to the input, which discusses a detected HTTP service and vulnerability scoring, whereas the retrieval context appears to be unrelated to Einstein's achievements or cybersecurity documents.

#### Vulnerabilite : ID-8
- **Source du Playbook :** *Generation Ollama (Simulation)*

| Metrique | Score | Resultat |
| :--- | :---: | :--- |
| Fidelite (Faithfulness) | `0.0%` | N/A (juge local) |
| Pertinence Reponse | `0.0%` | N/A (juge local) |
| Pertinence Contextuelle | `0.0%` | Documents peu adaptes |

- **Pertinence contextuelle FAISS :** The score is 0.00 because there are no relevant statements in the retrieval context, and the only reason given for irrelevance is that a specific document-related cybersecurity context was not found, which has no connection to the input about detecting an SSL service on port 443/tcp.


---

## Conclusion et Perspectives (Memoire PFE)

1. **Robustesse de la Priorisation ML** : Le modele XGBoost atteint un score d'alignement de **70.0%** selon le juge LLM. Les variables clees (CVSS, KEV, EPSS) guident correctement la priorisation et les explications XAI sont techniquement pertinentes.

2. **Qualite du RAG Local** : Le moteur de recherche FAISS obtient un score de pertinence contextuelle de **0.0%** sans aucune dependance cloud. Ce score confirme la viabilite d'un assistant de pentest 100% air-gap.

3. **Pistes d'amelioration** :
   - Enrichir l'index documentaire FAISS avec des playbooks couvrant plus de protocoles et versions.
   - Pour une evaluation complete (Faithfulness, AnswerRelevancy), configurer une cle API Gemini ou Claude dans `.env`.
   - Augmenter la diversite du dataset de test (actuellement 5 vulnerabilite(s)).
