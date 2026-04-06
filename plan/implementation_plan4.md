# Plan d'implémentation — PFE | Module 4 : Assistance LLM & RAG

Ce plan décrit comment nous allons construire la couche de génération (Playbooks automatiques) permettant un gain de temps massif lors de l'exploitation. Il s'appuie sur une **architecture RAG (Retrieval-Augmented Generation)** connectée à un modèle local (**Ollama**).

## User Review Required

> [!NOTE]
> Nous entamons l'un des modules les plus novateurs de votre PFE. Le système sera capable, pour une vulnérabilité donnée (issue du Top-N du composant ML précédent), d'interroger vos cheatsheets de pentest (FAISS) et de générer un rapport Markdown d'exploitation (via Mistral/Llama3/Phi3) sans jamais quitter votre réseau.
> 
> **Veuillez vérifier les hypothèses ("Open Questions") avant la phase de code.**

## Proposed Changes

### [NEW] `app/core/llm/rag.py` (Moteur de Recherche Vectoriel)
- Utilisation de `faiss-cpu` et `sentence-transformers`.
- Chargement de l'index stocké dans `data/faiss_index`.
- Fonction `retrieve_context(query, top_k=3)` : Convertit une requête (ex: la description d'un CVE ou "Exploitation SMB") en vecteur, fouille le FAISS et retourne les paragraphes/cheatsheets les plus pertinents.

### [NEW] `app/core/llm/ollama_client.py` (Connecteur IA)
- Client léger (basé sur `requests`) dialoguant avec l'API standard d'Ollama (`http://localhost:11434/api/generate`).
- Gestion des erreurs et de l'indisponibilité du modèle (Timeout, Air-Gap).
- Support du fallback "OpenAI-compatible" si configuré dans le `.env` (bonus).

### [NEW] `app/core/llm/generator.py` (L'Orchestrateur de Playbook)
- Fonction principale `generate_playbook(vuln_id)`:
  1. Récupère la `Vulnerability` et son `Service` en DB.
  2. Cherche le contexte associé dans le RAG.
  3. Formate un **System Prompt strict** ordonnant au LLM de produire un "Playbook Pentest" (étapes d'exploitation, payloads).
  4. Récupère la réponse et la stocke sous forme de Markdown dans la table `reports` (modèle `Report`).

### [MODIFY] `requirements.txt`
- Ajout de `faiss-cpu>=1.7.4`
- Ajout de `sentence-transformers>=2.2.0`

## Open Questions

> [!IMPORTANT]
> 1. **Index FAISS** : Le dossier `data/faiss_index` existe déjà. Souhaitez-vous que je code UNIQUEMENT le moteur de *recherche* (Lecture de l'index existant), ou dois-je aussi coder le script *d'ingestion* (Création de l'index à partir de fichiers Markdown bruts) ?
> 2. **Modèle LLM cible** : Quel modèle faites-vous tourner sous l'Ollama local de votre machine actuellement (Mistral, Phi-3, Llama-3) ? Bien que le code sera agnostique, adapter le prompt template à Mistral ou Llama peut grandement améliorer la qualité (balises `[INST]`, `<|start_header_id|>`, etc.).
> 3. **Validation Humaine (Garde-fous)** : Le cahier des charges mentionne "Validation humaine avant exploitation". Voulez-vous que le script marque le Playbook en `status="Draft"` et qu'on exige une commande CLI explicite pour l'approuver plus tard ?

## Verification Plan

### Automated Tests
- Création de `tests/test_llm.py`.
- Mock (simulation) de l'API Ollama (pour éviter d'avoir besoin du vrai démon à l'exécution de pytest).
- Vérification du pipeline RAG avec un index FAISS factice en mémoire.

### Manual Verification
- Appel réel au moteur de RAG et test avec une requête concrète (`"eternalblue"`).
- Génération d'un Playbook stocké dans SQLite et visible en Markdown.
