# SIATI - Système Intelligent d'Assistance aux Tests d'Intrusion

SIATI est un assistant de pentest moderne combinant Machine Learning (XGBoost) et LLM (Ollama/RAG) pour automatiser l'analyse de vulnérabilités et la génération de playbooks d'exploitation.

## 🚀 Démarrage Rapide (Windows)

Pour lancer l'interface web simplement :

1.  **Double-cliquez** sur le fichier `start_app.bat` à la racine du projet.
2.  Le script va automatiquement :
    *   Créer un environnement virtuel (`.venv`) si nécessaire.
    *   Installer les dépendances manquantes.
    *   Lancer le serveur dashboard.
3.  Ouvrez votre navigateur sur : **[http://127.0.0.1:8505](http://127.0.0.1:8505)**

## 💻 Utilisation via CLI

Si vous préférez utiliser la ligne de commande :

```bash
# Lancer le dashboard par défaut
python main.py

# Importer un scan XML (Nmap/Nessus)
python main.py ingest /chemin/du/scan.xml

# Lancer le pipeline complet (Ingest + Enrich + Score + Playbook)
python main.py auto /chemin/du/scan.xml
```

## 🛠️ Pré-requis

*   **Python 3.10+**
*   **Ollama** (pour la génération de playbooks via LLM local)
*   **Navigateur Web** moderne (Chrome, Firefox, Edge)

---
*Développé pour le projet de fin d'études — Pentest Assistant.*