import urllib.request
import base64
import os

diagrams = {
    "pipeline_generale.png": """graph TD
    A[Fichiers de Scan Nmap/Nessus/OpenVAS] -->|Upload / CLI| B[Phase 1: Ingestion & Parsing]
    B --> C[(Base de Données Centrale)]
    C -->|Données brutes| D[Phase 2: Enrichissement]
    D -.->|CPE, CVE, Exploit-DB| C
    C -->|Vulnérabilités enrichies| E[Phase 3: Priorisation ML XGBoost]
    E -.->|Scores prédictifs| C
    C -->|Top Vulnérabilités| F[Phase 4: Génération Playbooks LLM + RAG]
    KB[(FAISS Vector DB)] -.->|Contexte RAG| F
    F -.->|Rapports d'Audit / Payloads| C
    C --> G[Phase 5: Visualisation IHM / API]
    G --> H((Utilisateur Final))""",

    "module1_ingestion.png": """graph LR
    A[Fichier de Scan] --> B{Format ?}
    B -->|XML| C[XML Parsers]
    B -->|TXT| D[TXT Parsers]
    C --> E[Extraction Unifiée: Hosts, Ports]
    D --> E
    E --> F[Dédoublonnage]
    F --> G[(Tables BDD)]""",

    "module2_enrichissement.png": """graph TD
    A[Entités BDD] --> B{Tâches d'Enrichissement}
    B --> C[Rapprochement NVD]
    B --> D[Résolution CPE]
    B --> E[Cartographie Exploit-DB]
    DB1[(NVD Local)] -.-> C
    DB2[(CPE Dict Local)] -.-> D
    DB3[(Exploit-DB Local)] -.-> E
    C --> F[Ajout Description, CVSS]
    D --> G[Ajout OS/Version Exacte]
    E --> H[Ajout Flag Exploit]
    F --> I[(BDD Unifiée)]
    G --> I
    H --> I""",

    "module3_ml.png": """graph TD
    A[(Historique BDD)] -->|Features| B[Préparation Dataset]
    B -->|Train/Test| C[Entraînement XGBoost]
    C --> D[Sauvegarde Modèle]
    E[(Nouvelles Vulns)] -->|Features| F[Préparation Inférence]
    D -.-> G[Inférence ML]
    F --> G
    G -->|Score & Sévérité| H[(ScoreML)]""",

    "module4_rag.png": """graph TD
    A[Fichiers Markdown Métier] -->|Embedding| B[(Index FAISS Vectoriel)]
    C[Vulnérabilité Priorisée] -->|Requête Sémantique| D[Retriever RAG]
    B -.->|Top K Contexte| D
    D --> E[Construction Prompt]
    E --> F[Agent LLM Ollama/Mistral]
    F --> G{Mode Playbook}
    G -->|Audit| H[Playbook de Vérification]
    G -->|Payload| I[Instructions d'Exploitation]
    H --> J[(Sauvegarde Rapport BDD)]
    I --> J""",

    "module5_api.png": """graph LR
    A[Dashboard / Client API] -->|Requêtes HTTP| B[FastAPI Endpoint]
    B --> C{Rate Limiter Redis}
    C -->|Rejet| D[Erreur 429]
    C -->|Autorisé| E{Authentification JWT}
    E -->|Invalide| F[Erreur 401]
    E -->|Valide| G[Routage API]
    G --> H{Cache L1/L2}
    H -->|Hit| I[Retour JSON <100ms]
    H -->|Miss| J[(BDD Async)]
    J --> K[Mise en Cache]
    K --> I"""
}

# Paramètres de thème pour forcer un rendu propre, sans couleurs vives.
theme_config = "%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#ffffff', 'primaryBorderColor': '#333333', 'primaryTextColor': '#000000', 'lineColor': '#333333', 'clusterBkg': '#f4f4f4'}}}%%\n"

for filename, mermaid_str in diagrams.items():
    full_mermaid = theme_config + mermaid_str
    encoded = base64.urlsafe_b64encode(full_mermaid.encode('utf-8')).decode('utf-8')
    # On utilise !white pour avoir un fond blanc
    url = f'https://mermaid.ink/img/{encoded}?bgColor=!white'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    print(f"Downloading {filename}...")
    try:
        with urllib.request.urlopen(req) as response:
            with open(filename, 'wb') as f:
                f.write(response.read())
        print(f"Success: {filename}")
    except Exception as e:
        print(f"Error for {filename}: {e}")
