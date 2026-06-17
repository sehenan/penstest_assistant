import urllib.request
import base64
import os

mermaid_str = """flowchart TB
    classDef offline fill:#eceff1,stroke:#607d8b,stroke-width:2px,stroke-dasharray: 5 5;
    classDef input fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef process fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef database fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    classDef external fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;
    classDef output fill:#ffebee,stroke:#d32f2f,stroke-width:2px;

    subgraph Phase0 ["0. Préparation Hors-Ligne (siati_intel_builder)"]
        direction LR
        API_Ext{{APIs NVD, EPSS, KEV}}:::external
        IntelBuilder["Packager Air-Gapped"]:::process
        Bundle[/"Archive (tar.gz)"/]:::database
        
        API_Ext -->|ETL Fetch| IntelBuilder
        IntelBuilder -->|Packaging| Bundle
    end

    subgraph SIATI ["Système Central SIATI (Environnement Cible)"]

        subgraph Ingestion ["1. Sources & Ingestion"]
            Scans([Scans: .txt, .xml, .nessus]):::input
            Parsers["Parsers Multi-formats"]:::process
            Normalizer["Normalisation"]:::process
        end

        MainDB[(Base Centrale SQLite)]:::database

        subgraph Enrichissement ["2. Enrichissement Contextuel"]
            SyncManager["Sync Manager"]:::process
            EnrichmentCore["Core Enrichissement"]:::process
            LocalIntel[(Threat Intel DB)]:::database
            NVD_Cache[(Cache NVD JSON)]:::database
            CPE_Exploit[(Caches CPE & Exploits)]:::database
        end

        subgraph ML ["3. Scoring Machine Learning"]
            MLCore["Module ML XGBoost"]:::process
            XGB[(Modèle XGBoost)]:::database
        end

        subgraph RAG_LLM ["4. IA Générative (RAG + LLM)"]
            KnowledgeBase[(Docs Connaissances)]:::database
            FAISS[(Index Vectoriel FAISS)]:::database
            LLMCore["Module LLM"]:::process
            Ollama{{Serveur Local Ollama}}:::external
        end

        subgraph Restitution ["5. API & Interface Utilisateur"]
            API["FastAPI Backend"]:::process
            Redis[(Cache Redis)]:::database
            UI["Dashboard Web"]:::output
            Rapports["Rapports d'Audit & Payloads"]:::output
        end

    end

    Bundle -.->|Transfert USB| SyncManager
    SyncManager --> LocalIntel

    Scans --> Parsers
    Parsers --> Normalizer
    Normalizer -->|Upsert| MainDB

    MainDB -->|Vulnérabilités| EnrichmentCore
    EnrichmentCore --> LocalIntel
    EnrichmentCore --> NVD_Cache
    EnrichmentCore --> CPE_Exploit
    EnrichmentCore -->|Sauvegarde| MainDB

    MainDB -->|Features| MLCore
    MLCore --> XGB
    MLCore -->|Scores SHAP| MainDB

    KnowledgeBase --> FAISS
    MainDB -->|Contexte| LLMCore
    LLMCore --> FAISS
    LLMCore --> Ollama
    LLMCore -->|Markdown| MainDB
    LLMCore --> Rapports

    MainDB -->|Requêtes REST| API
    API --> Redis
    API --> UI
"""

theme_config = "%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#ffffff', 'primaryBorderColor': '#333333', 'primaryTextColor': '#000000', 'lineColor': '#333333', 'clusterBkg': '#f4f4f4'}}}%%\n"
full_mermaid = theme_config + mermaid_str
encoded = base64.urlsafe_b64encode(full_mermaid.encode('utf-8')).decode('utf-8')
url = f'https://mermaid.ink/img/{encoded}?bgColor=!white'

req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
output_path = os.path.join(os.path.dirname(__file__), "..", "architecture_siati_finale.png")
try:
    with urllib.request.urlopen(req) as response:
        with open(output_path, 'wb') as f:
            f.write(response.read())
    print(f'Image générée avec succès: {output_path}')
except Exception as e:
    print(f'Erreur: {e}')
