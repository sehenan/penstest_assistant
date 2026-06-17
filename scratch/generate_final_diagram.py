import urllib.request
import base64
import os

mermaid_str = """flowchart TB
    classDef process fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef database fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    classDef input fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef output fill:#ffebee,stroke:#d32f2f,stroke-width:2px;

    Scans([Fichiers Scans: .txt, .xml, .nessus]):::input

    subgraph Phase1 [1. Ingestion]
        Parsers[Parsing Nmap/Nessus]:::process
        Normalizer[Normalisation]:::process
    end

    MainDB[(Base Centrale SQLite)]:::database

    subgraph Phase2 [2. Enrichissement Hors-Ligne]
        LocalIntel[(Bases NVD, CPE, Exploit)]:::database
        EnrichCore[Moteur Enrichissement]:::process
    end

    subgraph Phase3 [3. Machine Learning]
        MLCore[Algorithme XGBoost + SHAP]:::process
    end

    subgraph Phase4 [4. IA Generative RAG]
        FAISS[(Index Vectoriel FAISS)]:::database
        LLMCore[Ollama Local Mistral]:::process
    end

    subgraph Phase5 [5. Restitution]
        API[Serveur FastAPI + Redis]:::process
        UI[Tableau de Bord Web]:::output
        Rapports[Rapports Audit & Payloads]:::output
    end

    Scans --> Parsers
    Parsers --> Normalizer
    Normalizer --> MainDB

    MainDB --> EnrichCore
    LocalIntel --> EnrichCore
    EnrichCore --> MainDB

    MainDB --> MLCore
    MLCore --> MainDB

    MainDB --> LLMCore
    FAISS --> LLMCore
    LLMCore --> MainDB
    LLMCore --> Rapports

    MainDB --> API
    API --> UI
"""

theme_config = "%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#ffffff', 'primaryBorderColor': '#333333', 'primaryTextColor': '#000000', 'lineColor': '#333333', 'clusterBkg': '#f4f4f4'}}}%%\n"
full_mermaid = theme_config + mermaid_str
encoded = base64.urlsafe_b64encode(full_mermaid.encode('utf-8')).decode('utf-8')
url = f'https://mermaid.ink/img/{encoded}?bgColor=!white'

req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
output_path = os.path.join(os.path.dirname(__file__), "..", "architecture_siati_memoire.png")
try:
    with urllib.request.urlopen(req) as response:
        with open(output_path, 'wb') as f:
            f.write(response.read())
    print(f'Image générée avec succès: {output_path}')
except Exception as e:
    print(f'Erreur: {e}')
