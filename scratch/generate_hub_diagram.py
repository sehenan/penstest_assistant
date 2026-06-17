import urllib.request
import base64
import os

mermaid_str = """graph TD
    classDef process fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef database fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    classDef input fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef output fill:#ffebee,stroke:#d32f2f,stroke-width:2px;
    classDef builder fill:#eceff1,stroke:#607d8b,stroke-width:2px;

    A([Scans: .txt, .xml, .nessus]):::input -->|Upload / CLI| B[Phase 1: Ingestion & Parsing]:::process
    
    P0[Phase 0: Build Air-Gapped]:::builder -.->|Bundle NVD/CPE/KEV| C[(Base de Données Centrale SQLite)]:::database
    B -->|Données Unifiées| C
    
    C -->|Vulnérabilités Brutes| D[Phase 2: Enrichissement]:::process
    D -.->|Mise à jour NVD & Exploits| C
    
    C -->|Features ML| E[Phase 3: Priorisation ML XGBoost]:::process
    E -.->|Scores SHAP & Sévérité| C
    
    C -->|Contexte Enrichi| F[Phase 4: Génération RAG + Ollama]:::process
    KB[(Index Vectoriel FAISS)]:::database -.->|Connaissances| F
    F -.->|Rapports d'Audit & Payloads| C
    
    C -->|Requêtes REST| G[Phase 5: API FastAPI + Cache Redis]:::process
    G --> H((Tableau de Bord Web)):::output
"""

theme_config = "%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#ffffff', 'primaryBorderColor': '#333333', 'primaryTextColor': '#000000', 'lineColor': '#333333', 'clusterBkg': '#f4f4f4'}}}%%\n"
full_mermaid = theme_config + mermaid_str
encoded = base64.urlsafe_b64encode(full_mermaid.encode('utf-8')).decode('utf-8')
url = f'https://mermaid.ink/img/{encoded}?bgColor=!white'

req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
output_path = os.path.join(os.path.dirname(__file__), "..", "architecture_siati_centrale.png")
try:
    with urllib.request.urlopen(req) as response:
        with open(output_path, 'wb') as f:
            f.write(response.read())
    print(f'Image générée avec succès: {output_path}')
except Exception as e:
    print(f'Erreur: {e}')
