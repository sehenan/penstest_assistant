import urllib.request
import base64
import os

diagrams = {
    "01_flux_donnees_global.png": """flowchart TD
    SCAN["Fichier de Scan (XML/TXT)"]
    PIPELINE["FullPipeline (app/core/pipeline.py)"]
    PARSER["Parsers & Normalizer"]

    SCAN -->|"[Donnée] Fichier Brut | [Module] FullPipeline.run() | [Produit] Flux d'exécution"| PIPELINE
    PIPELINE -->|"[Donnée] Contenu XML/TXT | [Module] NmapParser | [Produit] Liste de dicts standardisés"| PARSER

    DB_MAIN[("Base SQLite Principale (pentest.db)")]
    PARSER -->|"[Donnée] Dicts standardisés | [Module] Normalizer.upsert() | [Produit] Entités"| DB_MAIN

    ENRICH["Pipeline d'Enrichissement"]
    DB_THREAT[("Threat Intel DB locale (threat_intel.db)")]

    PIPELINE -->|"[Donnée] Vulns non enrichies | [Module] enrich_vulnerabilities"| ENRICH
    DB_THREAT -->|"[Donnée] NVD, CPE, KEV | [Module] Requêtes SQLite"| ENRICH
    ENRICH -->|"[Donnée] Métadonnées CVSS | [Module] SQLAlchemy"| DB_MAIN

    DATAMGR["DataManager"]
    PREDICT["Inférence ML XGBoost"]

    PIPELINE -->|"[Donnée] Ordre d'évaluation | [Module] predict_and_store()"| DATAMGR
    DB_MAIN -->|"[Donnée] Hosts, Services, Vulns | [Module] extract_real_data()"| DATAMGR
    DATAMGR -->|"[Donnée] DataFrame formaté | [Module] Modèle XGBoost"| PREDICT
    PREDICT -->|"[Donnée] Label, Score | [Module] SQLAlchemy"| DB_MAIN

    GENERATOR["LLM Generator"]
    RAG["Moteur RAG FAISS"]
    FAISS[("Index Vectoriel FAISS")]
    OLLAMA["Serveur Ollama"]

    DB_MAIN -->|"[Donnée] Vuln ciblé | [Module] generate_playbook()"| GENERATOR
    GENERATOR -->|"[Donnée] CVE, Service | [Module] build_rag_context()"| RAG
    FAISS -->|"[Donnée] Embeddings L2 | [Module] faiss.read_index()"| RAG
    RAG -->|"[Donnée] Extraits Markdown | [Module] Concaténation"| GENERATOR
    GENERATOR -->|"[Donnée] Prompt + Contexte | [Module] ollama_client.py"| OLLAMA
    OLLAMA -->|"[Donnée] Rapport généré | [Module] ReportValidator"| DB_MAIN

    API["API FastAPI"]
    UI["Interface Utilisateur"]

    DB_MAIN -->|"[Donnée] Entités | [Module] SQLAlchemy"| API
    API -->|"[Donnée] Données sérialisées | [Module] Endpoints"| UI
""",
    "02_architecture_globale.png": """flowchart TB
    subgraph Z7 ["Zone 7 - Utilisateurs"]
        PENT["Pentester"]
        SOC["Analyste SOC"]
        ADMIN["Administrateur Système"]
    end
    subgraph Z6 ["Zone 6 - Presentation Layer"]
        DASH["Dashboard SIATI"]
        REP["Rapports & Playbooks"]
        STAT["Statistiques & Recherche"]
    end
    subgraph Z5 ["Zone 5 - API Layer"]
        FASTAPI["FastAPI Framework"]
        ROUTES["Routes API (/api/...)"]
        AUTH["Authentification & Cors"]
        BACKEND["Services Backend"]
    end
    subgraph Z4 ["Zone 4 - Intelligence Layer"]
        subgraph ENRICH_ENG ["Enrichment Engine"]
            CORR["Corrélation CVE"]
            FUS["Fusion des données"]
        end
        subgraph ML_ENG ["Machine Learning Engine"]
            XGB["Modèle XGBoost"]
            SCORING["Scoring & SHAP"]
        end
        subgraph AI_ENG ["AI Engine (Génération)"]
            OLLAMA["Serveur Ollama"]
            RAG["RAG Vector Store"]
        end
    end
    subgraph Z3 ["Zone 3 - Data Layer"]
        SQLITE[("Base Relationnelle (SQLite)")]
        REDIS[("Cache (Redis)")]
        KB[("Knowledge Base (FAISS)")]
    end
    subgraph Z2 ["Zone 2 - Ingestion"]
        BUILDER["SIATI Intel Builder"]
        SYNC["Synchronisation"]
        PARS["Parsing XML/TXT"]
    end
    subgraph Z1 ["Zone 1 - Sources Externes"]
        NVD["NVD"]
        EDB["Exploit-DB"]
        EPSS["EPSS API"]
        NESSUS["Scans"]
    end

    Z7 --> Z6
    Z6 --> Z5
    Z5 --> Z4
    Z4 --> Z5
    Z5 --> Z3
    Z3 --> Z5
    Z4 --> Z3
    Z3 --> Z4
    Z2 --> Z3
    Z1 --> Z2
""",
    "03_architecture_enrichissement.png": """flowchart LR
    SRC1["API NVD"]
    SRC2["CISA KEV"]
    SRC3["EPSS Scores"]
    subgraph Builder["SIATI Intel Builder (Connecté)"]
        ETL1["etl.nvd.py"]
        ETL2["etl.kev.py"]
        ETL3["etl.epss.py"]
        PACK["packager.py"]
    end
    THREAT_DB[("threat_intel.db (Bundle)")]
    SRC1 --> ETL1
    SRC2 --> ETL2
    SRC3 --> ETL3
    ETL1 --> PACK
    ETL2 --> PACK
    ETL3 --> PACK
    PACK --> THREAT_DB
    
    subgraph SIATI_Core["Core SIATI (Air-Gapped)"]
        NVD_ENRICH["nvd.py"]
        CPE_ENRICH["cpe_to_cve.py"]
        EXP_ENRICH["exploit_db.py"]
    end
    PENTEST_DB[("pentest.db")]
    
    THREAT_DB --> NVD_ENRICH
    THREAT_DB --> CPE_ENRICH
    THREAT_DB --> EXP_ENRICH
    NVD_ENRICH --> PENTEST_DB
    CPE_ENRICH --> PENTEST_DB
    EXP_ENRICH --> PENTEST_DB
""",
    "04_architecture_pipeline_ia.png": """flowchart TD
    DB[("SQLite Vulnérabilités")]
    subgraph ML ["Machine Learning (Quantitatif)"]
        DM["DataManager (Extraction Features)"]
        XGB["Modèle XGBoost (Inférence)"]
        DM --> XGB
    end
    subgraph RAG_Ollama ["Generative AI (Qualitatif)"]
        FAISS[("FAISS Index (Documentation)")]
        RETRIEVER["SentenceTransformers"]
        PROMPT["Prompt Engineering"]
        OLLAMA["Conteneur Ollama (mistral:7b)"]
        VALIDATOR["ReportValidator"]
        FAISS --> RETRIEVER
        RETRIEVER --> PROMPT
        PROMPT --> OLLAMA
        OLLAMA --> VALIDATOR
    end
    DB --> DM
    XGB --> DB
    DB --> PROMPT
    VALIDATOR --> DB
""",
    "05_architecture_conceptuelle_presentation.png": """flowchart LR
    SCANS(["Scans de Vulnérabilités (Nmap, Nessus)"])
    INTEL(["Cyber Threat Intelligence (NVD, EPSS)"])
    subgraph SIATI ["Moteur Central SIATI"]
        INGEST["Normalisation & Ingestion"]
        ML["ML Scoring (XGBoost)"]
        LLM["RAG & Playbooks (Ollama Mistral)"]
    end
    USER(["Interface Pentester (FastAPI / SPA)"])

    SCANS --> INGEST
    INTEL --> INGEST
    INGEST --> ML
    ML --> LLM
    LLM --> USER
    USER --> LLM
"""
}

def generate_image(filename, mermaid_code):
    full_mermaid = "%%{init: {'theme': 'base', 'themeVariables': {'background': '#ffffff', 'primaryColor': '#ffffff', 'primaryBorderColor': '#333333', 'primaryTextColor': '#333333', 'lineColor': '#333333'}}}%%\n" + mermaid_code
    encoded = base64.urlsafe_b64encode(full_mermaid.encode('utf-8')).decode('utf-8')
    url = f'https://mermaid.ink/img/{encoded}?bgColor=!white'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    output_path = os.path.join("d:/Aptitudes/PFE/penstest_assistant/captures_pfe", filename)
    try:
        with urllib.request.urlopen(req) as response:
            with open(output_path, 'wb') as f:
                f.write(response.read())
        print(f"✅ Génération réussie : {output_path}")
    except Exception as e:
        print(f"❌ Erreur de génération pour {filename} : {e}")

if __name__ == "__main__":
    out_dir = "d:/Aptitudes/PFE/penstest_assistant/captures_pfe"
    os.makedirs(out_dir, exist_ok=True)
    print(f"Téléchargement des architectures dans le dossier: {out_dir}\\n")
    for name, code in diagrams.items():
        print(f"Génération de {name}...")
        generate_image(name, code)
