"""
Points d'entrée CLI (Typer).
Mappe les différentes phases (ingest, enrich, score, playbook) sur des commandes unifiées.
"""
import os
import sys
import subprocess
from pathlib import Path

try:
    import typer
except ImportError:
    print("Typer n'est pas installé. Exécutez: pip install typer")
    sys.exit(1)

from typing import List, Optional

# Import des composants backend (socle)
from app.db.database import init_db, get_session
from app.db.models import Vulnerability, ScoreML

app = typer.Typer(help="Assistant Pentest - CLI de contrôle du pipeline d'IA offensive.")

@app.command("ingest")
def ingest(file_paths: List[str]):
    """[Phase 1] Importe un ou plusieurs fichiers de scan (XML) dans la BDD SQLite."""
    init_db()
    session = get_session()
    try:
        from app.core.ingest import ingest_scan_file
        for file_path in file_paths:
            path = Path(file_path)
            if not path.is_file():
                typer.secho(f"Fichier inexistant : {path}", fg=typer.colors.RED)
                continue
            typer.secho(f"--> Ingestion de {path} en cours...", fg=typer.colors.BLUE)
            try:
                counts = ingest_scan_file(str(path), session)
                typer.secho(f"Succès | Ajouts: {counts}", fg=typer.colors.GREEN)
            except Exception as e:
                typer.secho(f"Erreur lors de l'ingestion de {path} : {e}", fg=typer.colors.RED)
    finally:
        session.close()

@app.command("enrich")
def enrich():
    """[Phase 2] Enrichissement CVE via cache local (NVD, CPE, Exploit)."""
    session = get_session()
    try:
        from app.core.enrichment import enrich_vulnerabilities_from_local_intel, enrich_services_with_cpe, enrich_exploits
        typer.secho("--> Rapprochement NVD / EPSS / KEV...", fg=typer.colors.BLUE)
        r1 = enrich_vulnerabilities_from_local_intel(session)
        typer.echo(f"  * {r1}")
        
        typer.secho("--> Résolution CPE...", fg=typer.colors.BLUE)
        r2 = enrich_services_with_cpe(session)
        typer.echo(f"  * {r2}")
        
        typer.secho("--> Cartographie Exploit-DB...", fg=typer.colors.BLUE)
        r3 = enrich_exploits(session)
        typer.echo(f"  * {r3}")
    finally:
        session.close()

@app.command("train")
def train(
    optimize: bool = typer.Option(False, "--optimize", "-o", help="Active l'optimisation des hyperparamètres (plus lent)"),
    target_size: int = typer.Option(500, "--target-size", help="Taille cible après augmentation")
):
    """[Phase 3a] Entraîne le modèle XGBoost via le DataManager (Pro)."""
    session = get_session()
    try:
        from app.core.ml.data_manager import DataManager, TRAIN_SET_PATH, TEST_SET_PATH, get_prepared_features
        from app.core.ml.train import train_and_save_model
        
        dm = DataManager()
        
        typer.secho("--> Préparation du dataset unifié (NVD + Local)...", fg=typer.colors.BLUE)
        df_unified = dm.prepare_unified_dataset(session, target_size=target_size)
        
        if df_unified.empty:
            typer.secho("Aucune donnée d'entraînement.", fg=typer.colors.RED)
            raise typer.Exit()
            
        typer.secho(dm.get_report(), fg=typer.colors.CYAN)
        
        typer.secho("--> Split Train/Test...", fg=typer.colors.BLUE)
        dm.split_and_save()
        
        X_train, y_train = get_prepared_features(TRAIN_SET_PATH)
        X_test, y_test   = get_prepared_features(TEST_SET_PATH)
        
        mode_str = "OPTIMISÉ" if optimize else "STANDARD"
        typer.secho(f"--> Entraînement XGBoost ({mode_str})...", fg=typer.colors.BLUE)
        
        stats = train_and_save_model(
            X_train, y_train, 
            optimize=optimize, 
            validation_data=(X_test, y_test)
        )
        
        typer.secho(f"Succès | RMSE Val: {stats.get('rmse', 0):.4f} | R2 Val: {stats.get('r2', 0):.4f}", fg=typer.colors.GREEN)
        typer.secho(f"Meilleure Itération : {stats.get('best_iteration')}", fg=typer.colors.GREEN)
    finally:
        session.close()


@app.command("score")
def score():
    """[Phase 3b] Priorisation ML : infère les scores depuis le modèle entraîné."""
    session = get_session()
    try:
        from app.core.ml.data_manager import DataManager
        from app.core.ml.predict import predict_and_store
        
        dm = DataManager()
        typer.secho("--> Extraction dynamique des features locales...", fg=typer.colors.BLUE)
        df = dm.extract_real_data(session)
        
        if df.empty:
            typer.secho("Base vide, aucune vulnérabilité à évaluer.", fg=typer.colors.RED)
            raise typer.Exit()
 
        typer.secho("--> Inférence par le modèle ML...", fg=typer.colors.BLUE)
        stats = predict_and_store(session, df)
        typer.secho(f"Succès | Modélisées : {stats}", fg=typer.colors.GREEN)
    finally:
        session.close()

@app.command("playbook")
def playbook(vuln_id: int, mode: str = "audit"):
    """[Phase 4] Génère un guide (audit ou payload) via RAG + Ollama."""
    session = get_session()
    try:
        from app.core.llm.generator import generate_playbook_for_vulnerability
        typer.secho(f"--> Lancement LLM Agent ({mode.upper()}) sur ID {vuln_id}...", fg=typer.colors.BLUE)
        repo_id = generate_playbook_for_vulnerability(session, vuln_id, mode=mode)
        if repo_id:
            typer.secho(f"Playbook [{mode.upper()}] créé (ID: {repo_id}).", fg=typer.colors.GREEN)
        else:
            typer.secho("Échec de la génération de playbook.", fg=typer.colors.RED)
    finally:
        session.close()

@app.command("playbook-v2")
def playbook_v2(vuln_id: int, top_k: int = 5):
    """[Phase 4 PRO] Génère un playbook RAG STRICT avec citations de sources."""
    import yaml
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
        
        from app.db.database import get_session
        from app.db.models import Vulnerability, ScoreML, Service, Host, Exploit
        from app.module_llm.llm.generator import Generator
        from app.module_llm.rag.retriever import Retriever, get_retrieval_query
        
        session = get_session()
        # Query pour récupérer toutes les infos nécessaires
        row = session.query(
            Vulnerability.id.label("vuln_id"), 
            Vulnerability.cve, Vulnerability.cvss_score, Vulnerability.cvss_vector, Vulnerability.description,
            Service.service, Service.port, Service.version,
            Exploit.disponible.label("exploit_disponible"), Exploit.metasploit_module
        ).join(Service).outerjoin(Exploit).filter(Vulnerability.id == vuln_id).first()
        
        if not row:
            typer.secho(f"Vulnérabilité ID {vuln_id} introuvable.", fg=typer.colors.RED)
            return

        vuln_dict = dict(row._mapping)
        
        typer.secho(f"--> Recherche RAG STRICT pour {vuln_dict['cve']}...", fg=typer.colors.BLUE)
        retriever = Retriever(config)
        context = retriever.retrieve(get_retrieval_query(vuln_dict), k=top_k)
        
        typer.secho(f"--> Génération Playbook via Ollama ({config['llm']['model']})...", fg=typer.colors.BLUE)
        generator = Generator(config)
        playbook_text = generator.generate_playbook(vuln_dict, context)
        
        if playbook_text:
            from datetime import datetime
            from app.db.models import Report
            report = Report(
                titre=f"Playbook V2 - {vuln_dict['cve']}",
                contenu_md=playbook_text,
                timestamp=datetime.utcnow(),
                vuln_id=vuln_id,
                stage="audit"
            )
            session.add(report)
            session.commit()
            typer.secho(f"Succès | Playbook V2 généré (Rapport ID: {report.id})", fg=typer.colors.GREEN)
            typer.echo("\n" + "="*20 + " APERÇU " + "="*20)
            typer.echo(playbook_text[:500] + "...")
        else:
            typer.secho("Échec de la génération.", fg=typer.colors.RED)
    except Exception as e:
        typer.secho(f"Erreur : {e}", fg=typer.colors.RED)

@app.command("exploit")
def exploit(vuln_id: int):
    """Génère le payload final d'exploitation pour une vulnérabilité validée."""
    playbook(vuln_id, mode="payload")

@app.command("ui")
def ui(
    host: str = typer.Option(
        os.environ.get("SIATI_HOST", "127.0.0.1"), "--host", help="Adresse d'écoute"
    ),
    port: int = typer.Option(
        int(os.environ.get("SIATI_PORT", "8505")), "--port", help="Port d'écoute"
    ),
):
    """[Phase 5] Démarre le Dashboard SIATI (FastAPI + HTML)."""
    typer.secho(f"--> Lancement de l'IHM SIATI sur http://{host}:{port}", fg=typer.colors.MAGENTA)
    server_module = "app.ui.server:app"
    env = {**os.environ, "OMP_NUM_THREADS": "1"}
    subprocess.run([
        sys.executable, "-m", "uvicorn", server_module,
        "--host", host,
        "--port", str(port),
    ], env=env)

def _chunk_markdown(text: str, size: int = 400, overlap: int = 50) -> list[str]:
    """Découpe un document en chunks de ~size mots avec recouvrement (overlap)."""
    words = text.split()
    if not words:
        return []
    step = max(1, size - overlap)
    chunks = []
    for i in range(0, len(words), step):
        chunks.append(" ".join(words[i:i + size]))
        if i + size >= len(words):
            break
    return chunks


@app.command("index-rag")
def index_rag(knowledge_dir: str = "data/knowledge_base"):
    """[Phase 4a] Indexe (récursivement + chunking) la base de connaissance Markdown dans FAISS (SBERT)."""
    typer.secho(f"--> Indexation RAG depuis {knowledge_dir}...", fg=typer.colors.BLUE)
    from app.core.llm.rag import build_index
    path = Path(knowledge_dir)
    if not path.is_dir():
        typer.secho(f"Dossier inexistant : {path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    # Parcours récursif de la grande base + cheatsheets curées historiques (data/knowledge)
    files = sorted(path.rglob("*.md"))
    legacy = Path("data/knowledge")
    if legacy.is_dir() and legacy.resolve() != path.resolve():
        files += sorted(legacy.glob("*.md"))

    docs = []
    for f in files:
        try:
            content = f.read_text(encoding="utf-8").strip()
        except Exception as e:
            typer.secho(f"Erreur lecture {f.name}: {e}", fg=typer.colors.YELLOW)
            continue
        if not content:
            continue
        try:
            source = str(f.relative_to(path))
        except ValueError:
            source = f.name
        for chunk in _chunk_markdown(content):
            if chunk.strip():
                docs.append({"content": chunk, "source": source})

    if not docs:
        typer.secho("Aucun chunk à indexer.", fg=typer.colors.YELLOW)
        return

    typer.secho(
        f"--> {len(files)} fichiers -> {len(docs)} chunks. Encodage SBERT en cours "
        f"(plusieurs minutes, CPU)...",
        fg=typer.colors.BLUE,
    )
    build_index(docs)
    typer.secho(f"Succès | {len(docs)} chunks indexés depuis {len(files)} fichiers.", fg=typer.colors.GREEN)

@app.command("index-rag-v2")
def index_rag_v2():
    """[Phase 4a PRO] Indexation FAISS V2 (Tiktoken + Metadata)."""
    import yaml
    from app.module_llm.rag.indexer import Indexer
    
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
        
        indexer = Indexer(config)
        indexer.build_index(config['rag']['knowledge_dir'], config['rag']['output_dir'])
        typer.secho("Indexation V2 terminée avec succès.", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Erreur : {e}", fg=typer.colors.RED)

@app.command("auto")
def auto(file_paths: List[str], top_n: int = 3):
    """Automatisation complète : Ingest -> Enrich -> Score -> Playbooks d'audit (Top N)."""
    # 1. Pipeline technique
    ingest(file_paths)
    enrich()
    
    # Entraînement auto si modèle manquant
    if not Path("data/model_xgb.joblib").exists():
        typer.secho("Modèle manquant, lancement d'un entraînement standard...", fg=typer.colors.YELLOW)
        train()

    score()
    
    # 2. Génération automatique des playbooks d'audit et de payload pour le Top N
    session = get_session()
    try:
        # Récupération des vulnérabilités les mieux scorées
        top_vulns = (
            session.query(Vulnerability)
            .join(ScoreML)
            .order_by(ScoreML.score.desc())
            .limit(top_n)
            .all()
        )
        
        if not top_vulns:
            typer.secho("Aucune vulnérabilité trouvée pour la génération de playbooks.", fg=typer.colors.YELLOW)
            return

        typer.secho(f"\n[+] Génération End-to-End des Playbooks (Audit puis Payload) pour les {len(top_vulns)} vulnérabilités critiques...", fg=typer.colors.MAGENTA)
        for v in top_vulns:
            typer.secho(f"\n--- Traitement de la Vulnérabilité ID {v.id} ---", fg=typer.colors.YELLOW)
            playbook(v.id, mode="audit")
            playbook(v.id, mode="payload")

    finally:
        session.close()

    typer.secho("\n[+] WORKFLOW AUTOMATIQUE END-TO-END TERMINÉ.", fg=typer.colors.GREEN)
    typer.secho("Vos playbooks complets ont été générés et rattachés aux vulnérabilités.", fg=typer.colors.CYAN)

@app.command("setup-data")
def setup_data():
    """Initialise les bases de données d'enrichissement (CPE, Exploits) pour la démo."""
    typer.secho("--> Initialisation des données locales...", fg=typer.colors.BLUE)
    from app.core.setup_data import setup_all_databases
    setup_all_databases()
    typer.secho("[+] Bases de données prêtes.", fg=typer.colors.GREEN)

@app.command("check")
def check():
    """Lance un diagnostic complet du système."""
    from app.core.check import run_diagnostics
    run_diagnostics()

@app.command("deepeval-evaluate")
def deepeval_evaluate(
    sample_size: int = typer.Option(5, "--sample-size", help="Nombre de vulnérabilités à évaluer (default: 5)"),
    model: str = typer.Option("claude-3-5-sonnet-latest", "--model", help="Modèle Claude à utiliser comme juge")
):
    """[PFE] Évalue les modèles de priorisation ML et de RAG avec DeepEval et Anthropic."""
    typer.secho("--> Lancement de l'évaluation DeepEval + Anthropic...", fg=typer.colors.MAGENTA)
    from app.scripts.evaluate_deepeval import run_evaluation
    try:
        run_evaluation(sample_size=sample_size, claude_model_name=model)
    except Exception as e:
        typer.secho(f"Erreur durant l'évaluation : {e}", fg=typer.colors.RED)

@app.command("sync-intel")
def sync_intel():
    """[Phase Air-Gap] Importe automatiquement le dernier bundle d'enrichissement (Threat Intel)."""
    try:
        from app.core.enrichment.sync_manager import ingest_bundle
        import glob
        import os
        
        # Chercher dans les répertoires probables
        search_paths = [
            "siati_intel_builder/bundles/*.tar.gz",
            "bundles/*.tar.gz",
            "data/bundles/*.tar.gz"
        ]
        
        latest_bundle = None
        latest_time = 0
        
        for pattern in search_paths:
            for file in glob.glob(pattern):
                mtime = os.path.getmtime(file)
                if mtime > latest_time:
                    latest_time = mtime
                    latest_bundle = file
                    
        if not latest_bundle:
            typer.secho("Aucun bundle (.tar.gz) trouvé dans les dossiers standards.", fg=typer.colors.RED)
            raise typer.Exit(1)
            
        typer.secho(f"--> Bundle le plus récent trouvé : {latest_bundle}", fg=typer.colors.BLUE)
        typer.secho("--> Lancement du Sync Manager (Vérification SHA256 + Hot-swap)...", fg=typer.colors.BLUE)
        
        success = ingest_bundle(latest_bundle)
        if success:
            typer.secho("[+] Base de Threat Intelligence mise à jour avec succès (Air-Gap) !", fg=typer.colors.GREEN)
        else:
            typer.secho("[-] Échec de la mise à jour (Vérifiez les logs).", fg=typer.colors.RED)
            raise typer.Exit(1)
    except Exception as e:
        typer.secho(f"Erreur : {e}", fg=typer.colors.RED)

@app.command("rollback-intel")
def rollback_intel():
    """Restaure la version précédente de la base d'enrichissement en cas d'erreur."""
    try:
        from app.core.enrichment.sync_manager import rollback_to_version, VERSIONS_FILE
        import json
        
        if not VERSIONS_FILE.exists():
            typer.secho("Aucun historique de version trouvé.", fg=typer.colors.RED)
            raise typer.Exit(1)
            
        with open(VERSIONS_FILE, "r", encoding="utf-8") as f:
            versions = json.load(f)
            
        history = versions.get("history", [])
        if not history:
            typer.secho("Aucun backup disponible pour le rollback.", fg=typer.colors.RED)
            raise typer.Exit(1)
            
        last_backup = history[-1]
        backup_path = last_backup.get("backup_path")
        import os
        backup_name = os.path.basename(backup_path)
        
        typer.secho(f"--> Restauration depuis le backup : {backup_name}", fg=typer.colors.BLUE)
        success = rollback_to_version(backup_name)
        
        if success:
            typer.secho("[+] Rollback réussi ! SIATI utilise l'ancienne base.", fg=typer.colors.GREEN)
        else:
            typer.secho("[-] Échec du rollback.", fg=typer.colors.RED)
    except Exception as e:
        typer.secho(f"Erreur : {e}", fg=typer.colors.RED)

if __name__ == "__main__":
    app()
