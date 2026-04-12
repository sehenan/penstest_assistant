"""
Points d'entrée CLI (Typer).
Mappe les différentes phases (ingest, enrich, score, playbook) sur des commandes unifiées.
"""
import subprocess
from pathlib import Path

try:
    import typer
except ImportError:
    import sys
    print("Typer n'est pas installé. Exécutez: pip install typer")
    sys.exit(1)

# Import des composants backend (socle)
from app.db.database import init_db, get_session

app = typer.Typer(help="Assistant Pentest - CLI de contrôle du pipeline d'IA offensive.")

@app.command("ingest")
def ingest(file_path: str):
    """[Phase 1] Importe un fichier de scan (XML) dans la BDD SQLite."""
    path = Path(file_path)
    if not path.is_file():
        typer.secho(f"Fichier inexistant : {path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
        
    init_db()
    session = get_session()
    try:
        from app.core.ingest import ingest_scan_file
        typer.secho(f"--> Ingestion de {path} en cours...", fg=typer.colors.BLUE)
        counts = ingest_scan_file(str(path), session)
        typer.secho(f"Succès | Ajouts: {counts}", fg=typer.colors.GREEN)
    finally:
        session.close()

@app.command("enrich")
def enrich():
    """[Phase 2] Enrichissement CVE via cache local (NVD, CPE, Exploit)."""
    session = get_session()
    try:
        from app.core.enrichment import enrich_vulnerabilities_from_nvd, enrich_services_with_cpe, enrich_exploits
        typer.secho("--> Rapprochement NVD...", fg=typer.colors.BLUE)
        r1 = enrich_vulnerabilities_from_nvd(session)
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
def train(optimize: bool = typer.Option(False, "--optimize", "-o", help="Active l'optimisation des hyperparamètres (plus lent mais plus précis)")):
    """[Phase 3a] Entraîne et sauvegarde le modèle XGBoost depuis les données réelles et officielles."""
    session = get_session()
    try:
        from app.core.ml.features import load_official_data, extract_real_data, augment_data, get_training_features
        from app.core.ml.train import train_and_save_model
        import pandas as pd
        
        typer.secho("--> Chargement des données officielles (NVD/CISA/ExploitDB)...", fg=typer.colors.BLUE)
        df_official = load_official_data()
        typer.secho(f"  * {len(df_official)} CVEs officielles chargées.", fg=typer.colors.CYAN)

        typer.secho("--> Extraction des vulnérabilités locales (scans)...", fg=typer.colors.BLUE)
        df_local = extract_real_data(session)
        typer.secho(f"  * {len(df_local)} vulnérabilité(s) locale(s) trouvée(s).", fg=typer.colors.CYAN)

        if df_official.empty and df_local.empty:
            typer.secho("Aucune donnée d'entraînement disponible.", fg=typer.colors.RED)
            raise typer.Exit()

        # Combine datasets
        dfs = []
        if not df_official.empty:
            dfs.append(df_official)
        if not df_local.empty:
            dfs.append(df_local)
            
        df_combined = pd.concat(dfs, ignore_index=True)
        typer.secho(f"  * Dataset total : {len(df_combined)} exemples.", fg=typer.colors.CYAN)

        typer.secho("--> Augmentation des données (Hybride Ancré)...", fg=typer.colors.BLUE)
        df_aug = augment_data(df_combined, target_size=200)
        typer.secho(f"  * Dataset final prêt : {len(df_aug)} exemples.", fg=typer.colors.CYAN)

        X, y = get_training_features(df_aug)
        
        mode_str = "OPTIMISÉ" if optimize else "STANDARD"
        typer.secho(f"--> Entraînement du modèle XGBoost ({mode_str})...", fg=typer.colors.BLUE)
        
        stats = train_and_save_model(X, y, optimize=optimize)
        
        typer.secho(f"Succès | RMSE: {stats.get('rmse', 0):.4f} | R2: {stats.get('r2', 0):.4f}", fg=typer.colors.GREEN)
        typer.secho("Modèle sauvegardé dans data/model_xgb.joblib", fg=typer.colors.GREEN)
    finally:
        session.close()


@app.command("score")
def score():
    """[Phase 3b] Priorisation ML : infère les scores depuis le modèle entraîné."""
    session = get_session()
    try:
        from app.core.ml.features import extract_real_data
        from app.core.ml.predict import predict_and_store
        typer.secho("--> Extraction dynamique des features...", fg=typer.colors.BLUE)
        df = extract_real_data(session)
        if df.empty:
            typer.secho("Base vide, aucune vulnérabilité à évaluer.", fg=typer.colors.RED)
            raise typer.Exit()

        typer.secho("--> Inférence par le modèle ML...", fg=typer.colors.BLUE)
        stats = predict_and_store(session, df)
        typer.secho(f"Succès | Modélisées : {stats}", fg=typer.colors.GREEN)
    finally:
        session.close()

@app.command("playbook")
def playbook(vuln_id: int):
    """[Phase 4] Génère automatiquement le code d'exploitation (RAG + Ollama)."""
    session = get_session()
    try:
        from app.core.llm.generator import generate_playbook_for_vulnerability
        typer.secho(f"--> Lancement LLM Agent sur ID {vuln_id}...", fg=typer.colors.BLUE)
        repo_id = generate_playbook_for_vulnerability(session, vuln_id)
        if repo_id:
            typer.secho(f"Le Playbook a été rédigé avec succès (DRAFT ID: {repo_id}).", fg=typer.colors.GREEN)
        else:
            typer.secho("Échec de la génération de playbook (Ollama down ou Contexte mort).", fg=typer.colors.RED)
    finally:
        session.close()

@app.command("ui")
def ui():
    """[Phase 5] Démarre le Dashboard interactif Streamlit."""
    import sys
    typer.secho("--> Lancement de l'IHM Opérateur...", fg=typer.colors.MAGENTA)
    ui_script = Path(__file__).resolve().parent / "ui" / "dashboard.py"
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(ui_script)])

@app.command("index-rag")
def index_rag(knowledge_dir: str = "data/knowledge"):
    """[Phase 4a] Indexe les fichiers Markdown de la base de connaissance dans FAISS."""
    typer.secho(f"--> Indexation RAG depuis {knowledge_dir}...", fg=typer.colors.BLUE)
    from app.core.llm.rag import build_index
    path = Path(knowledge_dir)
    if not path.is_dir():
        typer.secho(f"Dossier inexistant : {path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
        
    docs = []
    for f in path.glob("*.md"):
        try:
            content = f.read_text(encoding="utf-8")
            docs.append({"content": content, "source": f.name})
        except Exception as e:
            typer.secho(f"Erreur lecture {f.name}: {e}", fg=typer.colors.YELLOW)
        
    if not docs:
        typer.secho("Aucun fichier .md trouvé.", fg=typer.colors.YELLOW)
        return
        
    build_index(docs)
    typer.secho(f"Succès | {len(docs)} documents indexés.", fg=typer.colors.GREEN)

@app.command("pipeline")
def pipeline(file_path: str):
    """Automatise séquentiellement Ingest -> Enrich -> Train -> Score."""
    ingest(file_path)
    enrich()
    train()
    score()
    typer.secho("\n[+] AUTO-PIPELINE TERMINÉ. Prêt pour l'UI ou l'analyse.", fg=typer.colors.GREEN)

if __name__ == "__main__":
    app()
