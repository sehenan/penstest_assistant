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

# Import des composants backend
from app.db.database import init_db, get_session
from app.core.ingest import ingest_scan_file
from app.core.enrichment import enrich_vulnerabilities_from_nvd, enrich_services_with_cpe, enrich_exploits
from app.core.ml.features import extract_real_data
from app.core.ml.predict import predict_and_store
from app.core.llm.generator import generate_playbook_for_vulnerability

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

@app.command("score")
def score():
    """[Phase 3] Priorisation via Modèle ML XGBoost."""
    session = get_session()
    try:
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
    typer.secho("--> Lancement de l'IHM Opérateur...", fg=typer.colors.MAGENTA)
    ui_script = Path(__file__).resolve().parent / "ui" / "dashboard.py"
    subprocess.run(["streamlit", "run", str(ui_script)])

@app.command("pipeline")
def pipeline(file_path: str):
    """Automatise séquentiellement Ingest -> Enrich -> Score."""
    ingest(file_path)
    enrich()
    score()
    typer.secho("\n[+] AUTO-PIPELINE TERMINÉ. Prêt pour l'UI ou l'analyse.", fg=typer.colors.GREEN)

if __name__ == "__main__":
    app()
