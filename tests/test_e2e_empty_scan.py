import os
import tempfile
from typer.testing import CliRunner
from app.cmd import app

runner = CliRunner()

def test_ingest_empty_file_does_not_crash():
    """
    Vérifie que l'ingestion d'un fichier XML vide ne fait pas planter le système 
    et se termine proprement (gestion d'exception).
    """
    # Création d'un fichier vide temporaire
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        empty_file_path = tmp.name

    try:
        # On lance la commande CLI "ingest"
        result = runner.invoke(app, ["ingest", empty_file_path])
        
        if result.exit_code != 0:
            print(f"EXIT CODE: {result.exit_code}")
            print(f"STDOUT: {result.stdout}")
            if result.exception:
                print(f"EXCEPTION: {result.exception}")
        
        # Le système ne doit pas planter (exit_code == 0)
        assert result.exit_code == 0
        
        # On s'attend à ce que l'output mentionne l'ingestion puis un succès (avec Ajouts: 0 potentiellement)
        # ou un message d'erreur géré sans traceback.
        assert "Ingestion" in result.stdout
    finally:
        # Nettoyage
        if os.path.exists(empty_file_path):
            os.remove(empty_file_path)

if __name__ == "__main__":
    test_ingest_empty_file_does_not_crash()
    print("Test E2E résilience scan vide : SUCCÈS")
