import sys
from app.cmd import app

if __name__ == "__main__":
    # Si aucun argument n'est fourni, on lance l'interface web par défaut
    if len(sys.argv) == 1:
        sys.argv.append("ui")
    app()
