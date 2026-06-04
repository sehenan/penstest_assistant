import sys
from app.cmd import app

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "-web":
            # On remplace -web par la commande typer 'ui'
            sys.argv = [sys.argv[0], "ui"]
        elif sys.argv[1] == "-cli":
            # On enlève le flag -cli pour laisser typer traiter le reste
            sys.argv.pop(1)
            # Si l'utilisateur a juste tapé `main.py -cli`, on affiche l'aide
            if len(sys.argv) == 1:
                sys.argv.append("--help")
    else:
        # Aucun argument -> on affiche l'aide par défaut (ou on pourrait lancer l'UI, mais l'explicite est mieux)
        sys.argv.append("--help")
        
    app()
