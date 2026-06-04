import sqlite3
from pathlib import Path

def migrate():
    db_path = Path("data/pentest.db")
    if not db_path.exists():
        print("Base de données introuvable.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        print("Ajout de la colonne 'reasoning'...")
        cursor.execute("ALTER TABLE scores_ml ADD COLUMN reasoning TEXT")
    except sqlite3.OperationalError:
        print("Colonne 'reasoning' déjà présente.")

    try:
        print("Ajout de la colonne 'confidence'...")
        cursor.execute("ALTER TABLE scores_ml ADD COLUMN confidence FLOAT")
    except sqlite3.OperationalError:
        print("Colonne 'confidence' déjà présente.")

    conn.commit()
    conn.close()
    print("Migration terminée avec succès.")

if __name__ == "__main__":
    migrate()
