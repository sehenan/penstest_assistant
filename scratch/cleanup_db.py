import sqlite3
import os
from pathlib import Path

DB_PATH = Path("data") / "pentest.db"

def cleanup():
    if not DB_PATH.exists():
        print(f"Base de données introuvable : {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("Recherche de doublons dans la table 'scores_ml'...")
    
    # Compter avant
    cursor.execute("SELECT COUNT(*) FROM scores_ml")
    count_before = cursor.fetchone()[0]
    
    # Supprimer les doublons en gardant le plus récent (id le plus élevé)
    # On groupe par vuln_id et on garde le max(id)
    cursor.execute("""
        DELETE FROM scores_ml 
        WHERE id NOT IN (
            SELECT MAX(id) 
            FROM scores_ml 
            GROUP BY vuln_id
        )
    """)
    
    conn.commit()
    
    # Compter après
    cursor.execute("SELECT COUNT(*) FROM scores_ml")
    count_after = cursor.fetchone()[0]
    
    print(f"Nettoyage terminé.")
    print(f"Lignes avant : {count_before}")
    print(f"Lignes après : {count_after}")
    print(f"Doublons supprimés : {count_before - count_after}")
    
    conn.close()

if __name__ == "__main__":
    cleanup()
