import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db.database import get_session
from app.db.models import ScoreML

def fix_labels():
    session = get_session()
    try:
        # Moyen -> Moyenne
        moyen_count = session.query(ScoreML).filter(ScoreML.label == "Moyen").update(
            {"label": "Moyenne"}, synchronize_session=False
        )
        # Haut -> Haute
        haut_count = session.query(ScoreML).filter(ScoreML.label == "Haut").update(
            {"label": "Haute"}, synchronize_session=False
        )
        
        session.commit()
        print(f"Correction terminée :")
        print(f" - {moyen_count} labels 'Moyen' mis à jour en 'Moyenne'")
        print(f" - {haut_count} labels 'Haut' mis à jour en 'Haute'")
    except Exception as e:
        print(f"Erreur lors de la correction : {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    fix_labels()
