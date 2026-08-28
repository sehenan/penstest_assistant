import logging
import sys
from app.db.database import init_db, get_session
from app.core.enrichment.translate import translate_vulnerability_descriptions

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

def main():
    print("Fixing translations in the database...")
    init_db()
    session = get_session()
    try:
        stats = translate_vulnerability_descriptions(session, use_llm=True)
        print("Translation stats:", stats)
    finally:
        session.close()

if __name__ == "__main__":
    main()
