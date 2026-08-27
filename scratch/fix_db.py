"""
Retraduction des vulnérabilités en base via Ollama LLM.

Usage:
    python -m scratch.fix_db           # Traduit les descriptions encore en anglais
    python -m scratch.fix_db --force   # Force la retraduction de TOUTES les descriptions (y compris franglais)
"""
import argparse
import logging
import sys

from app.db.database import init_db, get_session
from app.core.enrichment.translate import translate_vulnerability_descriptions

logging.basicConfig(level=logging.INFO, stream=sys.stdout)


def main():
    parser = argparse.ArgumentParser(description="Retraduire les vulnérabilités en base.")
    parser.add_argument(
        "--force", action="store_true",
        help="Forcer la retraduction de toutes les descriptions (y compris le franglais)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  Retraduction des descriptions de vulnérabilités")
    print("  Mode :", "FORCE (toutes)" if args.force else "Normal (anglais seulement)")
    print("=" * 60)

    init_db()
    session = get_session()
    try:
        stats = translate_vulnerability_descriptions(
            session, use_llm=True, force_retranslate=args.force
        )
        print("\n--- Résultats ---")
        for k, v in stats.items():
            print(f"  {k}: {v}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
