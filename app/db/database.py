from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """
    Force l'activation du support des clés étrangères (Foreign Keys) pour SQLite.
    Par défaut, SQLite ne fait pas respecter les contraintes de clés étrangères (ni CASCADE).
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Base(DeclarativeBase):
    pass


def _default_db_url() -> str:
    root = Path(__file__).resolve().parents[2]
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{data_dir / 'pentest.db'}"


def _resolve_db_url() -> str:
    """Résout l'URL de la base à CHAQUE appel (et non au seul import).

    Priorité : PENTEST_DB_URL (URL SQLAlchemy complète) > SIATI_DB_PATH (chemin
    de fichier, cf. CLAUDE.md) > base par défaut data/pentest.db.
    Résolution dynamique => permet d'isoler les tests via une base temporaire
    positionnée par variable d'environnement avant les requêtes.
    """
    url = os.environ.get("PENTEST_DB_URL")
    if url:
        return url
    path = os.environ.get("SIATI_DB_PATH")
    if path:
        return f"sqlite:///{path}"
    return _default_db_url()


# Conservé pour compatibilité ascendante ; les fonctions résolvent dynamiquement.
DATABASE_URL = _resolve_db_url()


def get_engine(url: str | None = None):
    return create_engine(url or _resolve_db_url(), echo=False)


def get_session(engine=None):
    bind = engine or get_engine()
    Session = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=bind)
    return Session()


def init_db(engine=None) -> None:
    eng = engine or get_engine()
   
    from app.db import models 

    Base.metadata.create_all(bind=eng)

    # Nettoyage automatique des lignes orphelines (ScoreML & Report)
    from sqlalchemy import text
    with eng.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(text("DELETE FROM scores_ml WHERE vuln_id NOT IN (SELECT id FROM vulnerabilities)"))
            conn.execute(text("DELETE FROM reports WHERE vuln_id NOT IN (SELECT id FROM vulnerabilities) AND vuln_id IS NOT NULL"))
            transaction.commit()
        except Exception:
            transaction.rollback()
            raise
