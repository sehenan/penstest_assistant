from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def _default_db_url() -> str:
    root = Path(__file__).resolve().parents[2]
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{data_dir / 'pentest.db'}"


DATABASE_URL = os.environ.get("PENTEST_DB_URL", _default_db_url())


def get_engine(url: str | None = None):
    return create_engine(url or DATABASE_URL, echo=False)


def get_session(engine=None):
    bind = engine or get_engine()
    Session = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=bind)
    return Session()


def init_db(engine=None) -> None:
    eng = engine or get_engine()
    # Import models so metadata is registered
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=eng)
