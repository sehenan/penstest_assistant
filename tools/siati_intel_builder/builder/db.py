import os
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from builder.models import Base

def _fk_pragma_on_connect(dbapi_con, con_record):
    dbapi_con.execute('pragma foreign_keys=ON')

def get_engine(db_path="threat_intel.db"):
    engine = create_engine(f"sqlite:///{db_path}")
    event.listen(engine, 'connect', _fk_pragma_on_connect)
    return engine

def init_db(db_path="threat_intel.db"):
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    
    # Création de la table virtuelle FTS5 pour la recherche de CPE
    with engine.begin() as conn:
        conn.execute(text(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS intel_cpe_fts USING fts5(
                cpe_name, title,
                content='intel_cpe', content_rowid='id'
            );
            """
        ))
        
        # Trigger pour synchroniser intel_cpe et intel_cpe_fts
        conn.execute(text(
            """
            CREATE TRIGGER IF NOT EXISTS intel_cpe_ai AFTER INSERT ON intel_cpe BEGIN
                INSERT INTO intel_cpe_fts(rowid, cpe_name, title) VALUES (new.id, new.cpe_name, new.title);
            END;
            """
        ))
        conn.execute(text(
            """
            CREATE TRIGGER IF NOT EXISTS intel_cpe_ad AFTER DELETE ON intel_cpe BEGIN
                INSERT INTO intel_cpe_fts(intel_cpe_fts, rowid, cpe_name, title) VALUES ('delete', old.id, old.cpe_name, old.title);
            END;
            """
        ))
        conn.execute(text(
            """
            CREATE TRIGGER IF NOT EXISTS intel_cpe_au AFTER UPDATE ON intel_cpe BEGIN
                INSERT INTO intel_cpe_fts(intel_cpe_fts, rowid, cpe_name, title) VALUES ('delete', old.id, old.cpe_name, old.title);
                INSERT INTO intel_cpe_fts(rowid, cpe_name, title) VALUES (new.id, new.cpe_name, new.title);
            END;
            """
        ))

def get_session(db_path="threat_intel.db"):
    engine = get_engine(db_path)
    Session = sessionmaker(bind=engine)
    return Session()
