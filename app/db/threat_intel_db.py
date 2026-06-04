from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from pathlib import Path
import os
from sqlalchemy import event

# Define models that SIATI will use to read from threat_intel.db
BaseIntel = declarative_base()

# To keep it DRY, we redefine the models here or we could share them if we packaged the builder.
# Since it's a micro-project, we define read-only mappings here.
from sqlalchemy import Column, Integer, String, Float, Text, DateTime

class IntelCVE(BaseIntel):
    __tablename__ = "intel_cve"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True)
    description = Column(Text)
    cvss_v2_score = Column(Float)
    cvss_v3_score = Column(Float)
    cvss_v4_score = Column(Float)
    cvss_v3_vector = Column(String)
    cwe_id = Column(String)

class IntelEPSS(BaseIntel):
    __tablename__ = "intel_epss"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True)
    epss_score = Column(Float)
    percentile = Column(Float)

class IntelKEV(BaseIntel):
    __tablename__ = "intel_kev"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True)
    vendor_project = Column(String)
    known_ransomware_campaign_use = Column(String)

DATA_DIR = Path("data")
INTEL_DB_PATH = DATA_DIR / "threat_intel.db"

def get_intel_engine():
    # Use read-only URI if possible, but SQLite standard is fine
    # sqlite:////absolute/path/to/file.db
    # or relative: sqlite:///data/threat_intel.db
    engine = create_engine(f"sqlite:///{INTEL_DB_PATH}")
    return engine

def get_intel_session():
    if not INTEL_DB_PATH.exists():
        # Returns None if the db is not present (offline/air-gap without bundle)
        return None
    engine = get_intel_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()
