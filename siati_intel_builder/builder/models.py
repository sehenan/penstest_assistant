from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class IntelCVE(Base):
    __tablename__ = "intel_cve"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v4_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    published_date = Column(DateTime, nullable=True)
    last_modified_date = Column(DateTime, nullable=True)
    # Champs nécessaires pour la validation sans hallucination
    affected_versions = Column(Text, nullable=True)  # JSON array (format NVD CPE ranges)
    fixed_versions = Column(Text, nullable=True)      # JSON array
    keywords = Column(Text, nullable=True)            # JSON array — utilisé par ReportValidator
    poc_available = Column(Boolean, default=False, nullable=False)

class IntelEPSS(Base):
    __tablename__ = "intel_epss"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True, unique=True, nullable=False)
    epss_score = Column(Float, nullable=False)
    percentile = Column(Float, nullable=False)
    date_fetched = Column(String, nullable=True)

class IntelKEV(Base):
    __tablename__ = "intel_kev"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True, unique=True, nullable=False)
    vendor_project = Column(String, nullable=True)
    product = Column(String, nullable=True)
    short_description = Column(Text, nullable=True)
    date_added = Column(String, nullable=True)
    due_date = Column(String, nullable=True)
    known_ransomware_campaign_use = Column(String, nullable=True)

class IntelExploits(Base):
    __tablename__ = "intel_exploits"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, index=True, nullable=False)
    source = Column(String, nullable=False)  # e.g., 'exploitdb', 'metasploit', 'nuclei'
    reference_id = Column(String, nullable=True) # e.g., EDB-ID
    file_path_or_module = Column(String, nullable=True)

    __table_args__ = (UniqueConstraint('cve_id', 'source', 'reference_id', name='_cve_source_ref_uc'),)

# Pour la FTS, SQLite utilise des tables virtuelles, nous les créerons via des requêtes brutes
# mais voici le modèle pour le dictionnaire CPE standard (si on veut le stocker en relationnel aussi)
class IntelCPE(Base):
    __tablename__ = "intel_cpe"
    id = Column(Integer, primary_key=True)
    cpe_name = Column(String, index=True, unique=True, nullable=False)
    title = Column(String, nullable=True) # Ex: "Apache Tomcat 9.0"
