from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base

class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True, nullable=False)
    hostname = Column(String, nullable=True)
    os = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('ip', name='_host_ip_uc'),)

    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), index=True, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=True)
    service = Column(String, nullable=True)
    version = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    cpe = Column(String, nullable=True, index=True)   # CPE 2.3 extrait du scan
    
    __table_args__ = (UniqueConstraint('host_id', 'port', 'protocol', name='_service_port_proto_uc'),)

    host = relationship("Host", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey("services.id"), index=True, nullable=False)
    cve = Column(String, index=True, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    epss_score = Column(Float, nullable=True)
    is_kev = Column(Boolean, default=False)
    source = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('service_id', 'cve', 'description', name='_vuln_unique_uc'),)

    service = relationship("Service", back_populates="vulnerabilities")
    scores = relationship("ScoreML", back_populates="vulnerability", cascade="all, delete-orphan")

class Exploit(Base):
    __tablename__ = "exploits"
    id = Column(Integer, primary_key=True)
    cve = Column(String, index=True)
    exploit_db_id = Column(String, nullable=True)
    metasploit_module = Column(String, nullable=True)
    disponible = Column(Boolean, default=False)

class ScoreML(Base):
    __tablename__ = "scores_ml"
    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    score = Column(Float, nullable=True)
    label = Column(String, nullable=True)
    reasoning = Column(Text, nullable=True)  # Explication XAI
    confidence = Column(Float, nullable=True) # Confiance du modèle
    timestamp = Column(DateTime, default=datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="scores")

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), index=True, nullable=True)
    title = Column(String, nullable=False)
    content_md = Column(Text, nullable=True)
    stage = Column(String, nullable=True)  # 'audit' ou 'payload'
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    vulnerability = relationship("Vulnerability")
