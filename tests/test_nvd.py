"""
Tests de l'enrichissement des vulnérabilités.

L'implémentation interroge désormais une base de Threat Intel LOCALE (offline /
air-gap) via `enrich_vulnerabilities_from_local_intel`, et non plus l'API NVD en
direct. Ces tests montent une intel base en mémoire et vérifient l'enrichissement
NVD (CVSS/desc/CWE), EPSS et KEV.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enrichment import nvd
from app.core.enrichment.nvd import enrich_vulnerabilities_from_local_intel
from app.db import threat_intel_db as tidb
from app.db.threat_intel_db import BaseIntel, IntelCVE, IntelEPSS, IntelKEV
from app.db.models import Host, Service, Vulnerability


@pytest.fixture
def intel_session(monkeypatch):
    """Intel base SQLite en mémoire, injectée à la place de la vraie base locale."""
    engine = create_engine("sqlite:///:memory:")
    BaseIntel.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    session.add(IntelCVE(
        cve_id="CVE-2017-0143",
        description="EternalBlue SMBv1 remote code execution",
        cvss_v3_score=8.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-20",
    ))
    session.add(IntelEPSS(cve_id="CVE-2017-0143", epss_score=0.97, percentile=0.99))
    session.add(IntelKEV(cve_id="CVE-2017-0143", vendor_project="Microsoft"))
    session.commit()

    # La fonction enrichie récupère sa session via get_intel_session().
    monkeypatch.setattr(nvd, "get_intel_session", lambda: Session())
    yield session
    session.close()


def _seed_vuln(db_session, cve="CVE-2017-0143"):
    host = Host(ip="10.0.0.1")
    db_session.add(host)
    db_session.flush()
    svc = Service(host_id=host.id, port=445, protocol="tcp", service="smb")
    db_session.add(svc)
    db_session.flush()
    vuln = Vulnerability(service_id=svc.id, cve=cve, description=None, source="test")
    db_session.add(vuln)
    db_session.commit()
    return vuln


def test_enrich_populates_nvd_epss_kev(db_session, intel_session):
    """Une vuln avec CVE connue est enrichie CVSS + description + CWE + EPSS + KEV."""
    vuln = _seed_vuln(db_session)

    stats = enrich_vulnerabilities_from_local_intel(db_session)

    assert stats["updated"] == 1
    db_session.refresh(vuln)
    assert vuln.cvss_score == 8.8
    assert "CVSS:3.1" in (vuln.cvss_vector or "")
    assert vuln.cwe == "CWE-20"
    assert vuln.description and "EternalBlue" in vuln.description
    assert vuln.epss_score == 0.97
    assert vuln.is_kev is True


def test_enrich_skips_unknown_cve(db_session, intel_session):
    """Une CVE absente de l'intel base n'est pas modifiée (comptée en 'skipped')."""
    vuln = _seed_vuln(db_session, cve="CVE-2099-9999")

    stats = enrich_vulnerabilities_from_local_intel(db_session)

    assert stats["updated"] == 0
    assert stats["skipped"] >= 1
    db_session.refresh(vuln)
    assert vuln.cvss_score is None
    assert vuln.is_kev is False


def test_enrich_missing_intel_db(db_session, monkeypatch):
    """Si l'intel base est absente, la fonction le signale sans crasher."""
    monkeypatch.setattr(nvd, "get_intel_session", lambda: None)
    stats = enrich_vulnerabilities_from_local_intel(db_session)
    assert stats["missing_intel_db"] == 1
