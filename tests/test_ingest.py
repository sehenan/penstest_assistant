from pathlib import Path

from sqlalchemy import select, func

from app.core.ingest import ingest_scan_file
from app.db.models import Host, Service, Vulnerability

DATA = Path(__file__).resolve().parents[1] / "data" / "inputs"


def test_ingest_nmap_counts(db_session):
    counts = ingest_scan_file(str(DATA / "scan_nmap.xml"), db_session)
    assert counts["hosts"] == 2
    assert counts["services"] >= 3
    n_hosts = db_session.scalar(select(func.count()).select_from(Host))
    assert n_hosts == 2


def test_ingest_openvas_finds_cve(db_session):
    ingest_scan_file(str(DATA / "scan_openvas.xml"), db_session)
    n = db_session.scalar(select(func.count()).select_from(Vulnerability))
    assert n >= 1
    row = db_session.scalar(select(Vulnerability).where(Vulnerability.cve == "CVE-2017-0143"))
    assert row is not None
    assert row.source == "openvas"


def test_host_dedup_second_ingest(db_session):
    ingest_scan_file(str(DATA / "scan_openvas.xml"), db_session)
    ingest_scan_file(str(DATA / "scan_openvas.xml"), db_session)
    n_hosts = db_session.scalar(select(func.count()).select_from(Host))
    assert n_hosts == 1
    n_srv = db_session.scalar(select(func.count()).select_from(Service))
    assert n_srv == 2
