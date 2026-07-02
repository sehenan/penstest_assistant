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
    """Idempotence : ré-ingérer le même scan ne duplique NI hôtes NI services."""
    ingest_scan_file(str(DATA / "scan_openvas.xml"), db_session)
    hosts_after_first = db_session.scalar(select(func.count()).select_from(Host))
    srv_after_first = db_session.scalar(select(func.count()).select_from(Service))

    # Un seul hôte dans ce scan, dédupliqué sur l'IP.
    assert hosts_after_first == 1
    assert srv_after_first >= 1

    # Seconde ingestion du fichier identique : aucun ajout (upsert idempotent).
    counts = ingest_scan_file(str(DATA / "scan_openvas.xml"), db_session)
    assert counts["hosts"] == 0
    assert counts["services"] == 0

    assert db_session.scalar(select(func.count()).select_from(Host)) == hosts_after_first
    assert db_session.scalar(select(func.count()).select_from(Service)) == srv_after_first
