from __future__ import annotations

from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models import Host, Service, Vulnerability


def normalize_and_insert(
    parsed_list: List[Dict],
    session: Session,
    scan_source: str = "unknown",
) -> Dict[str, int]:
    """
    Insère les dicts host / services / vulns dans la base.
    Réutilise un hôte existant si la même IP existe déjà (évite les doublons OpenVAS).
    """
    created = {"hosts": 0, "services": 0, "vulns": 0}
    for h in parsed_list:
        ip = h.get("ip")
        if not ip:
            continue

        host = session.scalar(select(Host).where(Host.ip == ip))
        if host is None:
            host = Host(ip=ip, hostname=h.get("hostname"), os=h.get("os"))
            session.add(host)
            session.flush()
            created["hosts"] += 1
        else:
            if h.get("hostname") and not host.hostname:
                host.hostname = h.get("hostname")
            if h.get("os") and not host.os:
                host.os = h.get("os")

        for s in h.get("services", []):
            service = Service(
                host_id=host.id,
                port=s.get("port") or 0,
                protocol=s.get("protocol"),
                service=s.get("service"),
                version=s.get("version"),
                banner=s.get("banner"),
            )
            session.add(service)
            session.flush()
            created["services"] += 1

            cves = s.get("cves") or []
            desc = s.get("description")
            if cves:
                for cve in cves:
                    vuln = Vulnerability(
                        service_id=service.id,
                        cve=cve,
                        description=desc,
                        source=scan_source,
                    )
                    session.add(vuln)
                    created["vulns"] += 1
            elif desc:
                vuln = Vulnerability(
                    service_id=service.id,
                    cve=None,
                    description=desc,
                    source=scan_source,
                )
                session.add(vuln)
                created["vulns"] += 1

    try:
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise
    return created
