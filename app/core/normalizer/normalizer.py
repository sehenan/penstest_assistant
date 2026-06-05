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
            port = s.get("port") or 0
            proto = s.get("protocol")
            
            # Check if service already exists for this host/port/proto
            service = session.scalar(
                select(Service).where(
                    Service.host_id == host.id,
                    Service.port == port,
                    Service.protocol == proto
                )
            )
            
            if service is None:
                service = Service(
                    host_id=host.id,
                    port=port,
                    protocol=proto,
                    service=s.get("service"),
                    version=s.get("version"),
                    banner=s.get("banner"),
                    cpe=s.get("cpe"),   # CPE extrait par le parser (nmap/openvas)
                )
                session.add(service)
                session.flush()
                created["services"] += 1
            else:
                # Update existing service info if provided
                if s.get("service"): service.service = s.get("service")
                if s.get("version"): service.version = s.get("version")
                if s.get("banner"):  service.banner  = s.get("banner")
                if s.get("cpe") and not service.cpe: service.cpe = s.get("cpe")

            cves = s.get("cves") or []
            desc = s.get("description")
            
            def add_vuln_if_unique(cve_val, desc_val):
                # Normalisation
                cve_clean = cve_val.strip().upper() if cve_val else None
                desc_clean = desc_val.strip() if desc_val else None
                
                # Un CVE vide ou "NON-CVE" doit être traité comme None
                if cve_clean in ["", "NON-CVE", "UNKNOWN"]:
                    cve_clean = None

                # Check for existing vuln for THIS service
                query = select(Vulnerability).where(Vulnerability.service_id == service.id)
                
                if cve_clean:
                    # Si on a un CVE, on déduplique sur le CVE uniquement pour ce service
                    query = query.where(Vulnerability.cve == cve_clean)
                elif desc_clean:
                    # Si pas de CVE, on déduplique sur la description exacte
                    query = query.where(Vulnerability.description == desc_clean)
                else:
                    return # Rien pour l'identifier
                
                existing_vuln = session.scalar(query)
                if existing_vuln is None:
                    new_vuln = Vulnerability(
                        service_id=service.id,
                        cve=cve_clean,
                        description=desc_clean,
                        source=scan_source,
                    )
                    session.add(new_vuln)
                    session.flush() # Pour éviter les doublons dans la même boucle
                    created["vulns"] += 1
                else:
                    # On met à jour la description si elle était vide
                    if desc_clean and not existing_vuln.description:
                        existing_vuln.description = desc_clean

            if cves:
                for cve in cves:
                    add_vuln_if_unique(cve, desc)
            elif desc:
                add_vuln_if_unique(None, desc)


    try:
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise
    return created
