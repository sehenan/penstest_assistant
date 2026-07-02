# Parser de rapports de scan au format PDF (Nessus / OpenVAS / Nmap exportés en PDF).
from __future__ import annotations

import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Ligne de port style Nmap : "22/tcp open ssh OpenSSH 8.2p1"
_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\b\s*(?:open\s+)?([\w\-]+)?\s*(.*)$", re.IGNORECASE)
# Ligne qui désigne un hôte cible
_HOST_RE = re.compile(
    r"(?:nmap scan report for|host\s*[:\-]|target\s*[:\-]|ip address\s*[:\-]|adresse ip\s*[:\-])\s*(.+)",
    re.IGNORECASE,
)


def extract_text_from_pdf(path: str) -> str:
    """Extrait tout le texte d'un PDF (robuste : ignore les pages illisibles)."""
    try:
        from pypdf import PdfReader
    except ImportError as e:  # pragma: no cover
        raise ValueError(
            "Le support PDF nécessite la librairie 'pypdf' (pip install pypdf)."
        ) from e

    try:
        reader = PdfReader(path)
    except Exception as e:
        raise ValueError(f"Impossible de lire le fichier PDF : {e}") from e

    parts: List[str] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            continue
    return "\n".join(parts)


def _host_from_line(line: str) -> str | None:
    """Retourne l'IP si la ligne désigne un hôte cible, sinon None."""
    m = _HOST_RE.search(line)
    candidate = m.group(1) if m else line
    # Ligne réduite à une IP (éventuellement suivie d'un hostname entre parenthèses)
    ip_match = _IP_RE.search(candidate)
    if not ip_match:
        return None
    # On ne déclenche un changement d'hôte que si la ligne est "courte" et centrée
    # sur l'IP (titre de section), pas une phrase qui mentionne une IP au passage.
    if m or len(candidate.strip()) <= 60:
        return ip_match.group(0)
    return None


def parse_pdf(path: str) -> List[Dict]:
    """
    Parse un rapport de scan PDF et retourne la même structure que les autres parsers :
    { ip, hostname, os, services: [{ port, protocol, service, version, banner, cves, description }] }

    Heuristique : on suit l'hôte courant (titres de section / IP isolée), on détecte
    les lignes de ports style Nmap, et on rattache les CVE rencontrés au service courant
    (ou à un service générique de l'hôte si aucun port n'est actif).
    """
    text = extract_text_from_pdf(path)
    if not text.strip():
        logger.warning("PDF sans texte extractible : %s", path)
        return []

    hosts: Dict[str, Dict] = {}
    order: List[str] = []
    current_ip: str | None = None
    current_service: Dict | None = None

    def ensure_host(ip: str) -> Dict:
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "hostname": None, "os": None, "services": []}
            order.append(ip)
        return hosts[ip]

    def generic_service(host: Dict) -> Dict:
        """Service fourre-tout (port 0) pour les CVE sans contexte de port."""
        for s in host["services"]:
            if s["port"] == 0:
                return s
        svc = {
            "port": 0, "protocol": None, "service": "pdf-report",
            "version": None, "banner": None, "cves": [],
            "description": "Vulnérabilités importées depuis un rapport PDF.",
        }
        host["services"].append(svc)
        return svc

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        # 1. Changement d'hôte ?
        host_ip = _host_from_line(line)
        if host_ip:
            current_ip = host_ip
            host = ensure_host(current_ip)
            # hostname éventuel : "10.0.0.5 (srv-web)" ou "srv-web (10.0.0.5)"
            if not host["hostname"]:
                m = _HOST_RE.search(line)
                candidate = m.group(1) if m else line
                # On retire l'IP et les parenthèses, ce qui reste est le hostname
                leftover = _IP_RE.sub("", candidate).replace("(", " ").replace(")", " ").strip(" \t-")
                if leftover and not _IP_RE.search(leftover):
                    host["hostname"] = leftover
            current_service = None
            continue

        # 2. Ligne de port (style Nmap) ?
        m_port = _PORT_RE.match(line)
        if m_port and current_ip:
            port, proto, svc_name, rest = m_port.groups()
            current_service = {
                "port": int(port),
                "protocol": proto.lower(),
                "service": (svc_name or "").strip() or None,
                "version": rest.strip() or None,
                "banner": rest.strip() or None,
                "cves": [],
                "description": f"Service {svc_name or '?'} sur le port {port}/{proto} (rapport PDF).",
            }
            hosts[current_ip]["services"].append(current_service)
            continue

        # 3. CVE sur la ligne ?
        cves = [c.upper() for c in _CVE_RE.findall(line)]
        if cves and current_ip:
            host = hosts[current_ip]
            target = current_service or generic_service(host)
            for cve in cves:
                if cve not in target["cves"]:
                    target["cves"].append(cve)
            # On garde la ligne comme description si elle apporte du texte
            if len(line) > 20:
                target["description"] = line[:1000]

    # Repli : des CVE existent mais aucun hôte n'a été détecté → utiliser la 1re IP du doc
    if not order:
        all_cves = [c.upper() for c in _CVE_RE.findall(text)]
        ip_match = _IP_RE.search(text)
        if all_cves and ip_match:
            host = ensure_host(ip_match.group(0))
            svc = generic_service(host)
            svc["cves"] = list(dict.fromkeys(all_cves))

    return [hosts[ip] for ip in order]
