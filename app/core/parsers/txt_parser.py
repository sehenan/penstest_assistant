import re
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def parse_txt(path: str) -> List[Dict]:
    """
    Parse un fichier texte brut (ex: output nmap -oN) et extrait les hôtes.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du fichier txt: {e}")
        return []

    results = []
    current_host = None
    
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
            
        # Exemple: Nmap scan report for 192.168.1.10
        # Exemple: Nmap scan report for srv-web (10.0.0.5)
        m_report = re.match(r"^Nmap scan report for (.+)$", line)
        if m_report:
            target = m_report.group(1)
            m_target = re.match(r"^(.+) \(([\d\.]+)\)$", target)
            if m_target:
                hostname, ip = m_target.groups()
            else:
                if re.match(r"^[\d\.]+$", target):
                    ip = target
                    hostname = None
                else:
                    ip = target
                    hostname = target

            current_host = {
                "ip": ip,
                "hostname": hostname,
                "os": None,
                "services": []
            }
            results.append(current_host)
            continue
            
        # Exemple: 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
        m_port = re.match(r"^(\d+)/(\w+)\s+open\s+([\w\-]+)\s*(.*)$", line)
        if m_port and current_host:
            portnum, protocol, service, version = m_port.groups()
            current_host["services"].append({
                "port": int(portnum),
                "protocol": protocol,
                "service": service,
                "version": version.strip() if version else None,
                "banner": version.strip() if version else None,
                "cpes": [],
                "cpe": None,
                "cves": [],
                "description": f"Service détecté : {service} sur le port {portnum}/{protocol}. (Source txt)"
            })
            continue

    # Si c'est juste un fichier txt avec des IP sans format Nmap
    if not results:
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
        if ips:
            # deduplicate and add as simple hosts
            ips = list(dict.fromkeys(ips))
            for ip in ips:
                results.append({
                    "ip": ip,
                    "hostname": None,
                    "os": None,
                    "services": []
                })

    return results
