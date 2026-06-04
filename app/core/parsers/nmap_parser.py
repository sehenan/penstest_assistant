# src/core/parsers/nmap_parser.py
from lxml import etree
from typing import List, Dict
import re

# Mapping service name → CPE vendor:product pour inférence quand le CPE est absent
_SVC_CPE_MAP: dict[str, str] = {
    "http":       "cpe:2.3:a:apache:http_server:{}",
    "https":      "cpe:2.3:a:apache:http_server:{}",
    "ssh":        "cpe:2.3:a:openbsd:openssh:{}",
    "ftp":        "cpe:2.3:a:vsftpd:vsftpd:{}",
    "smtp":       "cpe:2.3:a:postfix:postfix:{}",
    "mysql":      "cpe:2.3:a:oracle:mysql:{}",
    "postgresql": "cpe:2.3:a:postgresql:postgresql:{}",
    "rdp":        "cpe:2.3:a:microsoft:remote_desktop_protocol:{}",
    "msrpc":      "cpe:2.3:a:microsoft:windows:{}",
    "smb":        "cpe:2.3:a:microsoft:windows:{}",
    "telnet":     "cpe:2.3:a:gnu:inetutils:{}",
    "nginx":      "cpe:2.3:a:nginx:nginx:{}",
    "iis":        "cpe:2.3:a:microsoft:iis:{}",
}


def _extract_cpe(service_el, port_el) -> str | None:
    """
    Extrait le CPE au format 2.3 depuis :
    1. Les balises <cpe> enfants de <service> (format natif Nmap)
    2. Inférence depuis service name + version si absent
    """
    # Priorité 1 : balises CPE natives Nmap
    cpes = []
    if service_el is not None:
        for cpe_el in service_el.findall("cpe"):
            if cpe_el.text:
                cpes.append(cpe_el.text.strip())
    # Chercher aussi dans les scripts du port
    for script in port_el.findall("script"):
        for cpe_el in script.findall(".//cpe"):
            if cpe_el.text:
                cpes.append(cpe_el.text.strip())
    if cpes:
        return cpes[0]  # On prend le premier CPE (le plus précis)

    # Priorité 2 : inférence depuis service name + version
    if service_el is None:
        return None
    svc_name = (service_el.get("name") or "").lower()
    version  = service_el.get("version") or "*"
    template = _SVC_CPE_MAP.get(svc_name)
    if template:
        return template.format(version)

    return None


def parse_nmap(xml_path: str) -> List[Dict]:
    """
    Parse Nmap XML (-oX) et retourne une liste de dicts hôtes :
    { ip, hostname, os, services: [
        { port, protocol, service, version, banner, cpes, cves, description }
    ]}

    Chaîne de résolution CVE :
      1. CVE directes dans les outputs de scripts (vuln, exploit categories)
      2. CPE extrait des balises <cpe> → enrichissement NVD ultérieur
      3. Inférence CPE depuis (service name + version) → fallback NVD
      Si aucune CVE n'est trouvée, une entrée de vulnérabilité "service détecté"
      est quand même créée pour permettre l'enrichissement aval.
    """
    from app.core.parsers.utils import load_xml_clean
    root = load_xml_clean(xml_path)

    results = []
    for host in root.findall("./host"):
        # ── Ignorer les hôtes down ──────────────────────────────────────────
        status_el = host.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        hostname_el = host.find("./hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        os_el = host.find("./os/osmatch")
        os_name = os_el.get("name") if os_el is not None else None

        services = []
        for port in host.findall(".//port"):
            # N'inclure que les ports ouverts
            state_el = port.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue

            portnum   = int(port.get("portid")) if port.get("portid") else 0
            protocol  = port.get("protocol")
            service_el = port.find("service")
            service_name = service_el.get("name")    if service_el is not None else None
            version      = service_el.get("version") if service_el is not None else None
            product      = service_el.get("product") if service_el is not None else None
            banner       = " ".join(x for x in (product, version) if x) or None

            # ── Extraction CPE ─────────────────────────────────────────────
            cpe = _extract_cpe(service_el, port)

            # ── CVE depuis les scripts (vuln/exploit NSE) ──────────────────
            cves: list[str] = []
            script_desc: str | None = None
            for script in port.findall("script"):
                output = script.get("output", "") or ""
                for c in re.findall(r"(CVE-\d{4}-\d+)", output, re.IGNORECASE):
                    cves.append(c.upper())
                # Récupérer une description depuis les elem de script vuln
                if not script_desc and script.get("id", "").startswith("vuln"):
                    script_desc = output.strip()[:500] or None

            cves = list(dict.fromkeys(cves))  # dédoublonnage stable

            # ── Description fallback ───────────────────────────────────────
            # Si aucune CVE ni description : on crée quand même une entrée
            # pour permettre l'enrichissement NVD/CPE ultérieur
            description = script_desc
            if not cves and not description and (cpe or (service_name and version)):
                description = (
                    f"Service détecté : {service_name or '?'} "
                    f"{version or ''} sur le port {portnum}/{protocol}. "
                    f"CPE : {cpe or 'inconnu'}. Enrichissement NVD requis."
                )

            services.append({
                "port":        portnum,
                "protocol":    protocol,
                "service":     service_name,
                "version":     version,
                "banner":      banner,
                "cpes":        [cpe] if cpe else [],   # liste pour compatibilité future
                "cpe":         cpe,                    # accès direct
                "cves":        cves,
                "description": description,
            })

        results.append({
            "ip":       ip,
            "hostname": hostname,
            "os":       os_name,
            "services": services,
        })
    return results
