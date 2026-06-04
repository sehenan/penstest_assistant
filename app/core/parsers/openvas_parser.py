from lxml import etree
from typing import List, Dict


def parse_openvas(xml_path: str) -> List[Dict]:
    """
    Parse a simple OpenVAS/GVM XML export and return host dicts.
    Note: OpenVAS exports vary; this is a pragmatic/simple parser.
    """
    from app.core.parsers.utils import load_xml_clean
    root = load_xml_clean(xml_path)
    results = []

    for result in root.findall(".//result"):
        host = result.findtext("host")
        port_text = result.findtext("port") or "0"
        try:
            port = int(str(port_text).strip())
        except (TypeError, ValueError):
            port = 0
        service = result.findtext("service")
        description = result.findtext("description")
        # collect CVEs under nvt/cve
        cves = []
        for n in result.findall(".//nvt"):
            for cve in n.findall(".//cve"):
                if cve.text:
                    cves.append(cve.text.strip())
        services = [{
            "port": port,
            "protocol": None,
            "service": service,
            "version": None,
            "banner": description,
            "cves": list(set(cves)),
            "description": description
        }]
        results.append({
            "ip": host,
            "hostname": None,
            "os": None,
            "services": services
        })
    return results
