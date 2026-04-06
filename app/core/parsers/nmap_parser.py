# src/core/parsers/nmap_parser.py
from lxml import etree
from typing import List, Dict
import re

def parse_nmap(xml_path: str) -> List[Dict]:
    """
    Parse Nmap XML (-oX) and return list of host dicts:
    { ip, hostname, os, services: [{port, protocol, service, version, banner, cves}] }
    """
    tree = etree.parse(xml_path)
    root = tree.getroot()

    results = []
    for host in root.findall("./host"):
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
            portnum = int(port.get("portid")) if port.get("portid") else 0
            protocol = port.get("protocol")
            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            banner = " ".join(x for x in (product, version) if x) or None

            # gather CVEs from script outputs (naive regex)
            cves = []
            for script in port.findall("script"):
                output = script.get("output", "") or ""
                for c in re.findall(r"(CVE-\d{4}-\d+)", output, re.IGNORECASE):
                    cves.append(c.upper())

            services.append({
                "port": portnum,
                "protocol": protocol,
                "service": service_name,
                "version": version,
                "banner": banner,
                "cves": list(set(cves))
            })

        results.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_name,
            "services": services
        })
    return results
