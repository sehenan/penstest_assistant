# Parser fichiers .nessus (XML Nessus / Tenable)
from __future__ import annotations

import re
from typing import List, Dict

from lxml import etree

_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)


def parse_nessus(xml_path: str) -> List[Dict]:
    """
    Parse un export Nessus (.nessus) et retourne la même structure que Nmap/OpenVAS :
    { ip, hostname, os, services: [{ port, protocol, service, version, banner, cves, description }] }
    """
    tree = etree.parse(xml_path)
    root = tree.getroot()
    results: List[Dict] = []

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.get("name")
        if not ip:
            continue
        hostname = None
        os_name = None
        for tag in report_host.findall("HostProperties/tag"):
            name = (tag.get("name") or "").lower()
            if name == "host-fqdn" and tag.text:
                hostname = tag.text.strip()
            if name == "operating-system" and tag.text:
                os_name = tag.text.strip()

        services: List[Dict] = []
        for item in report_host.findall("ReportItem"):
            port_s = item.get("port") or "0"
            try:
                port = int(port_s)
            except ValueError:
                port = 0
            protocol = item.get("protocol")
            svc_name = item.get("svc_name")
            plugin_out = item.findtext("plugin_output") or ""
            desc = item.findtext("description") or ""

            cves: List[str] = []
            for cve_el in item.findall("cve"):
                if cve_el.text:
                    cves.append(cve_el.text.strip().upper())
            for m in _CVE_RE.findall(plugin_out):
                cves.append(m.upper())
            cves = list(dict.fromkeys(cves))

            banner = plugin_out.strip()[:2000] if plugin_out else None

            services.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "service": svc_name,
                    "version": None,
                    "banner": banner,
                    "cves": cves,
                    "description": desc.strip() or None,
                }
            )

        results.append(
            {
                "ip": ip,
                "hostname": hostname,
                "os": os_name,
                "services": services,
            }
        )

    return results
