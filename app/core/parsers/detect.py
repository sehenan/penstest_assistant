from __future__ import annotations

from lxml import etree

from app.core.parsers.nessus_parser import parse_nessus
from app.core.parsers.nmap_parser import parse_nmap
from app.core.parsers.openvas_parser import parse_openvas


def detect_scan_format(path: str) -> str:
    """Identifie le type de fichier (nmap | nessus | openvas) via la racine XML."""
    tree = etree.parse(path)
    root = tree.getroot()
    local = etree.QName(root).localname
    if local == "nmaprun":
        return "nmap"
    if "NessusClientData" in local:
        return "nessus"
    if root.findall(".//result"):
        return "openvas"
    raise ValueError(
        f"Format de scan non reconnu (élément racine: {local!r}). "
        "Formats supportés: Nmap -oX, OpenVAS/GVM XML, Nessus .nessus."
    )


def parse_scan_file(path: str) -> list[dict]:
    """Parse un fichier de scan en fonction de son format détecté."""
    fmt = detect_scan_format(path)
    if fmt == "nmap":
        return parse_nmap(path)
    if fmt == "nessus":
        return parse_nessus(path)
    return parse_openvas(path)
