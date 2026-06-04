from __future__ import annotations

from lxml import etree

from app.core.parsers.nessus_parser import parse_nessus
from app.core.parsers.nmap_parser import parse_nmap
from app.core.parsers.openvas_parser import parse_openvas
from app.core.parsers.utils import load_xml_clean

def detect_scan_format(path: str) -> str:
    """Identifie le type de fichier (nmap | nessus | openvas | txt) via la racine XML ou l'extension."""
    if path.lower().endswith(".txt"):
        return "txt"

    root = load_xml_clean(path)
    if root is None:
        raise ValueError(f"Impossible d'analyser le fichier XML (ou format non supporté) : {path}")

    local = etree.QName(root).localname
    if local == "nmaprun":
        return "nmap"
    if "NessusClientData" in local:
        return "nessus"
    if root.findall(".//result"):
        return "openvas"
    raise ValueError(
        f"Format de scan non reconnu (élément racine: {local!r}). "
        "Formats supportés: Nmap -oX, OpenVAS/GVM XML, Nessus .nessus, TXT (Nmap -oN)."
    )


def parse_scan_file(path: str) -> list[dict]:
    """Parse un fichier de scan en fonction de son format détecté."""
    fmt = detect_scan_format(path)
    if fmt == "nmap":
        return parse_nmap(path)
    if fmt == "nessus":
        return parse_nessus(path)
    if fmt == "txt":
        from app.core.parsers.txt_parser import parse_txt
        return parse_txt(path)
    return parse_openvas(path)
