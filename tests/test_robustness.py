"""
Tests de robustesse pour la phase 1 (Ingestion).
Vérifie le comportement de l'application face à des inputs dégradés ou inattendus.
"""
from pathlib import Path

import pytest
from lxml.etree import XMLSyntaxError

from app.core.parsers.nmap_parser import parse_nmap

DATA = Path(__file__).resolve().parents[1] / "data" / "inputs"


def test_parse_nmap_malformed():
    """Vérifie que l'erreur XML est remontée proprement sur un fichier tronqué."""
    malformed_path = str(DATA / "scan_nmap_malformed.xml")
    
    with pytest.raises(XMLSyntaxError):
        parse_nmap(malformed_path)


def test_parse_missing_file():
    """Vérifie le comportement en cas de fichier inexistant."""
    missing_path = str(DATA / "ce_fichier_nexiste_pas.xml")
    with pytest.raises(OSError):
        parse_nmap(missing_path)
