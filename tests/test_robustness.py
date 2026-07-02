"""
Tests de robustesse pour la phase 1 (Ingestion).
Vérifie le comportement de l'application face à des inputs dégradés ou inattendus.
"""
from pathlib import Path

import pytest

from app.core.parsers.nmap_parser import parse_nmap

DATA = Path(__file__).resolve().parents[1] / "data" / "inputs"


def test_parse_nmap_malformed():
    """Contrat de robustesse : sur un export Nmap tronqué (crash réseau, export
    incomplet), le parser NE DOIT PAS crasher. Grâce au mode `recover=True`
    (load_xml_clean), il récupère les hôtes exploitables déjà présents et retourne
    une liste — comportement volontairement résilient, adapté à l'ingestion de
    scans réels souvent imparfaits."""
    malformed_path = str(DATA / "scan_nmap_malformed.xml")

    result = parse_nmap(malformed_path)

    # Pas d'exception + structure exploitable (liste, éventuellement partielle).
    assert isinstance(result, list)


def test_parse_missing_file():
    """Vérifie le comportement en cas de fichier inexistant."""
    missing_path = str(DATA / "ce_fichier_nexiste_pas.xml")
    with pytest.raises(OSError):
        parse_nmap(missing_path)
