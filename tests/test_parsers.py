from pathlib import Path

from app.core.parsers import detect_scan_format, parse_nmap, parse_nessus, parse_openvas

DATA = Path(__file__).resolve().parents[1] / "data" / "inputs"


def test_detect_format_samples():
    assert detect_scan_format(DATA / "scan_nmap.xml") == "nmap"
    assert detect_scan_format(DATA / "scan_nessus.nessus") == "nessus"
    assert detect_scan_format(DATA / "scan_openvas.xml") == "openvas"


def test_parse_nmap_sample():
    rows = parse_nmap(str(DATA / "scan_nmap.xml"))
    assert len(rows) == 2
    ips = {h["ip"] for h in rows}
    assert ips == {"192.168.56.101", "192.168.56.102"}
    web = next(h for h in rows if h["ip"] == "192.168.56.101")
    ports = {s["port"]: s for s in web["services"]}
    assert 80 in ports
    assert "CVE-2017-5638" in ports[80]["cves"]


def test_parse_nessus_sample():
    rows = parse_nessus(str(DATA / "scan_nessus.nessus"))
    assert len(rows) == 1
    assert rows[0]["ip"] == "192.168.56.103"
    assert len(rows[0]["services"]) == 2
    cves = {c for s in rows[0]["services"] for c in s["cves"]}
    assert "CVE-2020-1234" in cves


def test_parse_openvas_sample():
    rows = parse_openvas(str(DATA / "scan_openvas.xml"))
    assert len(rows) == 1
    assert rows[0]["ip"] == "192.168.56.104"
    assert rows[0]["services"][0]["cves"] == ["CVE-2017-0143"]
