from unittest.mock import MagicMock, patch

from app.core.enrichment.nvd import enrich_vulnerabilities_from_nvd, fetch_cve_from_nvd
from app.db.models import Host, Service, Vulnerability


def _sample_nvd_json():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2017-0143",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "weaknesses": [
                        {
                            "description": [{"lang": "en", "value": "CWE-200: Information Exposure"}]
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 8.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }


def test_fetch_cve_from_nvd_parses_metrics():
    mock_resp = MagicMock()
    mock_resp.json.return_value = _sample_nvd_json()
    mock_resp.raise_for_status = MagicMock()
    sess = MagicMock()
    sess.get.return_value = mock_resp

    out = fetch_cve_from_nvd("CVE-2017-0143", session=sess)
    assert out is not None
    assert out["cvss_score"] == 8.8
    assert "CVSS:3.1" in (out["cvss_vector"] or "")
    assert out["cwe"] == "CWE-200"


def test_enrich_updates_row(db_session):
    host = Host(ip="10.0.0.1", hostname=None, os=None)
    db_session.add(host)
    db_session.flush()
    svc = Service(host_id=host.id, port=445, protocol="tcp", service="smb", version=None, banner=None)
    db_session.add(svc)
    db_session.flush()
    v = Vulnerability(service_id=svc.id, cve="CVE-2017-0143", description=None, source="test")
    db_session.add(v)
    db_session.commit()

    parsed = {
        "cve_id": "CVE-2017-0143",
        "description": "Test description",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-200",
    }
    with patch("app.core.enrichment.nvd.fetch_cve_from_nvd", return_value=parsed):
        with patch("app.core.enrichment.nvd._rate_delay"):
            stats = enrich_vulnerabilities_from_nvd(db_session)
    assert stats["updated"] == 1
    db_session.refresh(v)
    assert v.cvss_score == 8.8
    assert v.cwe == "CWE-200"
