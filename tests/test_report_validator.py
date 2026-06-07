"""
Tests unitaires pour ReportValidator.
Couvre : troncature, commandes invalides, cohérence CVE, rapport valide.
"""
import pytest
from unittest.mock import patch

from app.core.llm.report_validator import ReportValidator, COMPLETION_MARKER


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_REPORT = f"""## Résumé exécutif

CVE-2019-9193 affecte PostgreSQL 8.3 à 11.2. La fonctionnalité COPY TO/FROM PROGRAM
permet à un superuser d'exécuter des commandes OS arbitraires.
Impact : Remote Code Execution (RCE) sans interaction utilisateur supplémentaire.

## Phase 1 — Reconnaissance

```bash
nmap -sV -p 5432 --script pgsql-brute,postgresql-info 172.16.160.114
```

## Phase 2 — Connexion

```bash
psql -h 172.16.160.114 -p 5432 -U postgres -c "SELECT version();"
```

## Phase 3 — Vérification

```bash
psql -h 172.16.160.114 -p 5432 -U postgres -c "COPY (SELECT '') TO PROGRAM 'id';"
```

## Recommandation

Mettre à jour PostgreSQL vers la version 11.3 ou supérieure.
Désactiver superuser pour les connexions distantes dans pg_hba.conf.

## Conclusion

La vulnérabilité est exploitable sans conditions supplémentaires si les credentials
par défaut sont actifs. Remédiation immédiate requise.

{COMPLETION_MARKER}
"""

CVE_ID = "CVE-2019-9193"
SERVICE = "postgresql"
VERSION = "8.3.20"


@pytest.fixture
def validator_no_intel():
    """Validateur avec base intel absente (get_cve retourne None)."""
    with patch("app.core.llm.report_validator.IntelReader") as MockIntel:
        instance = MockIntel.return_value
        instance.get_cve.return_value = None
        yield ReportValidator()


@pytest.fixture
def validator_with_intel():
    """Validateur avec base intel retournant des mots-clés pour CVE-2019-9193."""
    with patch("app.core.llm.report_validator.IntelReader") as MockIntel:
        instance = MockIntel.return_value
        instance.get_cve.return_value = {
            "cve_id": CVE_ID,
            "keywords": ["copy from program", "superuser", "rce"],
        }
        yield ReportValidator()


# ---------------------------------------------------------------------------
# Tests — rapport valide
# ---------------------------------------------------------------------------

def test_valid_report_passes(validator_with_intel):
    result = validator_with_intel.validate(VALID_REPORT, CVE_ID, SERVICE, VERSION)
    assert result["valid"] is True
    assert result["issues"] == []


# ---------------------------------------------------------------------------
# Tests — troncature
# ---------------------------------------------------------------------------

TRUNCATED_REPORTS = [
    "Dans ce rapport, nous avons explor",
    "Dans ce rapport, nous avons exploré la vulnérabilité",
    "... suite du rapport",
]

@pytest.mark.parametrize("tail", TRUNCATED_REPORTS)
def test_truncation_detected(validator_no_intel, tail):
    report = VALID_REPORT.replace(COMPLETION_MARKER, "") + "\n" + tail
    result = validator_no_intel.validate(report, CVE_ID, SERVICE, VERSION)
    codes = [i["code"] for i in result["issues"]]
    assert "TRUNCATION_DETECTED" in codes or "COMPLETION_MARKER_MISSING" in codes


def test_completion_marker_missing(validator_no_intel):
    report = VALID_REPORT.replace(COMPLETION_MARKER, "")
    result = validator_no_intel.validate(report, CVE_ID, SERVICE, VERSION)
    codes = [i["code"] for i in result["issues"]]
    assert "COMPLETION_MARKER_MISSING" in codes


# ---------------------------------------------------------------------------
# Tests — commandes invalides (les 9 prouvées en test réel)
# ---------------------------------------------------------------------------

INVALID_CMD_CASES = [
    "metasploit -s",
    "metasploit --start",
    "nc -vudp 172.16.160.114 5432",
    "nc -p 5432",
    "use exploits/postgresql_8_x",
    "use exploits/postgresql",
    "set PAYLOAD reverse_tcp",
    "run -p",
    "ssh -i id_rsa user@172.16.160.114",
    "ping -c 1",
]

@pytest.mark.parametrize("bad_cmd", INVALID_CMD_CASES)
def test_invalid_command_detected(validator_no_intel, bad_cmd):
    report = VALID_REPORT + f"\n```bash\n{bad_cmd}\n```\n"
    result = validator_no_intel.validate(report, CVE_ID, SERVICE, VERSION)
    codes = [i["code"] for i in result["issues"]]
    assert "INVALID_COMMAND" in codes, (
        f"La commande invalide {bad_cmd!r} n'a pas été détectée.\n"
        f"Issues : {result['issues']}"
    )


# ---------------------------------------------------------------------------
# Tests — cohérence CVE
# ---------------------------------------------------------------------------

def test_cve_description_mismatch(validator_with_intel):
    """Rapport qui ne contient aucun mot-clé lié à CVE-2019-9193."""
    generic_report = (
        "## Résumé exécutif\n\n"
        "Une vulnérabilité a été identifiée sur la cible lors de l'audit.\n"
        "Il convient de mettre à jour le service affecté dans les meilleurs délais.\n"
        "La correction doit être appliquée selon les recommandations du vendeur.\n\n"
        "## Recommandations\n\n"
        "Appliquer le correctif disponible. Surveiller les accès.\n\n"
        f"{COMPLETION_MARKER}\n"
    )
    result = validator_with_intel.validate(generic_report, CVE_ID, SERVICE, VERSION)
    codes = [i["code"] for i in result["issues"]]
    assert "CVE_DESCRIPTION_MISMATCH" in codes


def test_cve_no_entry_in_intel_skips_check(validator_no_intel):
    """Si la CVE est absente de la base locale, on ne bloque pas."""
    generic_report = (
        "## Résumé\n\nVulnérabilité sans description locale.\n\n"
        f"{COMPLETION_MARKER}\n"
    )
    result = validator_no_intel.validate(generic_report, CVE_ID, SERVICE, VERSION)
    codes = [i["code"] for i in result["issues"]]
    assert "CVE_DESCRIPTION_MISMATCH" not in codes


# ---------------------------------------------------------------------------
# Tests — rapport trop court
# ---------------------------------------------------------------------------

def test_report_too_short(validator_no_intel):
    result = validator_no_intel.validate("Rapport vide.", CVE_ID, SERVICE, VERSION)
    assert result["valid"] is False
    codes = [i["code"] for i in result["issues"]]
    assert "REPORT_TOO_SHORT" in codes


def test_empty_report(validator_no_intel):
    result = validator_no_intel.validate("", CVE_ID, SERVICE, VERSION)
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Tests — version hors-range dans IntelReader (test _version_in_range isolé)
# ---------------------------------------------------------------------------

def test_version_in_range_dict_format():
    from app.db.intel_reader import IntelReader
    reader = IntelReader()
    ranges = [{"version_start_including": "8.3", "version_end_excluding": "11.3"}]
    assert reader._version_in_range("8.3.20", ranges) is True
    assert reader._version_in_range("11.2", ranges) is True
    assert reader._version_in_range("11.3", ranges) is False
    assert reader._version_in_range("12.0", ranges) is False


def test_version_in_range_string_format():
    from app.db.intel_reader import IntelReader
    reader = IntelReader()
    assert reader._version_in_range("8.3.20", ["8.3.20"]) is True
    assert reader._version_in_range("8.3.21", ["8.3.20"]) is False


def test_version_in_range_unparseable():
    from app.db.intel_reader import IntelReader
    reader = IntelReader()
    assert reader._version_in_range("not-a-version", [{"version_start_including": "8.3"}]) is False


def test_version_in_range_empty():
    from app.db.intel_reader import IntelReader
    reader = IntelReader()
    assert reader._version_in_range("8.3.20", []) is False
