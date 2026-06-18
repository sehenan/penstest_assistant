"""
Tests du garde-fou d'impact CVSS contre les hallucinations LLM.
==============================================================
Cas réel : CVE-2019-3824 est un déni de service (C:N/I:N/A:H). Un playbook qui
décrit un RCE / reverse shell pour cette faille est une hallucination prouvée et
doit être détecté (CVE_IMPACT_CONTRADICTION) puis bloqué.
"""
from app.core.llm.generator import cvss_impact_profile
from app.core.llm.report_validator import ReportValidator

DOS_VECTOR = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"   # CVE-2019-3824
RCE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2_DOS = "AV:N/AC:L/Au:N/C:N/I:N/A:P"


# ─── Profil d'impact dérivé du vecteur ────────────────────────────────────────

def test_dos_profile_forbids_rce():
    p = cvss_impact_profile(DOS_VECTOR)
    assert p["avail"] is True
    assert p["conf"] is False and p["integ"] is False
    assert p["forbid"] is True
    assert "DÉNI DE SERVICE" in p["constraint"]


def test_real_rce_does_not_forbid():
    p = cvss_impact_profile(RCE_VECTOR)
    assert p["conf"] and p["integ"]
    assert p["forbid"] is False


def test_cvss_v2_dos_also_forbids():
    # En v2, 'P' (partial) compte comme impact ; 'N' = aucun.
    p = cvss_impact_profile(V2_DOS)
    assert p["forbid"] is True  # C:N et I:N
    assert p["avail"] is True   # A:P


def test_empty_vector_is_permissive():
    p = cvss_impact_profile("")
    assert p["forbid"] is False
    assert p["constraint"] == ""


# ─── Détection de contradiction par le validateur ────────────────────────────

_HALLUC = (
    "## Exploitation\n### Étape 3\nÉtablir un reverse shell avec meterpreter, "
    "puis lire /etc/passwd pour confirmer l'accès. " * 4
)
_LEGIT_DOS = (
    "## Vérification\nEnvoyer une requête LDAP malformée ; le service Samba "
    "devient indisponible (déni de service). Aucun accès aux données. " * 4
)


def test_validator_flags_rce_on_dos():
    res = ReportValidator().validate(_HALLUC, "CVE-2019-3824", "netbios-ssn",
                                     "3.X - 4.X", cvss_vector=DOS_VECTOR)
    codes = [i["code"] for i in res["issues"]]
    assert "CVE_IMPACT_CONTRADICTION" in codes
    assert res["valid"] is False


def test_validator_accepts_legit_dos_report():
    res = ReportValidator().validate(_LEGIT_DOS, "CVE-2019-3824", "netbios-ssn",
                                     "3.X - 4.X", cvss_vector=DOS_VECTOR)
    assert "CVE_IMPACT_CONTRADICTION" not in [i["code"] for i in res["issues"]]


def test_validator_no_contradiction_for_real_rce():
    res = ReportValidator().validate(_HALLUC, "CVE-X", "http", "1.0",
                                     cvss_vector=RCE_VECTOR)
    assert "CVE_IMPACT_CONTRADICTION" not in [i["code"] for i in res["issues"]]


def test_validator_backward_compatible_without_vector():
    # Appel historique sans cvss_vector : ne doit pas lever ni inventer de contradiction.
    res = ReportValidator().validate(_HALLUC, "CVE-X", "http", "1.0")
    assert "CVE_IMPACT_CONTRADICTION" not in [i["code"] for i in res["issues"]]
