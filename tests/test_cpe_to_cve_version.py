"""
Tests anti-hallucination du rapprochement CPE→CVE.
=================================================
Garantit que `cpe_to_cve` n'associe une CVE à un service que si la version
détectée tombe EXPLICITEMENT dans la plage vulnérable déclarée par le NVD.
Cas réels issus d'un scan Metasploitable 2 (services anciens).
"""
from app.core.enrichment.cpe_to_cve import (
    _ver_tuple,
    _ver_cmp,
    _version_confirmed,
)


# ─── Parsing de version tolérant ──────────────────────────────────────────────

def test_ver_tuple_tolerant():
    assert _ver_tuple("4.7p1 Debian 8ubuntu3") == (4, 7)
    assert _ver_tuple("5.0.96-0ubuntu3") == (5, 0, 96)
    assert _ver_tuple("8.3.20 - 8.3.23") == (8, 3, 20)
    assert _ver_tuple("9.4.2-P2.1") == (9, 4, 2)
    assert _ver_tuple("2.2.8") == (2, 2, 8)
    assert _ver_tuple(None) is None
    assert _ver_tuple("") is None
    assert _ver_tuple("v1") == (1,)


def test_ver_cmp_padding():
    assert _ver_cmp((2, 2), (2, 2, 8)) == -1
    assert _ver_cmp((2, 4), (2, 2, 8)) == 1
    assert _ver_cmp((8, 3), (8, 3, 0)) == 0


# ─── Confirmation par plage (versionStart*/versionEnd*) ───────────────────────

def test_range_end_including_keeps_lower():
    # OpenSSH 4.7 vs CVE-2018-20685 (<= 7.9, sans borne basse) → confirmé
    vc = {"vsi": None, "vse": None, "vei": "7.9", "vee": None, "crit_ver": "*"}
    assert _version_confirmed((4, 7), vc) is True


def test_range_start_excludes_old():
    # OpenSSH 4.7 vs CVE-2019-16905 (7.7 <= v <= 7.9) → rejeté
    vc = {"vsi": "7.7", "vse": None, "vei": "7.9", "vee": None, "crit_ver": "*"}
    assert _version_confirmed((4, 7), vc) is False


def test_range_end_excluding_boundary():
    # PostgreSQL 8.3 vs CVE-2015-3166 (< 9.0.20) → confirmé
    vc = {"vsi": None, "vse": None, "vei": None, "vee": "9.0.20", "crit_ver": "*"}
    assert _version_confirmed((8, 3, 20), vc) is True
    # PostgreSQL 8.3 vs CVE-2019-10164 (10.0 <= v < 10.9) → rejeté
    vc2 = {"vsi": "10.0", "vse": None, "vei": None, "vee": "10.9", "crit_ver": "*"}
    assert _version_confirmed((8, 3, 20), vc2) is False


# ─── Confirmation par version exacte du critère (pas de plage) ────────────────

def test_exact_criteria_prefix_match():
    # Apache 2.2.8 vs critère exact 2.4.17 → rejeté (hallucination historique)
    vc = {"vsi": None, "vse": None, "vei": None, "vee": None, "crit_ver": "2.4.17"}
    assert _version_confirmed((2, 2, 8), vc) is False
    # BIND 9.4.2 vs critère exact 9.9.8 → rejeté
    vc2 = {"vsi": None, "vse": None, "vei": None, "vee": None, "crit_ver": "9.9.8"}
    assert _version_confirmed((9, 4, 2), vc2) is False
    # Critère 2.2 couvre 2.2.8 détecté (préfixe) → confirmé
    vc3 = {"vsi": None, "vse": None, "vei": None, "vee": None, "crit_ver": "2.2"}
    assert _version_confirmed((2, 2, 8), vc3) is True


def test_wildcard_without_range_is_refused():
    # Règle stricte : critère '*' SANS aucune borne → non confirmable → REFUS.
    vc = {"vsi": None, "vse": None, "vei": None, "vee": None, "crit_ver": "*"}
    assert _version_confirmed((1, 8), vc) is False
