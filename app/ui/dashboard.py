"""
Pentest Assistant — Dashboard (Design fidèle au mockup HTML)
"""
import sys
import time
import unicodedata
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

import streamlit as st
from sqlalchemy import create_engine, select
from sqlalchemy.orm import scoped_session, sessionmaker

from app.db.database import DATABASE_URL
from app.db.models import Exploit, Host, Report, ScoreML, Service, Vulnerability
from app.core.ingest import ingest_scan_file
from app.core.enrichment.nvd import enrich_vulnerabilities_from_nvd
from app.core.enrichment.cpe import enrich_services_with_cpe
from app.core.enrichment.exploit_db import enrich_exploits
from app.core.ml.data_manager import DataManager
from app.core.ml.predict import predict_and_store
from app.core.llm.generator import generate_playbook_for_vulnerability

# ─── PAGE CONFIG ──────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PenTest Assistant",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── CSS — Fidèle au design HTML ──────────────────────────────────────────
st.markdown("""
<style>
/* ── FONT & BASE ─────────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    color: #e0e0e0;
}

/* ── BACKGROUND ──────────────────────────────────────────────────── */
.stApp {
    background: linear-gradient(135deg, #0f1419 0%, #1a2332 100%) !important;
    min-height: 100vh;
}

/* ── HIDE STREAMLIT CHROME ───────────────────────────────────────── */
section[data-testid="stSidebar"]  { display: none !important; }
[data-testid="collapsedControl"]  { display: none !important; }
#MainMenu, footer, header         { visibility: hidden !important; }

/* ── LAYOUT ──────────────────────────────────────────────────────── */
.block-container {
    padding: 28px 40px 60px 40px !important;
    max-width: 1400px !important;
}

/* ── COLUMNS AS PANELS — uniquement la 1ère ligne (Import | Overview) ── */
/* On utilise :has() pour cibler les colonnes qui contiennent le file uploader
   ou le panel-title, et les autres restent transparentes. */
div[data-testid="column"]:has([data-testid="stFileUploader"]),
div[data-testid="column"]:has(.panel-title) {
    background: rgba(30, 40, 55, 0.8) !important;
    border: 1px solid rgba(0, 212, 255, 0.2) !important;
    border-radius: 8px !important;
    padding: 24px 20px !important;
    backdrop-filter: blur(10px);
    transition: border-color .3s, box-shadow .3s;
}
div[data-testid="column"]:has([data-testid="stFileUploader"]):hover,
div[data-testid="column"]:has(.panel-title):hover {
    border-color: rgba(0, 212, 255, 0.5) !important;
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.1) !important;
}

/* ── BOUTON PAYLOAD INLINE ───────────────────────────────────────── */
.btn-payload > button {
    background: rgba(255, 100, 0, 0.15) !important;
    color: #ffaa33 !important;
    border: 1px solid rgba(255, 140, 0, 0.4) !important;
    font-weight: 600 !important;
    font-size: 12px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.8px !important;
    border-radius: 4px !important;
    padding: 5px 14px !important;
    width: auto !important;
    margin-top: 0 !important;
    transition: all .2s ease !important;
    white-space: nowrap !important;
}
.btn-payload > button:hover {
    background: rgba(255, 140, 0, 0.3) !important;
    border-color: rgba(255, 180, 0, 0.7) !important;
    box-shadow: 0 0 10px rgba(255, 140, 0, 0.2) !important;
    transform: none !important;
}

/* ── BOUTON MODE (radio) ─────────────────────────────────────────── */
.stRadio > div {
    flex-direction: row !important;
    gap: 16px !important;
}
.stRadio label {
    font-size: 13px !important;
    color: #aaa !important;
}
.stRadio [aria-checked='true'] + div {
    color: #00d4ff !important;
}

/* ── PURE PANEL (non-column) ─────────────────────────────────────── */
.panel {
    background: rgba(30, 40, 55, 0.8);
    border: 1px solid rgba(0, 212, 255, 0.2);
    border-radius: 8px;
    padding: 24px;
    backdrop-filter: blur(10px);
    margin-bottom: 20px;
    transition: border-color .3s, box-shadow .3s;
}
.panel:hover {
    border-color: rgba(0, 212, 255, 0.5);
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.1);
}
.panel-exp {
    background: linear-gradient(135deg,
        rgba(255, 51, 51, 0.10) 0%,
        rgba(255, 153, 0, 0.10) 100%) !important;
    border-left: 4px solid #ff6666 !important;
}
.panel-title {
    font-size: 18px;
    font-weight: bold;
    color: #00d4ff;
    margin-bottom: 20px;
}

/* ── HEADER ──────────────────────────────────────────────────────── */
.site-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 32px;
    padding-bottom: 20px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}
.logo {
    font-size: 24px;
    font-weight: bold;
    color: #00d4ff;
    text-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
    display: flex;
    align-items: center;
    gap: 10px;
}
.header-stats { display: flex; gap: 30px; }
.stat { text-align: center; }
.stat-value { font-size: 28px; font-weight: bold; color: #00d4ff; }
.stat-value-red { color: #ff6666 !important; }
.stat-label {
    font-size: 11px;
    color: #888;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── FILE UPLOADER ───────────────────────────────────────────────── */
[data-testid="stFileUploader"] > section {
    background: rgba(0, 212, 255, 0.05) !important;
    border: 2px dashed rgba(0, 212, 255, 0.3) !important;
    border-radius: 8px !important;
    transition: all .3s !important;
}
[data-testid="stFileUploader"] > section:hover {
    border-color: rgba(0, 212, 255, 0.6) !important;
    background: rgba(0, 212, 255, 0.1) !important;
}
[data-testid="stFileUploader"] label span {
    color: #00d4ff !important;
    font-size: 14px !important;
}
[data-testid="stFileUploader"] small { color: #888 !important; }
[data-testid="stFileUploaderDropzoneInstructions"] div span {
    color: #00d4ff !important;
}

/* ── BUTTONS ─────────────────────────────────────────────────────── */
.stButton > button {
    background: linear-gradient(135deg, #00d4ff 0%, #00a8cc 100%) !important;
    color: #000 !important;
    border: none !important;
    font-weight: bold !important;
    font-size: 13px !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    border-radius: 6px !important;
    padding: 10px 20px !important;
    width: 100% !important;
    transition: all .3s ease !important;
    margin-top: 12px !important;
}
.stButton > button:hover {
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.4) !important;
    transform: translateY(-2px) !important;
}
.stButton > button:active { transform: translateY(0) !important; }

/* Secondary button (download) */
.stDownloadButton > button {
    background: linear-gradient(135deg, #666 0%, #444 100%) !important;
    color: #e0e0e0 !important;
    border: none !important;
    font-weight: bold !important;
    font-size: 13px !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    border-radius: 6px !important;
    padding: 10px 20px !important;
    width: 100% !important;
    transition: all .3s ease !important;
}
.stDownloadButton > button:hover {
    box-shadow: 0 0 15px rgba(150,150,150,0.3) !important;
    transform: translateY(-1px) !important;
}

/* ── PROGRESS BARS ───────────────────────────────────────────────── */
.prog-section { margin-bottom: 16px; }
.prog-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
    font-size: 12px;
    color: #ccc;
}
.prog-bar {
    width: 100%;
    height: 8px;
    background: rgba(255, 255, 255, 0.08);
    border-radius: 4px;
    overflow: hidden;
}
.prog-fill { height: 100%; border-radius: 4px; transition: width .5s ease; }

/* ── VULNERABILITY ITEMS ─────────────────────────────────────────── */
.vuln-item {
    background: rgba(0, 0, 0, 0.3);
    border-left: 4px solid;
    padding: 14px;
    border-radius: 4px;
    margin-bottom: 12px;
    transition: all .2s ease;
    cursor: default;
}
.vuln-item:hover {
    background: rgba(0, 212, 255, 0.07);
    transform: translateX(4px);
}
.vuln-critical { border-left-color: #ff3333; background: rgba(255, 51, 51, 0.08); }
.vuln-high     { border-left-color: #ff9900; background: rgba(255,153,  0, 0.08); }
.vuln-medium   { border-left-color: #ffdd00; background: rgba(255,221,  0, 0.08); }
.vuln-low      { border-left-color: #00d4ff; background: rgba(  0,212,255, 0.05); }

.vuln-title  { font-weight: bold; color: #e0e0e0; margin-bottom: 6px; font-size: 14px; }
.vuln-meta   {
    font-size: 12px;
    color: #888;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
}

/* ── BADGES ──────────────────────────────────────────────────────── */
.badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.badge-critical { background: rgba(255, 51, 51,  0.2); color: #ff6666; }
.badge-high     { background: rgba(255,153,  0,  0.2); color: #ffaa33; }
.badge-medium   { background: rgba(255,221,  0,  0.2); color: #ffee33; }
.badge-low      { background: rgba(  0,212,255,  0.2); color: #00d4ff; }

/* ── EXPLOITATION PANEL ──────────────────────────────────────────── */
.exploitation-header {
    background: rgba(0, 0, 0, 0.3);
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 16px;
    font-size: 14px;
}
.playbook-item {
    background: rgba(0, 0, 0, 0.3);
    padding: 12px;
    border-radius: 4px;
    margin: 8px 0;
    font-size: 13px;
    border-left: 3px solid #00d4ff;
    color: #e0e0e0;
    line-height: 1.6;
}

/* ── BAR CHART ───────────────────────────────────────────────────── */
.chart-zone {
    background: rgba(0, 0, 0, 0.3);
    border-radius: 8px;
    padding: 20px 30px 50px 30px;
    height: 260px;
    display: flex;
    align-items: flex-end;
    gap: 20px;
    justify-content: space-around;
    margin-top: 16px;
}
.bar-grp {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    height: 100%;
    justify-content: flex-end;
    gap: 8px;
}
.bar-val-top { font-size: 18px; font-weight: bold; color: #00d4ff; }
.bar-fill    { width: 100%; border-radius: 4px 4px 0 0; min-height: 4px; transition: height .5s; }
.bar-lbl     { font-size: 12px; color: #888; text-align: center; }

/* ── ML CARDS ────────────────────────────────────────────────────── */
.ml-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-top: 8px;
}
.ml-card {
    background: rgba(0, 0, 0, 0.3);
    padding: 20px 16px;
    border-radius: 8px;
    text-align: center;
}
.ml-val { font-size: 28px; font-weight: bold; color: #00d4ff; }
.ml-lbl { font-size: 12px; color: #888; margin-top: 8px; }

/* ── ROW SPACING ─────────────────────────────────────────────────── */
[data-testid="stHorizontalBlock"] {
    gap: 20px !important;
    margin-bottom: 20px !important;
}

/* ── METRIC OVERRIDE (reset streamlit default) ───────────────────── */
div[data-testid="metric-container"] {
    background: transparent !important;
    border: none !important;
}

/* ── STATUS / SPINNER ────────────────────────────────────────────── */
[data-testid="stStatusWidget"] { color: #00d4ff !important; }
</style>
""", unsafe_allow_html=True)


# ─── DB — scoped_session thread-safe ──────────────────────────────────────
@st.cache_resource
def _make_session():
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
    )
    factory = sessionmaker(
        autocommit=False, autoflush=False,
        expire_on_commit=False, bind=engine,
    )
    return scoped_session(factory)

db = _make_session()()


# ─── HELPERS ──────────────────────────────────────────────────────────────
def _norm(s: str) -> str:
    """Normalise une chaîne (minuscule, sans accents)."""
    return "".join(
        c for c in unicodedata.normalize("NFD", (s or "").lower())
        if unicodedata.category(c) != "Mn"
    )

def _sev(label: str) -> str:
    n = _norm(label)
    if "crit" in n:                           return "critical"
    if any(x in n for x in ["elev","high","haut"]): return "high"
    if any(x in n for x in ["moyen","medium"]):     return "medium"
    return "low"

def _badge(label: str) -> str:
    s = _sev(label)
    return f'<span class="badge badge-{s}">{label or "—"}</span>'

def _ollama_ok() -> bool:
    try:
        import requests as rq
        return rq.get("http://localhost:11434", timeout=2).status_code == 200
    except Exception:
        return False


# ─── DONNÉES ──────────────────────────────────────────────────────────────
n_vulns = db.query(Vulnerability).count()

n_crit  = db.query(ScoreML).filter(ScoreML.label.in_(["Critique","Critical"])).count()
n_high  = db.query(ScoreML).filter(ScoreML.label.in_(["Élevé","Eleve","High","Haut"])).count()
n_med   = db.query(ScoreML).filter(ScoreML.label.in_(["Moyen","Medium"])).count()
n_low   = db.query(ScoreML).filter(ScoreML.label.in_(["Faible","Low"])).count()
n_scored = db.query(ScoreML).count()

scores_raw = [s[0] for s in db.query(ScoreML.score).filter(ScoreML.score.isnot(None)).all()]
avg_score  = round(sum(scores_raw) / max(len(scores_raw), 1), 1) if scores_raw else 0.0

n_exploits_ok = db.query(Exploit).filter(Exploit.disponible == True).count()
exploit_pct   = round(n_exploits_ok / max(n_vulns, 1) * 100) if n_vulns > 0 else 0

scan_pct      = 100 if n_scored > 0 else 0
analysis_time = st.session_state.get("analysis_time", 0.0)


# ═══════════════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown(f"""
<div class="site-header">
  <div class="logo">🔍 PenTest Assistant</div>
  <div class="header-stats">
    <div class="stat">
      <div class="stat-value">{n_vulns}</div>
      <div class="stat-label">Vulnérabilités</div>
    </div>
    <div class="stat">
      <div class="stat-value stat-value-red">{n_crit}</div>
      <div class="stat-label">Critiques</div>
    </div>
    <div class="stat">
      <div class="stat-value">{scan_pct}%</div>
      <div class="stat-label">Scans analysés</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# ROW 1 : IMPORT  |  VUE D'ENSEMBLE
# ═══════════════════════════════════════════════════════════════════════════
col_upload, col_stats = st.columns(2)

with col_upload:
    st.markdown('<div class="panel-title">Importer les scans</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader(
        "Nmap XML · OpenVAS · Nessus",
        type=["xml", "nessus"],
        label_visibility="collapsed",
        key="uploader",
    )
    if uploaded:
        sz = round(len(uploaded.getvalue()) / 1024, 1)
        st.markdown(
            f'<p style="font-size:12px;color:#00d4ff;margin:6px 0 0 0;">'
            f'📄 {uploaded.name} — {sz} KB</p>',
            unsafe_allow_html=True,
        )
    btn_run = st.button("▶  Analyser les scans", key="btn_run")

with col_stats:
    total_b = max(n_crit + n_high + n_med + n_low, 1)
    cp = int(n_crit / total_b * 100)
    hp = int(n_high / total_b * 100)
    mp = int(n_med  / total_b * 100)

    st.markdown(f"""
    <div class="panel-title">Vue d'ensemble</div>
    <div style="margin-top:10px;">
      <div class="prog-section">
        <div class="prog-header">
          <span>Critiques</span>
          <span style="color:#ff6666;">{n_crit}</span>
        </div>
        <div class="prog-bar">
          <div class="prog-fill" style="width:{cp}%;background:#ff3333;"></div>
        </div>
      </div>
      <div class="prog-section">
        <div class="prog-header">
          <span>Hauts</span>
          <span style="color:#ffaa33;">{n_high}</span>
        </div>
        <div class="prog-bar">
          <div class="prog-fill" style="width:{hp}%;background:#ff9900;"></div>
        </div>
      </div>
      <div class="prog-section">
        <div class="prog-header">
          <span>Moyens</span>
          <span style="color:#ffee33;">{n_med}</span>
        </div>
        <div class="prog-bar">
          <div class="prog-fill" style="width:{mp}%;background:#ffdd00;"></div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ─── PIPELINE — déclenché par le bouton ───────────────────────────────────
if btn_run:
    if not uploaded:
        st.warning("Veuillez sélectionner un fichier de scan avant d'analyser.")
    else:
        inputs_dir = Path("data/inputs")
        inputs_dir.mkdir(parents=True, exist_ok=True)
        fpath = inputs_dir / uploaded.name
        fpath.write_bytes(uploaded.getvalue())

        t0 = time.time()
        with st.status("Pipeline d'analyse en cours…", expanded=True) as status:
            st.write("1 / 4 — Ingestion du fichier de scan…")
            ingest_scan_file(str(fpath), db)

            st.write("2 / 4 — Enrichissement NVD (CVE / CVSS)…")
            enrich_vulnerabilities_from_nvd(db)

            st.write("3 / 4 — Résolution CPE + Exploit-DB…")
            enrich_services_with_cpe(db)
            enrich_exploits(db)

            st.write("4 / 4 — Scoring XGBoost (priorisation ML)…")
            dm = DataManager()
            df_r = dm.extract_real_data(db)
            if not df_r.empty:
                predict_and_store(db, df_r)
            else:
                st.warning("Aucune donnée extraite pour le scoring ML.")

            elapsed = round(time.time() - t0, 2)
            status.update(label=f"✓ Analyse terminée en {elapsed} s", state="complete")

        st.session_state["analysis_time"] = elapsed
        time.sleep(0.4)
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# ROW 2 : VULNÉRABILITÉS PRIORITAIRES — payload par vuln
# ═══════════════════════════════════════════════════════════════════════════
top5 = db.execute(
    select(
        Vulnerability.id.label("id"),
        Host.ip.label("ip"),
        Service.port.label("port"),
        Service.service.label("service"),
        Vulnerability.cve.label("cve"),
        Vulnerability.cvss_score.label("cvss"),
        Vulnerability.description.label("desc"),
        ScoreML.label.label("label"),
        ScoreML.score.label("score"),
    )
    .join(Service, Vulnerability.service_id == Service.id)
    .join(Host, Service.host_id == Host.id)
    .join(ScoreML, ScoreML.vuln_id == Vulnerability.id)
    .order_by(ScoreML.score.desc())
    .limit(5)
).fetchall()

# Sélecteur de mode global (audit / payload)
st.markdown('<div class="panel">', unsafe_allow_html=True)
st.markdown(
    '<div class="panel-title">Vuln&eacute;rabilit&eacute;s prioritaires (Top 5)</div>',
    unsafe_allow_html=True,
)

if top5:
    mode_radio = st.radio(
        "Mode de génération",
        ["payload", "audit"],
        format_func=lambda m: "⚡ Payload (exploitation)" if m == "payload" else "🔍 Audit (reconnaissance)",
        horizontal=True,
        key="global_mode",
    )

    # Suivi du payload demandé
    _payload_requested_id   = None
    _payload_requested_mode = mode_radio

    for i, v in enumerate(top5):
        sev   = _sev(v.label)
        badge = _badge(v.label)
        cvss_str  = f"CVSS {v.cvss:.1f}" if v.cvss else "CVSS —"
        score_str = f"ML {v.score:.3f}"  if v.score else ""
        desc_short = ((v.desc or "")[:120] + "…") if v.desc and len(v.desc) > 120 else (v.desc or "")

        # Ligne : carte (7/10) + bouton (3/10)
        col_card, col_btn = st.columns([7, 3])

        with col_card:
            st.markdown(
                f'<div class="vuln-item vuln-{sev}">'
                f'  <div class="vuln-title">{v.cve or "CVE inconnu"} &mdash; '
                f'{v.service or "?"} :{v.port} &nbsp; sur &nbsp; {v.ip}</div>'
                f'  <div class="vuln-meta">'
                f'    <span>{cvss_str}</span>'
                f'    {badge}'
                f'    <span style="color:#555;">{score_str}</span>'
                f'  </div>'
                + (f'  <div style="font-size:12px;color:#666;margin-top:6px;">{desc_short}</div>' if desc_short else "")
                + "</div>",
                unsafe_allow_html=True,
            )

        with col_btn:
            # Affiche le rapport existant pour cette vuln si disponible
            existing = db.query(Report).filter(
                Report.title.contains(v.cve or str(v.id))
            ).order_by(Report.id.desc()).first()

            st.markdown('<div class="btn-payload">', unsafe_allow_html=True)
            if st.button(
                f"⚡ Générer {mode_radio.upper()}",
                key=f"pl_{v.id}_{i}",
                help=f"Générer un playbook [{mode_radio}] pour {v.cve or 'cette vuln'} via Ollama + RAG",
            ):
                _payload_requested_id   = v.id
                _payload_requested_mode = mode_radio
            st.markdown('</div>', unsafe_allow_html=True)

            if existing:
                st.markdown(
                    f'<div style="font-size:11px;color:#10b981;margin-top:4px;">'
                    f'✓ Rapport #{existing.id} disponible</div>',
                    unsafe_allow_html=True,
                )
else:
    st.markdown(
        '<div style="text-align:center;color:#888;padding:24px 0;">'
        'Aucune vuln&eacute;rabilit&eacute; analys&eacute;e &mdash; '
        'importez un fichier de scan.</div>',
        unsafe_allow_html=True,
    )
    _payload_requested_id   = None
    _payload_requested_mode = "payload"

st.markdown('</div>', unsafe_allow_html=True)  # close .panel


# ─── GÉNÉRATION PAYLOAD (déclenché par bouton inline) ─────────────────────
if _payload_requested_id:
    if not _ollama_ok():
        st.error("Ollama est hors ligne. Lancez `ollama serve` dans un terminal.")
    else:
        target_cve = next(
            (v.cve for v in top5 if v.id == _payload_requested_id), str(_payload_requested_id)
        )
        with st.status(
            f"Génération [{_payload_requested_mode.upper()}] — {target_cve}…",
            expanded=True,
        ) as _status:
            st.write("Interrogation de l'index FAISS (RAG)…")
            st.write("Génération du playbook par le LLM local (Ollama)…")
            _rid = generate_playbook_for_vulnerability(
                db, _payload_requested_id, mode=_payload_requested_mode
            )
            if _rid:
                _status.update(
                    label=f"✓ Playbook #{_rid} généré — {target_cve}",
                    state="complete",
                )
                time.sleep(0.4)
                st.rerun()
            else:
                _status.update(
                    label="✗ Échec — Ollama n'a pas répondu",
                    state="error",
                )


# ═══════════════════════════════════════════════════════════════════════════
# ROW 3 : ASSISTANT D'EXPLOITATION — dernier rapport
# ═══════════════════════════════════════════════════════════════════════════
latest = db.query(Report).order_by(Report.id.desc()).first()

if latest:
    exp_header = (
        f'<strong style="color:#ffaa33;">{latest.title}</strong>'
        f' &mdash; généré le {str(latest.timestamp)[:16]}'
        f' <span style="font-size:11px;color:#666;">'
        f'({(latest.stage or "—").upper()})</span>'
    )
    lines = [
        l.strip() for l in (latest.content_md or "").split("\n")
        if l.strip() and len(l.strip()) > 5
    ]
    steps_html = "".join(
        f'<div class="playbook-item">{s}</div>' for s in lines[:5]
    ) or '<div class="playbook-item">Contenu disponible ci-dessous.</div>'
else:
    exp_header = (
        '<span style="color:#888;">Aucun playbook disponible — '
        'cliquez sur ⚡ pour générer le payload d\'une vuln.</span>'
    )
    steps_html = '<div class="playbook-item">Utilisez les boutons ⚡ ci-dessus pour générer un payload.</div>'

st.markdown(
    f'<div class="panel panel-exp">'
    f'<div class="panel-title">Assistant d\'exploitation — Dernier playbook</div>'
    f'<div class="exploitation-header">{exp_header}</div>'
    f'{steps_html}</div>',
    unsafe_allow_html=True,
)

# Bouton export uniquement
if latest and latest.content_md:
    _, dl_col = st.columns([5, 2])
    with dl_col:
        st.download_button(
            "⬇  Exporter Markdown",
            data=latest.content_md,
            file_name=f"playbook_{latest.id}_{latest.stage or 'report'}.md",
            mime="text/markdown",
            key="btn_dl",
        )


# ═══════════════════════════════════════════════════════════════════════════
# ROW 4 : MATRICE DE RISQUE (BAR CHART CSS)
# ═══════════════════════════════════════════════════════════════════════════
total_ch = max(n_crit + n_high + n_med, 1)
ch = max(int(n_crit / total_ch * 82), 4) if n_crit > 0 else 0
hh = max(int(n_high / total_ch * 82), 4) if n_high > 0 else 0
mh = max(int(n_med  / total_ch * 82), 4) if n_med  > 0 else 0

st.markdown(f"""
<div class="panel">
  <div class="panel-title">Matrice de risque</div>
  <div class="chart-zone">
    <div class="bar-grp">
      <div class="bar-val-top">{n_crit}</div>
      <div class="bar-fill" style="height:{ch}%;background:linear-gradient(180deg,#ff4444,#cc0000);"></div>
      <div class="bar-lbl">Critique</div>
    </div>
    <div class="bar-grp">
      <div class="bar-val-top">{n_high}</div>
      <div class="bar-fill" style="height:{hh}%;background:linear-gradient(180deg,#ffaa00,#cc7700);"></div>
      <div class="bar-lbl">Haute</div>
    </div>
    <div class="bar-grp">
      <div class="bar-val-top">{n_med}</div>
      <div class="bar-fill" style="height:{mh}%;background:linear-gradient(180deg,#ffee00,#ccaa00);"></div>
      <div class="bar-lbl">Moyen</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# ROW 5 : SCORING ML
# ═══════════════════════════════════════════════════════════════════════════
st.markdown(f"""
<div class="panel">
  <div class="panel-title">Scoring ML (XGBoost)</div>
  <div class="ml-grid">
    <div class="ml-card">
      <div class="ml-val">{avg_score:.1f}</div>
      <div class="ml-lbl">Score de risque moyen</div>
    </div>
    <div class="ml-card">
      <div class="ml-val">{exploit_pct}%</div>
      <div class="ml-lbl">Exploitabilité moyenne</div>
    </div>
    <div class="ml-card">
      <div class="ml-val">{analysis_time} s</div>
      <div class="ml-lbl">Temps d'analyse</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)
