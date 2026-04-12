"""
Tableau de Bord interactif (Streamlit) - UI Haute Qualité (Dev Pro).
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import pandas as pd
import streamlit as st
from sqlalchemy import select

from app.core.llm.generator import generate_playbook_for_vulnerability
from app.db.database import get_session
from app.db.models import Host, Report, ScoreML, Service, Vulnerability

st.set_page_config(page_title="Vuln-Assist Pro", page_icon="⚡", layout="wide", initial_sidebar_state="collapsed")

# ----------------- DESIGN PREMIUM (CSS CUSTOM) -----------------
st.markdown("""
<style>
/* Import de polices modernes */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

/* Corps principal */
html, body, [class*="css"]  {
    font-family: 'Inter', sans-serif;
}

/* Titre principal Gradient */
h1 {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 800;
    background: -webkit-linear-gradient(45deg, #FF3366, #FF9933);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 2rem;
}

h2, h3 {
    font-family: 'JetBrains Mono', monospace;
    color: #E2E8F0;
}

/* Cartes Métriques Premium (Glassmorphism) */
div[data-testid="metric-container"] {
    background: rgba(30, 41, 59, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    backdrop-filter: blur(10px);
    transition: transform 0.2s ease, border-color 0.2s ease;
}
div[data-testid="metric-container"]:hover {
    transform: translateY(-4px);
    border-color: #3B82F6;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
}

/* Valeurs des métriques glowing */
div[data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace;
    font-size: 3rem !important;
    font-weight: 800;
    color: #38BDF8 !important;
    text-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
}

/* Boutons d'Action (Gradient animés) */
.stButton>button {
    background: linear-gradient(135deg, #10B981 0%, #059669 100%);
    color: white;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    padding: 0.6rem 1.5rem;
    transition: all 0.3s ease;
}
.stButton>button:hover {
    box-shadow: 0 0 20px rgba(16, 185, 129, 0.6);
    transform: scale(1.02);
    color: white;
}

/* Conteneurs d'Avertissement (Drafts) */
.stAlert {
    border-radius: 8px;
    border-left: 5px solid #F59E0B;
}

/* Tableaux Pandas Styling */
[data-testid="stDataFrame"] {
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}
</style>
""", unsafe_allow_html=True)
# ---------------------------------------------------------------

st.title("⚡ Vuln-Assist Pro | Plateforme IA")

@st.cache_resource
def get_db():
    return get_session()

session = get_db()

# Onglets modernes
tab1, tab2, tab3 = st.tabs(["📊 METRICS & RECO", "🎯 MACHINE LEARNING (Targets)", "📝 PLAYBOOKS IA"])

# --- TAB 1 : DASHBOARD ---
with tab1:
    st.markdown("### Cartographie & Reconnaissance réseau")
    c1, c2, c3 = st.columns(3)
    c1.metric("Hôtes Scannés", session.query(Host).count())
    c2.metric("Vulnérabilités Brutes", session.query(Vulnerability).count())
    c_crit = session.query(ScoreML).filter(ScoreML.label == "Critique").count()
    c3.metric("Vulnérabilités Critiques (IA)", c_crit)
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.info("💡 **Conseil d'Auditeur** : L'ingestion Nmap/Nessus a fourni la base de connaissances. Basculez sur l'onglet **Machine Learning** pour attaquer la surface priorisée.")

# --- TAB 2 : MACHINE LEARNING ---
with tab2:
    st.markdown("### Top Priorité (Score XGBoost Engine)")
    st.markdown("*Modèle d'ancrage local (Contexte d'exposition réseaux + Exploits DB)*")
    
    query = (
        select(
            Vulnerability.id,
            Host.ip,
            Service.port,
            Service.service,
            Vulnerability.cve,
            ScoreML.label,
            ScoreML.score
        )
        .join(Service, Vulnerability.service_id == Service.id)
        .join(Host, Service.host_id == Host.id)
        .join(ScoreML, ScoreML.vuln_id == Vulnerability.id)
        .order_by(ScoreML.score.desc())
    )
    rows = session.execute(query).fetchall()
    
    if not rows:
        st.warning("⚠️ Module ML non exécuté. Utilisez le CLI `python main.py score`.")
    else:
        df = pd.DataFrame(rows)
        # Visualisation premium du tableau
        st.dataframe(
            df.style.background_gradient(subset=['score'], cmap='viridis'),
            width='stretch',
            hide_index=True
        )
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### 💥 Orchestration LLM (Génération Automatisée)")
        
        # Formulaire UI Clean
        with st.container(border=True):
            st.markdown("Ciblez une faille pour invoquer le modèle IA (Llama/Mistral) avec le socle FAISS.")
            with st.form("llm_attack_form", clear_on_submit=False):
                colA, colB = st.columns([3, 1])
                with colA:
                    target_id = st.selectbox(
                        "Identifiant Interne de la Vulnérabilité", 
                        df['id'].tolist(),
                        format_func=lambda x: f"ID: {x} | {df.loc[df['id'] == x, 'ip'].values[0]} | {df.loc[df['id'] == x, 'cve'].values[0] or 'No-CVE'}"
                    )
                with colB:
                    st.markdown("<br>", unsafe_allow_html=True)
                    submit = st.form_submit_button("🚀 INVOQUER LE RAG", width='stretch')
                
                if submit:
                    with st.spinner("🧠 L'IA fouille le RAG et rédige le plan d'assaut..."):
                        report_id = generate_playbook_for_vulnerability(session, target_id)
                    if report_id:
                        st.success(f"Opération Réussie ! Playbook verrouillé sous la Réf: #{report_id}")
                    else:
                        st.error("Problème rencontré avec le LLM ou le RAG. Le démon Ollama est-il up ?")

# --- TAB 3 : RAPPORTS RAG ---
with tab3:
    st.markdown("### Playbooks d'Exploitation (Générés par IA)")
    reports = session.query(Report).order_by(Report.id.desc()).all()
    
    if not reports:
        st.info("Aucun rapport généré. L'Arsenal IA est en attente d'ordres.")
    else:
        for r in reports:
            # Emboîtement Premium
            with st.expander(f"🔴 {r.title} | Réf: {r.id}", expanded=(r.id == reports[0].id)):
                st.caption(f"🗓️ Horodatage : {r.timestamp}")
                st.markdown("---")
                # L'affichage du markdown par streamlit englobe la couleur d'Alerte (DRAFT)
                st.markdown(r.content_md)
