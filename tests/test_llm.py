"""
Tests unitaires pour l'Architecture LLM et RAG.
Mock de FAISS et de l'URL Ollama pour tourner sans GPU.
"""
from unittest.mock import patch, MagicMock
from app.db.models import Vulnerability, Service, Host, Report
from app.core.llm.generator import generate_playbook_for_vulnerability

def test_generate_playbook_draft_status(db_session):
    # Setup Data
    h = Host(ip="10.0.0.99")
    db_session.add(h)
    db_session.flush()
    
    s = Service(host_id=h.id, port=445, protocol="tcp", service="smb")
    db_session.add(s)
    db_session.flush()
    
    v = Vulnerability(service_id=s.id, cve="CVE-2017-0144")
    db_session.add(v)
    db_session.commit()
    
    rag_ctx = "Cheatsheet mockée pour ms17-010. EternalBlue exploite SMBv1."
    llm_out = "```bash\nuse exploit/windows/smb/ms17_010_eternalblue\n```"

    with patch("app.core.llm.generator.build_rag_context", return_value=rag_ctx):
        with patch("app.core.llm.generator.generate_text", return_value=llm_out):
            report_id = generate_playbook_for_vulnerability(db_session, v.id)

            assert report_id is not None

            # Vérification de l'enregistrement en base
            rep = db_session.get(Report, report_id)
            assert rep is not None
            # Le titre contient le tag de validation (incomplet = VALIDATION ÉCHOUÉE,
            # complet sans problème = pas de tag)
            assert "VÉRIFICATION" in rep.title
            assert "ms17_010" in rep.content_md
