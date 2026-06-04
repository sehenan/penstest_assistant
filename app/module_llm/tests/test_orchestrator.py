# === FICHIER : app/module_llm/tests/test_orchestrator.py ===
import pytest
import sqlite3
from unittest.mock import MagicMock, patch
from app.module_llm.llm.orchestrator import Orchestrator

@pytest.fixture
def mock_db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE scores_ml (vuln_id INTEGER, score REAL)")
    cursor.execute("CREATE TABLE vulnerabilites (id INTEGER, cve TEXT, service_id INTEGER, cvss_score REAL, cvss_vector TEXT, description TEXT)")
    cursor.execute("CREATE TABLE services (id INTEGER, port INTEGER, service TEXT, version TEXT)")
    cursor.execute("CREATE TABLE exploits (cve TEXT, disponible BOOLEAN, metasploit_module TEXT)")
    cursor.execute("CREATE TABLE rapports (id INTEGER PRIMARY KEY, titre TEXT, contenu_md TEXT, timestamp TEXT, vuln_id INTEGER)")
    
    cursor.execute("INSERT INTO services VALUES (1, 80, 'http', 'Apache')")
    cursor.execute("INSERT INTO vulnerabilites VALUES (1, 'CVE-TEST', 1, 9.0, 'VEC', 'Desc')")
    cursor.execute("INSERT INTO scores_ml VALUES (1, 0.95)")
    conn.commit()
    conn.close()
    return str(db_path)

@pytest.fixture
def mock_config(mock_db):
    return {
        'database': {'path': mock_db, 'top_n_vulns': 5},
        'rag': {
            'index_path': 'fake', 'chunks_path': 'fake', 'embedding_model': 'fake', 'top_k': 3,
            'knowledge_dir': 'fake', 'output_dir': 'fake', 'chunk_size': 500, 'chunk_overlap': 50
        },
        'llm': {'ollama_url': 'fake', 'model': 'fake', 'timeout_seconds': 5, 'max_tokens': 100}
    }

@patch('app.module_llm.rag.retriever.Retriever.retrieve')
@patch('app.module_llm.llm.generator.Generator.generate_playbook')
def test_pipeline_run(mock_gen, mock_ret, mock_config):
    mock_ret.return_value = [{"text": "context", "source_name": "src"}]
    mock_gen.return_value = "## 1. Summary\n## 3. Steps\n## 9. Sources"
    
    orch = Orchestrator(mock_config)
    results = orch.run_llm_pipeline(top_n=1)
    
    assert results["total"] == 1
    assert results["success"] == 1
    assert len(results["rapports_ids"]) == 1
    
    # Vérifier que le rapport est bien en base
    conn = sqlite3.connect(mock_config['database']['path'])
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM rapports")
    count = cursor.fetchone()[0]
    assert count == 1
    conn.close()
