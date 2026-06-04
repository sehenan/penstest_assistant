# === FICHIER : app/module_llm/tests/test_retriever.py ===
import pytest
from app.module_llm.rag.retriever import Retriever, get_retrieval_query
from app.module_llm.rag.indexer import Indexer

@pytest.fixture
def indexed_data(tmp_path):
    knowledge_dir = tmp_path / "knowledge_base"
    knowledge_dir.mkdir()
    (knowledge_dir / "smb.md").write_text("SMB exploit technique for CVE-2017-0144 EternalBlue.")
    
    output_dir = tmp_path / "data"
    output_dir.mkdir()
    
    config = {
        'rag': {
            'embedding_model': 'all-MiniLM-L6-v2',
            'chunk_size': 500,
            'chunk_overlap': 50,
            'knowledge_dir': str(knowledge_dir),
            'output_dir': str(output_dir),
            'index_path': str(output_dir / "pentest.index"),
            'chunks_path': str(output_dir / "chunks.json"),
            'top_k': 3
        }
    }
    
    indexer = Indexer(config)
    indexer.build_index(str(knowledge_dir), str(output_dir))
    return config

def test_retrieve(indexed_data):
    retriever = Retriever(indexed_data)
    results = retriever.retrieve("EternalBlue SMB", k=1)
    
    assert len(results) == 1
    assert "EternalBlue" in results[0]['text']
    assert "score" in results[0]

def test_query_construction():
    vuln = {
        "cve": "CVE-2017-0144",
        "service": "smb",
        "version": "v1",
        "description": "Remote Code Execution in SMBv1"
    }
    query = get_retrieval_query(vuln)
    assert "CVE-2017-0144" in query
    assert "smb" in query
    assert "Remote Code" in query
