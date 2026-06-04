# === FICHIER : app/module_llm/tests/test_indexer.py ===
import pytest
import os
import shutil
import json
from app.module_llm.rag.indexer import Indexer

@pytest.fixture
def mock_config(tmp_path):
    knowledge_dir = tmp_path / "knowledge_base"
    knowledge_dir.mkdir()
    (knowledge_dir / "test.md").write_text("# Test Document\nThis is a test chunk for RAG indexer.")
    
    output_dir = tmp_path / "data"
    
    return {
        'rag': {
            'embedding_model': 'all-MiniLM-L6-v2',
            'chunk_size': 500,
            'chunk_overlap': 50,
            'knowledge_dir': str(knowledge_dir),
            'output_dir': str(output_dir),
            'index_path': str(output_dir / "pentest.index"),
            'chunks_path': str(output_dir / "chunks.json")
        }
    }

def test_chunking(mock_config):
    indexer = Indexer(mock_config)
    text = "A" * 2000 # Environ 2000 tokens si chaque lettre est un token
    chunks = indexer._chunk_text(text)
    assert len(chunks) > 1
    assert all(len(c) > 0 for c in chunks)

def test_build_index(mock_config):
    indexer = Indexer(mock_config)
    indexer.build_index(mock_config['rag']['knowledge_dir'], mock_config['rag']['output_dir'])
    
    assert os.path.exists(mock_config['rag']['index_path'])
    assert os.path.exists(mock_config['rag']['chunks_path'])
    
    with open(mock_config['rag']['chunks_path'], 'r') as f:
        data = json.load(f)
        assert len(data) >= 1
        assert "text" in data[0]
        assert "source_name" in data[0]
