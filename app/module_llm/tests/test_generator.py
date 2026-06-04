# === FICHIER : app/module_llm/tests/test_generator.py ===
import pytest
from unittest.mock import patch, MagicMock
from app.module_llm.llm.generator import Generator

@pytest.fixture
def mock_config():
    return {
        'llm': {
            'ollama_url': 'http://localhost:11434',
            'model': 'mistral',
            'timeout_seconds': 5,
            'max_tokens': 100
        }
    }

def test_prompt_building(mock_config):
    gen = Generator(mock_config)
    vuln = {"cve": "CVE-TEST", "service": "http"}
    chunks = [{"text": "Found exploit info", "source_name": "TestDB"}]
    
    user_prompt = gen._build_user_prompt(vuln, chunks)
    assert "CVE-TEST" in user_prompt
    assert "TestDB" in user_prompt
    assert "Found exploit info" in user_prompt

@patch('requests.post')
def test_generate_success(mock_post, mock_config):
    # Mock de la réponse Ollama
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "## 1. Summary\n## 3. Steps\n## 9. Sources\n[Source: TestDB] content"}
    mock_post.return_value = mock_response
    
    gen = Generator(mock_config)
    res = gen.generate_playbook({"cve": "CVE-X"}, [])
    
    assert res is not None
    assert "## 1." in res
    assert "[Source: TestDB]" in res

@patch('requests.post')
def test_generate_failure(mock_post, mock_config):
    mock_post.side_effect = Exception("Connection Error")
    
    gen = Generator(mock_config)
    res = gen.generate_playbook({"cve": "CVE-X"}, [])
    assert res is None
