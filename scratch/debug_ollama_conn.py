import requests
import os

OLLAMA_HOST = "http://localhost:11434"
OLLAMA_HOST_IP = "http://127.0.0.1:11434"

def test_conn(url):
    print(f"Testing {url}/api/tags ...")
    try:
        r = requests.get(f"{url}/api/tags", timeout=5)
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text[:100]}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

print("--- Test Localhost ---")
test_conn(OLLAMA_HOST)
print("\n--- Test 127.0.0.1 ---")
test_conn(OLLAMA_HOST_IP)
