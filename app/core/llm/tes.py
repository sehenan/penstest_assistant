import requests

def test_model(model_name):
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": model_name,
            "prompt": "Explique le scan Nmap en 2 lignes.",
            "stream": False
        },
        timeout=120
    )

    print("MODEL:", model_name)
    print("STATUS:", response.status_code)
    print("BODY:", response.text[:500])

test_model("qwen2.5:0.5b")
test_model("tinyllama")