import json, os

cache_dir = "data/nvd_cache"
files = sorted(os.listdir(cache_dir))

# Study full NVD 2.0 item structure
with open(os.path.join(cache_dir, files[0]), "r", encoding="utf-8") as f:
    data = json.load(f)

item = data[0]
cve = item["cve"]
print("CVE ID:", cve["id"])
print("Metrics keys:", list(cve.get("metrics", {}).keys()))

# CVSS
metrics = cve.get("metrics", {})
if "cvssMetricV31" in metrics:
    m = metrics["cvssMetricV31"][0]["cvssData"]
    print("CVSS v3.1:", m.get("baseScore"), m.get("vectorString"))
if "cvssMetricV2" in metrics:
    m = metrics["cvssMetricV2"][0]["cvssData"]
    print("CVSS v2:", m.get("baseScore"), m.get("vectorString"))

# Configurations / CPE
configs = cve.get("configurations", [])
print(f"\nConfigurations: {len(configs)}")
if configs:
    nodes = configs[0].get("nodes", [])
    if nodes:
        cpe_matches = nodes[0].get("cpeMatch", [])
        if cpe_matches:
            print("Sample cpeMatch:", cpe_matches[0])

# Now search ALL cache files for OpenSSH 4.7
print("\n--- Searching for openssh 4.7 CVEs ---")
found_cves = []
for fname in files:
    fpath = os.path.join(cache_dir, fname)
    with open(fpath, "r", encoding="utf-8") as f:
        items = json.load(f)
    for item in items:
        cve = item.get("cve", {})
        desc_list = cve.get("descriptions", [])
        desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
        configs = cve.get("configurations", [])
        cpe_str = json.dumps(configs)
        if "openssh" in cpe_str.lower() or "openssh" in desc.lower():
            cve_id = cve.get("id", "?")
            metrics = cve.get("metrics", {})
            score = None
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")
            found_cves.append((cve_id, score, desc[:80]))

print(f"Found {len(found_cves)} OpenSSH CVEs in cache:")
for c in found_cves[:10]:
    print(f"  {c[0]} CVSS={c[1]} | {c[2]}")
