import datetime
import json
import logging
import time
import urllib.request
from builder.models import IntelCVE

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Termes techniques extraits de la description pour alimenter ReportValidator
_KEYWORD_PATTERNS = [
    "copy to/from program", "copy from program", "superuser", "rce",
    "remote code execution", "command injection", "sql injection",
    "buffer overflow", "path traversal", "directory traversal",
    "authentication bypass", "privilege escalation", "arbitrary code",
    "execute", "exploit", "metasploit", "reverse shell", "backdoor",
]

def _extract_keywords(description: str, cve_id: str) -> list[str]:
    """Extrait les mots-clés techniques depuis la description NVD."""
    if not description:
        return []
    desc_lower = description.lower()
    found = [kw for kw in _KEYWORD_PATTERNS if kw in desc_lower]
    # Ajoute le CVE-ID lui-même comme mot-clé de cohérence
    found.append(cve_id.lower())
    return found


def fetch_and_load_nvd(session, days_back=30, api_key=None):
    """
    Télécharge et charge les CVEs depuis NVD (API v2.0).
    Par défaut, on ne télécharge que les X derniers jours pour l'exemple.
    Pour une base complète, il faudrait itérer depuis 1999 (plusieurs heures).
    """
    logger.info(f"Downloading NVD CVEs for the last {days_back} days...")
    
    end_dt = datetime.datetime.now(datetime.timezone.utc)
    start_dt = end_dt - datetime.timedelta(days=days_back)
    
    start_str = start_dt.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_str = end_dt.strftime('%Y-%m-%dT%H:%M:%S.000')
    
    start_index = 0
    total_results = 1
    delay = 0.6 if api_key else 6.0
    headers = {"apiKey": api_key} if api_key else {}
    
    # Mode incrémental: on ne vide pas la table, on fait des merges/upserts
    # Pour SQLite natif, il n'y a pas d'upsert simple dans SQLAlchemy sans l'extension SQLite dialect,
    # on va utiliser un insert simple avec gestion des exceptions pour l'exemple de MVP.
    
    loaded = 0
    while start_index < total_results:
        url = f"{NVD_BASE_URL}?pubStartDate={start_str}&pubEndDate={end_str}&resultsPerPage=2000&startIndex={start_index}"
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    
                    # Extraction basique
                    desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                    
                    # Extraction CVSS
                    cvss_v2 = cvss_v3 = cvss_v4 = None
                    cvss_v3_vector = None
                    metrics = cve.get("metrics", {})
                    
                    if "cvssMetricV31" in metrics:
                        cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
                        cvss_v3_vector = metrics["cvssMetricV31"][0].get("cvssData", {}).get("vectorString")
                    elif "cvssMetricV30" in metrics:
                        cvss_v3 = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
                        cvss_v3_vector = metrics["cvssMetricV30"][0].get("cvssData", {}).get("vectorString")
                        
                    if "cvssMetricV2" in metrics:
                        cvss_v2 = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
                        
                    # Extraction CWE
                    cwe_id = None
                    weaknesses = cve.get("weaknesses", [])
                    if weaknesses:
                        cwe_id = next((d.get("value") for d in weaknesses[0].get("description", []) if d.get("value", "").startswith("CWE-")), None)
                    
                    # Extraction affected_versions (format NVD CPE match ranges)
                    affected_versions = []
                    fixed_versions = []
                    for config in cve.get("configurations", []):
                        for node in config.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                if not match.get("vulnerable", False):
                                    continue
                                entry = {}
                                if "versionStartIncluding" in match:
                                    entry["version_start_including"] = match["versionStartIncluding"]
                                if "versionEndExcluding" in match:
                                    entry["version_end_excluding"] = match["versionEndExcluding"]
                                    fixed_versions.append(match["versionEndExcluding"])
                                if "versionEndIncluding" in match:
                                    entry["version_end_including"] = match["versionEndIncluding"]
                                if entry:
                                    affected_versions.append(entry)
                                elif "criteria" in match:
                                    # fallback: extract version from CPE string
                                    parts = match["criteria"].split(":")
                                    if len(parts) > 5 and parts[5] not in ("*", "-", ""):
                                        affected_versions.append(parts[5])

                    # Extraction keywords depuis la description
                    keywords = _extract_keywords(desc, cve_id)

                    # poc_available : présence de références de type exploit
                    poc_refs = {"exploit-db", "packetstorm", "github", "exploit"}
                    poc_available = any(
                        any(tag.lower() in poc_refs for tag in ref.get("tags", []))
                        for ref in cve.get("references", [])
                    )

                    # Upsert : supprime l'existant puis réinsère
                    existing = session.query(IntelCVE).filter_by(cve_id=cve_id).first()
                    if existing:
                        session.delete(existing)

                    session.add(IntelCVE(
                        cve_id=cve_id,
                        description=desc,
                        cvss_v2_score=cvss_v2,
                        cvss_v3_score=cvss_v3,
                        cvss_v4_score=cvss_v4,
                        cvss_v3_vector=cvss_v3_vector,
                        cwe_id=cwe_id,
                        affected_versions=json.dumps(affected_versions),
                        fixed_versions=json.dumps(fixed_versions),
                        keywords=json.dumps(keywords),
                        poc_available=poc_available,
                    ))
                    loaded += 1
                
                session.commit()
                start_index += len(vulnerabilities)
                logger.info(f"Loaded {start_index}/{total_results} NVD CVEs...")
                
        except Exception as e:
            logger.error(f"Error fetching NVD at index {start_index}: {e}")
            break
            
        time.sleep(delay)
        
    logger.info(f"Successfully loaded/updated {loaded} CVEs from NVD.")
