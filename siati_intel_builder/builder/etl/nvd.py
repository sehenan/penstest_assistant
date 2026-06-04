import datetime
import logging
import time
import urllib.request
import json
from builder.models import IntelCVE

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
                    
                    # On supprime s'il existe déjà (upsert pauvre)
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
                        cwe_id=cwe_id
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
