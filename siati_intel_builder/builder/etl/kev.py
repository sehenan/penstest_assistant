import json
import logging
import urllib.request
from builder.models import IntelKEV

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_and_load_kev(session):
    logger.info("Downloading CISA KEV catalog...")
    try:
        req = urllib.request.Request(KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            vulnerabilities = data.get("vulnerabilities", [])
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities in KEV.")
            
            session.query(IntelKEV).delete()
            
            objects = []
            for v in vulnerabilities:
                objects.append(IntelKEV(
                    cve_id=v.get("cveID"),
                    vendor_project=v.get("vendorProject"),
                    product=v.get("product"),
                    short_description=v.get("shortDescription"),
                    date_added=v.get("dateAdded"),
                    due_date=v.get("dueDate"),
                    known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse")
                ))
            
            if objects:
                session.bulk_save_objects(objects)
                session.commit()
                
            logger.info("Successfully loaded CISA KEV catalog.")

    except Exception as e:
        logger.error(f"Error fetching KEV: {e}")
        session.rollback()
