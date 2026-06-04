import csv
import gzip
import logging
import urllib.request
from io import TextIOWrapper
from builder.models import IntelEPSS

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

def fetch_and_load_epss(session):
    logger.info("Downloading EPSS scores...")
    try:
        # Download the gz file
        req = urllib.request.Request(EPSS_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            with gzip.open(response, 'rt', encoding='utf-8') as f:
                reader = csv.reader(f)
                
                # The first row is usually a comment with the model version and date
                header_comment = next(reader, None)
                # The second row is the actual header: cve,epss,percentile
                header = next(reader, None)
                
                if not header or header[0] != 'cve':
                    logger.error("Unexpected EPSS CSV format")
                    return

                logger.info("Parsing and loading EPSS data into DB...")
                count = 0
                batch_size = 10000
                objects = []
                
                # Vider la table pour un rechargement complet (plus propre que l'upsert pour un builder offline)
                session.query(IntelEPSS).delete()
                
                for row in reader:
                    if len(row) < 3:
                        continue
                    cve, epss, percentile = row[0], row[1], row[2]
                    objects.append(IntelEPSS(
                        cve_id=cve,
                        epss_score=float(epss),
                        percentile=float(percentile)
                    ))
                    
                    count += 1
                    if count % batch_size == 0:
                        session.bulk_save_objects(objects)
                        session.commit()
                        objects = []
                        logger.debug(f"Loaded {count} EPSS records...")
                
                # Remaining objects
                if objects:
                    session.bulk_save_objects(objects)
                    session.commit()
                
                logger.info(f"Successfully loaded {count} EPSS records.")

    except Exception as e:
        logger.error(f"Error fetching EPSS: {e}")
        session.rollback()
