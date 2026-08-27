import argparse
import logging
from builder.db import init_db, get_session
from builder.etl.nvd import fetch_and_load_nvd
from builder.etl.epss import fetch_and_load_epss
from builder.etl.kev import fetch_and_load_kev
from builder.packager import create_bundle

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="SIATI Intel Builder (Air-Gapped Packager)")
    parser.add_argument("--nvd-days", type=int, default=30, help="Nombre de jours pour l'historique NVD (défaut: 30)")
    parser.add_argument("--skip-nvd", action="store_true", help="Ignorer le téléchargement NVD")
    parser.add_argument("--skip-epss", action="store_true", help="Ignorer le téléchargement EPSS")
    parser.add_argument("--skip-kev", action="store_true", help="Ignorer le téléchargement CISA KEV")
    args = parser.parse_args()

    logger.info("Initializing local Threat Intel Database...")
    init_db("threat_intel.db")
    session = get_session("threat_intel.db")

    if not args.skip_nvd:
        fetch_and_load_nvd(session, days_back=args.nvd_days)
    
    if not args.skip_epss:
        fetch_and_load_epss(session)
        
    if not args.skip_kev:
        fetch_and_load_kev(session)
        
    session.close()
    
    bundle_path = create_bundle("threat_intel.db")
    if bundle_path:
        logger.info(f"✅ Build Process Complete. Bundle ready for Air-Gapped transfer: {bundle_path}")

if __name__ == "__main__":
    main()
