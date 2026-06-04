import hashlib
import json
import logging
import tarfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

def generate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def create_bundle(db_path: str = "threat_intel.db", output_dir: str = "bundles"):
    logger.info("Packaging Threat Intel Bundle...")
    
    db_file = Path(db_path)
    if not db_file.exists():
        logger.error(f"Database {db_path} not found. Run ETL first.")
        return None

    out_dir = Path(output_dir)
    out_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version = f"v{timestamp}"
    
    # Generate metadata
    metadata = {
        "version": version,
        "created_at": datetime.now().isoformat(),
        "files": {
            "threat_intel.db": {
                "sha256": generate_sha256(db_file),
                "size_bytes": db_file.stat().st_size
            }
        },
        "sources": ["NVD", "EPSS", "CISA KEV"]
    }
    
    metadata_path = out_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
        
    bundle_name = f"siati_intel_{version}.tar.gz"
    bundle_path = out_dir / bundle_name
    
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(db_file, arcname="threat_intel.db")
        tar.add(metadata_path, arcname="metadata.json")
        
    logger.info(f"Bundle created successfully at: {bundle_path}")
    
    # Cleanup metadata
    metadata_path.unlink()
    
    return bundle_path
