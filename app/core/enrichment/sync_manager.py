import hashlib
import json
import logging
import os
import shutil
import tarfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = Path("data")
INTEL_DB_PATH = DATA_DIR / "threat_intel.db"
VERSIONS_FILE = DATA_DIR / "intel_versions.json"
BACKUP_DIR = DATA_DIR / "intel_backups"

def _generate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def init_version_tracker():
    if not VERSIONS_FILE.exists():
        DATA_DIR.mkdir(exist_ok=True)
        with open(VERSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump({"active_version": None, "history": []}, f)
    BACKUP_DIR.mkdir(exist_ok=True)

def ingest_bundle(bundle_path: str) -> bool:
    """
    Ingère un bundle tar.gz généré par le siati_intel_builder.
    Vérifie l'intégrité (SHA256) et remplace la base en assurant le versioning.
    """
    init_version_tracker()
    
    bundle_file = Path(bundle_path)
    if not bundle_file.exists():
        logger.error(f"Bundle not found: {bundle_path}")
        return False
        
    temp_dir = DATA_DIR / "temp_bundle_extract"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir()
    
    try:
        # 1. Extraction
        logger.info(f"Extracting bundle {bundle_path}...")
        with tarfile.open(bundle_file, "r:gz") as tar:
            tar.extractall(path=temp_dir)
            
        metadata_file = temp_dir / "metadata.json"
        db_file = temp_dir / "threat_intel.db"
        
        if not metadata_file.exists() or not db_file.exists():
            logger.error("Invalid bundle format: missing metadata.json or threat_intel.db")
            return False
            
        with open(metadata_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)
            
        # 2. Vérification intégrité
        expected_hash = metadata.get("files", {}).get("threat_intel.db", {}).get("sha256")
        logger.info("Verifying SHA256 integrity...")
        actual_hash = _generate_sha256(db_file)
        
        if actual_hash != expected_hash:
            logger.error(f"Integrity check failed! Expected {expected_hash}, got {actual_hash}")
            return False
            
        new_version = metadata.get("version", "unknown")
        logger.info(f"Integrity verified for version {new_version}.")
        
        # 3. Versioning et Rotation (Backup)
        with open(VERSIONS_FILE, "r", encoding="utf-8") as f:
            versions = json.load(f)
            
        if INTEL_DB_PATH.exists():
            current_active = versions.get("active_version", "old")
            backup_name = f"threat_intel_{current_active}_{datetime.now().strftime('%Y%m%d%H%M%S')}.db"
            backup_path = BACKUP_DIR / backup_name
            shutil.move(str(INTEL_DB_PATH), str(backup_path))
            logger.info(f"Backed up current DB to {backup_path}")
            
            versions["history"].append({
                "version": current_active,
                "backup_path": str(backup_path),
                "replaced_at": datetime.now().isoformat()
            })
            
        # 4. Installation
        shutil.move(str(db_file), str(INTEL_DB_PATH))
        
        # Update tracker
        versions["active_version"] = new_version
        with open(VERSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(versions, f, indent=4)
            
        logger.info(f"Successfully installed Threat Intel version {new_version}.")
        return True
        
    except Exception as e:
        logger.error(f"Error ingesting bundle: {e}")
        return False
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

def rollback_to_version(backup_file_name: str) -> bool:
    """
    Restaure une ancienne base d'enrichissement.
    """
    backup_path = BACKUP_DIR / backup_file_name
    if not backup_path.exists():
        logger.error("Backup file not found.")
        return False
        
    try:
        if INTEL_DB_PATH.exists():
            shutil.move(str(INTEL_DB_PATH), str(BACKUP_DIR / f"threat_intel_rolledback_{datetime.now().strftime('%Y%m%d%H%M%S')}.db"))
            
        shutil.copy(str(backup_path), str(INTEL_DB_PATH))
        
        with open(VERSIONS_FILE, "r", encoding="utf-8") as f:
            versions = json.load(f)
            versions["active_version"] = f"rolled_back_to_{backup_file_name}"
            
        with open(VERSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(versions, f, indent=4)
            
        logger.info(f"Successfully rolled back to {backup_file_name}")
        return True
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        return False
