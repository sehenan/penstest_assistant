"""
Module de téléchargement des sources brutes pour la knowledge base.
"""
import subprocess
import requests
import gzip
import shutil
from pathlib import Path
from loguru import logger

def download_all(base_dir: str = "data/knowledge_base") -> None:
    """
    Télécharge toutes les sources requises dans le dossier spécifié.
    
    Args:
        base_dir (str): Répertoire de base pour les téléchargements. Par défaut "data/knowledge_base".
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    base_path = Path(base_dir)
    base_path.mkdir(parents=True, exist_ok=True)
    
    commands = [
        {
            "name": "HackTricks",
            "cmd": f"git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks.git {base_path / 'hacktricks'}",
            "check_path": base_path / "hacktricks" / ".git"
        },
        {
            "name": "PayloadsAllTheThings",
            "cmd": f"git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git {base_path / 'patt'}",
            "check_path": base_path / "patt" / ".git"
        },
        {
            "name": "Exploit-DB",
            "cmd": f"git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git {base_path / 'exploitdb'}",
            "check_path": base_path / "exploitdb" / ".git"
        }
    ]
    
    # 1. Cloner les dépôts Git
    for item in commands:
        if item["check_path"].exists():
            logger.info(f"{item['name']} est déjà présent. Ignoré.")
            continue
            
        logger.info(f"Téléchargement de {item['name']} (Git clone)...")
        try:
            subprocess.run(
                item["cmd"], 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            logger.success(f"{item['name']} téléchargé avec succès.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Erreur lors du téléchargement de {item['name']}: {e.stderr}")

    # 2. Télécharger MITRE ATT&CK
    mitre_dir = base_path / "mitre"
    mitre_dir.mkdir(parents=True, exist_ok=True)
    mitre_file = mitre_dir / "enterprise-attack.json"
    
    if not mitre_file.exists():
        logger.info("Téléchargement de MITRE ATT&CK (JSON)...")
        try:
            response = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json", headers=headers, stream=True)
            response.raise_for_status()
            with open(mitre_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.success("MITRE ATT&CK téléchargé avec succès.")
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement de MITRE ATT&CK : {e}")
    else:
        logger.info("MITRE ATT&CK est déjà présent. Ignoré.")

    # 3. Télécharger NVD (JSON.gz puis extraction)
    nvd_dir = base_path / "nvd"
    nvd_dir.mkdir(parents=True, exist_ok=True)
    for year in range(2020, 2025):
        nvd_json_file = nvd_dir / f"nvdcve-1.1-{year}.json"
        nvd_gz_file = nvd_dir / f"nvdcve-1.1-{year}.json.gz"
        
        if nvd_json_file.exists():
            logger.info(f"NVD {year} est déjà présent. Ignoré.")
            continue
            
        logger.info(f"Téléchargement de NVD {year}...")
        try:
            # Téléchargement
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            response = requests.get(url, headers=headers, stream=True)
            response.raise_for_status()
            with open(nvd_gz_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            # Extraction (gunzip)
            logger.info(f"Extraction de NVD {year}...")
            with gzip.open(nvd_gz_file, 'rb') as f_in:
                with open(nvd_json_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
            # Suppression du fichier .gz
            nvd_gz_file.unlink()
            
            logger.success(f"NVD {year} téléchargé et extrait avec succès.")
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement/extraction de NVD {year} : {e}")

if __name__ == "__main__":
    download_all()
