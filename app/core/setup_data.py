import sqlite3
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def setup_all_databases():
    """Initialise les bases de données minimales pour le fonctionnement de l'outil."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    setup_cpe_db(data_dir / "cpe.db")
    setup_exploits_db(data_dir / "exploits.db")

def setup_cpe_db(path):
    """Crée une base CPE minimale pour la démonstration."""
    if path.exists():
        logger.info("Base CPE déjà présente.")
        return
        
    logger.info("Création de la base CPE fictive pour démonstration...")
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE cpe_entries (id INTEGER PRIMARY KEY, title TEXT, version TEXT)")
        # Quelques données de démo pour Nginx, Apache, Struts
        demo_data = [
            ("nginx", "1.14.0"),
            ("apache", "2.4.41"),
            ("struts", "2.3.12"),
            ("tomcat", "9.0.31")
        ]
        conn.executemany("INSERT INTO cpe_entries (title, version) VALUES (?, ?)", demo_data)
        conn.commit()

def setup_exploits_db(path):
    """Crée une base Exploits minimale pour la démonstration."""
    if path.exists():
        logger.info("Base Exploits déjà présente.")
        return
        
    logger.info("Création de la base Exploits fictive pour démonstration...")
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE exploits (id INTEGER PRIMARY KEY, cve TEXT, exploit_db_id TEXT, metasploit_module TEXT)")
        # Données de démo pour CVE critiques connues
        demo_data = [
            ("CVE-2017-5638", "42324", "exploit/multi/http/struts2_content_type_ognl"),
            ("CVE-2020-1472", "48859", "exploit/windows/smb/ms20_010_eternalblue"),
            ("CVE-2021-44228", "50592", "exploit/multi/http/log4shell_header_injection")
        ]
        conn.executemany("INSERT INTO exploits (cve, exploit_db_id, metasploit_module) VALUES (?, ?, ?)", demo_data)
        conn.commit()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    setup_all_databases()
