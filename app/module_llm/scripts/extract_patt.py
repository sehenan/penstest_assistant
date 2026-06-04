"""
Module d'extraction des données PayloadsAllTheThings.
"""
import re
import yaml
from pathlib import Path
from loguru import logger

def extract_patt(source_dir: str, output_dir: str) -> None:
    """
    Extrait les fichiers markdown de PayloadsAllTheThings et ajoute les métadonnées.
    
    Args:
        source_dir (str): Répertoire source (/opt/patt).
        output_dir (str): Répertoire de sortie (knowledge_base/payloadsallthethings).
    """
    src_path = Path(source_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    if not src_path.exists():
        logger.error(f"Le dossier source {src_path} n'existe pas.")
        return

    re_cve = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    processed_count = 0

    for md_file in src_path.rglob("*.md"):
        rel_path = md_file.relative_to(src_path)
        dest_file = out_path / rel_path
        
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            content = md_file.read_text(encoding="utf-8", errors="ignore")
            
            cves = list(set(cve.upper() for cve in re_cve.findall(content)))
            
            url_path = str(rel_path).replace("\\", "/")
            source_url = f"https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/{url_path}"
            
            frontmatter = {
                "source_name": "PayloadsAllTheThings",
                "source_url": source_url,
                "source_date": "2024-01-15",
                "cve_tags": cves,
                "chunk_id": ""
            }
            
            yaml_block = f"---\n{yaml.dump(frontmatter, default_flow_style=False, allow_unicode=True, sort_keys=False)}---\n\n"
            
            dest_file.write_text(yaml_block + content.strip(), encoding="utf-8")
            processed_count += 1
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de {md_file}: {e}")
            
    logger.success(f"PayloadsAllTheThings: {processed_count} fichiers traités.")

if __name__ == "__main__":
    extract_patt("data/knowledge_base/patt", "data/knowledge_base/payloadsallthethings")
