"""
Module d'extraction et nettoyage des données HackTricks.
"""
import re
import yaml
from pathlib import Path
from loguru import logger

def extract_hacktricks(source_dir: str, output_dir: str) -> None:
    """
    Extrait et nettoie les fichiers markdown de HackTricks.
    
    Args:
        source_dir (str): Répertoire source (/opt/hacktricks/src).
        output_dir (str): Répertoire de sortie (knowledge_base/hacktricks_cleaned).
    """
    src_path = Path(source_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    if not src_path.exists():
        logger.error(f"Le dossier source {src_path} n'existe pas.")
        return

    # Fichiers à ignorer à la racine
    ignore_files = {"SUMMARY.md", "README.md", "book.toml"}
    
    # Regex pour le nettoyage
    re_badges = re.compile(r'\[!\[.*?\]\(https://(?:img\.shields\.io|.*gitbook).*?\)\]\(.*?\)', re.IGNORECASE)
    re_edit_page = re.compile(r'\[<img src="https://github.com/.*?Edit this page.*?\]\(.*?\)', re.IGNORECASE)
    re_toc = re.compile(r'<details>\s*<summary>.*?TOC.*?</summary>.*?</details>', re.IGNORECASE | re.DOTALL)
    re_hint = re.compile(r'{%\s*hint.*?%}.*?{%\s*endhint\s*%}', re.IGNORECASE | re.DOTALL)
    re_empty_lines = re.compile(r'\n{3,}')
    re_cve = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    processed_count = 0

    for md_file in src_path.rglob("*.md"):
        # Ignorer certains fichiers à la racine
        if md_file.parent == src_path and md_file.name in ignore_files:
            continue
            
        rel_path = md_file.relative_to(src_path)
        dest_file = out_path / rel_path
        
        # S'assurer que le dossier parent existe
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            content = md_file.read_text(encoding="utf-8", errors="ignore")
            
            # Extraction des CVE
            cves = list(set(cve.upper() for cve in re_cve.findall(content)))
            
            # Nettoyage
            content = re_badges.sub("", content)
            content = re_edit_page.sub("", content)
            content = re_toc.sub("", content)
            content = re_hint.sub("", content)
            content = re_empty_lines.sub("\n\n", content)
            
            # Reconstruction de l'URL
            url_path = str(rel_path.with_suffix("")).replace("\\", "/")
            source_url = f"https://book.hacktricks.xyz/{url_path}"
            
            # Frontmatter
            frontmatter = {
                "source_name": "HackTricks",
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
            
    logger.success(f"HackTricks: {processed_count} fichiers traités.")

if __name__ == "__main__":
    extract_hacktricks("data/knowledge_base/hacktricks/src", "data/knowledge_base/hacktricks_cleaned")
