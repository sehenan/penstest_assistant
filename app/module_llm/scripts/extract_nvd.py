"""
Module d'extraction des vulnérabilités depuis les flux NVD JSON.
"""
import json
import yaml
from pathlib import Path
from loguru import logger

def extract_nvd(nvd_dir: str, output_dir: str) -> None:
    """
    Extrait les informations CVE depuis les fichiers JSON du NVD.
    
    Args:
        nvd_dir (str): Répertoire source contenant les fichiers JSON (/opt/nvd).
        output_dir (str): Répertoire de sortie (knowledge_base/nvd_cache).
    """
    src_path = Path(nvd_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    if not src_path.exists():
        logger.error(f"Le dossier source {src_path} n'existe pas.")
        return

    processed_count = 0

    for json_file in src_path.glob("nvdcve-1.1-*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            cve_items = data.get('CVE_Items', [])
            
            for item in cve_items:
                cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                if not cve_id:
                    continue
                    
                # Extraire la description en anglais
                desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
                description = "No description available."
                for d in desc_data:
                    if d.get('lang') == 'en':
                        description = d.get('value', description)
                        break
                        
                # Extraire CVSS v3
                impact = item.get('impact', {})
                base_metric_v3 = impact.get('baseMetricV3', {})
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                
                cvss_score = cvss_v3.get('baseScore', "N/A")
                cvss_vector = cvss_v3.get('vectorString', "N/A")
                
                # Extraire CWE
                cwe_list = []
                problemtype_data = item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
                for ptd in problemtype_data:
                    for desc in ptd.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_list.append(desc.get('value'))
                
                md_content = f"# {cve_id}\n\n"
                md_content += f"## Description\n\n{description}\n"
                
                source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                
                frontmatter = {
                    "source_name": "NVD",
                    "source_url": source_url,
                    "source_date": "2024-01-15",
                    "cve_tags": [cve_id],
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cwe": cwe_list,
                    "chunk_id": ""
                }
                
                yaml_block = f"---\n{yaml.dump(frontmatter, default_flow_style=False, allow_unicode=True, sort_keys=False)}---\n\n"
                
                dest_file = out_path / f"{cve_id}.md"
                dest_file.write_text(yaml_block + md_content, encoding="utf-8")
                processed_count += 1
                
        except Exception as e:
            logger.error(f"Erreur lors du traitement de {json_file}: {e}")
            
    logger.success(f"NVD: {processed_count} CVEs extraites.")

if __name__ == "__main__":
    extract_nvd("data/knowledge_base/nvd", "data/knowledge_base/nvd_cache")
