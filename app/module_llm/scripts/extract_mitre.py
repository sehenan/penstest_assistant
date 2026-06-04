"""
Module d'extraction des techniques MITRE ATT&CK depuis le format STIX.
"""
import json
import yaml
from pathlib import Path
from loguru import logger

def extract_mitre(json_path: str, output_dir: str) -> None:
    """
    Extrait les techniques MITRE ATT&CK du fichier JSON (STIX).
    
    Args:
        json_path (str): Chemin vers le fichier enterprise-attack.json.
        output_dir (str): Répertoire de sortie (knowledge_base/mitre_attack).
    """
    src_file = Path(json_path)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    if not src_file.exists():
        logger.error(f"Le fichier source {src_file} n'existe pas.")
        return

    try:
        with open(src_file, 'r', encoding='utf-8') as f:
            stix_data = json.load(f)
            
        objects = stix_data.get('objects', [])
        
        # 1. Indexer les objets par ID
        obj_dict = {obj.get('id'): obj for obj in objects}
        
        # 2. Trouver les relations "mitigates"
        mitigates_rel = {}
        for obj in objects:
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
                source_ref = obj.get('source_ref')
                target_ref = obj.get('target_ref')
                if target_ref not in mitigates_rel:
                    mitigates_rel[target_ref] = []
                mitigates_rel[target_ref].append(source_ref)

        processed_count = 0
        
        for obj in objects:
            if obj.get('type') != 'attack-pattern':
                continue
                
            external_references = obj.get('external_references', [])
            mitre_id = ""
            source_url = ""
            for ref in external_references:
                if ref.get('source_name') == 'mitre-attack':
                    ext_id = ref.get('external_id', '')
                    if ext_id.startswith('T'):
                        mitre_id = ext_id
                        source_url = ref.get('url', '')
                        break
                        
            if not mitre_id:
                continue
                
            name = obj.get('name', 'Unknown')
            description = obj.get('description', 'No description provided.')
            detection = obj.get('x_mitre_detection', 'No detection guidance provided.')
            
            # Construire la section Mitigation
            mitigations_text = ""
            mitigation_refs = mitigates_rel.get(obj.get('id'), [])
            if mitigation_refs:
                mitigations_text += "## Mitigations\n\n"
                for m_ref in mitigation_refs:
                    m_obj = obj_dict.get(m_ref)
                    if m_obj and m_obj.get('type') == 'course-of-action':
                        m_name = m_obj.get('name', 'Unknown Mitigation')
                        m_desc = m_obj.get('description', '')
                        mitigations_text += f"### {m_name}\n{m_desc}\n\n"
            else:
                mitigations_text += "## Mitigations\n\nNo mitigations provided.\n\n"

            md_content = f"# {name}\n\n"
            md_content += f"## Description\n\n{description}\n\n"
            md_content += f"## Detection\n\n{detection}\n\n"
            md_content += mitigations_text
            
            frontmatter = {
                "source_name": "MITRE ATT&CK",
                "source_url": source_url,
                "source_date": "2024-01-15",
                "cve_tags": [],
                "mitre_id": mitre_id,
                "chunk_id": ""
            }
            
            yaml_block = f"---\n{yaml.dump(frontmatter, default_flow_style=False, allow_unicode=True, sort_keys=False)}---\n\n"
            
            dest_file = out_path / f"{mitre_id}.md"
            dest_file.write_text(yaml_block + md_content, encoding="utf-8")
            processed_count += 1
            
        logger.success(f"MITRE ATT&CK: {processed_count} techniques extraites.")
        
    except Exception as e:
        logger.error(f"Erreur lors du traitement de {src_file}: {e}")

if __name__ == "__main__":
    extract_mitre("data/knowledge_base/mitre/enterprise-attack.json", "data/knowledge_base/mitre_attack")
