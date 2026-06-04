Tu es un développeur Python senior. Génère un système complet de consolidation de knowledge base pour un RAG pentest. Tu dois produire 7 fichiers Python dans l'ordre strict ci-dessous.

STRUCTURE DE SORTIE :
module_llm/
├── scripts/
│   ├── download_sources.py
│   ├── extract_hacktricks.py
│   ├── extract_patt.py
│   ├── extract_exploitdb.py
│   ├── extract_mitre.py
│   ├── extract_nvd.py
│   └── run_all_extractions.py
└── knowledge_base/
├── hacktricks_cleaned/
├── payloadsallthethings/
├── exploitdb_verified/
├── mitre_attack/
└── nvd_cache/
plain
Copy

FORMAT DE CHAQUE FICHIER .md GÉNÉRÉ :
```yaml
---
source_name: "NOM"
source_url: "URL"
source_date: "2024-01-15"
cve_tags: []
chunk_id: ""
---
source_name ∈ {HackTricks, PayloadsAllTheThings, Exploit-DB, MITRE ATT&CK, NVD}
CONTRAINTES : Python 3.11, pyyaml, loguru, pathlib, type hints, docstrings, pas de print, idempotent, regex CVE : CVE-\d{4}-\d{4,}
download_sources.py
Télécharge dans /opt/ :
git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks.git /opt/hacktricks
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/patt
git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
wget https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json -O /opt/enterprise-attack.json
mkdir -p /opt/nvd && for year in 2020 2021 2022 2023 2024; do wget "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-${year}.json.gz" -P /opt/nvd/ && gunzip -f /opt/nvd/nvdcve-1.1-${year}.json.gz; done
Vérifie chaque étape, log avec loguru.
Fonction : download_all(base_dir: str = "/opt") -> None
extract_hacktricks.py
Entrée : /opt/hacktricks/src/**/*.md
Sortie : knowledge_base/hacktricks_cleaned/ (arborescence conservée)
Nettoyage : supprimer SUMMARY.md, README.md (racine src), book.toml, badges shields.io/gitbook, liens "Edit this page", TOC auto, blocs {% hint %}, lignes vides multiples (>2).
source_url : reconstruire depuis chemin relatif -> https://book.hacktricks.xyz/<chemin_sans_md>
cve_tags : extraire via regex CVE-\d{4}-\d{4,}
Fonction : extract_hacktricks(source_dir: str, output_dir: str) -> None
extract_patt.py
Entrée : /opt/patt/**/*.md
Sortie : knowledge_base/payloadsallthethings/ (arborescence conservée)
Ajouter frontmatter. source_url : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/<chemin_relatif>
cve_tags : extraire via regex
Fonction : extract_patt(source_dir: str, output_dir: str) -> None
extract_exploitdb.py
Entrée : /opt/exploitdb/files_exploits.csv + /opt/exploitdb/exploits/
Sortie : knowledge_base/exploitdb_verified/<id>
Filtrer CSV sur verified == "1" uniquement.
Pour chaque ligne vérifiée : lire le fichier dans exploits/, créer un .md avec description (CSV), type, plateforme, date, et le code source dans un bloc <type>.
source_url : https://www.exploit-db.com/exploits/<id>
cve_tags : extraire du contenu du fichier
Fonction : extract_exploitdb(source_dir: str, output_dir: str) -> None
extract_mitre.py
Entrée : /opt/enterprise-attack.json (STIX)
Sortie : knowledge_base/mitre_attack/TXXXX.md
Extraire type="attack-pattern" avec external_id commençant par T.
Contenu : nom, description, x_mitre_detection, mitigations liées via relationships type="mitigates".
Frontmatter avec mitre_id: "TXXXX"
Fonction : extract_mitre(json_path: str, output_dir: str) -> None
extract_nvd.py
Entrée : /opt/nvd/nvdcve-1.1-YYYY.json
Sortie : knowledge_base/nvd_cache/CVE-XXXX-XXXX.md
Pour chaque CVE : description EN (lang="en"), CVSS v3 score/vector, CWE.
Frontmatter avec cvss_score, cvss_vector, cwe (liste), cve_tags: ["CVE-XXXX-XXXX"]
Fonction : extract_nvd(nvd_dir: str, output_dir: str) -> None
run_all_extractions.py
Orchestrateur qui appelle dans l'ordre :
download_all("/opt") si les dossiers n'existent pas
extract_hacktricks("/opt/hacktricks/src", "knowledge_base/hacktricks_cleaned")
extract_patt("/opt/patt", "knowledge_base/payloadsallthethings")
extract_exploitdb("/opt/exploitdb", "knowledge_base/exploitdb_verified")
extract_mitre("/opt/enterprise-attack.json", "knowledge_base/mitre_attack")
extract_nvd("/opt/nvd", "knowledge_base/nvd_cache")
Affiche un récapitulatif : nombre de .md par dossier.
Fonction : main() -> None
RÈGLE DE PRÉSENTATION : Pour chaque fichier, commence EXACTEMENT par :
=== FICHIER : scripts/nom_du_fichier.py ===
Ne passe au fichier suivant que quand le précédent est complet.