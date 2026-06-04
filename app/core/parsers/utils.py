from lxml import etree

def load_xml_clean(path: str):
    """
    Lit un fichier XML en ignorant de manière robuste les lignes textuelles
    qui pourraient précéder la déclaration XML (par exemple, l'output console de nmap).
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    start_idx = content.find("<?xml")
    if start_idx == -1:
        start_idx = content.find("<nmaprun")
    if start_idx == -1:
        start_idx = content.find("<NessusClientData")
    if start_idx == -1:
        start_idx = content.find("<report")
    if start_idx == -1:
        start_idx = content.find("<")

    if start_idx > 0:
        content = content[start_idx:]
        
    parser = etree.XMLParser(recover=True)
    try:
        root = etree.fromstring(content.encode("utf-8", errors="ignore"), parser=parser)
        return root
    except Exception:
        # Fallback standard si fromstring échoue
        tree = etree.parse(path)
        return tree.getroot()
