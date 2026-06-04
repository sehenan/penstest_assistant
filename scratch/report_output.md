> [!IMPORTANT]
> **ÉTAPE: PAYLOAD**
> Ce document est une suggestion générée par IA. État Validation: ✅ OK

# Exploitation

## Scanner le port 22 pour détecter la version de SSH
```bash
nmap -sV -p 22 192.168.56.101
```
Analyse l'en-tête Server pour identifier la version d'OpenSSH.

## Identifier les failles dans le service SSH
Utilisez des outils tels que OpenVAS, Nessus ou Burp Suite pour détecter et exploiter les vulnérabilités du service SSH.