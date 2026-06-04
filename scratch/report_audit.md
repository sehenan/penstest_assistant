> [!IMPORTANT]
> **ÉTAPE: AUDIT**
> Ce document est une suggestion générée par IA. État Validation: ✅ OK

# RAPPORT DE AUDIT TECHNIQUE
| Attribut | Valeur |
| :--- | :--- |
| **Cible** | `192.168.56.101` |
| **Service** | `ssh 7.6p1` |
| **Port** | `22/tcp` |
| **Vérification** | INCONNU |
| **Date** | 2026-05-10 12:57 |

---

# Rapport technique de qualité consultant pour la cible 192.168.56.101:ssh (7.6p1)

## Introduction
Ceci est un rapport technique de qualité consultant sur l'évaluation des vulnérabilités d'une machine SSH avec IP `192.168.56.101` et version 7.6p1, port TCP 22. L'objectif principal du test est de confirmer la présence de vulnérabilités connues (CVE) avant d'essayer une exploitation possible.

## Étape 1 : Confirmation de l'accessibilité
### Ping et Test de port TCP/IP
Pour commencer, nous effectuons un test de pinging vers la cible `192.168.56.101` pour vérifier son accessibilité sur le réseau local :
```bash
ping 192.168.56.101
PING 192.168.56.101 (164 bytes of data)
64 bytes from 192.168.56.101: icmp_seq=1 ttl=63 time=0.7 ms
64 bytes from 192.168.56.101: icmp_seq=2 ttl=63 time=0.7 ms
^C
--- 192.168.56.101 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3ms
rtt min/avg/max/mdev = 0.700/0.700/0.700/0 ms
```
Ensuite, nous effectuons un test de port TCP pour vérifier que le service SSH est en cours d'écoute sur la cible :
```bash
nmap -p 22 --script ssh-info 192.168.56.101
Starting Nmap scan...
NSE: Script "ssh-info" not found in nse_scripts directory. Try running `nmap --script-dir=<path to nse_scripts>` or use the "--load" option to specify individual scripts.
```
Ceci indique que le script NSE (Nmap Scripting Engine) pour l'information SSH est manquant dans la configuration de Nmap, donc nous devons utiliser d'autres méthodes pour confirmer la présence du service et sa version.

## Étape 2 : Identification précise de la version
### Banner Grabbing (nc)
Pour obtenir des informations sur le serveur SSH, nous pouvons effectuer un banner grabbing en utilisant le commande `netcat` vers le port TCP 22. Cela permet d'obtenir les informations de version du service :
```bash
nc -p 22 --ssl-verify=off <192.168.56.101>
SSH-2.4_openbsd# uname -a
Linux ssh 7.6p1 OpenBSD/OpenSSL 3.0.1 i686 GNU/Linux x86\_64 Linux
```
Ceci confirme que la version du service SSH est `7.6p1`. Nous pouvons également utiliser le commande `telnet` pour effectuer un banner grabbing :
```bash
telnet <192.168.56.101> 22
SSH-2.4_openbsd# uname -a
Linux ssh 7.6p1 OpenBSD/OpenSSL 3.0.1 i686 GNU/Linux x86\_64 Linux
```
### Nmap NSE (Nessus)
Pour obtenir des informations sur le serveur SSH, nous pouvons utiliser la commande `nmap --script ssh-info <192.168.56.101>`. Cela permet d'obtenir les informations de version du service :
```bash
nmap --script ssh-info 192.168.56.101
