# ELK Stack Cheatsheet - SOC/DFIR

## Syntaxe de base (KQL)

```
champ:valeur                    # Recherche exacte
champ:"valeur exacte"           # Phrase exacte avec espaces
champ:*valeur*                  # Wildcard
champ:val?r                     # ? = 1 caractère

AND, OR, NOT                    # Opérateurs booléens (majuscules)
_exists_:champ                  # Champ existe
NOT _exists_:champ              # Champ n'existe pas
champ:>=100                     # Comparaison numérique
champ:[100 TO 500]              # Range inclusif
```

## Filtres temporels

```
@timestamp >= "2024-01-01"
@timestamp <= "now-1h"          # Dernière heure
@timestamp >= "now-24h"         # Dernières 24h
@timestamp:[now-7d TO now]      # 7 derniers jours
```

## Windows Event IDs Essentiels

### Authentification
| Event ID | Description |
|----------|-------------|
| 4624 | Logon réussi |
| 4625 | Logon échoué (brute force) |
| 4634 | Logoff |
| 4648 | Logon avec credentials explicites |
| 4672 | Privilèges spéciaux assignés (admin) |
| 4768 | Kerberos TGT demandé |
| 4769 | Kerberos Service Ticket |
| 4771 | Kerberos pre-auth failed |

### Gestion des comptes
| Event ID | Description |
|----------|-------------|
| 4720 | Compte créé |
| 4722 | Compte activé |
| 4724 | Réinitialisation mot de passe |
| 4725 | Compte désactivé |
| 4726 | Compte supprimé |
| 4728 | Membre ajouté groupe global |
| 4732 | Membre ajouté groupe local |
| 4738 | Compte modifié |
| 4740 | Compte verrouillé |

### Système & Sécurité Critiques
| Event ID | Description |
|----------|-------------|
| **1102** | **Logs d'audit effacés (CRITIQUE)** |
| 4719 | Politique d'audit modifiée |
| 4688 | Nouveau processus créé |
| 4698 | Tâche planifiée créée |
| 7045 | Nouveau service installé |
| 5140 | Partage réseau accédé |

## Sysmon Event IDs Clés

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image/DLL Loaded |
| 8 | CreateRemoteThread (injection) |
| 10 | Process Access |
| 11 | File Created |
| 13 | Registry Value Set |
| 22 | DNS Query |
| 23 | File Delete |

## Requêtes SOC par Use Case

### 🔴 Brute Force Detection
```
event.code:4625 AND source.ip:*
# Grouper par source.ip (>5 en 5min)

event.code:4771                 # Kerberos brute force
```

### 🔴 Lateral Movement
```
event.code:4648                 # Logon avec creds explicites
event.code:4624 AND winlog.logon.type:3  # Network logon
event.code:5140                 # Partage réseau (C$, ADMIN$)
destination.port:(445 OR 3389)
```

### 🔴 PowerShell/CMD Suspect
```
process.name:powershell.exe AND process.command_line:(*encodedcommand* OR *bypass* OR *downloadstring*)
process.name:cmd.exe AND process.command_line:*/c*
event.code:1 AND process.name:powershell.exe  # Sysmon
```

### 🔴 Persistence Mechanisms
```
event.code:4698                 # Scheduled tasks
event.code:7045                 # New service
event.code:13 AND registry.path:*\\Run*
file.path:*\\Startup\\*
```

### 🔴 Privilege Escalation
```
event.code:4672                 # Special privileges assigned
process.name:psexec.exe
process.command_line:*mimikatz*
```

### 🔴 Exfiltration
```
network.bytes_sent:>10485760    # >10MB sortant
destination.port:(21 OR 22 OR 443 OR 8080) AND network.direction:outbound
NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
```

### 🔴 C2 Communication
```
destination.port:(4444 OR 1337 OR 8080 OR 8443)
destination.domain:(*ngrok* OR *duckdns*)
http.request.method:POST AND url.path:*/admin/*
```

### 🔴 Ransomware Indicators
```
process.command_line:*vssadmin*delete*shadows*
file.extension:(encrypted OR locked OR crypto)
event.code:23                   # Mass file deletion (Sysmon)
process.name:(*crypt* OR *locker*)
```

### 🔴 Reconnaissance
```
process.name:(net.exe OR nltest.exe OR whoami.exe OR systeminfo.exe)
process.name:net.exe AND process.command_line:(*user* OR *group*)
```

### 🔴 Log Tampering (CRITIQUE)
```
event.code:1102                 # Logs effacés - ALERTE MAX
event.code:104                  # System log cleared
process.command_line:(*wevtutil*cl* OR *Clear-EventLog*)
```

## IOC Hunting

```
# Hash de fichier
file.hash.md5:HASH_VALUE
file.hash.sha256:HASH_VALUE

# IP/Domaine malveillant
source.ip:MALICIOUS_IP OR destination.ip:MALICIOUS_IP
destination.domain:MALICIOUS_DOMAIN

# User-Agent suspect
user_agent.original:(*python* OR *curl* OR *scanner*)
```

## Baseline Queries

```
# Logons hors heures ouvrables
event.code:4624 AND @timestamp:[now/d+18h TO now/d+6h]

# Logons depuis IPs inhabituelles
event.code:4624 AND NOT source.ip:(LISTE_IPS_CORP)

# Comptes de service utilisés interactivement
event.code:4624 AND user.name:*svc* AND winlog.logon.type:2
```

## Agrégations Utiles

```
# Top 10 IPs sources
Terms → source.ip

# Timeline événements critiques
Date Histogram + Filters → event.code:(4625 OR 4720 OR 1102)

# Échecs auth par utilisateur
Terms → user.name + Filter → event.code:4625

# Volume par destination
Sum → network.bytes_sent, Group by → destination.ip
```

## Tips Performance & Alerting

✅ **Toujours** filtrer par timestamp en premier  
✅ Crée des alertes sur `event.code:1102` (PRIORITÉ HAUTE)  
✅ Configure seuils: >5 échecs auth en 5min = alerte  
✅ Whitelist processus/IPs légitimes pour réduire le bruit  
✅ Combine Event IDs: `event.code:(4624 AND 4672)` = admin logon  

## Corrélation Multi-Events

```
# Admin créé puis utilisé immédiatement
1. event.code:4720 AND user.name:*
2. event.code:4624 AND user.name:(même user) [dans les 5min]

# Process créé puis connexion réseau
1. event.code:1 AND process.name:X
2. event.code:3 AND process.name:X

# Service créé puis démarré
1. event.code:7045
2. event.code:7036 (service started)


