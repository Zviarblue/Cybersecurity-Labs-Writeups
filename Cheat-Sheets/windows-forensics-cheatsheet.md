# Windows Forensics Cheat Sheet

Quick reference for Windows digital forensics and artifact analysis.

## File System Artifacts

### Locations to Check

```
C:\Users\<username>\AppData\Local\Temp\          # Temporary files
C:\Users\<username>\Downloads\                   # Downloaded files
C:\Users\<username>\Desktop\                     # Desktop items
C:\Users\<username>\Documents\                   # User documents
C:\Users\<username>\Recent\                      # Recent files
C:\Windows\Temp\                                 # System temp files
C:\Windows\Prefetch\                             # Prefetch files
C:\$Recycle.Bin\                                 # Recycle Bin
```

### Prefetch Files

**Location:** `C:\Windows\Prefetch\`

**Analysis:**
- Shows program execution history
- Contains timestamps of last execution
- File format: `PROGRAMNAME-HASH.pf`

**Tools:**
- WinPrefetchView
- PECmd.exe (Eric Zimmerman)

```powershell
# Parse prefetch with PECmd
PECmd.exe -f "CHROME.EXE-A1B2C3D4.pf"
```

### Recent Files (LNK)

**Location:** `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`

**What it shows:**
- Recently accessed files and folders
- Original file path
- Creation and access timestamps

**Tools:**
- LECmd.exe (Eric Zimmerman)

```powershell
# Parse LNK file
LECmd.exe -f "document.lnk"
```

### Jump Lists

**Location:** `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`

**What it shows:**
- Recently accessed files per application
- Tracks user activity

**Tools:**
- JLECmd.exe (Eric Zimmerman)

```powershell
# Parse Jump List
JLECmd.exe -f "5f7b5f1e01b83767.automaticDestinations-ms"
```

### ShimCache (Application Compatibility Cache)

**Location:** Registry - `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

**What it shows:**
- Programs executed on the system
- Full path to executable
- Last modified time

**Tools:**
- AppCompatCacheParser.exe (Eric Zimmerman)

```powershell
# Parse ShimCache
AppCompatCacheParser.exe -f SYSTEM --csv output
```

### AmCache

**Location:** `C:\Windows\AppCompat\Programs\Amcache.hve`

**What it shows:**
- Detailed program execution information
- First execution time
- SHA1 hashes of executables

**Tools:**
- AmcacheParser.exe (Eric Zimmerman)

```powershell
# Parse AmCache
AmcacheParser.exe -f Amcache.hve --csv output
```

## Registry Forensics

### Important Hives

```
SAM      - C:\Windows\System32\config\SAM          # User accounts
SECURITY - C:\Windows\System32\config\SECURITY     # Security settings
SOFTWARE - C:\Windows\System32\config\SOFTWARE     # Installed software
SYSTEM   - C:\Windows\System32\config\SYSTEM       # System configuration
NTUSER.DAT - C:\Users\<username>\NTUSER.DAT        # User settings
```

### Registry Keys of Interest

#### Autorun Locations (Persistence)

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
```

#### Recent Documents

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```

#### Typed URLs (Browser History)

```
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```

#### USB Devices

```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKLM\SYSTEM\CurrentControlSet\Enum\USB
```

#### Network Information

```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
```

#### User Accounts

```
HKLM\SAM\SAM\Domains\Account\Users
```

### Registry Analysis Tools

```bash
# Registry Explorer (Eric Zimmerman)
RegistryExplorer.exe

# RegRipper
rip.exe -r NTUSER.DAT -p userassist

# Command line registry viewing
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

## Event Logs

### Important Event Log Locations

```
C:\Windows\System32\winevt\Logs\Security.evtx    # Security events
C:\Windows\System32\winevt\Logs\System.evtx      # System events
C:\Windows\System32\winevt\Logs\Application.evtx # Application events
```

### Key Event IDs

#### Security Log

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon attempt |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned to new logon |
| 4688 | New process created |
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4732 | Member added to security-enabled local group |
| 4738 | User account changed |
| 4756 | Member added to security-enabled universal group |
| 5140 | Network share object accessed |
| 4776 | Credential validation |

#### System Log

| Event ID | Description |
|----------|-------------|
| 7034 | Service crashed unexpectedly |
| 7035 | Service start/stop |
| 7036 | Service started or stopped |
| 7040 | Service startup type changed |

#### Application Log

Check for errors and warnings from specific applications.

### Event Log Analysis Tools

```bash
# Event Log Explorer
# EvtxECmd.exe (Eric Zimmerman)
EvtxECmd.exe -f Security.evtx --csv output

# PowerShell
Get-WinEvent -Path .\Security.evtx | Where-Object {$_.Id -eq 4624}
```

## Browser Forensics

### Chrome

**Profile Location:** `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\`

```
History          # Browsing history (SQLite)
Cookies          # Stored cookies (SQLite)
Login Data       # Saved passwords (encrypted)
Web Data         # Form autofill data
Downloads        # Download history
Cache\           # Cached files
```

### Firefox

**Profile Location:** `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\`

```
places.sqlite    # History and bookmarks
cookies.sqlite   # Cookies
logins.json      # Saved passwords (encrypted)
formhistory.sqlite # Form data
downloads.sqlite # Download history
cache2\          # Cached files
```

### Edge (Chromium)

**Profile Location:** `C:\Users\<username>\AppData\Local\Microsoft\Edge\User Data\Default\`

Similar structure to Chrome.

### Browser Analysis Tools

```bash
# DB Browser for SQLite (view .sqlite files)
# Hindsight (Chrome forensics)
# Nirsoft Browser Tools
```

## Timeline Analysis

### Key Timestamp Artifacts

1. **$MFT** (Master File Table) - File system activity
2. **USN Journal** - File system change log
3. **Prefetch** - Program execution
4. **Event Logs** - System/security events
5. **Registry** - System changes
6. **Browser History** - Web activity

### Timeline Creation Tools

```bash
# Log2Timeline / Plaso
log2timeline.py -z UTC timeline.plaso image.dd

# Export to CSV
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# MFTECmd (Eric Zimmerman)
MFTECmd.exe -f $MFT --csv output --csvf mft_timeline.csv
```

## Memory Analysis

### Collecting Memory

```bash
# FTK Imager
# DumpIt
# Magnet RAM Capture
# WinPmem
```

### Common Memory Artifacts

- Running processes
- Network connections
- Loaded DLLs
- Registry hives in memory
- Passwords and credentials
- Command line arguments

See Volatility cheat sheet for detailed commands.

## Network Artifacts

### Network Configuration

```
ipconfig /all                   # Current network config
arp -a                          # ARP cache
netstat -ano                    # Active connections
route print                     # Routing table
```

### DNS Cache

```powershell
ipconfig /displaydns            # View DNS cache
Get-DnsClientCache              # PowerShell equivalent
```

### Firewall Logs

```
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

## Malware Analysis Indicators

### Suspicious Locations

```
%TEMP%                          # Temporary folders
%APPDATA%                       # Application data
%LOCALAPPDATA%                  # Local app data
C:\ProgramData\                 # Hidden program data
C:\Users\Public\                # Public folder
```

### Suspicious File Names

- Random character strings (e.g., `asd98f7h.exe`)
- Legitimate system names in wrong locations (e.g., `svchost.exe` not in System32)
- Double extensions (e.g., `document.pdf.exe`)

### Persistence Mechanisms

1. **Registry Run Keys** (see Registry section)
2. **Scheduled Tasks** - `C:\Windows\System32\Tasks\`
3. **Startup Folder** - `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
4. **Services** - `sc query` or `Get-Service`
5. **WMI Event Subscriptions**

## Eric Zimmerman Tools Suite

Essential forensic tools (all free):

```
PECmd.exe           # Prefetch analysis
LECmd.exe           # LNK file analysis
JLECmd.exe          # Jump List analysis
RECmd.exe           # Registry analysis
EvtxECmd.exe        # Event Log analysis
MFTECmd.exe         # MFT analysis
AmcacheParser.exe   # AmCache analysis
AppCompatCacheParser.exe  # ShimCache
Registry Explorer   # GUI registry viewer
Timeline Explorer   # Timeline analysis
```

**Download:** https://ericzimmerman.github.io/

## Quick Investigation Checklist

### Initial Triage

- [ ] Collect system information (hostname, IP, OS version)
- [ ] Capture memory image
- [ ] Document running processes
- [ ] Check network connections
- [ ] Review recent Event Logs (last 7 days)

### User Activity

- [ ] Check Recent files (LNK)
- [ ] Review browser history
- [ ] Analyze Jump Lists
- [ ] Check typed URLs

### Execution Evidence

- [ ] Parse Prefetch files
- [ ] Review ShimCache
- [ ] Analyze AmCache
- [ ] Check scheduled tasks

### Persistence Mechanisms

- [ ] Registry Run keys
- [ ] Startup folders
- [ ] Scheduled tasks
- [ ] Services
- [ ] WMI subscriptions

### Network Activity

- [ ] Event ID 5140 (Network shares)
- [ ] DNS cache
- [ ] Firewall logs
- [ ] Browser downloads

## PowerShell One-Liners

```powershell
# List running processes
Get-Process | Select Name, Id, Path

# Check for suspicious services
Get-Service | Where-Object {$_.Status -eq "Running"} | Select Name, DisplayName

# View recent Event Logs
Get-WinEvent -LogName Security -MaxEvents 100

# List scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}

# Check autorun locations
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

# View network connections
Get-NetTCPConnection | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State

# List installed programs
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
```

---

**Resources:**
- [SANS Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis/)
- [Eric Zimmerman Tools](https://ericzimmerman.github.io/)
- [Windows Incident Response Blog](https://www.fireeye.com/blog/threat-research.html)
