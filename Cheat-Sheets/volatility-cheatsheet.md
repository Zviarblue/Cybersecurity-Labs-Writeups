# Volatility Cheat Sheet

Quick reference for memory forensics using Volatility 3.

## Basic Usage

### Volatility 3
```bash
vol.py -f memory.dmp <plugin>
```

## Image Identification

### Check OS Info (Vol 3)
```bash
vol.py -f memory.dmp windows.info
vol.py -f memory.dmp banners.Banners
```

## Process Analysis

### List Processes
```bash
# Vol 3
vol.py -f memory.dmp windows.pslist
vol.py -f memory.dmp windows.pstree
vol.py -f memory.dmp windows.psscan
```

### Process Details
```bash
# Vol 3
vol.py -f memory.dmp windows.dumpfiles --pid <PID>
vol.py -f memory.dmp windows.memmap --pid <PID> --dump
```

### Command Line Arguments
```bash
# Vol 3
vol.py -f memory.dmp windows.cmdline
```

## Network Analysis

### Network Connections
```bash
# Vol 3
vol.py -f memory.dmp windows.netscan
vol.py -f memory.dmp windows.netstat
```

## DLL & Handles

### List DLLs
```bash
# Vol 3
vol.py -f memory.dmp windows.dlllist --pid <PID>
```

### Handles
```bash
# Vol 3
vol.py -f memory.dmp windows.handles --pid <PID>
```

## Registry Analysis

### Hive List
```bash
# Vol 3
vol.py -f memory.dmp windows.registry.hivelist
```

### Print Registry Key
```bash
# Vol 3
vol.py -f memory.dmp windows.registry.printkey --key "Microsoft\Windows\CurrentVersion\Run"

vol.py -f memory.dmp windows.registry.printkey --key "ControlSet001\Control\ComputerName\ComputerName" // to get the computerName (used on rootme)
```

### UserAssist (Recent Programs)
```bash
# Vol 3
vol.py -f memory.dmp windows.registry.userassist
```

## Malware Detection

### Detect Code Injection
```bash
# Vol 3
vol.py -f memory.dmp windows.malfind
```

### Scan for Hooks
```bash
# Vol 3
vol.py -f memory.dmp windows.ssdt
```

### Detect Rootkits
```bash
# Vol 3
vol.py -f memory.dmp windows.driverscan
```

## File Extraction

### Dump Files from Memory
```bash
# Vol 3
vol.py -f memory.dmp windows.filescan
vol.py -f memory.dmp windows.dumpfiles --virtaddr 0x...
```

### Extract Cached Files
```bash
# Vol 3
vol.py -f memory.dmp windows.dumpfiles --physaddr 0x...
```

## Credential Extraction

### Dump Hashes (Mimikatz)
```bash
# Vol 3
vol.py -f memory.dmp windows.hashdump
vol.py -f memory.dmp windows.lsadump
```

## Timeline Analysis

### Timeline Creation
```bash
# Vol 3
vol.py -f memory.dmp windows.timeliner
```

## Useful Plugins for Malware Analysis

| Plugin | Purpose |
|--------|---------|
| `malfind` | Find hidden/injected code |
| `psxview` | Cross-reference process listings |
| `ldrmodules` | Detect unlinked DLLs |
| `modscan` | Scan for kernel modules |
| `svcscan` | List Windows services |
| `mutantscan` | List mutex objects |

## Pro Tips

1. **Always start with imageinfo/kdbgscan** to identify the correct profile
2. **Use pstree** to understand process relationships
3. **Check cmdline** for process arguments (often reveals malicious commands)
4. **Combine netscan + pslist** to correlate network activity with processes
5. **Use malfind** to detect injected code in legitimate processes
6. **Check registry Run keys** for persistence mechanisms
7. **Extract suspicious processes** with procdump for further analysis

## Common Indicators of Compromise

- Processes with no parent (PPID = 0 or orphaned)
- Processes running from unusual locations (Temp, AppData)
- Svchost.exe not running from System32
- Multiple instances of explorer.exe
- Unsigned DLLs in system processes
- Hidden processes (visible in psscan but not pslist)
- Suspicious network connections from unexpected processes

## Output Options

```bash
# Save output to file
--output=text --output-file=results.txt
--output=json --output-file=results.json
--output=html --output-file=results.html

# Vol 3
-o output_dir/ --output-dir
```

---

**Resources:**
- [Volatility Documentation](https://volatility3.readthedocs.io/)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- [SANS Volatility Cheat Sheet](https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf)
