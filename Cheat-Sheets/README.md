# Forensics & Security Cheat Sheets

Quick reference guides for digital forensics and security analysis tools.

## Available Cheat Sheets

### 🧠 [Volatility Cheat Sheet](./volatility-cheatsheet.md)
Memory forensics with Volatility 3. Covers:
- Process analysis
- Network connections
- Registry extraction
- Malware detection
- Credential dumping

### 🦈 [Wireshark Cheat Sheet](./wireshark-cheatsheet.md)
Network traffic analysis with Wireshark. Includes:
- Display filters
- Protocol analysis
- Malicious traffic detection
- IOC extraction
- Command-line usage

### 🪟 [Windows Forensics Cheat Sheet](./windows-forensics-cheatsheet.md)
Windows artifact analysis and incident response. Features:
- File system artifacts
- Registry forensics
- Event log analysis
- Browser forensics
- Timeline creation

## Usage

These cheat sheets are designed for quick reference during:
- CTF challenges
- Lab exercises
- Real-world investigations
- Study sessions
- Certification prep

## Quick Command Reference

### Memory Analysis
```bash
vol.py -f memory.dmp windows.pslist
```

### Network Analysis
```bash
wireshark capture.pcap
```

### Windows Forensics
```bash
PECmd.exe -d C:\Windows\Prefetch --csv output
EvtxECmd.exe -f Security.evtx --csv output
```

## Tool Downloads

### Essential Forensic Tools

- **Eric Zimmerman Tools**: https://ericzimmerman.github.io/
- **Volatility**: https://www.volatilityfoundation.org/
- **Wireshark**: https://www.wireshark.org/
- **FTK Imager**: https://www.exterro.com/ftk-imager
- **Autopsy**: https://www.autopsy.com/

### Additional Resources

- **SANS Cheat Sheets**: https://www.sans.org/security-resources/posters
- **DFIR Training**: https://www.dfir.training/
- **13Cubed YouTube**: Excellent Windows forensics tutorials

## Contributing

These cheat sheets are continuously updated based on hands-on experience from CTF challenges and lab work. Suggestions and improvements are welcome!

---

*Last Updated: 2025*
