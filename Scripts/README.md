# Forensics & SOC Automation Scripts

Collection of Python scripts for automating common forensic analysis and SOC tasks.

## Categories

### Log Analysis
Scripts for parsing and analyzing various log formats:
- Windows Event Logs
- Sysmon logs
- Web server logs
- Network device logs

### Artifact Extraction
Tools for extracting forensic artifacts:
- Browser history extraction
- Prefetch file analysis
- Registry key extraction
- Timeline generation

## Requirements

Most scripts require Python 3.8+ and common libraries:
```bash
pip install -r requirements.txt
```

Common dependencies:
- `python-evtx` - Windows Event Log parsing
- `argparse` - Command-line argument handling
- `json` - JSON data handling
- `csv` - CSV file operations
- `datetime` - Timestamp manipulation

## Usage

Each script includes:
- Help documentation (`-h` or `--help`)
- Example usage in comments
- Error handling
- Output formatting options

### Basic Example
```bash
python script_name.py -i input_file -o output_file
```

## Script Categories

### 1. Log Analysis
Parse and analyze log files to identify suspicious activities.

### 2. IOC Extraction
Extract Indicators of Compromise from various sources.

### 3. Timeline Analysis
Generate timelines from multiple artifact sources.

### 4. Report Generation
Automate forensic report creation.

## Best Practices

- Always test scripts on sample data first
- Preserve original evidence (work on copies)
- Document your analysis process
- Validate output for accuracy
- Handle errors gracefully

## Contributing

These scripts are continually improved based on real-world use cases encountered during CTF challenges and lab exercises.

---

**Note**: These scripts are for educational and authorized investigation purposes only.
