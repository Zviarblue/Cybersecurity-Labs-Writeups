#!/usr/bin/env python3
"""
Windows Event Log Security Parser
Author: Zviar
Description: Parse Windows Security Event Logs for suspicious activity
Usage: python evtx_security_parser.py -i Security.evtx -o output.json
"""

import argparse
import json
from datetime import datetime
from collections import Counter

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
except ImportError:
    print("[!] Please install python-evtx: pip install python-evtx")
    exit(1)

# Suspicious Event IDs to monitor
SUSPICIOUS_EVENTS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon with Explicit Credentials",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4720: "User Account Created",
    4732: "Member Added to Security-Enabled Local Group",
    4738: "User Account Changed",
    4756: "Member Added to Security-Enabled Universal Group",
    5140: "Network Share Object Accessed",
    4776: "Credential Validation Attempt"
}

def parse_evtx(file_path):
    """Parse EVTX file and extract relevant security events"""
    print(f"[*] Parsing {file_path}...")
    
    events = []
    event_counts = Counter()
    
    try:
        with Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    event_id = record.event_id()
                    timestamp = record.timestamp()
                    
                    # Count all events
                    event_counts[event_id] += 1
                    
                    # Extract suspicious events
                    if event_id in SUSPICIOUS_EVENTS:
                        event_data = {
                            'event_id': event_id,
                            'description': SUSPICIOUS_EVENTS[event_id],
                            'timestamp': str(timestamp),
                            'xml': xml
                        }
                        events.append(event_data)
                        
                except Exception as e:
                    continue
                    
    except Exception as e:
        print(f"[!] Error parsing file: {e}")
        return None, None
    
    return events, event_counts

def analyze_logon_events(events):
    """Analyze logon patterns for anomalies"""
    print("\n[*] Analyzing logon patterns...")
    
    failed_logons = [e for e in events if e['event_id'] == 4625]
    successful_logons = [e for e in events if e['event_id'] == 4624]
    
    print(f"    Total Successful Logons: {len(successful_logons)}")
    print(f"    Total Failed Logons: {len(failed_logons)}")
    
    if len(failed_logons) > 10:
        print(f"    [!] WARNING: High number of failed logons detected!")
    
    return {
        'successful': len(successful_logons),
        'failed': len(failed_logons)
    }

def analyze_privilege_escalation(events):
    """Detect potential privilege escalation"""
    print("\n[*] Checking for privilege escalation indicators...")
    
    special_privs = [e for e in events if e['event_id'] == 4672]
    account_changes = [e for e in events if e['event_id'] in [4720, 4738]]
    group_additions = [e for e in events if e['event_id'] in [4732, 4756]]
    
    suspicious = []
    
    if special_privs:
        print(f"    [!] {len(special_privs)} special privilege assignments detected")
        suspicious.extend(special_privs)
    
    if account_changes:
        print(f"    [!] {len(account_changes)} account modifications detected")
        suspicious.extend(account_changes)
        
    if group_additions:
        print(f"    [!] {len(group_additions)} group membership changes detected")
        suspicious.extend(group_additions)
    
    return suspicious

def generate_report(events, event_counts, analysis, output_file):
    """Generate JSON report of findings"""
    print(f"\n[*] Generating report: {output_file}")
    
    report = {
        'analysis_date': str(datetime.now()),
        'total_events': sum(event_counts.values()),
        'suspicious_events_count': len(events),
        'event_id_distribution': dict(event_counts.most_common(20)),
        'logon_analysis': analysis['logons'],
        'privilege_escalation_indicators': len(analysis['privilege_esc']),
        'suspicious_events': events[:100]  # Limit to first 100 for report size
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"[+] Report saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Parse Windows Security Event Logs for suspicious activity'
    )
    parser.add_argument('-i', '--input', required=True, help='Input EVTX file')
    parser.add_argument('-o', '--output', default='analysis_report.json', 
                       help='Output JSON file (default: analysis_report.json)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Windows Security Event Log Analyzer")
    print("=" * 60)
    
    # Parse events
    events, event_counts = parse_evtx(args.input)
    
    if not events:
        print("[!] No suspicious events found or error parsing file")
        return
    
    print(f"[+] Found {len(events)} suspicious events")
    
    # Analyze patterns
    analysis = {
        'logons': analyze_logon_events(events),
        'privilege_esc': analyze_privilege_escalation(events)
    }
    
    # Generate report
    generate_report(events, event_counts, analysis, args.output)
    
    print("\n" + "=" * 60)
    print("[+] Analysis Complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
