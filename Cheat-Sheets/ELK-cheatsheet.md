# ELK Stack Cheatsheet - SOC/DFIR

> Quick cheatsheet for log analysis with ELK Stack  
> **Context**: CyberDefenders Labs, SOC L1, Threat Hunting

---

## Kibana Query Language (KQL)

### Quick Syntax

```kql
# Simple search
user.name: "admin"
event.code: 4624

# Wildcards
process.name: cmd*
file.path: *\temp\*

# Multiple values
event.code: (4624 OR 4625 OR 4672)

# Logic
user.name: "admin" AND event.action: "logon"
NOT status: 200

# Ranges
bytes: [1000 TO 5000]
@timestamp: [now-1h TO now]

# Existence
_exists_: file.hash.sha256
NOT _exists_: user.name
```

---

## Windows Detections

### Authentication

```kql
# Logons
event.code: 4624                                    # Success
event.code: 4624 AND winlog.event_data.LogonType: 10  # RDP
event.code: 4625                                    # Failed
event.code: 4672                                    # Privilege escalation

# Account management
event.code: 4720    # Account created
event.code: 4732    # Member added to group
```

### Suspicious Processes

```kql
# Creation
event.code: 4688
event.code: 7045    # Service
event.code: 4698    # Scheduled task

# Malicious PowerShell
process.command_line: (*-enc* OR *-encodedcommand*)
process.command_line: (*downloadstring* OR *iwr*)
process.command_line: (*-nop* OR *-w hidden* OR *-ep bypass*)
process.command_line: *iex*

# LOLBins
process.name: (certutil.exe OR bitsadmin.exe OR regsvr32.exe OR rundll32.exe)

# Scripts
process.name: (wscript.exe OR cscript.exe OR mshta.exe)
```

### Persistence

```kql
# Registry Run keys
event.code: 13 AND registry.path: (*\Run OR *\RunOnce*)

# Suspicious services
event.code: 7045 AND service.binary_path: (*\temp\* OR *\appdata\*)

# Scheduled tasks
event.code: 4698
```

---

## Network Detections

```kql
# Suspicious outbound connections
destination.port: (4444 OR 1337 OR 8080) AND network.direction: outbound

# External IPs
NOT destination.ip: (10.* OR 172.16.* OR 192.168.*)

# Large volumes (exfiltration)
bytes > 10000000 AND network.direction: outbound

# Suspicious DNS
dns.question.name: (*pastebin* OR *ngrok* OR *duckdns*)
```

---

## Web Detections

```kql
# Error codes
http.response.status_code: [400 TO 599]

# Web exploitation
url.path: (*admin* OR *wp-admin* OR *cmd=* OR *exec=*)

# SQL Injection
url.query: (*union* OR *select* OR *1=1*)

# Suspicious user-agents
user_agent.original: (*sqlmap* OR *nikto* OR *nmap*)
```

---

## Elasticsearch Query DSL

### Basic Search

```json
GET /logs-*/_search
{
  "query": {
    "match": { "event.code": "4624" }
  }
}
```

### Boolean Query

```json
GET /logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "process.name": "powershell.exe" }}
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-1h" }}}
      ],
      "must_not": [
        { "term": { "user.name.keyword": "SYSTEM" }}
      ]
    }
  }
}
```

### Wildcard

```json
GET /logs-*/_search
{
  "query": {
    "wildcard": {
      "file.path": "*\\temp\\*.exe"
    }
  }
}
```

---

## Aggregations

### Top N

```json
GET /logs-*/_search
{
  "size": 0,
  "aggs": {
    "top_processes": {
      "terms": {
        "field": "process.name.keyword",
        "size": 20
      }
    }
  }
}
```

### Timeline

```json
GET /logs-*/_search
{
  "size": 0,
  "aggs": {
    "events_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "1h"
      }
    }
  }
}
```

### Nested

```json
GET /logs-*/_search
{
  "size": 0,
  "aggs": {
    "by_user": {
      "terms": { "field": "user.name.keyword" },
      "aggs": {
        "by_action": {
          "terms": { "field": "event.action.keyword" }
        }
      }
    }
  }
}
```

---

## Detection Patterns

### Brute Force

```kql
event.code: 4625 AND source.ip: *
```
→ Group by `source.ip`, look for >10 in 5min

### Lateral Movement

```kql
event.code: 4624 AND winlog.event_data.LogonType: 3 
AND NOT user.name: (*$)
```

### Credential Dumping

```kql
process.name: (lsass.exe OR mimikatz.exe)
process.command_line: (*sekurlsa* OR *lsadump*)
event.code: 4656 AND object.name: *lsass.exe*
```

### C2 Beaconing

```kql
destination.ip: * AND network.direction: outbound
```
→ Timeline to detect regular communications

### Exfiltration

```kql
bytes > 10000000 AND network.direction: outbound
destination.hostname: (*mega.nz* OR *dropbox* OR *wetransfer*)
```

---

## Essential Fields

| Category | Key Fields |
|----------|------------|
| **Time** | `@timestamp` |
| **Network** | `source.ip`, `destination.ip`, `destination.port` |
| **User** | `user.name`, `user.domain` |
| **Process** | `process.name`, `process.command_line`, `process.parent.name` |
| **Files** | `file.name`, `file.path`, `file.hash.sha256` |
| **Events** | `event.code`, `event.action`, `event.category` |
| **Host** | `host.name`, `host.ip` |

---

## Quick Methodology

1. **Global timeline** → Identify activity spikes
2. **Zoom in** → On suspicious periods
3. **Filter** → By event.code, user, IP, process
4. **Correlate** → Same user/IP/hash across multiple events
5. **Document** → Attack timeline (MITRE ATT&CK)

---

## CyberDefenders Tips

✅ **Do**
- Always limit time: `@timestamp: [now-24h TO now]`
- Use `.keyword` for aggregations
- Save important queries
- Create dashboards per use case
- Export to CSV for external analysis

❌ **Don't**
- Use regex on large volumes (slow)
- Query without time filter
- Forget `.keyword` fields

---

## Critical Windows Event IDs

| Event ID | Description |
|----------|-------------|
| **4624** | Successful logon |
| **4625** | Failed logon |
| **4672** | Special privileges assigned |
| **4688** | Process creation |
| **4720** | Account created |
| **4732** | Member added to group |
| **7045** | Service installed |
| **4698** | Scheduled task created |
| **4663** | Object access attempt |
| **4656** | Handle to object requested |

---

## Resources

- [Elastic Query DSL](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)
- [KQL Syntax](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Elastic Security Rules](https://github.com/elastic/detection-rules)

---

**Version**: 1.0 | **Last update**: January 2026
