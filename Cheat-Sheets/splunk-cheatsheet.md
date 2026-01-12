# Splunk Cheat Sheet

Quick reference for SOC analysts using Splunk for log analysis and threat hunting.

## Basic Search Syntax

### Used on Cyberdefenders Labs

```spl
AWSRaid
index="aws_cloudtrail" eventName="*login*" (used after GetLoginProfile)
index="aws_cloudtrail" eventSource="signin.amazonaws.com" responseElements.ConsoleLogin="Failure"
index="aws_cloudtrail" "userIdentity.userName"="_user_" eventName=GetObject | stats min(_time) as first_access_timestamp ( https://www.unixtimestamp.com/ convert the timestamp)
index="aws_cloudtrail" "userIdentity.userName"=_user_" eventName=GetObject "*dwg" (for a file)


```


### Simple Searches

```spl
index=main                          # Search all events in 'main' index
index=main error                    # Search for 'error' in main index
index=main "failed login"           # Search exact phrase
index=main source="access.log"      # Search specific source
index=main sourcetype=apache        # Search by sourcetype
index=main host="webserver01"       # Search specific host
```

### Time Ranges

```spl
earliest=-24h latest=now            # Last 24 hours
earliest=-7d latest=now             # Last 7 days
earliest="01/05/2024:00:00:00"      # Specific start time
index=main earliest=-1h@h           # Last hour (snap to hour)
```

## Search Operators

### Boolean Logic

```spl
index=main error OR fail            # Either 'error' OR 'fail'
index=main error AND critical       # Both 'error' AND 'critical'
index=main error NOT warning        # 'error' but NOT 'warning'
index=main (error OR fail) AND critical  # Combine with parentheses
```

### Wildcards

```spl
index=main fail*                    # Starts with 'fail' (fail, failed, failure)
index=main *error*                  # Contains 'error' anywhere
index=main user=admin*              # Username starts with 'admin'
```

### Field Searches

```spl
index=main status=404               # Exact match
index=main status!=200              # Not equal to 200
index=main src_ip=192.168.1.*       # IP range with wildcard
index=main user=*                   # Field exists
```

## Essential Commands

### stats - Statistical Analysis

```spl
# Count events
index=main | stats count

# Count by field
index=main | stats count by status

# Count unique values
index=main | stats dc(user) as unique_users

# Multiple statistics
index=main | stats count, avg(bytes), max(response_time) by host

# Count with condition
index=main status=404 | stats count by uri
```

**Common stats functions:**
- `count` - Count events
- `dc(field)` - Distinct count (unique values)
- `sum(field)` - Sum of values
- `avg(field)` - Average
- `min(field)` / `max(field)` - Min/Max values
- `values(field)` - List unique values
- `list(field)` - List all values

### table - Display Fields

```spl
index=main | table _time, user, action, status
index=main | table src_ip, dest_ip, bytes | head 10
```

### where - Filter Results

```spl
index=main | where status>=400              # Numerical comparison
index=main | where count > 100              # After stats
index=main | where like(user, "admin%")    # Pattern matching
index=main | where isnotnull(error_code)   # Field is not null
```

### eval - Create/Modify Fields

```spl
# Create new field
index=main | eval duration=end_time-start_time

# Conditional field
index=main | eval threat_level=if(status>=500, "high", "low")

# Case statement
index=main | eval category=case(
    status<300, "success",
    status<400, "redirect", 
    status<500, "client_error",
    status>=500, "server_error"
)

# String manipulation
index=main | eval user_upper=upper(user)
index=main | eval full_name=user." ".domain
```

### rex - Extract Fields with Regex

```spl
# Extract IP address
index=main | rex field=_raw "(?<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# Extract between patterns
index=main | rex "User: (?<username>\w+)"

# Extract multiple groups
index=main | rex "(?<method>\w+) (?<uri>/\S+) HTTP"
```

### search - Filter within Results

```spl
index=main | search status=200
index=main error | search user=admin  # Combine searches
```

### dedup - Remove Duplicates

```spl
index=main | dedup user                    # Keep first occurrence per user
index=main | dedup user, src_ip            # Deduplicate by multiple fields
index=main | dedup user sortby -_time      # Keep most recent
```

### sort - Order Results

```spl
index=main | sort -count                   # Descending order (-)
index=main | sort +_time                   # Ascending order (+)
index=main | sort -count, +user            # Multiple fields
index=main | stats count by user | sort -count | head 10  # Top 10
```

### top/rare - Quick Statistics

```spl
index=main | top user                      # Top users
index=main | top src_ip limit=20           # Top 20 IPs
index=main | rare dest_port                # Least common ports
index=main | top user by host              # Top users per host
```

### timechart - Time-Based Statistics

```spl
index=main | timechart count               # Events over time
index=main | timechart count by status     # Multiple series
index=main | timechart span=1h count       # 1-hour buckets
index=main | timechart avg(response_time)  # Average over time
```

### chart - Multi-Dimensional Statistics

```spl
index=main | chart count by status, host   # 2D table
index=main | chart avg(bytes) over user by action
```

### transaction - Group Related Events

```spl
# Group by session ID
index=main | transaction session_id maxspan=30m

# Group by user with time constraint
index=main | transaction user maxpause=5m startswith="login" endswith="logout"
```

## Field Extraction & Manipulation

### fields - Select/Remove Fields

```spl
index=main | fields user, action, status   # Keep only these fields
index=main | fields - _raw, _time          # Remove these fields
```

### rename - Rename Fields

```spl
index=main | rename user AS username
index=main | rename src_ip AS source_ip, dest_ip AS destination_ip
```

### fillnull - Handle Missing Values

```spl
index=main | fillnull value="unknown" user
index=main | fillnull value=0 failed_attempts
```

## Advanced Analysis

### Subsearches

```spl
# Find events matching subsearch results
index=main [search index=threats | fields malicious_ip | rename malicious_ip as src_ip]

# Count events where user appears in both indexes
index=main user=[search index=suspicious | return 1000 user]
```

### join - Combine Data

```spl
index=main sourcetype=access 
| join user [search index=main sourcetype=auth | stats count by user]
```

### append - Combine Results

```spl
index=main error | append [search index=main critical]
```

### lookup - Enrich Data

```spl
index=main | lookup threat_intel_csv ip as src_ip OUTPUT threat_level, category
```

## Security Use Cases

### Failed Login Analysis

```spl
# Count failed logins by user
index=security EventCode=4625 
| stats count by user 
| where count > 5
| sort -count

# Failed logins over time
index=security EventCode=4625 
| timechart span=1h count by user

# Brute force detection
index=security EventCode=4625 
| stats count, dc(src_ip) as ip_count by user 
| where count > 10 AND ip_count > 1
```

### Suspicious Network Activity

```spl
# High volume data transfers
index=firewall 
| stats sum(bytes_out) as total_bytes by src_ip 
| where total_bytes > 1000000000
| sort -total_bytes

# Uncommon ports
index=firewall 
| rare dest_port limit=20
| where count > 100

# External connections from internal hosts
index=firewall src_ip=10.* NOT dest_ip=10.* 
| stats count by src_ip, dest_ip, dest_port
| sort -count
```

### User Behavior Analysis

```spl
# User activity timeline
index=windows user=* 
| table _time, user, EventCode, action, src_ip
| sort _time

# Users with multiple failed then successful login
index=security 
| transaction user maxspan=5m 
| search EventCode=4625 EventCode=4624
| table user, duration, EventCount

# Accounts created
index=security EventCode=4720 
| table _time, user, TargetUserName, src_ip
```

### Malware Indicators

```spl
# Process execution from temp directories
index=sysmon EventCode=1 
| search Image="*\\Temp\\*" OR Image="*\\AppData\\*"
| stats count by Image, CommandLine, user

# Suspicious PowerShell commands
index=powershell 
| search CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"
| table _time, user, CommandLine

# Outbound connections to rare domains
index=proxy 
| rare url limit=50
| where count < 10
```

### Privilege Escalation

```spl
# Special privileges assigned
index=security EventCode=4672 
| stats count by user, PrivilegeList
| sort -count

# User added to admin group
index=security EventCode=4732 TargetUserName="Administrators"
| table _time, SubjectUserName, MemberName

# Service installations
index=security EventCode=7045 
| table _time, ServiceName, ServiceFileName, user
```

## Performance Optimization

### Best Practices

```spl
# ✅ GOOD - Be specific with index and time
index=main earliest=-1h sourcetype=apache status=404

# ❌ BAD - Too broad
index=* 

# ✅ GOOD - Filter early
index=main status=404 | stats count by uri

# ❌ BAD - Filter late
index=main | stats count by uri | where status=404

# ✅ GOOD - Use stats instead of transaction when possible
index=main | stats count by session_id

# ❌ BAD - Transaction is resource-intensive
index=main | transaction session_id
```

### Search Optimization Tips

1. **Be specific**: Use index, sourcetype, time range
2. **Filter first**: Apply filters before pipes
3. **Limit results**: Use `head` or time constraints
4. **Avoid wildcards at start**: `*error` is slower than `error*`
5. **Use `tstats`**: For indexed fields (faster than stats)

```spl
# Fast - uses indexed fields
| tstats count where index=main by host

# Slower - searches raw events
index=main | stats count by host
```

## Common Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4697 | Service installed |
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4732 | User added to security-enabled local group |
| 4756 | User added to security-enabled universal group |
| 5140 | Network share accessed |
| 7045 | Service installed (System log) |

## Quick Reference

### Find unique values
```spl
index=main | stats values(user)
index=main | stats dc(user)  # Count unique
```

### Count occurrences
```spl
index=main | stats count by user
index=main | top user
```

### Time-based analysis
```spl
index=main | timechart count
index=main | bin _time span=1h | stats count by _time
```

### Filter and sort
```spl
index=main | where count > 100 | sort -count
```

### Create alerts
```spl
index=security EventCode=4625 
| stats count by user 
| where count > 10
```

## Pro Tips for Labs

1. **Start broad, then narrow**: Begin with `index=main` then add filters
2. **Use table for exploration**: `| table *` to see all fields
3. **Check field names**: Click on interesting fields in left sidebar
4. **Use head for testing**: `| head 10` to limit results while building query
5. **Format time properly**: Use `| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")`
6. **Save useful queries**: Use Splunk's "Save As" feature

## Common Lab Patterns

### "How many times did X occur?"
```spl
index=main <search terms> | stats count
```

### "What are the top N of X?"
```spl
index=main | top limit=N <field>
```

### "Show me all events with X"
```spl
index=main <search terms> | table _time, field1, field2
```

### "What happened between time A and B?"
```spl
index=main earliest="MM/DD/YYYY:HH:MM:SS" latest="MM/DD/YYYY:HH:MM:SS"
```

### "Find rare/unusual events"
```spl
index=main | rare <field> limit=10
```

---

**Resources:**
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
- [Splunk Quick Reference Guide](https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf)
- [Boss of the SOC Dataset](https://github.com/splunk/botsv3) - Practice dataset
