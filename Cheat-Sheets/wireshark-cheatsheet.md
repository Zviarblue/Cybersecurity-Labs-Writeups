# Wireshark Cheat Sheet

Quick reference for network traffic analysis with Wireshark.

## Display Filters

### Basic Filtering

```
ip.addr == 192.168.1.1          # Traffic to/from specific IP
ip.src == 192.168.1.1           # Traffic from source IP
ip.dst == 192.168.1.1           # Traffic to destination IP
tcp.port == 80                  # Traffic on TCP port 80
udp.port == 53                  # Traffic on UDP port 53
```

### Protocol Filtering

```
http                            # HTTP traffic only
https || tls || ssl             # HTTPS/TLS/SSL traffic
dns                             # DNS queries and responses
ftp                             # FTP traffic
smtp                            # Email (SMTP) traffic
ssh                             # SSH traffic
rdp                             # Remote Desktop Protocol
smb || smb2                     # SMB file sharing
icmp                            # ICMP (ping) traffic
arp                             # ARP requests/responses
```

### Combining Filters

```
ip.addr == 192.168.1.1 && tcp.port == 80
http && ip.src == 10.0.0.5
!(arp || icmp)                  # Exclude ARP and ICMP
tcp.port == 443 || tcp.port == 80
```

## HTTP/HTTPS Analysis

### HTTP Specific Filters

```
http.request                    # All HTTP requests
http.response                   # All HTTP responses
http.request.method == "GET"    # GET requests only
http.request.method == "POST"   # POST requests only
http.response.code == 200       # Successful responses
http.response.code == 404       # Not found errors
http.host contains "google"     # Requests to hosts containing "google"
http.user_agent contains "curl" # Specific user agents
```

### Extract HTTP Objects

1. File → Export Objects → HTTP
2. Select files to save
3. Analyze downloaded content

### Follow HTTP Stream

Right-click packet → Follow → HTTP Stream (or Ctrl+Alt+Shift+H)

## Malicious Traffic Detection

### Suspicious Patterns

```
http.request.uri contains ".exe"           # Downloading executables
http.request.uri contains "cmd"            # Command injection attempts
http.request.uri contains "../"            # Path traversal attempts
http contains "password"                   # Cleartext passwords
http.cookie contains "admin"               # Cookie manipulation
dns.qry.name contains ".top"               # Suspicious TLDs
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN scan detection
http contains "cmd="                       # Command injection attempts (used on Cyberdefenders labs JetBrains)
tcp.flags == 0x012                         # SYN-ACK packets (Tomcat labs)
```

### C2 Communication Indicators

```
http.request.uri matches "^/[a-z]{8}$"     # Beacon-like patterns
dns.qry.name matches "^[a-z0-9]{20,}\.com" # DGA domains
tls.handshake.extensions_server_name contains "pastebin"
```

## DNS Analysis

### DNS Filters

```
dns.qry.name == "example.com"   # Specific domain query
dns.flags.response == 1         # DNS responses only
dns.flags.rcode != 0            # DNS errors (NXDOMAIN, etc.)
dns.qry.type == 1               # A record queries
dns.qry.type == 28              # AAAA record queries
dns.qry.type == 15              # MX record queries
```

### Detect DNS Tunneling

```
dns && frame.len > 512          # Unusually large DNS packets
dns.qry.name.len > 50           # Long domain names (potential tunneling)
```

## TCP Analysis

### TCP Flags

```
tcp.flags.syn == 1              # SYN packets
tcp.flags.rst == 1              # RST packets
tcp.flags.fin == 1              # FIN packets
tcp.flags.ack == 1              # ACK packets
tcp.flags.push == 1             # PUSH packets
```

### Connection Analysis

```
tcp.analysis.retransmission     # Retransmitted packets
tcp.analysis.lost_segment       # Lost segments
tcp.analysis.duplicate_ack      # Duplicate ACKs
tcp.stream eq 1                 # All packets in TCP stream #1
```

### Follow TCP Stream

Right-click packet → Follow → TCP Stream (or Ctrl+Alt+Shift+T)

## TLS/SSL Analysis

### TLS Filters

```
tls.handshake.type == 1         # Client Hello
tls.handshake.type == 2         # Server Hello
tls.handshake.extensions_server_name  # SNI (Server Name Indication)
ssl.record.content_type == 23   # Application Data
```

### Certificate Analysis

```
tls.handshake.certificate       # Certificate packets
x509ce.dNSName                  # Certificate domain names
```

## File Transfers

### Detect File Downloads

```
http.content_type contains "application/octet-stream"
http.content_type contains "application/x-msdownload"
ftp-data                        # FTP data transfers
```

### Extract Files

1. File → Export Objects → HTTP/SMB/FTP
2. Select the file
3. Save to disk

## Credential Hunting

### Cleartext Credentials

```
http.authbasic                  # HTTP Basic Auth
ftp.request.command == "PASS"   # FTP passwords
smtp.req.command == "AUTH"      # SMTP authentication
telnet contains "Password:"     # Telnet passwords
```

### Common Credential Patterns

```
http contains "password"
http contains "username"
http.request.uri contains "login"
```

## Statistics & Analysis

### Useful Statistics

- Statistics → Protocol Hierarchy (Overview of all protocols)
- Statistics → Conversations (Top talkers)
- Statistics → Endpoints (Active endpoints)
- Statistics → IO Graphs (Traffic over time)
- Statistics → HTTP → Requests (HTTP request summary)

### Expert Info

Analyze → Expert Information (Shows warnings, errors, notes)

## Time & Packet Analysis

### Time-based Filters

```
frame.time >= "2024-01-01 00:00:00"
frame.time_delta > 5            # Packets with >5 second gap
```

### Packet Size

```
frame.len > 1000                # Large packets
frame.len < 64                  # Small packets
```

## Common Attack Patterns

### Port Scans

```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024
```

### ARP Spoofing

```
arp.duplicate-address-detected || arp.duplicate-address-frame
```

### ICMP Tunneling

```
icmp && data.len > 64
```

### SQL Injection Attempts

```
http.request.uri contains "union select"
http.request.uri contains "1=1"
http.request.uri contains "or 1=1"
```

## Regular Expressions

Wireshark supports regex matching:

```
http.host matches ".*\.ru$"     # Domains ending in .ru
dns.qry.name matches "^[0-9]+\." # Domains starting with numbers
```

## Command Line (tshark)

### Basic Usage

```bash
# Capture live traffic
tshark -i eth0

# Read from file
tshark -r capture.pcap

# Apply display filter
tshark -r capture.pcap -Y "http"

# Export specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e http.host
```

### Useful tshark Commands

```bash
# Extract HTTP hosts
tshark -r capture.pcap -Y "http.request" -T fields -e http.host | sort -u

# Count packets per IP
tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn

# Extract DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u

# Statistics
tshark -r capture.pcap -q -z io,phs
```

## Pro Tips

1. **Use display filters, not capture filters** for analysis
2. **Right-click is your friend** - most useful features are there
3. **Follow streams** to see full conversations
4. **Color rules** help spot anomalies quickly (View → Coloring Rules)
5. **Export objects** to analyze files transferred
6. **Use time display format** that suits your analysis (View → Time Display Format)
7. **Save your display filters** for reuse (Bookmarks)
8. **Use profiles** for different analysis scenarios
9. **Check Expert Info** for quick anomaly detection
10. **Combine with tshark** for automated analysis

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+F | Find packet |
| Ctrl+G | Go to packet |
| Ctrl+E | Export packets |
| Ctrl+Shift+P | Print |
| Ctrl+/ | Display filter |
| Alt+← | Go back |
| Alt+→ | Go forward |

## Quick IOC Extraction

```bash
# Extract all IPs
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort -u

# Extract all domains
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u

# Extract all User-Agents
tshark -r capture.pcap -Y "http.user_agent" -T fields -e http.user_agent | sort -u

# Extract all URIs
tshark -r capture.pcap -Y "http.request.uri" -T fields -e http.request.uri
```

---

**Resources:**
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark Wiki](https://wiki.wireshark.org/)
