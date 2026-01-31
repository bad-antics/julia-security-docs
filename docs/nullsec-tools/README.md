# NullSec Tools Documentation

> **Professional Security Toolkit - Multi-Language Tools for Penetration Testing**

NullSec Tools is a comprehensive collection of security utilities written in Python, Go, Rust, C, Node.js, and more. Designed for penetration testers, security researchers, and red teams.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      NULLSEC TOOLS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Tool Categories                        │   │
│  ├──────────┬──────────┬──────────┬──────────┬────────────┤   │
│  │ Recon    │ Exploit  │ Post-Exp │ Cracking │ OSINT      │   │
│  │ Network  │ Web      │ Priv Esc │ Forensic │ Reporting  │   │
│  └──────────┴──────────┴──────────┴──────────┴────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Languages                              │   │
│  │  Python │ Go │ Rust │ C │ Node.js │ Bash │ PowerShell  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Integration                            │   │
│  │  NullSec Linux │ Julia Suite │ Marshall │ BlackFlag     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Tool Categories

### 🔍 Reconnaissance

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-scan` | Go | Fast network scanner |
| `nullsec-enum` | Python | Service enumeration |
| `nullsec-dns` | Rust | DNS reconnaissance |
| `nullsec-subdomain` | Go | Subdomain discovery |
| `nullsec-whois` | Python | WHOIS lookup |
| `nullsec-crawl` | Node.js | Web crawler |

### 🌐 Web Security

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-sqli` | Python | SQL injection tester |
| `nullsec-xss` | Node.js | XSS scanner |
| `nullsec-fuzz` | Rust | Web fuzzer |
| `nullsec-dir` | Go | Directory brute force |
| `nullsec-param` | Python | Parameter discovery |
| `nullsec-cors` | Node.js | CORS misconfiguration |

### 🔐 Password Attacks

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-crack` | C | Password cracker |
| `nullsec-hash` | Rust | Hash identifier/cracker |
| `nullsec-brute` | Go | Login brute forcer |
| `nullsec-spray` | Python | Password spraying |
| `nullsec-gen` | Rust | Wordlist generator |

### 📡 Network

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-sniff` | C | Packet sniffer |
| `nullsec-mitm` | Go | MITM proxy |
| `nullsec-arp` | C | ARP spoofing |
| `nullsec-tunnel` | Rust | Traffic tunneling |
| `nullsec-proxy` | Go | SOCKS/HTTP proxy |

### 🎯 Exploitation

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-exploit` | Python | Exploit framework |
| `nullsec-payload` | Rust | Payload generator |
| `nullsec-shell` | C | Reverse shell handler |
| `nullsec-inject` | C | Process injection |
| `nullsec-buffer` | Python | Buffer overflow helper |

### 🔒 Post-Exploitation

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-priv` | Go | Privilege escalation |
| `nullsec-persist` | Python | Persistence techniques |
| `nullsec-exfil` | Rust | Data exfiltration |
| `nullsec-creds` | C | Credential harvesting |
| `nullsec-lateral` | Go | Lateral movement |

### 🕵️ OSINT

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-social` | Python | Social media OSINT |
| `nullsec-email` | Go | Email reconnaissance |
| `nullsec-phone` | Python | Phone number lookup |
| `nullsec-domain` | Rust | Domain intelligence |
| `nullsec-person` | Python | Person search |

### 🔬 Forensics

| Tool | Language | Description |
|------|----------|-------------|
| `nullsec-mem` | C | Memory forensics |
| `nullsec-disk` | Rust | Disk analysis |
| `nullsec-log` | Go | Log analysis |
| `nullsec-timeline` | Python | Timeline creation |
| `nullsec-artifact` | Rust | Artifact extraction |

## Installation

### Full Suite

```bash
# Clone repository
git clone https://github.com/bad-antics/nullsec-tools
cd nullsec-tools

# Install all tools
./install.sh --all

# Install by category
./install.sh --category recon
./install.sh --category web
./install.sh --category network

# Install by language
./install.sh --lang python
./install.sh --lang go
./install.sh --lang rust
```

### Individual Tools

```bash
# Python tools
pip install nullsec-scan nullsec-enum nullsec-sqli

# Go tools
go install github.com/bad-antics/nullsec-tools/cmd/nullsec-scan@latest

# Rust tools
cargo install nullsec-fuzz nullsec-hash
```

### NullSec Linux

Pre-installed in NullSec Linux:

```bash
# All tools available in PATH
nullsec-scan --help
nullsec-enum --help

# Access via menu
nullsec-menu
```

## Quick Start

### Network Scanning

```bash
# Quick scan
nullsec-scan 192.168.1.0/24

# Full port scan
nullsec-scan 192.168.1.100 -p 1-65535

# Service detection
nullsec-scan 192.168.1.100 -sV

# OS detection
nullsec-scan 192.168.1.100 -O

# Output to JSON
nullsec-scan 192.168.1.0/24 -o json > results.json
```

### Web Enumeration

```bash
# Directory brute force
nullsec-dir http://target.com -w /usr/share/wordlists/dirb/common.txt

# Parameter discovery
nullsec-param http://target.com/search

# SQL injection test
nullsec-sqli http://target.com/page?id=1

# XSS scan
nullsec-xss http://target.com/search?q=test

# Full web audit
nullsec-web-audit http://target.com --full
```

### Password Attacks

```bash
# Identify hash
nullsec-hash identify '5f4dcc3b5aa765d61d8327deb882cf99'

# Crack hash
nullsec-crack -m 0 -a 0 hash.txt wordlist.txt

# Brute force login
nullsec-brute -t ssh -H 192.168.1.100 -u admin -w passwords.txt

# Password spray
nullsec-spray -t smb -H targets.txt -u users.txt -p 'Summer2024!'
```

### OSINT

```bash
# Domain reconnaissance
nullsec-domain example.com

# Email lookup
nullsec-email john@example.com

# Social media search
nullsec-social -n "John Doe" -p linkedin,twitter,facebook

# Full OSINT report
nullsec-osint --target company.com --deep
```

## Tool Details

### nullsec-scan (Go)

High-performance network scanner:

```go
package main

import "github.com/bad-antics/nullsec-tools/scan"

func main() {
    scanner := scan.New(scan.Config{
        Targets:    []string{"192.168.1.0/24"},
        Ports:      scan.TopPorts(1000),
        Threads:    100,
        Timeout:    5 * time.Second,
        ServiceDetection: true,
    })
    
    results := scanner.Run()
    
    for _, host := range results.Hosts {
        fmt.Printf("Host: %s\n", host.IP)
        for _, port := range host.Ports {
            fmt.Printf("  %d/%s - %s\n", port.Number, port.Protocol, port.Service)
        }
    }
}
```

CLI Usage:

```bash
nullsec-scan [options] <targets>

Options:
  -p, --ports <ports>     Ports to scan (default: top 1000)
  -sV                     Service detection
  -O                      OS detection
  -T <0-5>                Timing template
  -o <format>             Output format (json, xml, txt)
  --threads <n>           Number of threads
  --timeout <seconds>     Connection timeout
```

### nullsec-sqli (Python)

SQL injection detection and exploitation:

```python
from nullsec.sqli import SQLiScanner

scanner = SQLiScanner(
    url="http://target.com/page",
    params={"id": "1"},
    technique="BEUSTQ",  # Boolean, Error, Union, Stacked, Time, Query
    level=3,
    risk=2
)

# Detect vulnerability
if scanner.is_vulnerable():
    print("SQL Injection found!")
    
    # Get database info
    print(f"DBMS: {scanner.get_dbms()}")
    print(f"Current DB: {scanner.get_current_db()}")
    
    # Enumerate
    tables = scanner.get_tables()
    for table in tables:
        columns = scanner.get_columns(table)
        print(f"Table: {table}")
        print(f"  Columns: {columns}")
    
    # Dump data
    data = scanner.dump_table("users", columns=["username", "password"])
    for row in data:
        print(row)
```

CLI Usage:

```bash
nullsec-sqli [options] -u <url>

Options:
  -u, --url <url>         Target URL with parameters
  -p, --param <param>     Parameter to test
  --data <data>           POST data
  --cookie <cookie>       Cookie string
  --technique <BEUSTQ>    Techniques to use
  --level <1-5>           Test level
  --risk <1-3>            Risk level
  --dump                  Dump database
  --tables                List tables
  --columns               List columns
```

### nullsec-fuzz (Rust)

High-speed web fuzzer:

```rust
use nullsec_fuzz::{Fuzzer, Config, Wordlist};

fn main() {
    let config = Config {
        url: "http://target.com/FUZZ".to_string(),
        wordlist: Wordlist::from_file("wordlist.txt"),
        threads: 50,
        filter: Filter {
            status_codes: vec![200, 301, 302, 403],
            min_length: Some(100),
            max_length: None,
        },
        extensions: vec![".php", ".html", ".txt"],
        follow_redirects: true,
        timeout: Duration::from_secs(10),
    };
    
    let fuzzer = Fuzzer::new(config);
    let results = fuzzer.run();
    
    for result in results {
        println!("{} [{}] {} bytes", 
            result.url, 
            result.status_code, 
            result.content_length
        );
    }
}
```

CLI Usage:

```bash
nullsec-fuzz [options] -u <url> -w <wordlist>

Options:
  -u, --url <url>         Target URL (use FUZZ as placeholder)
  -w, --wordlist <file>   Wordlist file
  -t, --threads <n>       Number of threads (default: 50)
  -x, --extensions <ext>  File extensions to append
  -fc <codes>             Filter out status codes
  -fs <size>              Filter out response sizes
  -mc <codes>             Match status codes
  -ms <size>              Match response sizes
  --timeout <seconds>     Request timeout
  -o <file>               Output file
```

### nullsec-shell (C)

Reverse shell handler:

```c
// nullsec-shell - Multi-handler reverse shell
#include "nullsec/shell.h"

int main(int argc, char *argv[]) {
    // Create handler
    shell_handler_t *handler = shell_create_handler(
        SHELL_TYPE_TCP,
        "0.0.0.0",
        4444
    );
    
    // Set options
    shell_set_option(handler, SHELL_OPT_SSL, 1);
    shell_set_option(handler, SHELL_OPT_TIMEOUT, 300);
    
    // Start listening
    shell_listen(handler);
    
    // Handle connections
    shell_session_t *session;
    while ((session = shell_accept(handler)) != NULL) {
        printf("[*] Connection from %s:%d\n", 
            session->client_ip, 
            session->client_port
        );
        
        // Interactive shell
        shell_interact(session);
    }
    
    shell_destroy(handler);
    return 0;
}
```

CLI Usage:

```bash
nullsec-shell [options]

Options:
  -l, --listen <port>     Listen for connections
  -c, --connect <host>    Connect to host
  -p, --port <port>       Port number
  -s, --ssl               Use SSL/TLS
  -e, --execute <cmd>     Execute command on connect
  --http                  HTTP tunnel mode
  --dns <domain>          DNS tunnel mode
  -g, --generate <type>   Generate payload
```

### nullsec-priv (Go)

Privilege escalation assistant:

```go
package main

import (
    "github.com/bad-antics/nullsec-tools/priv"
)

func main() {
    // Auto-detect OS
    scanner := priv.NewScanner()
    
    // Run all checks
    results := scanner.CheckAll()
    
    // Print findings
    for _, finding := range results {
        fmt.Printf("[%s] %s\n", finding.Severity, finding.Name)
        fmt.Printf("    Description: %s\n", finding.Description)
        fmt.Printf("    Exploit: %s\n", finding.Exploit)
    }
    
    // Specific checks
    sudoResults := scanner.CheckSudo()
    suidResults := scanner.CheckSUID()
    cronResults := scanner.CheckCron()
    capResults := scanner.CheckCapabilities()
}
```

CLI Usage:

```bash
nullsec-priv [options]

Options:
  -a, --all               Run all checks
  -s, --sudo              Check sudo permissions
  -u, --suid              Check SUID binaries
  -c, --cron              Check cron jobs
  -k, --kernel            Check kernel exploits
  -n, --network           Check network services
  --caps                  Check capabilities
  --docker                Check Docker escape
  -o <file>               Output file
  --json                  JSON output
```

## Configuration

```yaml
# nullsec-tools.yml
global:
  threads: 50
  timeout: 30
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  proxy: null
  
scan:
  default_ports: "1-1000"
  service_detection: true
  os_detection: false
  
web:
  follow_redirects: true
  verify_ssl: false
  
wordlists:
  default: /usr/share/wordlists/rockyou.txt
  directories: /usr/share/wordlists/dirb/common.txt
  
output:
  format: json
  path: ./results/
  
logging:
  level: INFO
  file: nullsec-tools.log
```

## API Integration

### Python SDK

```python
from nullsec import Client

# Initialize client
client = Client(api_key="your-key")

# Run scan
results = client.scan.run(
    targets=["192.168.1.0/24"],
    ports="1-1000",
    service_detection=True
)

# Get results
for host in results.hosts:
    print(f"{host.ip}: {[p.number for p in host.ports]}")
```

### REST API

```bash
# Start API server
nullsec-api --port 8080

# Run scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"], "ports": "1-1000"}'

# Get results
curl http://localhost:8080/api/v1/scan/{scan_id}/results
```

## Reporting

```bash
# Generate HTML report
nullsec-report --input results.json --format html --output report.html

# Generate PDF report
nullsec-report --input results.json --format pdf --output report.pdf

# Executive summary
nullsec-report --input results.json --format pdf --template executive

# Technical report
nullsec-report --input results.json --format pdf --template technical
```

---

[Back to Main Documentation](../../README.md)
