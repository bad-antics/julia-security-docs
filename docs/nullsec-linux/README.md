# NullSec Linux Documentation

> **Security-Focused Linux Distribution with 135+ Penetration Testing Tools**

NullSec Linux is a purpose-built security operating system designed for penetration testers, security researchers, and red teams. Built on Ubuntu 24.04 LTS with a hardened kernel and custom tooling.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      NULLSEC LINUX                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Base OS    │  │  Desktop    │  │    Security Layer       │ │
│  │             │  │             │  │                         │ │
│  │ Ubuntu 24.04│  │  XFCE 4.18  │  │ • AppArmor profiles     │ │
│  │ Kernel 6.8  │  │  Custom GTK │  │ • Hardened sysctls      │ │
│  │ systemd     │  │  NullSec UI │  │ • Encrypted home        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Tool Categories (135+ tools)                │   │
│  ├─────────────┬─────────────┬─────────────┬───────────────┤   │
│  │ Network     │ Web         │ Wireless    │ Forensics     │   │
│  │ Recon       │ Exploitation│ Hardware    │ Reverse Eng   │   │
│  │ OSINT       │ Password    │ Cloud       │ AI/ML         │   │
│  │ Social Eng  │ Automotive  │ Mobile      │ Reporting     │   │
│  └─────────────┴─────────────┴─────────────┴───────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Download

```bash
# Desktop Edition (Recommended)
wget https://github.com/bad-antics/nullsec-linux/releases/latest/download/nullsec-desktop-4.2.0.iso

# Minimal Edition (Servers/VMs)
wget https://github.com/bad-antics/nullsec-linux/releases/latest/download/nullsec-minimal-4.2.0.iso

# Cloud Edition (AWS/GCP/Azure)
wget https://github.com/bad-antics/nullsec-linux/releases/latest/download/nullsec-cloud-4.2.0.iso
```

### Installation

#### Live USB

```bash
# Create bootable USB (replace /dev/sdX with your USB device)
sudo dd if=nullsec-desktop-4.2.0.iso of=/dev/sdX bs=4M status=progress
sync
```

#### Virtual Machine

| Platform | Recommended Settings |
|----------|---------------------|
| VMware | 4 vCPU, 8GB RAM, 80GB disk, NAT + Host-Only |
| VirtualBox | 4 vCPU, 8GB RAM, 80GB disk, Bridged |
| QEMU/KVM | 4 vCPU, 8GB RAM, 80GB disk, virtio |
| Proxmox | 4 vCPU, 8GB RAM, 80GB disk, SCSI |

```bash
# QEMU quick start
qemu-system-x86_64 -enable-kvm -m 8G -smp 4 \
  -drive file=nullsec-desktop-4.2.0.iso,media=cdrom \
  -drive file=nullsec.qcow2,format=qcow2 \
  -net nic -net user
```

### First Boot

Default credentials:
- **User**: `nullsec`
- **Password**: `nullsec`

```bash
# Change password immediately
passwd

# Update system
nullsec-update

# Launch tool menu
nullsec-menu
```

## Tool Categories

### 🔍 Reconnaissance & OSINT

| Tool | Description | Category |
|------|-------------|----------|
| `nmap` | Network scanner | Network |
| `masscan` | Fast port scanner | Network |
| `theHarvester` | Email/domain harvester | OSINT |
| `recon-ng` | Recon framework | OSINT |
| `maltego` | Link analysis | OSINT |
| `shodan` | Internet scanner | OSINT |
| `amass` | Subdomain enum | Recon |
| `subfinder` | Subdomain discovery | Recon |
| `httpx` | HTTP prober | Web |

### 🌐 Web Application Testing

| Tool | Description | Category |
|------|-------------|----------|
| `burpsuite` | Web proxy | Proxy |
| `zaproxy` | OWASP ZAP | Proxy |
| `sqlmap` | SQL injection | Injection |
| `nikto` | Web scanner | Scanner |
| `dirb` | Directory brute | Fuzzing |
| `gobuster` | Dir/DNS brute | Fuzzing |
| `ffuf` | Fast fuzzer | Fuzzing |
| `wpscan` | WordPress scanner | CMS |
| `nuclei` | Template scanner | Scanner |

### 🔐 Password & Credential Attacks

| Tool | Description | Category |
|------|-------------|----------|
| `hashcat` | GPU password cracker | Cracking |
| `john` | John the Ripper | Cracking |
| `hydra` | Login brute forcer | Brute |
| `medusa` | Parallel brute | Brute |
| `crackmapexec` | AD post-exploit | AD |
| `responder` | LLMNR/NBT-NS poison | AD |
| `mimikatz` | Credential dump | AD |
| `impacket` | AD toolkit | AD |

### 📡 Wireless & RF

| Tool | Description | Category |
|------|-------------|----------|
| `aircrack-ng` | WiFi auditing | WiFi |
| `wifite` | Automated WiFi attack | WiFi |
| `bettercap` | MITM framework | MITM |
| `kismet` | Wireless detector | WiFi |
| `gqrx` | SDR receiver | SDR |
| `gnuradio` | SDR toolkit | SDR |
| `hackrf` | HackRF tools | SDR |
| `rtl_433` | ISM band decoder | SDR |

### 🚗 Automotive Security

| Tool | Description | Category |
|------|-------------|----------|
| `can-utils` | CAN bus tools | CAN |
| `caringcaribou` | Car ECU tool | ECU |
| `uds-scanner` | UDS protocol | UDS |
| `savvycan` | CAN analyzer | CAN |
| `blackflag` | ECU diagnostics | ECU |
| `opendbc` | Vehicle signals | Signals |

### ☁️ Cloud Security

| Tool | Description | Category |
|------|-------------|----------|
| `aws-cli` | AWS CLI | AWS |
| `gcloud` | GCP CLI | GCP |
| `az` | Azure CLI | Azure |
| `scout-suite` | Multi-cloud audit | Audit |
| `prowler` | AWS security | AWS |
| `cloudsplaining` | IAM analysis | IAM |
| `pacu` | AWS exploit | AWS |
| `gcp-scanner` | GCP audit | GCP |

### 🤖 AI/ML Security

| Tool | Description | Category |
|------|-------------|----------|
| `nullsec-llmred` | LLM red teaming | LLM |
| `garak` | LLM vulnerability | LLM |
| `promptmap` | Prompt injection | LLM |
| `adversarial-robustness` | ML attacks | ML |
| `mirage` | Adversarial ML | ML |
| `oracle` | Vuln prediction | ML |

### 🔧 NullSec Custom Tools

| Tool | Description |
|------|-------------|
| `nullsec-ai` | AI-powered threat analysis |
| `nullsec-scan` | Comprehensive scanner |
| `nullsec-enum` | Service enumeration |
| `nullsec-exploit` | Exploit framework |
| `nullsec-report` | Report generator |
| `spectra` | Julia security toolkit |

## System Architecture

### Directory Structure

```
/opt/nullsec/
├── bin/                  # NullSec binaries
├── tools/                # Third-party tools
│   ├── recon/
│   ├── web/
│   ├── wireless/
│   ├── forensics/
│   └── ...
├── wordlists/            # Password lists
├── payloads/             # Exploit payloads
├── templates/            # Report templates
└── config/               # Tool configurations

/usr/share/nullsec/
├── icons/                # Custom icons
├── themes/               # GTK themes
├── wallpapers/           # Backgrounds
└── sounds/               # Notification sounds

/var/log/nullsec/
├── audit/                # Security audit logs
├── tools/                # Tool execution logs
└── system/               # System logs
```

### Custom Commands

```bash
# System management
nullsec-update           # Update all tools
nullsec-status           # System status
nullsec-backup           # Backup configs

# Tool launcher
nullsec-menu             # Interactive menu
nullsec-search <term>    # Search tools
nullsec-run <tool>       # Run tool with logging

# Security
nullsec-anon             # Anonymity mode
nullsec-vpn              # VPN manager
nullsec-tor              # Tor routing

# AI features
nullsec-ai               # AI assistant
nullsec-analyze          # AI threat analysis
```

## Configuration

### Network Setup

```bash
# Configure network interfaces
nullsec-netconfig

# WiFi monitor mode
nullsec-airmon start wlan0

# Virtual interfaces
nullsec-veth create pentest0
```

### Anonymity Mode

```bash
# Enable full anonymity
nullsec-anon enable

# Features:
# - MAC address randomization
# - DNS over Tor
# - Traffic through Tor
# - Hostname randomization
# - Timezone spoofing

# Disable
nullsec-anon disable
```

### Tool Configuration

```bash
# Edit tool configs
nullsec-config burpsuite
nullsec-config metasploit
nullsec-config nmap

# Reset to defaults
nullsec-config reset <tool>
```

## Editions

### Desktop Edition (Recommended)

Full-featured security workstation:
- XFCE 4.18 desktop
- All 135+ tools pre-installed
- NullSec AI assistant
- Report generation
- 2.8GB ISO

### Minimal Edition

Headless server/container:
- CLI only
- Core tools (50+)
- Lower resource usage
- 1.2GB ISO

### Cloud Edition

Optimized for cloud platforms:
- AWS/GCP/Azure ready
- Auto-scaling support
- API-first design
- 1.5GB ISO

### Automotive Edition

Vehicle security focus:
- CAN bus tools
- ECU diagnostics
- UDS/OBD-II
- Signal analysis
- SDR integration

## Building from Source

```bash
# Clone repository
git clone https://github.com/bad-antics/nullsec-linux
cd nullsec-linux

# Install dependencies
./scripts/install-deps.sh

# Build ISO
./build-iso.sh --edition desktop --version 4.2.0

# Build options
./build-iso.sh --help
  --edition <desktop|minimal|cloud|auto>
  --version <version>
  --output <path>
  --no-ai         # Exclude AI components
  --extra-tools   # Include experimental tools
```

## Hardening Features

### Kernel Hardening

```
# Applied sysctls
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.perf_event_paranoid=3
kernel.yama.ptrace_scope=2
net.core.bpf_jit_harden=2
```

### AppArmor Profiles

All security tools run with custom AppArmor profiles:

```bash
# Check profile status
aa-status

# View tool profile
cat /etc/apparmor.d/nullsec-nmap
```

### Secure Boot

NullSec Linux supports Secure Boot with signed bootloader.

## Updates

```bash
# Full system update
nullsec-update

# Tools only
nullsec-update --tools-only

# Specific tool
nullsec-update --tool metasploit

# Check for updates
nullsec-update --check
```

## Support

- **Documentation**: https://github.com/bad-antics/nullsec-linux/wiki
- **Issues**: https://github.com/bad-antics/nullsec-linux/issues
- **Twitter**: x.com/AnonAntics

---

[Back to Main Documentation](../../README.md)
