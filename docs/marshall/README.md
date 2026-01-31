# Marshall Browser Documentation

> **NullSec Privacy Browser | Secure. Private. Untraceable.**

Marshall is a hardened privacy-focused browser built for security researchers, penetration testers, and privacy advocates. Based on Firefox with extensive security modifications and built-in anonymity features.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      MARSHALL BROWSER                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Privacy Layer                         │   │
│  │  • Tor Integration    • Fingerprint Resistance          │   │
│  │  • DNS over HTTPS     • Canvas/WebGL Spoofing           │   │
│  │  • First-Party Isolation • Referrer Stripping           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Security Layer                        │   │
│  │  • Hardened about:config • Disabled WebRTC              │   │
│  │  • Script Blocking       • HTTPS Everywhere             │   │
│  │  • Cookie Isolation      • Tracking Protection          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    OSINT Extensions                      │   │
│  │  • Wappalyzer  • BuiltWith  • Shodan  • HaveIBeenPwned │   │
│  │  • IP Info     • Headers    • SSL Labs • SecurityTrails│   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Privacy Protection

| Feature | Description |
|---------|-------------|
| **Tor Integration** | One-click Tor routing for anonymous browsing |
| **Fingerprint Resistance** | Canvas, WebGL, audio fingerprint spoofing |
| **First-Party Isolation** | Cookies isolated per domain |
| **DNS over HTTPS** | Encrypted DNS queries |
| **Referrer Stripping** | Remove tracking referrers |
| **User-Agent Rotation** | Randomize browser identity |

### Security Hardening

| Feature | Description |
|---------|-------------|
| **WebRTC Disabled** | Prevent IP leaks |
| **JavaScript Isolation** | Per-site script control |
| **HTTPS Only** | Force secure connections |
| **Cookie Auto-Delete** | Clear cookies on close |
| **History Disabled** | No local history storage |
| **Telemetry Blocked** | No data sent to Mozilla |

### OSINT Tools

Built-in extensions for reconnaissance:

| Extension | Purpose |
|-----------|---------|
| **Wappalyzer** | Technology detection |
| **BuiltWith** | Site profiling |
| **Shodan** | Device/service lookup |
| **HaveIBeenPwned** | Breach checking |
| **SecurityTrails** | DNS history |
| **SSL Labs** | Certificate analysis |
| **Wayback Machine** | Historical snapshots |
| **EXIF Viewer** | Image metadata |

## Installation

### Linux

```bash
# Debian/Ubuntu
wget https://github.com/bad-antics/marshall/releases/latest/download/marshall-linux-amd64.deb
sudo dpkg -i marshall-linux-amd64.deb

# Arch Linux
yay -S marshall-browser

# Fedora
sudo dnf install marshall-browser

# AppImage (Universal)
wget https://github.com/bad-antics/marshall/releases/latest/download/marshall-linux.AppImage
chmod +x marshall-linux.AppImage
./marshall-linux.AppImage
```

### Windows

```powershell
# Download installer
Invoke-WebRequest -Uri "https://github.com/bad-antics/marshall/releases/latest/download/marshall-windows-x64.exe" -OutFile "marshall-setup.exe"

# Silent install
.\marshall-setup.exe /S

# Or use winget
winget install bad-antics.marshall
```

### macOS

```bash
# Homebrew
brew install --cask marshall-browser

# Or download DMG
wget https://github.com/bad-antics/marshall/releases/latest/download/marshall-macos.dmg
```

## Quick Start

### First Launch

1. Launch Marshall from applications menu or command line:
   ```bash
   marshall
   ```

2. Select privacy profile:
   - **Standard**: Balanced privacy/usability
   - **Strict**: Maximum privacy, some sites may break
   - **OSINT**: Optimized for reconnaissance

3. Configure Tor (optional):
   - Click shield icon → Enable Tor
   - Verify at https://check.torproject.org

### Privacy Modes

#### Standard Mode
```
Default browsing with:
- First-party isolation
- Tracking protection
- HTTPS upgrades
- Fingerprint resistance (basic)
```

#### Strict Mode
```
Maximum privacy:
- Tor routing
- JavaScript disabled by default
- All cookies blocked
- Full fingerprint resistance
- WebGL/Canvas blocked
```

#### OSINT Mode
```
Reconnaissance optimized:
- All OSINT extensions enabled
- Screenshot tools
- Developer tools open
- Network monitor active
- JavaScript enabled (for recon)
```

## Configuration

### Privacy Settings

Access via `about:preferences#privacy` or:

```javascript
// Marshall security preferences (about:config)

// Fingerprinting
privacy.resistFingerprinting = true
privacy.resistFingerprinting.letterboxing = true

// WebRTC
media.peerconnection.enabled = false
media.peerconnection.ice.no_host = true

// First-Party Isolation
privacy.firstparty.isolate = true

// DNS over HTTPS
network.trr.mode = 3  // DoH only
network.trr.uri = "https://dns.quad9.net/dns-query"

// Referrer
network.http.referer.XOriginPolicy = 2
network.http.referer.XOriginTrimmingPolicy = 2

// Cookies
network.cookie.cookieBehavior = 1  // Block third-party
network.cookie.lifetimePolicy = 2  // Clear on close
```

### Tor Configuration

```bash
# Enable Tor
marshall --tor

# Custom Tor config
marshall --tor-config /path/to/torrc

# Use existing Tor instance
marshall --tor-socks 127.0.0.1:9050
```

### User Agent Rotation

```javascript
// Random user agent on each request
privacy.userAgent.random = true

// Fixed user agent
general.useragent.override = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

// Rotate user agents from list
privacy.userAgent.rotateList = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
  "Mozilla/5.0 (X11; Linux x86_64)..."
]
```

## OSINT Extensions

### Wappalyzer

Detect technologies used by websites:

```
Usage:
1. Visit target website
2. Click Wappalyzer icon
3. View detected technologies:
   - Web server
   - CMS
   - JavaScript frameworks
   - Analytics
   - CDN
```

### Shodan Integration

Look up IP/host information:

```
Setup:
1. Get API key from shodan.io
2. Marshall → Extensions → Shodan → Settings
3. Enter API key

Usage:
1. Right-click on page
2. "Lookup in Shodan"
3. View services, ports, vulnerabilities
```

### SecurityTrails

DNS and historical data:

```
Features:
- DNS history
- Subdomains
- Associated domains
- WHOIS history
- IP history
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+T` | Toggle Tor |
| `Ctrl+Shift+P` | Private window |
| `Ctrl+Shift+N` | New identity (Tor) |
| `Ctrl+Shift+O` | OSINT panel |
| `Ctrl+Shift+S` | Screenshot tool |
| `Ctrl+Shift+D` | Developer tools |
| `F12` | Network monitor |

## Command Line

```bash
# Basic usage
marshall [URL]

# Privacy modes
marshall --mode strict
marshall --mode osint
marshall --mode standard

# Tor options
marshall --tor
marshall --tor-new-identity

# Profiles
marshall --profile pentest
marshall --profile osint
marshall --profile anonymous

# Developer
marshall --devtools
marshall --debug

# Portable
marshall --portable --datadir /path/to/data
```

## Building from Source

```bash
# Clone repository
git clone https://github.com/bad-antics/marshall
cd marshall

# Install dependencies
npm install

# Build
npm run build

# Package
npm run package -- --platform linux --arch x64
npm run package -- --platform win32 --arch x64
npm run package -- --platform darwin --arch x64

# Development
npm run dev
```

## Marshall Extensions Pack

Additional extensions available:

```bash
# Install extensions pack
marshall --install-extensions osint-pack

# Available packs:
# - osint-pack: Full OSINT toolkit
# - privacy-pack: Enhanced privacy
# - dev-pack: Developer tools
# - pentest-pack: Pentesting tools
```

### Extension List

| Pack | Extensions |
|------|------------|
| **osint-pack** | Wappalyzer, BuiltWith, Shodan, SecurityTrails, DNSlytics, IPInfo, EXIF Viewer, Wayback |
| **privacy-pack** | uBlock Origin, Privacy Badger, HTTPS Everywhere, Decentraleyes, ClearURLs |
| **dev-pack** | React DevTools, Vue DevTools, Redux DevTools, EditThisCookie |
| **pentest-pack** | HackTools, FoxyProxy, Cookie Editor, User-Agent Switcher |

## Comparison

| Feature | Marshall | Firefox | Tor Browser | Chrome |
|---------|----------|---------|-------------|--------|
| Fingerprint Resistance | ✅ Full | ❌ | ✅ Full | ❌ |
| Built-in Tor | ✅ | ❌ | ✅ | ❌ |
| OSINT Extensions | ✅ Pre-installed | Manual | Limited | Manual |
| WebRTC Disabled | ✅ Default | Manual | ✅ | ❌ |
| First-Party Isolation | ✅ Default | Manual | ✅ | ❌ |
| Telemetry | ✅ Blocked | Opt-out | ✅ Blocked | ❌ |

## Security Audit

Marshall has been audited for:
- Memory safety
- Extension sandboxing
- Network isolation
- Cryptographic implementation

See [SECURITY.md](https://github.com/bad-antics/marshall/blob/main/SECURITY.md) for details.

---

[Back to Main Documentation](../../README.md)
