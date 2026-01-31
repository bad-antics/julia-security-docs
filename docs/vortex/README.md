# Vortex Documentation

> **Real-time Threat Intelligence Fusion Engine**

Vortex aggregates, correlates, and analyzes threat data from 50+ sources in real-time. Transform raw indicators into actionable intelligence.

## Overview

Vortex delivers enterprise-grade threat intelligence:

- **50+ Feed Sources**: OSINT, commercial, and private feeds
- **Real-time Correlation**: Connect disparate indicators
- **Risk Scoring**: ML-powered threat assessment
- **Detection Export**: Snort, Suricata, YARA, Sigma rules

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      VORTEX ENGINE                          │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────┐     │
│  │              Feed Aggregation Layer                 │     │
│  │                                                     │     │
│  │  URLhaus  │  AlienVault  │  VirusTotal  │  MISP    │     │
│  │  Feodo    │  AbuseIPDB   │  Shodan      │  Custom  │     │
│  └─────────────────────────┬───────────────────────────┘     │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Correlation Engine                      │    │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────────────┐   │    │
│  │  │ Temporal │  │  Graph   │  │   ML Cluster    │   │    │
│  │  │  Correlation │  Analysis │  │   Attribution   │   │    │
│  │  └──────────┘  └──────────┘  └─────────────────┘   │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Intelligence Output                     │    │
│  │  STIX 2.1  │  MISP  │  Snort  │  YARA  │  Sigma    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```julia
using Vortex

# Create and configure engine
engine = create_vortex_engine()

# Add free feeds (no API key needed)
add_feed!(engine, urlhaus_feed())
add_feed!(engine, feodo_tracker_feed())
add_feed!(engine, spamhaus_drop_feed())
add_feed!(engine, ssl_blacklist_feed())

# Start real-time processing
start!(engine)

# Wait for initial sync
sleep(15)

# Check indicators
suspicious_ips = ["185.220.101.1", "91.219.236.166", "103.145.13.110"]

for ip in suspicious_ips
    results = search_ioc(engine, ip)
    if !isempty(results)
        ioc = first(results)
        println("⚠️  $ip is MALICIOUS")
        println("   Risk: $(ioc.risk_score)/100")
        println("   Tags: $(join(ioc.tags, ", "))")
        println("   Source: $(ioc.source)")
    else
        println("✅ $ip not found in threat feeds")
    end
end
```

## Feed Configuration

### Free OSINT Feeds

```julia
# URLhaus - Malicious URLs
add_feed!(engine, urlhaus_feed())

# Feodo Tracker - Banking trojans
add_feed!(engine, feodo_tracker_feed())

# Spamhaus DROP - Known bad networks
add_feed!(engine, spamhaus_drop_feed())

# SSL Blacklist - Malicious SSL certs
add_feed!(engine, ssl_blacklist_feed())

# Emerging Threats - Open rules
add_feed!(engine, emerging_threats_feed())

# Malware Bazaar - Malware samples
add_feed!(engine, malware_bazaar_feed())
```

### Commercial Feeds (API Key Required)

```julia
# VirusTotal
add_feed!(engine, virustotal_feed(ENV["VT_API_KEY"]))

# AlienVault OTX
add_feed!(engine, alienvault_otx_feed(ENV["OTX_API_KEY"]))

# AbuseIPDB
add_feed!(engine, abuseipdb_feed(ENV["ABUSE_API_KEY"]))

# Shodan
add_feed!(engine, shodan_feed(ENV["SHODAN_API_KEY"]))

# Recorded Future
add_feed!(engine, recorded_future_feed(ENV["RF_API_KEY"]))
```

### Custom Feeds

```julia
# Define custom feed
my_feed = CustomFeed(
    name = "Internal Threat Intel",
    url = "https://internal.example.com/threats.json",
    format = :json,
    refresh_interval = Minute(15),
    parser = json -> begin
        [IOC(
            value = item["indicator"],
            type = parse_ioc_type(item["type"]),
            source = "Internal",
            risk_score = item["risk"],
            tags = item["tags"]
        ) for item in json["indicators"]]
    end
)

add_feed!(engine, my_feed)
```

## IOC Types

| Type | Description | Example |
|------|-------------|---------|
| `IOC_IP_ADDRESS` | IPv4/IPv6 addresses | `185.220.101.1` |
| `IOC_DOMAIN` | Domain names | `malware.example.com` |
| `IOC_URL` | Full URLs | `http://bad.site/malware.exe` |
| `IOC_HASH_MD5` | MD5 file hashes | `d41d8cd98f00b204e9800998ecf8427e` |
| `IOC_HASH_SHA1` | SHA1 hashes | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `IOC_HASH_SHA256` | SHA256 hashes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4...` |
| `IOC_EMAIL` | Email addresses | `phisher@malicious.com` |
| `IOC_CVE` | CVE identifiers | `CVE-2024-1234` |
| `IOC_CIDR` | Network ranges | `192.168.0.0/16` |
| `IOC_JA3` | TLS fingerprints | `e7d705a3286e19ea42f587b344ee6865` |

## Correlation Engine

### Temporal Correlation

```julia
using Vortex.Correlation

# Find indicators seen together in time windows
correlations = correlate_temporal(engine,
    window = Hour(24),
    min_confidence = 0.7
)

for corr in correlations
    println("Correlation (confidence: $(corr.confidence))")
    for ioc in corr.indicators
        println("  - $(ioc.value) ($(ioc.type))")
    end
end
```

### Graph Analysis

```julia
using Vortex.Graph

# Build relationship graph
graph = build_threat_graph(engine)

# Find connected components (campaigns)
campaigns = find_campaigns(graph)

for campaign in campaigns
    println("Campaign: $(campaign.id)")
    println("  Indicators: $(length(campaign.indicators))")
    println("  Timespan: $(campaign.first_seen) - $(campaign.last_seen)")
    println("  Attribution: $(campaign.attributed_to)")
end

# Find shortest path between indicators
path = shortest_path(graph, ioc_a, ioc_b)
```

### ML Clustering

```julia
using Vortex.Clustering

# Cluster similar threats
clusters = cluster_threats(engine,
    algorithm = :kmeans,
    n_clusters = 10,
    features = [:type, :risk_score, :tags, :temporal]
)

for cluster in clusters
    println("Cluster $(cluster.id):")
    println("  Size: $(length(cluster.members))")
    println("  Cohesion: $(cluster.cohesion)")
    println("  Dominant tags: $(cluster.top_tags)")
end
```

## Threat Hunting

### Predefined Hunts

```julia
using Vortex.Hunting

# Hunt for C2 infrastructure
c2_results = execute_hunt(engine, hunt_c2_infrastructure())
println("C2 indicators: $(c2_results.match_count)")

# Hunt for ransomware indicators
ransom_results = execute_hunt(engine, hunt_ransomware())
println("Ransomware indicators: $(ransom_results.match_count)")

# Hunt for APT activity
apt_results = execute_hunt(engine, hunt_apt_activity())
println("APT indicators: $(apt_results.match_count)")
```

### Custom Hunts

```julia
# Define custom hunt
my_hunt = HuntRule(
    name = "Financial Sector Threats",
    description = "Hunt for threats targeting financial institutions",
    query = HuntQuery(
        ioc_types = [IOC_IP_ADDRESS, IOC_DOMAIN, IOC_URL],
        tags_any = ["banking", "financial", "swift", "atm"],
        risk_min = 60,
        timeframe = Day(30)
    )
)

results = execute_hunt(engine, my_hunt)
```

## Enrichment

### IP Enrichment

```julia
using Vortex.Enrichment

# Enrich an IP address
ip = "185.220.101.1"
enriched = enrich_ip(engine, ip)

println("IP: $ip")
println("GeoIP: $(enriched.geo.country), $(enriched.geo.city)")
println("ASN: $(enriched.asn.number) - $(enriched.asn.org)")
println("WHOIS: $(enriched.whois.registrar)")
println("Reputation: $(enriched.reputation.score)/100")
println("Categories: $(join(enriched.reputation.categories, ", "))")
```

### Bulk Enrichment

```julia
# Enrich multiple indicators
indicators = ["185.220.101.1", "malware.example.com", "d41d8cd..."]
enriched = bulk_enrich(engine, indicators)

for (ind, data) in enriched
    println("$ind: risk=$(data.risk_score), enriched=$(data.enrichment_count)")
end
```

## Detection Rule Export

### STIX 2.1

```julia
# Export as STIX bundle
stix = export_stix(engine.intel_store,
    title = "Weekly Threat Report",
    description = "Indicators from week 42",
    filter = IOCFilter(risk_min=70, types=[IOC_IP_ADDRESS, IOC_DOMAIN])
)

write("threat_report.stix.json", stix)
```

### Snort Rules

```julia
# Generate Snort rules
snort = export_snort(engine.intel_store,
    filter = IOCFilter(risk_min=80, types=[IOC_IP_ADDRESS]),
    sid_start = 1000001
)

write("vortex_threats.rules", snort)
# alert ip any any -> 185.220.101.1 any (msg:"Vortex: Malicious IP"; sid:1000001; rev:1;)
```

### Suricata Rules

```julia
# Generate Suricata rules with metadata
suricata = export_suricata(engine.intel_store,
    filter = IOCFilter(tags_any=["c2", "malware"]),
    sid_start = 2000001
)

write("vortex_suricata.rules", suricata)
```

### YARA Rules

```julia
# Generate YARA rules for file hashes
yara = export_yara(engine.intel_store,
    filter = IOCFilter(types=[IOC_HASH_SHA256])
)

write("vortex_hashes.yar", yara)
```

### Sigma Rules

```julia
# Generate Sigma rules for SIEM
sigma = export_sigma(engine.intel_store,
    title = "Vortex Threat Indicators",
    level = :high
)

write("vortex_sigma.yml", sigma)
```

## Alerting

### Real-time Alerts

```julia
using Vortex.Alerting

# Define alert rules
add_alert_rule!(engine, AlertRule(
    name = "Critical Threat Alert",
    condition = ioc -> ioc.risk_score >= 90,
    severity = ALERT_CRITICAL,
    notify = [
        WebhookNotification("https://slack.webhook.url"),
        EmailNotification("soc@example.com")
    ]
))

add_alert_rule!(engine, AlertRule(
    name = "APT Alert",
    condition = ioc -> "apt" in ioc.tags,
    severity = ALERT_HIGH,
    notify = [WebhookNotification("https://pagerduty.webhook")]
))
```

### Alert Handlers

```julia
# Custom alert handler
on_alert(engine) do alert
    println("ALERT: $(alert.rule_name)")
    println("  IOC: $(alert.ioc.value)")
    println("  Severity: $(alert.severity)")
    println("  Time: $(alert.timestamp)")
    
    # Custom action
    log_to_siem(alert)
end
```

## Performance

| Metric | Value |
|--------|-------|
| IOC ingestion rate | 50,000/sec |
| Search latency (1M IOCs) | <5ms |
| Memory usage (1M IOCs) | ~2GB |
| Feed sync (50 feeds) | ~30 sec |
| Correlation (100K IOCs) | ~2 sec |

## Configuration

```julia
Vortex.configure(
    # Storage
    storage_path = "/var/lib/vortex",
    max_iocs = 10_000_000,
    retention_days = 90,
    
    # Performance
    worker_threads = 8,
    batch_size = 1000,
    
    # Enrichment
    enrichment_enabled = true,
    enrichment_cache_ttl = Hour(24),
    
    # Alerting
    alert_enabled = true,
    alert_cooldown = Minute(5),
    
    # Logging
    log_level = :info,
    metrics_enabled = true
)
```

## API Reference

See the complete [API Reference](api.md) for detailed function signatures.

---

[Back to Main Documentation](../../README.md)
