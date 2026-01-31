# Getting Started with Julia Security Suite

Welcome to the Julia Security Suite! This guide will help you get up and running with our five revolutionary security tools.

## Prerequisites

Before you begin, ensure you have:

- **Julia 1.10+** installed ([download](https://julialang.org/downloads/))
- **Git** for cloning repositories
- **Internet connection** for threat feeds (Vortex)
- Basic familiarity with Julia syntax

## Quick Installation

### Option 1: Install All Tools

```julia
using Pkg

# Install the complete suite
for tool in ["spectra", "oracle", "phantom", "vortex", "mirage"]
    Pkg.add(url="https://github.com/bad-antics/$tool")
end
```

### Option 2: Install Individual Tools

```julia
using Pkg

# Choose what you need
Pkg.add(url="https://github.com/bad-antics/spectra")   # Core toolkit
Pkg.add(url="https://github.com/bad-antics/oracle")    # Vuln prediction
Pkg.add(url="https://github.com/bad-antics/phantom")   # ZK proofs
Pkg.add(url="https://github.com/bad-antics/vortex")    # Threat intel
Pkg.add(url="https://github.com/bad-antics/mirage")    # Adversarial ML
```

## Your First Scan

### Vulnerability Discovery with Oracle

```julia
using Oracle

# Create the prediction engine
engine = create_oracle_engine()

# Scan a file or directory
results = scan("vulnerable_app.c")

# Print findings
for vuln in results
    println("Found: $(vuln.type)")
    println("  Location: $(vuln.file):$(vuln.line)")
    println("  Severity: $(vuln.severity)")
    println("  Confidence: $(round(vuln.confidence * 100))%")
    println()
end
```

### Threat Intelligence with Vortex

```julia
using Vortex

# Create the engine
engine = create_vortex_engine()

# Add free threat feeds (no API key required)
add_feed!(engine, urlhaus_feed())
add_feed!(engine, feodo_tracker_feed())
add_feed!(engine, spamhaus_drop_feed())

# Start processing
start!(engine)

# Wait for initial sync
sleep(10)

# Check an IP address
results = search_ioc(engine, "185.220.101.1")

if !isempty(results)
    println("⚠️  Malicious IP detected!")
    for ioc in results
        println("  Source: $(ioc.source)")
        println("  Risk Score: $(ioc.risk_score)")
        println("  Tags: $(join(ioc.tags, ", "))")
    end
else
    println("✅ IP not found in threat feeds")
end
```

### Zero-Knowledge Proofs with Phantom

```julia
using Phantom

# Define a vulnerability (details stay private)
vuln = create_vulnerability(
    vuln_type=VULN_SQL_INJECTION,
    severity=SEVERITY_CRITICAL,
    affected_component="login.php",
    evidence_hash=sha256("SELECT * FROM users WHERE id='$input'")
)

# Generate ZK proof
proof = generate_vulnerability_proof(vuln)

# The proof can be verified without revealing the vulnerability
println("Proof generated: $(proof.id)")
println("Verifiable: $(verify_proof(proof))")

# Create anonymous disclosure
disclosure = create_disclosure(
    proof,
    vendor="Example Corp",
    timeline_days=90
)
```

## Common Workflows

### 1. CI/CD Security Pipeline

```julia
# security_check.jl
using Oracle

function main()
    engine = create_oracle_engine()
    vulns = scan_codebase("src/")
    
    critical = filter(v -> v.severity == :critical, vulns)
    high = filter(v -> v.severity == :high, vulns)
    
    println("Security Scan Results:")
    println("  Critical: $(length(critical))")
    println("  High: $(length(high))")
    println("  Total: $(length(vulns))")
    
    # Fail build if critical vulnerabilities found
    if length(critical) > 0
        println("\n❌ Critical vulnerabilities found!")
        for v in critical
            println("  - $(v.type) at $(v.location)")
        end
        exit(1)
    end
    
    println("\n✅ No critical vulnerabilities")
    exit(0)
end

main()
```

### 2. Threat Hunting Session

```julia
using Vortex

# Initialize with multiple feeds
engine = create_vortex_engine()
add_feed!(engine, urlhaus_feed())
add_feed!(engine, alienvault_otx_feed(ENV["OTX_API_KEY"]))
add_feed!(engine, virustotal_feed(ENV["VT_API_KEY"]))
start!(engine)

# Wait for sync
sleep(30)

# Hunt for C2 infrastructure
c2_hunt = hunt_c2_infrastructure()
results = execute_hunt(engine, c2_hunt)

println("C2 Hunt Results:")
println("  Matches: $(results.match_count)")
println("  Risk Distribution:")
for (level, count) in results.risk_distribution
    println("    $level: $count")
end

# Export to STIX for sharing
stix = export_stix(results.matches)
write("c2_indicators.stix.json", stix)
```

### 3. ML Model Security Audit

```julia
using Mirage

# Load your model
model = load_model("classifier.onnx")

# Define attack suite
attacks = [
    FGSM(epsilon=0.03),
    PGD(epsilon=0.03, steps=20),
    DeepFool(max_iterations=50)
]

# Load test data
test_data = load_test_data("test_samples.npz")

# Evaluate robustness
println("Evaluating model robustness...")
for attack in attacks
    result = evaluate_attack(model, test_data, attack)
    println("$(typeof(attack)):")
    println("  Success Rate: $(round(result.success_rate * 100, digits=1))%")
    println("  Avg Perturbation: $(round(result.avg_perturbation, digits=4))")
end

# Generate robustness report
report = generate_robustness_report(model, test_data, attacks)
write("robustness_report.md", report)
```

## Next Steps

1. **Explore the API Reference** - Detailed documentation for each tool
2. **Check Examples** - Real-world usage scenarios
3. **Join the Community** - Report issues and contribute
4. **Read Best Practices** - Security and performance tips

## Getting Help

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides for each tool
- **Examples**: Working code for common scenarios

---

[Back to Main Documentation](../README.md)
