# Oracle Documentation

> **AI-Powered Vulnerability Discovery Engine**

Oracle leverages machine learning and static analysis to predict security vulnerabilities before they're exploited. Revolutionary zero-day prediction with 87% accuracy.

## Overview

Oracle transforms vulnerability discovery with:

- **ML Prediction**: Trained on millions of vulnerabilities
- **Pattern Analysis**: Deep code pattern recognition
- **Zero-Day Detection**: Predict unknown vulnerabilities
- **Multi-Language**: C, C++, Python, Java, Go, Rust, JavaScript

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ORACLE ENGINE                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │   Scanner    │  │   ML Engine   │  │  Pattern Match  │  │
│  │              │  │               │  │                 │  │
│  │  - Tokenize  │  │  - Neural Net │  │  - Regex        │  │
│  │  - Parse     │  │  - Random For │  │  - AST Match    │  │
│  │  - Extract   │  │  - Gradient   │  │  - Data Flow    │  │
│  └──────┬───────┘  └───────┬───────┘  └────────┬────────┘  │
│         │                  │                    │           │
│         └──────────────────┼────────────────────┘           │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Vulnerability Analyzer                  │   │
│  │                                                      │   │
│  │  - Confidence Scoring  - Context Analysis            │   │
│  │  - Severity Ranking    - Fix Suggestions             │   │
│  │  - Report Generation   - SARIF Export                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```julia
using Oracle

# Create the engine
engine = create_oracle_engine()

# Enable all detection modules
enable_module!(engine, :ml_prediction)
enable_module!(engine, :pattern_matching)
enable_module!(engine, :dataflow_analysis)

# Scan a project
results = scan_project(engine, "/path/to/project")

# Filter by severity
critical = filter(r -> r.severity == :critical, results)

# Generate report
report = generate_report(results, :markdown)
write("security_report.md", report)
```

## Detection Capabilities

### Vulnerability Types

| Category | Types Detected |
|----------|---------------|
| **Injection** | SQL, Command, LDAP, XPath, XML, Template |
| **Memory** | Buffer Overflow, Use-After-Free, Double-Free, Null Pointer |
| **Crypto** | Weak Algorithms, Hardcoded Keys, Insufficient Entropy |
| **Auth** | Broken Auth, Session Issues, Credential Leaks |
| **Config** | Misconfigurations, Debug Mode, Verbose Errors |
| **Logic** | Race Conditions, TOCTOU, Integer Overflow |

### Supported Languages

```julia
# Scan specific language
results = scan(engine, "src/", language=:python)
results = scan(engine, "src/", language=:c)
results = scan(engine, "src/", language=:java)
results = scan(engine, "src/", language=:go)
results = scan(engine, "src/", language=:rust)
results = scan(engine, "src/", language=:javascript)

# Auto-detect language
results = scan(engine, "src/")  # Automatic detection
```

## ML Prediction Engine

### Vulnerability Prediction

```julia
using Oracle.ML

# Get predictions for code
code = read("vulnerable.c", String)
predictions = predict_vulnerabilities(engine, code)

for pred in predictions
    println("Vulnerability: $(pred.vuln_type)")
    println("  Confidence: $(round(pred.confidence * 100))%")
    println("  Location: lines $(pred.start_line)-$(pred.end_line)")
    println("  Description: $(pred.description)")
    println()
end
```

### Model Training

Train custom models for your codebase:

```julia
using Oracle.Training

# Prepare training data
training_data = load_training_data("labeled_vulnerabilities/")

# Train custom model
model = train_model(
    training_data,
    model_type = :neural_network,
    epochs = 100,
    validation_split = 0.2
)

# Evaluate model
metrics = evaluate_model(model, test_data)
println("Accuracy: $(metrics.accuracy)")
println("Precision: $(metrics.precision)")
println("Recall: $(metrics.recall)")
println("F1 Score: $(metrics.f1_score)")

# Save for use
save_model(model, "custom_model.onnx")
```

### Pre-trained Models

| Model | Training Data | Accuracy | Focus |
|-------|--------------|----------|-------|
| `general_v3` | CVE Database | 87% | All languages |
| `web_v2` | Web CVEs | 91% | Web vulnerabilities |
| `memory_v2` | Memory CVEs | 89% | C/C++ memory issues |
| `crypto_v1` | Crypto CVEs | 93% | Cryptographic flaws |

## Pattern Analysis

### Custom Patterns

```julia
using Oracle.Patterns

# Define custom vulnerability pattern
my_pattern = VulnPattern(
    name = "Hardcoded AWS Key",
    language = :any,
    pattern = r"AKIA[0-9A-Z]{16}",
    severity = :critical,
    description = "AWS Access Key ID found in source code",
    remediation = "Use environment variables or secrets manager"
)

# Add to engine
add_pattern!(engine, my_pattern)

# Scan with custom patterns
results = scan(engine, "src/", include_custom=true)
```

### Built-in Pattern Sets

```julia
# Enable specific pattern sets
enable_patterns!(engine, :owasp_top_10)
enable_patterns!(engine, :sans_top_25)
enable_patterns!(engine, :cwe_top_25)
enable_patterns!(engine, :pci_dss)

# List available patterns
patterns = list_patterns(engine)
```

## Data Flow Analysis

```julia
using Oracle.DataFlow

# Trace data flow from sources to sinks
analysis = analyze_dataflow(engine, "src/")

# Find tainted data paths
tainted_paths = find_tainted_paths(analysis)

for path in tainted_paths
    println("Source: $(path.source)")
    println("Sink: $(path.sink)")
    println("Path:")
    for step in path.steps
        println("  → $(step.location): $(step.operation)")
    end
    println()
end
```

## Configuration

```julia
# Full configuration
Oracle.configure(
    # Analysis settings
    max_file_size = 10_000_000,  # 10MB
    exclude_patterns = ["test/", "vendor/", "*.min.js"],
    include_patterns = ["src/", "lib/"],
    
    # ML settings
    model = "general_v3",
    confidence_threshold = 0.7,
    use_gpu = true,
    
    # Output settings
    output_format = :sarif,
    verbose = false,
    
    # Performance
    thread_count = 8,
    cache_enabled = true
)
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  oracle-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Julia
        uses: julia-actions/setup-julia@v1
        with:
          version: '1.10'
          
      - name: Install Oracle
        run: julia -e 'using Pkg; Pkg.add(url="https://github.com/bad-antics/oracle")'
        
      - name: Run Security Scan
        run: julia --project -e '
          using Oracle
          engine = create_oracle_engine()
          results = scan_project(engine, ".")
          critical = filter(r -> r.severity == :critical, results)
          if length(critical) > 0
              println("❌ Critical vulnerabilities found!")
              for v in critical
                  println("  $(v.file):$(v.line) - $(v.type)")
              end
              exit(1)
          end
          println("✅ No critical vulnerabilities")
        '
```

### GitLab CI

```yaml
oracle-scan:
  image: julia:1.10
  script:
    - julia -e 'using Pkg; Pkg.add(url="https://github.com/bad-antics/oracle")'
    - julia scan.jl
  artifacts:
    reports:
      sast: oracle-report.sarif
```

## Output Formats

### SARIF Export

```julia
# Export for IDE integration
sarif = export_sarif(results)
write("oracle.sarif", sarif)
```

### HTML Report

```julia
# Generate interactive HTML report
html = export_html(results, template=:detailed)
write("security_report.html", html)
```

### JSON Export

```julia
# Machine-readable format
json = export_json(results)
write("oracle_results.json", json)
```

## Performance

| Operation | Time | Files |
|-----------|------|-------|
| Small project scan | 2.3s | 100 files |
| Medium project scan | 12.5s | 1,000 files |
| Large project scan | 45.2s | 10,000 files |
| ML prediction (per file) | 0.05s | - |

## API Reference

See the complete [API Reference](api.md) for detailed function signatures.

---

[Back to Main Documentation](../../README.md)
