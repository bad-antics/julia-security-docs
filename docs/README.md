# Julia Security Docs

## Overview

Central documentation hub for the Julia security tool ecosystem maintained by bad-antics.

## Tool Documentation

| Tool | Repo | Documentation |
|------|------|--------------|
| Spectra | [spectra](https://github.com/bad-antics/spectra) | Security toolkit |
| Oracle | [oracle](https://github.com/bad-antics/oracle) | ML vulnerability discovery |
| Vortex | [vortex](https://github.com/bad-antics/vortex) | Threat intelligence |
| Phantom | [phantom](https://github.com/bad-antics/phantom) | Zero-knowledge proofs |
| Mirage | [mirage](https://github.com/bad-antics/mirage) | Adversarial ML |
| SecureVault | [securevault](https://github.com/bad-antics/securevault) | Credential vault |
| Seduction | [seduction](https://github.com/bad-antics/seduction) | SE analysis |
| Transparency | [transparency](https://github.com/bad-antics/transparency) | Traffic analysis |
| Cool Memories | [cool-memories](https://github.com/bad-antics/cool-memories) | Memory forensics |
| Desert | [desert](https://github.com/bad-antics/desert) | Fuzzing framework |

## Getting Started with Julia Security

```julia
# Install the core tools
using Pkg
Pkg.add(url="https://github.com/bad-antics/spectra")
Pkg.add(url="https://github.com/bad-antics/oracle")

# Quick vulnerability scan
using Spectra, Oracle
results = Spectra.scan("target.com", modules=[:port, :web, :vuln])
predictions = Oracle.predict(results)
```

## Community

- [awesome-julia-security](https://github.com/bad-antics/awesome-julia-security) — Curated list of Julia security resources
- [Baudrillard Suite](https://github.com/bad-antics/baudrillard-suite) — The umbrella project
