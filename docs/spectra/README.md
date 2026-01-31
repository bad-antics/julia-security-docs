# Spectra Documentation

> **High-Performance Security Toolkit in Julia**

Spectra is the foundational security toolkit of the Julia Security Suite, providing core cryptographic operations, network analysis, and security primitives used by other tools in the suite.

## Overview

Spectra delivers enterprise-grade security operations with Julia's performance advantages:

- **Zero-Cost Abstractions**: Security patterns without runtime overhead
- **Type-Safe Operations**: Compile-time verification of security operations
- **Parallel Processing**: Native threading for bulk operations
- **Memory Safety**: Automatic buffer management prevents vulnerabilities

## Core Modules

### Crypto Module

Full-featured cryptographic operations:

```julia
using Spectra.Crypto

# Symmetric encryption
key = generate_key(AES256_GCM)
ciphertext, nonce = encrypt(plaintext, key, AES256_GCM)
decrypted = decrypt(ciphertext, nonce, key, AES256_GCM)

# Asymmetric operations
keypair = generate_keypair(ED25519)
signature = sign(message, keypair.private_key)
verify(message, signature, keypair.public_key)  # => true

# Hashing
hash = sha256(data)
hash = sha3_256(data)
hash = blake3(data)  # Fastest secure hash
hash = argon2id(password, salt; t=3, m=65536, p=4)

# Key derivation
derived = hkdf(secret, salt, info; length=32)
derived = pbkdf2(password, salt; iterations=100000)
```

### Network Module

Network scanning and analysis:

```julia
using Spectra.Network

# Port scanning
results = port_scan("192.168.1.0/24", ports=[22, 80, 443, 8080])

for host in results
    println("$(host.ip):")
    for port in host.open_ports
        println("  $(port.number)/$(port.protocol) - $(port.service)")
    end
end

# Service fingerprinting
services = fingerprint("target.example.com", [22, 80, 443])

# DNS operations
records = dns_lookup("example.com", [A, AAAA, MX, TXT])
reverse = reverse_dns("8.8.8.8")

# Network monitoring
packets = capture_packets("eth0"; filter="tcp port 443", count=1000)
for pkt in packets
    analyze_packet(pkt)
end
```

### Analysis Module

Security analysis primitives:

```julia
using Spectra.Analysis

# Entropy analysis
entropy = calculate_entropy(data)
is_compressed = entropy > 7.5
is_encrypted = entropy > 7.9

# Pattern detection
patterns = detect_patterns(binary_data, [
    PATTERN_CRYPTO_CONSTANTS,
    PATTERN_SHELLCODE,
    PATTERN_BASE64,
    PATTERN_URL_ENCODED
])

# Binary analysis
pe_info = analyze_pe("malware.exe")
elf_info = analyze_elf("suspicious_binary")

# String extraction
strings = extract_strings(binary; min_length=4, encoding=:ascii)
strings = extract_strings(binary; encoding=:unicode)
```

### Encoding Module

Encoding and format conversions:

```julia
using Spectra.Encoding

# Base encodings
encoded = base64_encode(data)
decoded = base64_decode(encoded)
encoded = base32_encode(data)
encoded = base85_encode(data)

# URL encoding
safe = url_encode("query string with spaces")
original = url_decode(safe)

# Hex operations
hex = to_hex(bytes)
bytes = from_hex(hex)

# Serialization
json = to_json(obj; pretty=true)
obj = from_json(json, MyType)
```

### Protection Module

Defense and hardening tools:

```julia
using Spectra.Protection

# Input validation
validate(email, EMAIL_PATTERN) || error("Invalid email")
validate(phone, PHONE_PATTERN) || error("Invalid phone")

# Sanitization
safe_html = sanitize_html(user_input)
safe_sql = escape_sql(user_input)
safe_cmd = escape_shell(user_input)

# Rate limiting
limiter = RateLimiter(100, Minute(1))  # 100 requests per minute

function handle_request(client_ip)
    if !check_limit(limiter, client_ip)
        return HTTP.Response(429, "Too Many Requests")
    end
    # Process request
end

# Token generation
csrf_token = generate_token(32)
api_key = generate_api_key()
session_id = generate_session_id()
```

## Performance Benchmarks

| Operation | Spectra | Python Equivalent | Speedup |
|-----------|---------|-------------------|---------|
| SHA256 1GB | 0.8s | 4.2s | 5.2x |
| AES-GCM encrypt 1GB | 1.2s | 8.5s | 7.1x |
| Port scan /24 | 0.9s | 12.3s | 13.6x |
| Pattern matching 10M strings | 2.1s | 45.0s | 21.4x |
| Entropy calculation 100MB | 0.3s | 2.8s | 9.3x |

## Configuration

```julia
# Global configuration
Spectra.configure(
    thread_pool_size = 8,
    network_timeout = Second(30),
    dns_servers = ["8.8.8.8", "1.1.1.1"],
    crypto_backend = :native,  # or :openssl
    log_level = :warn
)
```

## Thread Safety

All Spectra operations are thread-safe:

```julia
using Base.Threads

# Parallel scanning
hosts = ["192.168.1.$i" for i in 1:254]
results = Vector{ScanResult}(undef, length(hosts))

@threads for i in eachindex(hosts)
    results[i] = port_scan(hosts[i], ports=[22, 80, 443])
end
```

## Integration with Other Tools

Spectra provides the foundation for other suite tools:

```julia
# Oracle uses Spectra for code analysis
using Spectra.Analysis
entropy = calculate_entropy(code_section)

# Vortex uses Spectra for network operations
using Spectra.Network
dns_records = dns_lookup(domain, [A, AAAA])

# Phantom uses Spectra for cryptography
using Spectra.Crypto
hash = sha256(evidence)
```

## API Reference

See the complete [API Reference](api.md) for detailed function signatures and parameters.

---

[Back to Main Documentation](../../README.md)
