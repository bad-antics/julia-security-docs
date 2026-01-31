# NullKia Mobile Security Framework

> **Comprehensive Mobile Security Testing in 12 Languages**

NullKia is a polyglot mobile security framework providing tools for Android and iOS security testing, written in Nim, Crystal, V, D, Red, Odin, Haxe, Zig, Kotlin, Lua, PHP, and Python.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     NULLKIA FRAMEWORK                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Android   │  │    iOS      │  │     Cross-Platform      │ │
│  │             │  │             │  │                         │ │
│  │ • APK Anal  │  │ • IPA Anal  │  │ • Traffic Intercept     │ │
│  │ • Smali     │  │ • Obj-C     │  │ • SSL Pinning Bypass    │ │
│  │ • Frida     │  │ • Swift     │  │ • Runtime Hooks         │ │
│  │ • Root Det  │  │ • JB Detect │  │ • Dynamic Analysis      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Language Implementations                    │   │
│  ├──────────┬──────────┬──────────┬──────────┬────────────┤   │
│  │ Nim      │ Crystal  │ V        │ D        │ Red        │   │
│  │ Odin     │ Haxe     │ Zig      │ Kotlin   │ Lua        │   │
│  │ PHP      │ Python   │          │          │            │   │
│  └──────────┴──────────┴──────────┴──────────┴────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Android Security

| Tool | Language | Description |
|------|----------|-------------|
| `nullkia-apk` | Nim | APK analysis and extraction |
| `nullkia-smali` | Crystal | Smali disassembly/patching |
| `nullkia-dex` | Zig | DEX file analysis |
| `nullkia-manifest` | V | AndroidManifest parser |
| `nullkia-root` | Kotlin | Root detection bypass |
| `nullkia-frida-android` | Python | Frida scripts for Android |

### iOS Security

| Tool | Language | Description |
|------|----------|-------------|
| `nullkia-ipa` | Nim | IPA analysis and extraction |
| `nullkia-objc` | D | Objective-C class dump |
| `nullkia-swift` | Odin | Swift metadata analysis |
| `nullkia-plist` | Crystal | Property list parser |
| `nullkia-jb` | Kotlin | Jailbreak detection bypass |
| `nullkia-frida-ios` | Python | Frida scripts for iOS |

### Cross-Platform

| Tool | Language | Description |
|------|----------|-------------|
| `nullkia-proxy` | Nim | MITM proxy with SSL interception |
| `nullkia-ssl` | Zig | SSL pinning bypass |
| `nullkia-hook` | Python | Universal runtime hooking |
| `nullkia-traffic` | Crystal | Traffic analysis |
| `nullkia-storage` | V | Secure storage analysis |

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/bad-antics/nullkia
cd nullkia

# Install all tools
./install.sh --all

# Install specific language tools
./install.sh --nim
./install.sh --crystal
./install.sh --zig
```

### Individual Tools

```bash
# Nim tools
nimble install nullkia-apk nullkia-ipa nullkia-proxy

# Crystal tools
shards install nullkia-smali nullkia-traffic

# Zig tools
zig build -Drelease-fast

# Python tools
pip install nullkia-frida nullkia-hook
```

### NullSec Linux

Pre-installed in NullSec Linux:

```bash
nullsec-menu
# Navigate to: Mobile Security → NullKia
```

## Quick Start

### Android APK Analysis

```bash
# Basic APK analysis
nullkia-apk analyze app.apk

# Extract APK contents
nullkia-apk extract app.apk -o ./extracted

# Decompile to Smali
nullkia-smali disassemble app.apk -o ./smali

# Find hardcoded secrets
nullkia-apk secrets app.apk

# Check for vulnerabilities
nullkia-apk vulnscan app.apk
```

### iOS IPA Analysis

```bash
# Basic IPA analysis
nullkia-ipa analyze app.ipa

# Extract IPA contents
nullkia-ipa extract app.ipa -o ./extracted

# Dump Objective-C classes
nullkia-objc dump app.ipa

# Find hardcoded secrets
nullkia-ipa secrets app.ipa

# Check Info.plist
nullkia-plist analyze ./extracted/Info.plist
```

### Dynamic Analysis with Frida

```python
# nullkia-frida script for Android
import nullkia.frida as nkf

# Connect to device
device = nkf.connect_usb()

# Spawn app with hooks
session = nkf.spawn(device, "com.example.app", [
    nkf.hooks.ssl_bypass(),
    nkf.hooks.root_bypass(),
    nkf.hooks.log_crypto(),
])

# Custom hook
@nkf.hook("com.example.app.LoginActivity", "login")
def on_login(username, password):
    print(f"Login: {username}:{password}")
    return nkf.CONTINUE
```

### Traffic Interception

```bash
# Start MITM proxy
nullkia-proxy start --port 8080 --ssl

# Configure device to use proxy
# Android: Settings → WiFi → Proxy → Manual → IP:8080
# iOS: Settings → WiFi → Configure Proxy → Manual → IP:8080

# Install CA certificate
nullkia-proxy cert export --format pem > nullkia-ca.pem
# Install on device

# Monitor traffic
nullkia-proxy monitor --filter "*.api.example.com"

# Intercept and modify
nullkia-proxy intercept --script modify.lua
```

## Language Modules

### Nim Tools

High-performance binary analysis:

```nim
# nullkia-apk - APK analyzer
import nullkia/apk

let apk = loadApk("app.apk")
echo "Package: ", apk.packageName
echo "Version: ", apk.versionName
echo "Permissions: ", apk.permissions
echo "Activities: ", apk.activities

for vuln in apk.findVulnerabilities():
  echo "Vulnerability: ", vuln.name
  echo "  Severity: ", vuln.severity
  echo "  Location: ", vuln.location
```

### Crystal Tools

Fast string and pattern analysis:

```crystal
# nullkia-smali - Smali processor
require "nullkia/smali"

smali = Nullkia::Smali.parse("classes.dex")

# Find method calls
smali.find_calls("Ljavax/crypto/Cipher;->getInstance").each do |call|
  puts "Crypto usage at: #{call.location}"
  puts "  Mode: #{call.arguments[0]}"
end

# Patch method
smali.patch("Lcom/app/Security;->isRooted", "const/4 v0, 0x0\nreturn v0")
smali.save("patched.dex")
```

### Zig Tools

Memory-safe binary operations:

```zig
// nullkia-dex - DEX analyzer
const std = @import("std");
const nullkia = @import("nullkia");

pub fn main() !void {
    const dex = try nullkia.Dex.open("classes.dex");
    defer dex.close();

    for (dex.classes()) |class| {
        std.debug.print("Class: {s}\n", .{class.name});
        
        for (class.methods()) |method| {
            if (method.containsString("password")) {
                std.debug.print("  Potential secret in: {s}\n", .{method.name});
            }
        }
    }
}
```

### V Tools

Simple manifest parsing:

```v
// nullkia-manifest - AndroidManifest parser
import nullkia.manifest

fn main() {
    m := manifest.parse('AndroidManifest.xml')!
    
    println('Package: ${m.package_name}')
    println('Min SDK: ${m.min_sdk}')
    println('Target SDK: ${m.target_sdk}')
    
    // Check for dangerous permissions
    for perm in m.permissions {
        if perm.is_dangerous() {
            println('⚠️  Dangerous: ${perm.name}')
        }
    }
    
    // Check for exported components
    for activity in m.activities.filter(it.exported) {
        println('📤 Exported: ${activity.name}')
    }
}
```

### Kotlin Tools

Android-native integration:

```kotlin
// nullkia-root - Root detection bypass
package com.nullkia.root

import de.robv.android.xposed.*

class RootBypass : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        // Hook common root detection methods
        XposedHelpers.findAndHookMethod(
            "java.io.File", lpparam.classLoader, "exists",
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val path = (param.thisObject as File).absolutePath
                    if (isRootPath(path)) {
                        param.result = false
                    }
                }
            }
        )
    }
    
    private fun isRootPath(path: String): Boolean {
        return rootPaths.any { path.contains(it) }
    }
}
```

### Python Tools

Frida integration and scripting:

```python
# nullkia-hook - Universal hooking framework
from nullkia import hook, Device

# Connect to device
device = Device.usb()

# Attach to running process
session = device.attach("com.example.app")

# Hook encryption
@hook.method("javax.crypto.Cipher", "doFinal")
def on_encrypt(self, data):
    print(f"Encrypting: {data.hex()}")
    result = hook.call_original(self, data)
    print(f"Result: {result.hex()}")
    return result

# Hook SSL
@hook.ssl_bypass()
def on_ssl():
    print("SSL pinning bypassed!")

# Start hooks
session.run()
```

## Frida Scripts

### Android Scripts

```javascript
// bypass_root.js - Root detection bypass
Java.perform(function() {
    // Hook File.exists()
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su"];
        
        if (rootPaths.some(p => path.includes(p))) {
            console.log("[Root] Blocked: " + path);
            return false;
        }
        return this.exists();
    };
    
    // Hook Runtime.exec()
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.includes("su") || cmd.includes("which")) {
            console.log("[Root] Blocked exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Not found");
        }
        return this.exec(cmd);
    };
});
```

### iOS Scripts

```javascript
// bypass_jailbreak.js - Jailbreak detection bypass
if (ObjC.available) {
    // Hook NSFileManager
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            var jbPaths = ["/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd"];
            if (jbPaths.some(p => this.path.includes(p))) {
                console.log("[JB] Blocked: " + this.path);
                retval.replace(0);
            }
        }
    });
    
    // Hook canOpenURL
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.includes("cydia://")) {
                console.log("[JB] Blocked URL: " + this.url);
                retval.replace(0);
            }
        }
    });
}
```

## Vulnerability Checks

### Android Checks

| Check | Description |
|-------|-------------|
| Exported Components | Unprotected activities/services |
| Backup Enabled | Allowes backup extraction |
| Debuggable | Debug mode enabled |
| Weak Crypto | Insecure algorithms |
| Hardcoded Secrets | API keys, passwords |
| WebView Vulns | JavaScript/file access |
| SQL Injection | Raw queries |
| Path Traversal | File path issues |

### iOS Checks

| Check | Description |
|-------|-------------|
| ATS Disabled | App Transport Security bypass |
| Weak Crypto | Insecure algorithms |
| Hardcoded Secrets | API keys, passwords |
| Keychain Issues | Insecure storage |
| URL Schemes | Deep link vulnerabilities |
| Pasteboard Leaks | Sensitive clipboard data |
| Binary Protections | PIE, ARC, stack canaries |

## Configuration

```yaml
# nullkia.yml
android:
  adb_path: /usr/bin/adb
  sdk_path: /opt/android-sdk
  
ios:
  idevice_path: /usr/bin/ideviceinfo
  
proxy:
  port: 8080
  ssl_port: 8443
  ca_cert: ~/.nullkia/ca.pem
  ca_key: ~/.nullkia/ca.key
  
frida:
  gadget_path: ~/.nullkia/gadgets/
  scripts_path: ~/.nullkia/scripts/
  
output:
  format: json  # json, html, pdf
  path: ./reports/
```

## Reports

Generate comprehensive security reports:

```bash
# Full analysis report
nullkia-report --apk app.apk --output report.html

# JSON for automation
nullkia-report --apk app.apk --format json --output report.json

# Compare versions
nullkia-report --compare app-v1.apk app-v2.apk
```

---

[Back to Main Documentation](../../README.md)
