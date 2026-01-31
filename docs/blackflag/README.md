# BlackFlag ECU Documentation

> **Professional ECU Diagnostics & Tuning Suite**

BlackFlag is a comprehensive automotive security and diagnostics platform for ECU analysis, CAN bus research, and vehicle security testing. Available in two editions: Standard (passenger vehicles) and HD (heavy-duty commercial vehicles).

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      BLACKFLAG ECU SUITE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Protocol Support                      │   │
│  │  CAN 2.0  │  CAN-FD  │  J1939  │  UDS  │  KWP2000       │   │
│  │  OBD-II   │  ISO-TP  │  DoIP   │  XCP  │  Seed-Key      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Diagnostics │  │  Security   │  │     Analysis            │ │
│  │             │  │             │  │                         │ │
│  │ • DTC Read  │  │ • Seed-Key  │  │ • Traffic Capture       │ │
│  │ • Live Data │  │ • Auth      │  │ • Message Decode        │ │
│  │ • Calibrate │  │ • Fuzzing   │  │ • Signal Analysis       │ │
│  │ • Flash     │  │ • Bypass    │  │ • Reverse Engineering   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Hardware Support                      │   │
│  │  Peak PCAN  │  Kvaser  │  Vector  │  SocketCAN          │   │
│  │  CANtact    │  USB2CAN │  ELM327  │  J2534              │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Editions

### BlackFlag Standard

Passenger vehicle focus:
- OBD-II diagnostics
- CAN bus analysis
- UDS security testing
- ECU flashing
- DBC file support

### BlackFlag HD (Heavy Duty)

Commercial vehicle focus:
- J1939 protocol support
- HD-OBD diagnostics
- Multi-ECU systems
- Fleet diagnostics
- DOT compliance tools

## Features

### Diagnostics

| Feature | Description |
|---------|-------------|
| **DTC Read/Clear** | Diagnostic trouble codes |
| **Live Data** | Real-time sensor values |
| **Freeze Frame** | Snapshot at fault |
| **VIN Decode** | Vehicle identification |
| **ECU Info** | Module identification |
| **Calibration** | Parameter adjustment |

### Security Testing

| Feature | Description |
|---------|-------------|
| **Seed-Key Cracking** | Security access bypass |
| **UDS Fuzzing** | Protocol fuzzing |
| **Auth Analysis** | Authentication testing |
| **Replay Attacks** | Message replay |
| **CAN Injection** | Frame injection |
| **DoS Testing** | Denial of service |

### Analysis

| Feature | Description |
|---------|-------------|
| **Traffic Capture** | CAN bus recording |
| **Message Decode** | DBC/KCD parsing |
| **Signal Graphs** | Visual analysis |
| **Diff Analysis** | Compare captures |
| **Reverse Engineering** | Unknown protocol analysis |

## Installation

### Linux

```bash
# Debian/Ubuntu
wget https://github.com/bad-antics/blackflag-ecu/releases/latest/download/blackflag-linux-amd64.deb
sudo dpkg -i blackflag-linux-amd64.deb

# Configure SocketCAN
sudo modprobe can
sudo modprobe can_raw
sudo modprobe vcan  # Virtual CAN for testing

# Set up interface
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up
```

### Windows

```powershell
# Download installer
Invoke-WebRequest -Uri "https://github.com/bad-antics/blackflag-ecu/releases/latest/download/blackflag-windows-x64.exe" -OutFile "blackflag-setup.exe"

# Install with drivers
.\blackflag-setup.exe /DRIVERS
```

### Hardware Setup

```bash
# Peak PCAN-USB
sudo modprobe peak_usb
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# Kvaser
sudo modprobe kvaser_usb
# Use Kvaser CANlib

# SocketCAN (Generic USB adapters)
sudo slcand -o -c -s6 /dev/ttyUSB0 slcan0
sudo ip link set slcan0 up
```

## Quick Start

### Basic Diagnostics

```bash
# List available interfaces
blackflag list

# Connect to vehicle
blackflag connect can0 --bitrate 500000

# Read VIN
blackflag vin

# Read DTCs
blackflag dtc read

# Clear DTCs
blackflag dtc clear

# Live data
blackflag live --pids 0x0C,0x0D,0x05  # RPM, Speed, Coolant
```

### CAN Bus Analysis

```bash
# Capture traffic
blackflag capture -i can0 -o capture.log

# Monitor live
blackflag monitor -i can0

# Filter specific IDs
blackflag monitor -i can0 --filter 0x7E0-0x7EF

# Decode with DBC
blackflag monitor -i can0 --dbc vehicle.dbc

# Analyze capture
blackflag analyze capture.log
```

### UDS Security Testing

```bash
# Enumerate ECUs
blackflag uds scan -i can0

# Read ECU info
blackflag uds info -i can0 --ecu 0x7E0

# Security access
blackflag uds security -i can0 --ecu 0x7E0 --level 1

# Seed-key analysis
blackflag seedkey analyze -i can0 --ecu 0x7E0 --samples 100

# Fuzz UDS services
blackflag uds fuzz -i can0 --ecu 0x7E0 --services 0x10-0x3F
```

## Protocol Support

### OBD-II

```python
# Python API
from blackflag import OBD

obd = OBD("can0")

# Mode 01 - Current Data
rpm = obd.query(0x01, 0x0C)       # Engine RPM
speed = obd.query(0x01, 0x0D)     # Vehicle Speed
coolant = obd.query(0x01, 0x05)   # Coolant Temp

# Mode 03 - DTCs
dtcs = obd.get_dtcs()
for dtc in dtcs:
    print(f"{dtc.code}: {dtc.description}")

# Mode 09 - Vehicle Info
vin = obd.get_vin()
```

### UDS (ISO 14229)

```python
from blackflag import UDS

uds = UDS("can0", tx_id=0x7E0, rx_id=0x7E8)

# Diagnostic Session Control
uds.diagnostic_session(0x01)  # Default session
uds.diagnostic_session(0x02)  # Programming session
uds.diagnostic_session(0x03)  # Extended session

# Security Access
seed = uds.request_seed(0x01)
key = calculate_key(seed)  # Your algorithm
uds.send_key(0x02, key)

# Read Data By Identifier
vin = uds.read_data(0xF190)
ecu_serial = uds.read_data(0xF18C)

# Write Data By Identifier (after security)
uds.write_data(0xF190, new_vin)

# Routine Control
uds.start_routine(0x0203)  # Start routine
result = uds.request_routine_results(0x0203)
```

### J1939 (Heavy Duty)

```python
from blackflag import J1939

j1939 = J1939("can0")

# Request PGN
engine_speed = j1939.request_pgn(0xF004)  # Electronic Engine Controller 1

# Monitor broadcast PGNs
for msg in j1939.listen():
    if msg.pgn == 0xFEF1:  # Cruise Control/Vehicle Speed
        print(f"Speed: {msg.data['wheel_speed']} km/h")

# DM1 - Active DTCs
dtcs = j1939.get_dm1()

# DM2 - Previously Active DTCs
prev_dtcs = j1939.get_dm2()
```

### CAN-FD

```python
from blackflag import CANFD

canfd = CANFD("can0", bitrate=500000, data_bitrate=2000000)

# Send FD frame
canfd.send(0x123, b'\x01\x02\x03' * 20, fd=True, brs=True)

# Monitor FD traffic
for frame in canfd.listen():
    if frame.is_fd:
        print(f"FD Frame: {frame.id:03X} [{len(frame.data)}] {frame.data.hex()}")
```

## Security Research

### Seed-Key Cracking

```python
from blackflag.security import SeedKeyAnalyzer

analyzer = SeedKeyAnalyzer("can0", ecu_id=0x7E0)

# Collect samples
samples = analyzer.collect_samples(count=1000)

# Analyze patterns
patterns = analyzer.analyze_patterns(samples)
print(f"Seed length: {patterns.seed_length}")
print(f"Key length: {patterns.key_length}")
print(f"Potential algorithm: {patterns.algorithm_guess}")

# Brute force (if applicable)
key_func = analyzer.brute_force(samples, algorithm="xor")

# Test key function
seed = b'\x12\x34\x56\x78'
key = key_func(seed)
success = analyzer.test_key(seed, key)
```

### CAN Fuzzing

```python
from blackflag.fuzzing import CANFuzzer

fuzzer = CANFuzzer("can0")

# Random fuzzing
fuzzer.fuzz_random(
    id_range=(0x000, 0x7FF),
    data_length=8,
    count=10000,
    delay=0.001
)

# Targeted fuzzing
fuzzer.fuzz_targeted(
    target_id=0x7E0,
    template=b'\x10\x01\x00\x00\x00\x00\x00\x00',
    positions=[2, 3, 4],  # Bytes to fuzz
    count=1000
)

# Monitor for crashes
fuzzer.monitor_responses(timeout=5.0)
```

### Replay Attacks

```python
from blackflag.replay import ReplayEngine

replay = ReplayEngine("can0")

# Record sequence
replay.record(duration=60, filter_ids=[0x100, 0x200, 0x300])

# Analyze captured sequence
replay.analyze()
print(f"Unique IDs: {replay.unique_ids}")
print(f"Total frames: {replay.frame_count}")

# Replay at original timing
replay.play()

# Replay with modifications
replay.play(
    speed=2.0,  # 2x speed
    modify={0x200: lambda data: data[:4] + b'\xFF\xFF\xFF\xFF'}
)
```

## DBC File Support

### Loading DBC Files

```python
from blackflag import DBC

# Load DBC
dbc = DBC.load("vehicle.dbc")

# Decode message
frame = can_interface.recv()
decoded = dbc.decode(frame)

print(f"Message: {decoded.name}")
for signal in decoded.signals:
    print(f"  {signal.name}: {signal.value} {signal.unit}")
```

### Creating DBC Files

```python
from blackflag.dbc import DBCBuilder

builder = DBCBuilder()

# Define message
builder.add_message(
    id=0x123,
    name="EngineData",
    length=8,
    signals=[
        Signal("RPM", start=0, length=16, scale=0.25, unit="rpm"),
        Signal("Speed", start=16, length=16, scale=0.01, unit="km/h"),
        Signal("Temp", start=32, length=8, offset=-40, unit="°C"),
    ]
)

# Save DBC
builder.save("my_vehicle.dbc")
```

## GUI Application

```bash
# Launch GUI
blackflag-gui

# Features:
# - Visual CAN bus monitor
# - DTC manager
# - Live data dashboard
# - Signal graph plotting
# - DBC editor
# - Seed-key calculator
```

## Configuration

```yaml
# blackflag.yml
interfaces:
  default: can0
  bitrate: 500000
  
protocols:
  obd:
    tx_id: 0x7DF
    rx_id: 0x7E8
  uds:
    tx_id: 0x7E0
    rx_id: 0x7E8
    
security:
  seed_key_timeout: 5.0
  max_auth_attempts: 3
  
logging:
  level: INFO
  file: blackflag.log
  
output:
  format: json
  path: ./reports/
```

## Hardware Compatibility

| Adapter | Support | Notes |
|---------|---------|-------|
| Peak PCAN-USB | ✅ Full | Recommended |
| Kvaser Leaf Light | ✅ Full | Good performance |
| CANtact | ✅ Full | Budget option |
| Vector VN1610 | ✅ Full | Professional |
| ELM327 | ⚠️ Limited | OBD-II only |
| SocketCAN | ✅ Full | Linux native |
| J2534 | ✅ Full | Windows |

## Safety Warning

⚠️ **IMPORTANT**: Improper use of ECU diagnostic tools can:
- Damage vehicle electronics
- Create safety hazards
- Void warranties
- Violate laws

Only use on vehicles you own or have explicit authorization to test. Never use while driving.

---

[Back to Main Documentation](../../README.md)
