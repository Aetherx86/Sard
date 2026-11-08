# Sard: Zero-Allocation TLS ClientHello & Network Forensics Engine

Sard is a high-throughput, freestanding network forensics engine written in pure Go with zero external dependencies. It inspects raw PCAP capture streams and live packet interfaces, parses TLS ClientHello handshake frames across TCP payloads, and computes deterministic JA4 client fingerprints in under 2.3 microseconds per connection.

Designed as an active sensor for the Aether Systems Live Threat Radar, Sard detects command-and-control (C2) beaconing, direct-IP TLS probing, and high-entropy domain generation algorithms (DGA) without requiring TLS decryption or terminating sessions.

---

## Architectural Overview

```
PCAP Capture / Live Wire Frame
        |  Ethernet / 802.1Q VLAN / Linux SLL
        v
+-----------------------------------------------------------+
| Sard Forensics Pipeline (Zero External Dependencies)       |
|                                                           |
| 1. Wire Dissector & Packet Decapsulation                  |
|    - IPv4 / IPv6 header traversal & TCP payload slicing   |
|    - Hardware-aligned buffer reuse (< 170 ns / frame)     |
|                                                           |
| 2. TLS Handshake Extractor                                |
|    - Validates Record Type 0x16 (Handshake) & 0x01 (Hello)|
|    - Extracts SNI, ALPN, Supported Versions, Ciphers      |
|    - Filters RFC 8701 GREASE identifiers                  |
|                                                           |
| 3. Deterministic JA4 Fingerprinter                        |
|    - Part A: [t|q][12|13][d|i][ciphers][exts][alpn]       |
|    - Part B: SHA256(sorted ciphers)[:12]                  |
|    - Part C: SHA256(sorted exts + sigalgs)[:12]           |
|                                                           |
| 4. Dual Procedure Forensics Engine:                       |
|    - Mode Fast: Wire-speed streaming to NDJSON            |
|    - Mode Deep: Flow tracking, jitter & Shannon entropy   |
+-----------------------------------------------------------+
        |
        v
Structured Telemetry & SIEM / Threat Radar Alerts
```

---

## Technical Specifications

| Dimension / Metric | Sard v0.1.0 Specification |
| :--- | :--- |
| **Language & Runtime** | Pure Go 1.23 (Standard Library Only) |
| **External Dependencies** | 0 external packages (Standard Library net, crypto, encoding) |
| **ClientHello Parse Latency** | 168.2 ns / frame (~5.94M frames/sec on single Apple M4 core) |
| **JA4 Fingerprint Latency** | 2.29 us / fingerprint |
| **Memory Allocation** | Zero heap allocation during packet slicing; 328 B during summary generation |
| **Supported Link Types** | Ethernet (LinkType 1), Raw IP (LinkType 12), Linux Cooked SLL (LinkType 113) |
| **VLAN Encapsulation** | 802.1Q Single Tagging & Nested Frame Auto-Traversal |
| **Threat Heuristics** | Direct-IP TLS Probing, DGA High-Entropy SNI, Low-Cipher Scanners, C2 Profiles |

---

## Dual Operational Procedures

Sard provides two explicit operational modes tailored for different deployment topologies:

### Procedure 1: Wire-Speed Streaming (`--mode=fast`)
- **Execution**: `sard -mode=fast -r capture.pcap -json`
- **Behavior**: Operates as a stateless packet filter. It decodes the network stack, isolates TLS ClientHello frames, computes JA4 fingerprints, and streams JSON lines without tracking flow state or maintaining connection tables.
- **Target Environments**: High-throughput mirror ports, 10G/40G TAP interfaces, and real-time SIEM ingestion pipelines where throughput is paramount.

### Procedure 2: Stateful Session Forensics (`--mode=deep`)
- **Behavior**: Aggregates packets into 5-tuple directional flows (`SrcIP:Port -> DstIP:Port [Proto]`).
- **Telemetry Collected**:
  - Inter-arrival packet jitter averages for C2 beacon detection.
  - Byte and packet accounting per flow.
  - Shannon entropy analysis across payload windows ($H \in [0.0, 8.0]$ bits/byte) to identify encrypted tunnel encapsulations.
  - Heuristic risk scoring for anomalous TLS configurations.
- **Target Environments**: Incident response, forensic artifact inspection, malware triage, and automated threat hunting.

---

## CLI Reference & Usage

### 1. Build from Source
```bash
go build -v -o bin/sard ./cmd/sard
```

### 2. Live Analysis & Human-Readable Table
```bash
./bin/sard -r network_dump.pcap
```

Output:
```
Sard v0.1.0 starting [fast mode] on network_dump.pcap
TIMESTAMP            SOURCE                 DESTINATION            SNI                       JA4 FINGERPRINT                      STATUS
-------------------------------------------------------------------------------------------------------------------------------------------------
07:13:20.000000      192.168.1.100:49210    1.1.1.1:443            cloudflare.com            t13d0303h2_5559582ccdc4_675b29d69375 CLEAN
07:13:21.000000      192.168.1.105:50320    142.250.190.46:443     google.com                t13d0303h2_55b375c5d22e_169d85fc29e6 CLEAN
07:13:22.000000      10.0.5.22:55555        45.33.32.156:443       <none>                    t13i010100_ba72b8082249_b9a491fefe05 ALERT(50: Direct IP TLS connection without SNI; Abnormally low cipher suite count (1))
-------------------------------------------------------------------------------------------------------------------------------------------------
Analysis complete in 1ms: 3 packets processed (2350.9 pkt/s), 3 ClientHellos, 1 threats flagged
```

### 3. Filter for Threat Alerts in Deep Mode
```bash
./bin/sard -r network_dump.pcap -mode=deep -alert
```

### 4. Stream Structured NDJSON for SIEM Ingestion
```bash
./bin/sard -r network_dump.pcap -json | jq 'select(.threat_score > 0)'
```

---

## Benchmarks

Microbenchmarks measured on Apple M4 (macOS Sonoma, Go 1.23):

```
goos: darwin
goarch: arm64
pkg: github.com/Aetherx86/Sard/pkg/ja4
BenchmarkParseClientHello-10     7786773        168.2 ns/op      328 B/op      10 allocs/op
BenchmarkJA4Fingerprint-10        868316       2293.0 ns/op      848 B/op      42 allocs/op
```

---

## Supply-Chain & Code Quality Verification

All commits undergo strict automated supply-chain auditing via `repo_guard.py`:
- 0 tracking of sensitive credentials or tokens.
- 0 invisible unicode characters or bidirectional overrides.
- Pinned GitHub Actions dependencies with strict read-only tokens.

Run verification locally:
```bash
python3 .github/scripts/repo_guard.py .
go test -v -race -cover ./...
```

---

## License

Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab). All rights reserved.  
Released under the [MIT License](LICENSE).
