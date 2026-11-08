# Sard

Wire-Speed PCAP Forensics & JA4 TLS Fingerprinting Daemon

Sard is a zero-allocation TLS session dissector, JA4 fingerprinting engine, and network forensics daemon written in pure Go with zero external dependencies. It parses raw network packet captures (PCAP/PCAPNG) and live network streams to extract cryptographic client fingerprints, calculate packet timing jitter, evaluate DGA Shannon entropy, and isolate anomalous or malicious connection flows.

## Architecture

```
                  +-----------------------------------+
                  |     Raw PCAP / Network Stream     |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |      Bare-Metal PCAP Reader       |
                  |  (Ethernet, 802.1Q VLAN, SLL)     |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |     IP Packet Dissector & TCP     |
                  |     Zero-Copy Header Slicing      |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |   TLS ClientHello Fast Parser     |
                  |  - RFC 8701 GREASE Filtering      |
                  |  - Cipher Suites & Extensions     |
                  |  - SNI, ALPN, Supported Curves    |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |    JA4 Fingerprinting Engine      |
                  |       t13d1516h2_..._...          |
                  +-----------------+-----------------+
                                    |
                                    v
     +------------------------------+------------------------------+
     |                                                             |
     v                                                             v
+----+-----------------------------+  +----------------------------+----+
| Procedure A: High-Throughput Wire|  | Procedure B: Deep Forensics     |
| (--mode=fast)                    |  | (--mode=deep)                   |
| Zero-copy streaming             |  | Stateful 5-tuple flow tracking  |
| >5,000,000 packets/sec           |  | Timing jitter & inter-arrival   |
| Raw JA4 extraction               |  | DGA Shannon entropy analysis    |
| Direct stdout / NDJSON           |  | Heuristic threat scoring        |
+----------------------------------+  +---------------------------------+
```

### Protocol & Cryptographic Invariants

1. Zero External Dependencies: Implemented strictly on the Go standard library (`encoding/binary`, `crypto/sha256`, `math`, `sync`).
2. RFC 8701 GREASE Filtering: Automatically filters out Generate Random Extensions And Sustain Extensibility (GREASE) values (`0x?a?a`) to ensure reproducible fingerprints across modern TLS stacks (BoringSSL, Chromium, Apple Network).
3. Deterministic Sorting: Cipher suites and extensions are sorted in ascending hexadecimal order before hashing to yield canonical JA4 signatures.
4. Memory Safety: All packet slicing relies on pre-validated bounds checking and slice sub-referencing, avoiding dynamic allocations in hot ingestion loops.

## Dual Operational Procedures

Sard provides two execution modes tailored to operational requirements:

### 1. High-Throughput Wire Streaming (`--mode=fast`)
Optimized for line-rate packet ingestion, real-time IDS sensor feeds, and embedded packet tap appliances. Bypasses stateful flow caches to emit parsed TLS ClientHello fingerprints directly to stdout or NDJSON with zero heap churn.
- Throughput: Exceeds 5,000,000 packets/sec per worker core.
- Memory: Constant overhead (< 16 MB RSS).

### 2. Deep Forensics & Threat Analytics (`--mode=deep`)
Optimized for incident response, malware traffic analysis (MTA), and SOC telemetry. Reassembles 5-tuple TCP conversation flows, monitors inter-arrival packet timing jitter, computes sliding-window Shannon entropy on SNI hostnames to detect Domain Generation Algorithms (DGA), and flags anomalies (e.g. direct-IP TLS connections without SNI, low-cipher enumeration).

## Installation

```bash
git clone https://github.com/Aetherx86/Sard.git
cd Sard
go build -o bin/sard ./cmd/sard
```

## CLI Usage

```bash
# Analyze a PCAP capture in fast wire streaming mode
./bin/sard -r capture.pcap

# Deep stateful forensics with structured NDJSON output
./bin/sard -r capture.pcap --mode=deep --json

# Filter for specific SNI domain
./bin/sard -r capture.pcap -filter-sni="internal.vault"

# Filter by JA4 fingerprint prefix
./bin/sard -r capture.pcap -filter-ja4="t13d1516h2"

# Alert mode: emit only flows with positive threat heuristics
./bin/sard -r capture.pcap --mode=deep --alert
```

## Command-Line Flags

| Flag | Default | Description |
|---|---|---|
| `-r <file>` | `""` | Path to PCAP capture file (use `-` for stdin) |
| `--mode` | `fast` | Analysis procedure: `fast` (wire streaming) or `deep` (stateful forensics) |
| `--json` | `false` | Output events as newline-delimited JSON (NDJSON) |
| `--alert` | `false` | Only emit flows with positive threat heuristic scores |
| `-filter-sni` | `""` | Filter emitted events by SNI substring |
| `-filter-ja4` | `""` | Filter emitted events by JA4 fingerprint prefix |
| `--version` | `false` | Display engine version and exit |

## Library API

Sard can be embedded directly into custom Go network monitoring daemons or eBPF user-space consumers:

```go
package main

import (
    "fmt"
    "github.com/Aetherx86/Sard/pkg/ja4"
)

func main() {
    engine := ja4.NewForensicsEngine("deep")

    packet := &ja4.Packet{
        SrcIP:     "192.168.1.50",
        DstIP:     "198.51.100.20",
        SrcPort:   51234,
        DstPort:   443,
        Payload:   rawTLSPayload,
    }

    flow, isClientHello := engine.ProcessPacket(packet)
    if isClientHello {
        fmt.Printf("JA4: %s SNI: %s ThreatScore: %d\n",
            flow.JA4, flow.SNI, flow.ThreatScore)
    }
}
```

## Benchmarks

Micro-benchmarks executed on an Apple M-series core (freestanding Go 1.23 runtime):

```
BenchmarkParseClientHello-10       14,200,000 ops/s      70.4 ns/op       0 B/op     0 allocs/op
BenchmarkJA4Computation-10          4,850,000 ops/s     206.1 ns/op       0 B/op     0 allocs/op
BenchmarkShannonEntropy-10         18,600,000 ops/s      53.8 ns/op       0 B/op     0 allocs/op
BenchmarkFastStreamingLoop-10       5,400,000 pkt/s     185.0 ns/op       0 B/op     0 allocs/op
```

## Verification & Supply Chain Safety

Run the complete test suite with Go's race detector enabled:

```bash
go test -v -race ./...
```

Verify compliance with repository integrity and supply-chain policies:

```bash
python3 .github/scripts/repo_guard.py . --strict
```

## License

MIT License. Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab).
