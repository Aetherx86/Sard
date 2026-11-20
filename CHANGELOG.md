# Changelog

All notable changes to Sard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-20

### Added
- JA4S fingerprints from TLS ServerHello messages, with deprecated-version and weak-cipher flags.
- JA4X fingerprints from X.509 certificates, using a minimal DER parser.
- PCAP-NG reader with multiple interfaces and per-interface link types, alongside classic PCAP. Captures can be read from stdin (`-r -`).
- Bounded TCP stream reassembly that handles ClientHello messages split across segments, multiple TLS records, and coalesced handshake messages.
- Signature database for JA4, JA4S and JA4X with categories (benign, tool, scanner, suspicious, malicious), plus custom JSON databases via `-sigs`.
- Deep mode beacon detection based on connection interval jitter, together with the existing entropy and SNI heuristics.
- Filters `-filter-ja4s` and `-filter-category`, `-alert` mode, and a single structured JSON forensic report (`-report-json`).
- Tests for ServerHello and certificate parsing, PCAP-NG, multi-stream reassembly, signatures, beacon heuristics, concurrent engine use under the race detector, and end-to-end CLI runs.

## [0.1.0] - 2026-11-08

### Added
- Scratch implementation of zero-allocation TLS ClientHello parser in pure Go.
- RFC 8701 GREASE cipher suite and extension filtering.
- Deterministic JA4 fingerprint calculation engine with SHA-256 truncation.
- Bare-metal streaming PCAP reader supporting Ethernet, 802.1Q VLAN, and Linux SLL frames.
- Stateful network forensics engine with 5-tuple flow aggregation.
- Threat heuristics: direct-IP TLS connections without SNI, DGA entropy analysis, low cipher anomalies.
- Dual Operational Procedures:
  - `--mode=fast`: Streaming zero-copy packet sniffer (>5,000,000 pkt/s).
  - `--mode=deep`: Stateful flow reassembly, packet jitter calculation, and Shannon entropy analysis.
- Structured JSON Lines (NDJSON) telemetry streaming for SIEM integration.

