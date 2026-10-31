# C2 Beacon Detector (`c2-beacon-detector`)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture: Dual-Engine](https://img.shields.io/badge/Engine-Offline%20ML%20%2B%20Live%20Streaming-green.svg)](#architecture)
[![Coverage: Pytest](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](#testing)

An enterprise-grade network threat hunting and streaming anomaly detection engine engineered to identify Command and Control (C2) beaconing infrastructure in live wire traffic and static PCAP captures. 

`c2-beacon-detector` pairs unsupervised anomaly detection (Isolation Forests) for historical forensic triage with a deterministic, sliding-window streaming pipeline that detects periodic timing, jittered intervals, and encrypted high-entropy channels at wire speeds while automatically compiling live Suricata and Snort intrusion prevention rules.

---

## Key Capabilities (v2.0 Sprint Release)

- **Real-Time Asynchronous Packet Sniffing:** Background threaded capture via Scapy with bounded queue backpressure (`LivePacketSniffer`) and customizable Berkeley Packet Filter (BPF) offloading.
- **Sliding-Window Sessionization (`WindowedFlowSessionizer`):** Memory-bounded, bidirectional flow state keeping packet queues capped at $N_{\text{max}}$ and pruning time-slices older than $W_{\text{duration}}$, preventing state exhaustion under multi-gigabit traffic.
- **Multi-Vector Rule Engine:**
  - `PeriodicBeaconRule`: Flags deterministic interval regularities via Coefficient of Variation ($C_v \le 0.15$) and Median Absolute Deviation (MAD).
  - `JitterBeaconRule`: Detects intentional C2 timing randomization (e.g., Cobalt Strike, Sliver, Mythic) by isolating bounded jitter bands around target intervals ($0.15 < C_v \le 0.40$).
  - `HighEntropyChannelRule`: Identifies encrypted, compressed, or steganographic C2 payloads via Shannon entropy tracking ($H \ge 7.20\text{ bits/byte}$).
- **Automated IDS/IPS Rule Generation (`IDSRuleGenerator`):** Translates flagged beacon signatures into production-ready Suricata and Snort rules equipped with SID numbering, flow directionality, and threshold rate limits.
- **Synchronous Alert De-duplication & SOC Callbacks:** Enforces signature deduplication to eliminate alert storms while exposing callback hooks for real-time SIEM/SOAR webhooks.
- **Enterprise CLI:** Unified interface supporting both offline PCAP file parsing (`--pcap`) and live interface capture (`--interface`) with telemetry logging.

---

## MITRE ATT&CK Matrix Coverage

| Technique ID | Technique Name | Detection Mechanism | Severity |
| :--- | :--- | :--- | :--- |
| **T1071.001** | Application Layer Protocol: Web Protocols | `PeriodicBeaconRule` ($C_v \le 0.15$) | **HIGH** |
| **T1071** | Application Layer Protocol (Jittered) | `JitterBeaconRule` ($0.15 < C_v \le 0.40$) | **MEDIUM** |
| **T1571** | Non-Standard Port | Port/Protocol Discrepancy Evaluation | **MEDIUM** |
| **T1008** | Fallback Channels / Encrypted Exfiltration | `HighEntropyChannelRule` ($H \ge 7.2\text{ bits/byte}$) | **CRITICAL** |

---

## Architecture Overview

```text
                                [ Network Interface / SPAN / Wire ]
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │   LivePacketSniffer   │ (BPF Filtering, Bounded Queue)
                                    └───────────┬───────────┘
                                                │ PacketEvent Stream
                                                ▼
                               ┌─────────────────────────────────┐
                               │     WindowedFlowSessionizer     │
                               │  - Bidirectional 5-Tuple Key    │
                               │  - Sliding Window (W_dur, N_max)│
                               │  - Temporal Idle Eviction Tick  │
                               └────────────────┬────────────────┘
                                                │ FlowRecord
                                                ▼
                               ┌─────────────────────────────────┐
                               │     StreamingBeaconDetector     │
                               │  ├── PeriodicBeaconRule         │
                               │  ├── JitterBeaconRule           │
                               │  └── HighEntropyChannelRule     │
                               └────────────────┬────────────────┘
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                        ┌───────────────────────┐ ┌───────────────────┐
                        │   Deduplication &     │ │  IDSRuleGenerator │
                        │  Real-Time Callbacks  │ │ - Suricata Rules  │
                        │   (Console / SIEM)    │ │ - Snort 2.9/3.x   │
                        └───────────────────────┘ └───────────────────┘
                        