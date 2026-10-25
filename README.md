# C2 Beacon Detector: Unsupervised Network Telemetry Anomaly Detection

[![CI Pipeline](https://github.com/Simiyuu/c2-beacon-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/Simiyuu/c2-beacon-detector/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker Compliant](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade behavioral anomaly detection engine designed to detect covert Command and Control (C2) beaconing patterns within promiscuous network telemetry (PCAP) without requiring payload decryption or signature matching.

---

## Threat Model & MITRE ATT&CK Mapping

Modern post-exploitation frameworks (e.g., Cobalt Strike, Sliver, Mythic, Havoc) utilize encrypted HTTP/S or DNS channels to maintain command loops. While Layer 7 payload inspection fails against TLS 1.3 or double-encrypted channels, beaconing traffic exhibits deterministic behavioral artifacts in timing and payload geometry.

| Tactic | Technique ID | Technique Name | Detection Vector |
| :--- | :--- | :--- | :--- |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Low timing variance ($\sigma_{\text{IAT}}$) across persistent outbound flows |
| **Command and Control** | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Encrypted Channel: Symmetric Cryptography | High-entropy payload distribution with narrow byte standard deviations |
| **Defense Evasion** | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated/Encrypted Files or Information | Detection resilience against stochastic sleep jitter up to 50% |

---

## Architectural Data Flow

```text
       Raw PCAP Telemetry / Mirror Tap
                     │
                     ▼
       ┌───────────────────────────┐
       │     L2-L4 Decapsulator    │  <-- Strips 802.1Q VLANs, drops non-IP/ARP,
       │     (src/parser.py)       │      guarantees monotonic frame ordering
       └─────────────┬─────────────┘
                     │ Normalized Packet Stream
                     ▼
       ┌───────────────────────────┐
       │  Bidirectional Aggregator │  <-- Normalizes flow tuple: (min(IP), max(IP),
       │     (src/models.py)       │      min(Port), max(Port), Protocol)
       └─────────────┬─────────────┘
                     │ Session Flow Records
                     ▼
       ┌───────────────────────────┐
       │ Behavioral Feature Engine │  <-- Computes Inter-Arrival Time variance (IAT),
       │    (src/features.py)      │      packet length entropy, and burst metrics
       └─────────────┬─────────────┘
                     │ Multivariate Feature Matrix (X)
                     ▼
       ┌───────────────────────────┐
       │ Isolation Forest Detector │  <-- Unsupervised isolation tree partitioning;
       │    (src/detector.py)      │      short path lengths flag anomalous periodicity
       └─────────────┬─────────────┘
                     │ Anomaly Decisions (-1 / +1)
                     ▼
       ┌───────────────────────────┐
       │   CLI / SIEM Integration  │  <-- Structured JSON alerts via stdout
       │      (src/cli.py)         │      or formatted console threat reports
       └───────────────────────────┘
```

---

## Mathematical Foundation

### 1. Inter-Arrival Time (IAT) Variance
Legitimate human web traffic is bursty, Poisson-distributed, or multi-modal. Automated beacon check-ins cluster tightly around a deterministic interval $T$:

$$\mu_{\text{IAT}} = \frac{1}{N - 1} \sum_{i=2}^{N} (t_i - t_{i-1})$$

$$\sigma_{\text{IAT}} = \sqrt{\frac{1}{N - 1} \sum_{i=2}^{N} \left((t_i - t_{i-1}) - \mu_{\text{IAT}}\right)^2}$$

Where $t_i$ represents the packet arrival epoch. A near-zero $\sigma_{\text{IAT}}$ indicates a periodic machine heartbeat.

### 2. Unsupervised Anomaly Isolation
The detection engine employs an **Isolation Forest** ensemble. The anomaly score $s$ for an instance $x$ given a dataset of size $n$ is defined as:

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where $h(x)$ is the path length (number of random hyperplane splits required to isolate $x$), $E(h(x))$ is the expectation across trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree:

$$c(n) = 2 \left( \ln(n - 1) + 0.5772156649 \right) - \frac{2(n - 1)}{n}$$

Because periodic beacons occupy sparse, low-variance regions of the feature hyperspace, they require significantly fewer splits ($E(h(x)) \ll c(n)$), resulting in anomaly scores close to $-1.0$.

---

## Empirical Sleep Jitter Resilience Benchmark

To validate resilience against adversarial evasion, the engine was benchmarked against synthetic traffic traces injected with bounded sleep jitter $j \in [0.0, 0.50]$ sampled from $\mathcal{U}[T(1 - j), T(1 + j)]$:

```powershell
python -m scripts.evaluate
```

### Benchmark Results

| Jitter % | Status | Std Dev ($\sigma_{\text{IAT}}$) | Anomaly Score | Empirical Assessment |
| :---: | :---: | :---: | :---: | :--- |
| **0%** | **DETECTED** | `0.0000s` | `-0.6562` | Fixed metronome check-in; isolated in early tree splits. |
| **10%** | **DETECTED** | `0.2487s` | `-0.6495` | Light jitter; tight clustering maintains high anomaly score. |
| **20%** | **DETECTED** | `0.6233s` | `-0.6420` | Standard Cobalt Strike sleep variance; cleanly flagged. |
| **30%** | **DETECTED** | `0.8298s` | `-0.6380` | Moderate perturbation; low entropy profile maintains separation. |
| **40%** | **DETECTED** | `1.1827s` | `-0.6233` | Elevated jitter; variance remains distinct from bursty browsing. |
| **50%** | **DETECTED** | `1.2643s` | `-0.6195` | Heavy perturbation; successfully isolated across multivariate cuts. |

---

## Getting Started

### Prerequisites
* Python 3.11+
* Docker (optional for containerized deployment)

### Local Setup
```powershell
# Clone the repository
git clone [https://github.com/Simiyuu/c2-beacon-detector.git](https://github.com/Simiyuu/c2-beacon-detector.git)
cd c2-beacon-detector

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1   # On Linux/macOS: source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest
```

### Running Tests
```powershell
# Run the complete unit, integration, and fuzzing suite (18 tests)
python -m pytest -v
```

---

## Deployment & Usage

### 1. Command-Line Interface (CLI)

```powershell
# Human-readable console alert report
python -m src.cli --pcap sample_data/traffic.pcap

# Machine-readable JSON output for SIEM ingestion (Splunk, Elastic)
python -m src.cli --pcap sample_data/traffic.pcap --json
```

### 2. Containerized Execution (Docker)

The container image runs with an unprivileged system user (`appuser:10001`) to protect the host against packet-parsing memory corruption exploits.

```powershell
# Build the container image
docker build -t c2-beacon-detector:latest .

# Run analysis by mounting a local PCAP volume
docker run --rm -v ${PWD}/sample_data:/data c2-beacon-detector:latest --pcap /data/traffic.pcap --json
```

---

## Security Engineering Standards Applied

* **Defensive Input Handling:** Strict Pydantic contracts and header guards prevent crashes on malformed 802.1Q tags or truncated IP packets.
* **Hermetic CI Pipeline:** GitHub Actions runs all regression and fuzzing tests across clean Ubuntu containers on every push.
* **Least Privilege Containerization:** Unprivileged UID assignment prevents container escapes during PCAP parsing.