# C2 Beacon Detector

An enterprise-grade network threat hunting and Command & Control (C2) beacon detection engine built in Python. Streams raw PCAP captures, reconstructs stateful bi-directional network flows, extracts scale-invariant timing and payload dispersion metrics, and evaluates flows against behavioral detection rules aligned to the MITRE ATT&CK framework.

---

## Architecture Overview

The detection engine operates as a streaming pipeline designed to process packet captures without unbounded memory consumption:

```
[ Raw PCAP / Wire Stream ]
           │
           ▼
  StreamingPacketReader (scapy.PcapReader lazy iteration)
           │
           ▼
    FlowSessionizer (Bi-directional 5-tuple session table + timeout eviction)
           │
           ▼
       RuleEngine (Concurrent heuristic & statistical rule evaluation)
      ├── PeriodicBeaconRule (T1071 - Zero/Low jitter clockwork beacons)
      ├── JitterTolerantRule (T1071.001 - Sleep randomized beaconing)
      ├── HighEntropyRule    (T1573 - Encrypted/packed egress tunnels)
      └── NonStandardPortRule (T1571 - Common services on anomalous ports)
           │
           ▼
    Deduplication Engine (Priority-weighted alert resolution)
           │
           ▼
      AlertExporter (SIEM JSON / NDJSON / Triage CSV)
```

---

## MITRE ATT&CK Coverage Matrix

| Technique ID | Technique Name | Tactic | Detection Methodology & Statistical Bounds | Default Severity |
| :--- | :--- | :--- | :--- | :--- |
| **T1071** | Application Layer Protocol | Command and Control | Clockwork inter-arrival timing: $C_v \le 0.10$, $\text{MAD} \le 0.50\text{s}$, $N \ge 5$ packets | `HIGH` |
| **T1071.001** | Web Protocols (Jittered) | Command and Control | Sleep variance tolerant: $0.10 < C_v \le 0.35$, $\text{MAD} \le 1.50\text{s}$, $N \ge 6$ packets | `MEDIUM` |
| **T1573** | Encrypted Channel | Command and Control | Payload dispersion: Vectorized Shannon entropy $H(X) \ge 7.20$ bits/byte | `HIGH` |
| **T1571** | Non-Standard Port | Command and Control | Egress port divergence: HTTP/TLS/C2 traffic over ports outside IANA standards | `CRITICAL` |

---

## Mathematical Formulations

### 1. Coefficient of Variation ($C_v$)
Used to identify invariant periodic timing while remaining scale-invariant across long and short sleep cycles:

$$C_v = \frac{\sigma}{\mu} = \frac{\sqrt{\frac{1}{N-1}\sum_{i=1}^{N}(x_i - \mu)^2}}{\mu}$$

### 2. Median Absolute Deviation ($\text{MAD}$)
Provides outlier-resistant dispersion measurement to prevent beacon bursts from masking underlying periodicity:

$$\text{MAD} = \text{median}(\vert{}x_i - \text{median}(X)\vert{})$$

### 3. Vectorized Shannon Entropy ($H$)
Quantifies information density and randomness across packet payload byte arrays to detect encrypted tunnels:

$$H(X) = -\sum_{i=0}^{255} P(b_i) \log_2 P(b_i)$$

---

## Installation & Setup

### Prerequisites
* Python 3.11, 3.12, or 3.13
* `libpcap` development libraries (Linux/macOS) or Npcap (Windows)

### Virtual Environment Setup
```bash
git clone [https://github.com/Simiyuu/c2-beacon-detector.git](https://github.com/Simiyuu/c2-beacon-detector.git)
cd c2-beacon-detector
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Usage Guide

### CLI Threat Hunting
Analyze a PCAP capture and print an ASCII triage table to stdout:
```bash
python -m src.cli --pcap traffic.pcap
```

Export deduplicated alerts directly to SIEM-ready formats:
```bash
# JSON array export
python -m src.cli -p traffic.pcap -o alerts.json

# Streaming NDJSON / JSON Lines export
python -m src.cli -p traffic.pcap -o alerts.jsonl -f jsonl

# Flattened CSV triage spreadsheet
python -m src.cli -p traffic.pcap -o alerts.csv -f csv
```

Enforce strict exit gating in CI/CD pipelines (returns code `1` if `HIGH` or `CRITICAL` alerts occur):
```bash
python -m src.cli -p capture.pcap --strict
```

### Docker Execution
Run hunts within a hardened, unprivileged container:
```bash
docker build -t c2-beacon-detector .
docker run --rm -v $(pwd):/data c2-beacon-detector -p /data/capture.pcap -o /data/alerts.json
```

---

## Empirical Benchmark Evaluation

Run the automated multi-class evaluation harness to generate a synthetic ground-truth trace and measure classification accuracy:

```bash
python evaluate.py --json-out scorecard.json
```

### Typical Benchmark Scorecard
```text
==============================================================
       C2-BEACON-DETECTOR EVALUATION BENCHMARK SCORECARD       
==============================================================
 True Positives (TP):  3     | False Positives (FP): 0    
 False Negatives (FN): 0     | True Negatives (TN):  2    
--------------------------------------------------------------
 Precision:            100.00%
 Recall (Sensitivity): 100.00%
 F1-Score:              1.0000
 False Positive Rate:     0.00%
--------------------------------------------------------------
 Ingestion Throughput: ~1,200 packets/sec
==============================================================
```

---

## Running Test Suites

Run the complete test suite across all 20+ unit and integration modules:

```bash
python -m pytest -v
```

---

## Project Structure

```text
c2-beacon-detector/
├── .github/workflows/ci.yml # GitHub Actions multi-version CI matrix
├── src/
│   ├── rules/               # Behavioral rule definitions (MITRE mapped)
│   │   ├── base.py          # Abstract rule contract
│   │   ├── periodic.py      # T1071 periodic timing detection
│   │   ├── jitter.py        # T1071.001 sleep-variance beaconing
│   │   ├── entropy.py       # T1573 payload entropy inspection
│   │   └── port.py          # T1571 anomalous egress port detection
│   ├── cli.py               # Enterprise hunting CLI interface
│   ├── engine.py            # Multi-rule evaluation & deduplication
│   ├── exporter.py          # SIEM JSON, JSONL, and CSV serializer
│   ├── hunter.py            # Streaming pipeline orchestrator
│   ├── models.py            # Pydantic v2 domain schemas & MITRE enums
│   ├── reader.py            # Streaming PCAP packet reader
│   ├── sessionizer.py       # Bi-directional 5-tuple flow session table
│   └── stats.py             # Scale-invariant dispersion metrics (Cv, MAD)
├── tests/                   # Full pytest suite (unit, integration, fuzzing)
├── evaluate.py              # Automated accuracy and performance benchmark
├── Dockerfile               # Production multi-stage container build
└── requirements.txt         # Core dependencies (scapy, numpy, pydantic)
```
