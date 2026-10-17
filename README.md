# Network Traffic Anomaly & C2 Beaconing Detector

An unsupervised machine learning pipeline for detecting covert Command and Control (C2) beaconing patterns in network flow telemetry.

## Architecture
- **Ingestion**: Packet capture parsing via Scapy
- **Flow Aggregation**: 5-Tuple bi-directional session reconstruction
- **Feature Engineering**: Inter-Arrival Time (IAT) statistics, byte variance, and payload length distributions
- **Anomaly Detection**: Unsupervised Isolation Forest (scikit-learn)