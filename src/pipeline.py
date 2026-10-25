from typing import Any, Dict, List, Optional
import numpy as np

from src.detector import BeaconDetector
from src.features import FeatureExtractor
from src.models import FlowRecord
from src.parser import PCAPParser


def _extract_metric(features: Any, key: str, default: float = 0.0) -> float:
    """Helper to extract metric values whether features are a dict or a model."""
    if isinstance(features, dict):
        return float(features.get(key, default))
    return float(getattr(features, key, default))


class DetectionPipeline:
    def __init__(
        self,
        contamination: float = 0.05,
        min_packets: int = 3,
    ):
        """End-to-end orchestration pipeline for network beacon anomaly detection."""
        self.contamination = contamination
        self.min_packets = min_packets
        self.detector = BeaconDetector(contamination=self.contamination)
        self.extractor = FeatureExtractor()

    def run(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Parses a PCAP file, extracts behavioral timing features, and returns detected beacon alerts."""
        parser = PCAPParser(pcap_path=pcap_path)
        flows = parser.parse_pcap(pcap_path)

        if not flows:
            return []

        candidate_flows: List[FlowRecord] = []
        feature_rows: List[List[float]] = []

        for flow_id, flow in flows.items():
            if flow.packet_count < self.min_packets:
                continue

            feats = self.extractor.extract_from_flow(flow)
            iat_mean = _extract_metric(feats, "iat_mean", 0.0)
            iat_std = _extract_metric(feats, "iat_std", 0.0)
            bytes_mean = _extract_metric(
                feats, "bytes_mean", _extract_metric(feats, "packet_length_mean", 0.0)
            )
            bytes_std = _extract_metric(
                feats, "bytes_std", _extract_metric(feats, "packet_length_std", 0.0)
            )

            candidate_flows.append(flow)
            feature_rows.append([iat_mean, iat_std, bytes_mean, bytes_std])

        if not candidate_flows:
            return []

        X = np.array(feature_rows, dtype=np.float64)

        # In small or synthetic traces, augment with standard benign background distribution
        # to calibrate the Isolation Forest baseline against expected web noise
        if len(X) < 15:
            rng = np.random.default_rng(seed=42)
            baseline_background = rng.uniform(
                low=[0.1, 1.2, 200.0, 100.0],
                high=[10.0, 5.0, 1200.0, 400.0],
                size=(30, 4),
            )
            train_data = np.vstack([baseline_background, X])
        else:
            train_data = X

        self.detector.fit(train_data)
        predictions = self.detector.predict(X)
        scores = self.detector.score_samples(X)

        alerts: List[Dict[str, Any]] = []
        for i, flow in enumerate(candidate_flows):
            iat_mean, iat_std, bytes_mean, bytes_std = feature_rows[i]
            is_anomaly = predictions[i] == -1 or (iat_std <= 0.1 and flow.packet_count >= 5)

            if is_anomaly:
                alerts.append({
                    "flow_id": flow.flow_id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "packet_count": flow.packet_count,
                    "total_bytes": flow.total_bytes,
                    "iat_mean": iat_mean,
                    "iat_std": iat_std,
                    "anomaly_score": float(scores[i]),
                })

        return alerts