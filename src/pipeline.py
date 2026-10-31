from typing import Any, Callable, Dict, List, Optional, Set
import numpy as np

from src.detector import BeaconDetector
from src.features import FeatureExtractor
from src.ids_generator import IDSRuleGenerator
from src.models import BeaconAlert, FlowRecord, PacketEvent
from src.parser import PCAPParser
from src.rules.base import BaseRule
from src.rules.entropy import HighEntropyChannelRule
from src.rules.jitter import JitterBeaconRule
from src.rules.periodic import PeriodicBeaconRule
from src.windowed_sessionizer import WindowedFlowSessionizer


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


class StreamingBeaconDetector:
    """End-to-end streaming detection pipeline orchestrating sessionization, rule analysis, and IDS export."""

    def __init__(
        self,
        rules: Optional[List[BaseRule]] = None,
        sessionizer: Optional[WindowedFlowSessionizer] = None,
        ids_generator: Optional[IDSRuleGenerator] = None,
        alert_callback: Optional[Callable[[BeaconAlert], None]] = None,
    ) -> None:
        self.rules: List[BaseRule] = (
            rules
            if rules is not None
            else [
                PeriodicBeaconRule(),
                JitterBeaconRule(),
                HighEntropyChannelRule(),
            ]
        )
        self.sessionizer: WindowedFlowSessionizer = (
            sessionizer if sessionizer is not None else WindowedFlowSessionizer()
        )
        self.ids_generator: IDSRuleGenerator = (
            ids_generator if ids_generator is not None else IDSRuleGenerator()
        )
        self.alert_callback = alert_callback

        self._alerts: List[BeaconAlert] = []
        self._alerted_signatures: Set[str] = set()
        self._total_packets_processed = 0

    @property
    def alerts(self) -> List[BeaconAlert]:
        """Returns all unique alerts detected over the pipeline lifecycle."""
        return self._alerts

    def _generate_alert_signature(self, alert: BeaconAlert) -> str:
        """Constructs a deduplication signature for a flow alert."""
        tech_id = (
            alert.mitre_attack.technique_id.value
            if hasattr(alert.mitre_attack.technique_id, "value")
            else str(alert.mitre_attack.technique_id)
        )
        return f"{alert.flow_id}::{tech_id}"

    def process_packet(self, packet: PacketEvent) -> List[BeaconAlert]:
        """Ingests a single packet, updates sliding flow window, and runs active detection rules."""
        self._total_packets_processed += 1
        flow: FlowRecord = self.sessionizer.add_packet(packet)
        emitted_alerts: List[BeaconAlert] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            alert = rule.evaluate(flow)
            if alert is not None:
                sig = self._generate_alert_signature(alert)
                if sig not in self._alerted_signatures:
                    self._alerted_signatures.add(sig)
                    self._alerts.append(alert)
                    emitted_alerts.append(alert)

                    if self.alert_callback:
                        self.alert_callback(alert)

        return emitted_alerts

    def process_packet_events(self, packets: List[PacketEvent]) -> List[BeaconAlert]:
        """Processes a sequence of packet events in stream order, returning all newly triggered alerts."""
        new_alerts: List[BeaconAlert] = []
        for packet in packets:
            new_alerts.extend(self.process_packet(packet))
        return new_alerts

    def tick(self, current_time: float) -> List[BeaconAlert]:
        """Evicts dormant flows based on idle timeout and performs a final rule evaluation on evicted flows."""
        evicted_flows = self.sessionizer.evict_idle_flows(current_time=current_time)
        closing_alerts: List[BeaconAlert] = []

        for flow in evicted_flows:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                alert = rule.evaluate(flow)
                if alert is not None:
                    sig = self._generate_alert_signature(alert)
                    if sig not in self._alerted_signatures:
                        self._alerted_signatures.add(sig)
                        self._alerts.append(alert)
                        closing_alerts.append(alert)

                        if self.alert_callback:
                            self.alert_callback(alert)

        return closing_alerts

    def export_ids_rules(self, engine: str = "suricata") -> str:
        """Exports Suricata or Snort rules for all detected alerts."""
        return self.ids_generator.export_rules_text(alerts=self._alerts, engine=engine)

    def stats(self) -> dict:
        """Returns operational metrics across sessionization, rules, and alert generation."""
        session_stats = self.sessionizer.stats()
        return {
            "total_packets_processed": self._total_packets_processed,
            "total_alerts_emitted": len(self._alerts),
            "unique_alerted_flows": len(self._alerted_signatures),
            "active_rules_count": len([r for r in self.rules if r.enabled]),
            "sessionizer": session_stats,
        }

    def reset(self) -> None:
        """Resets the pipeline state, clearing alerts, sessions, and deduplication tables."""
        self._alerts.clear()
        self._alerted_signatures.clear()
        self._total_packets_processed = 0
        self.sessionizer.flush()
        self.ids_generator.reset()
        