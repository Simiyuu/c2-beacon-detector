from typing import Optional
import numpy as np

from src.metrics import calculate_iat
from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    FlowRecord,
    JitterMetrics,
)
from src.rules.base import BaseRule
from src.stats import (
    calculate_coefficient_of_variation,
    calculate_median_absolute_deviation,
)


class HighEntropyChannelRule(BaseRule):
    """Detection rule identifying persistent high-entropy payloads matching MITRE ATT&CK T1573."""

    rule_id: str = "NET-RULE-003"
    name: str = "High-Entropy Encrypted C2 Channel"
    description: str = (
        "Detects network flows exhibiting consistently high payload Shannon entropy "
        "characteristic of encrypted or custom-obfuscated C2 communications."
    )
    technique: DetectionTechnique = DetectionTechnique.HIGH_ENTROPY_CHANNEL
    technique_name: str = "Encrypted Channel"
    default_severity: AlertSeverity = AlertSeverity.HIGH

    def __init__(
        self,
        min_packets: int = 5,
        entropy_threshold: float = 7.0,
        severity_override: Optional[AlertSeverity] = None,
        enabled: bool = True,
    ):
        super().__init__(
            min_packets=min_packets,
            severity_override=severity_override,
            enabled=enabled,
        )
        self.entropy_threshold = entropy_threshold

    def evaluate(self, flow: FlowRecord) -> Optional[BeaconAlert]:
        """Evaluates mean payload Shannon entropy across the flow."""
        if not self.enabled or flow.packet_count < self.min_packets:
            return None

        if not flow.payload_entropies:
            return None

        # Filter out empty or header-only ACK packets (entropy == 0.0)
        active_entropies = [e for e in flow.payload_entropies if e > 0.0]
        if len(active_entropies) < max(3, self.min_packets // 2):
            return None

        mean_entropy = float(np.mean(active_entropies))

        if mean_entropy >= self.entropy_threshold:
            deltas = calculate_iat(flow.timestamps)
            iat_mean = float(np.mean(deltas)) if len(deltas) > 0 else 0.0
            iat_std = float(np.std(deltas, ddof=1)) if len(deltas) > 1 else 0.0
            cv = calculate_coefficient_of_variation(deltas) if len(deltas) > 1 else 0.0
            mad = calculate_median_absolute_deviation(deltas) if len(deltas) > 1 else 0.0

            anomaly_score = round(float(-(mean_entropy / 8.0) * 10.0), 2)

            metrics = JitterMetrics(
                iat_mean=round(iat_mean, 4),
                iat_std=round(iat_std, 4),
                coefficient_of_variation=round(cv, 4),
                median_absolute_deviation=round(mad, 4),
                shannon_entropy=round(mean_entropy, 4),
            )

            description = (
                f"High-entropy C2 channel detected on {flow.flow_id}: "
                f"{len(active_entropies)} data packets evaluated with mean Shannon entropy "
                f"H={mean_entropy:.4f} bits (threshold >= {self.entropy_threshold})."
            )

            return self.create_alert(
                flow=flow,
                anomaly_score=anomaly_score,
                jitter_metrics=metrics,
                description=description,
            )

        return None
        