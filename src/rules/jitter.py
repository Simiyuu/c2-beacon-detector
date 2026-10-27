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
    estimate_jitter_percentage,
)


class JitterBeaconRule(BaseRule):
    """Detection rule identifying randomized, jitter-tolerant network beacons matching MITRE ATT&CK T1071.001."""

    rule_id: str = "NET-RULE-002"
    name: str = "Jitter-Tolerant C2 Beacon"
    description: str = (
        "Detects randomized C2 check-in channels operating with sleep jitter (10-40%) "
        "by measuring non-parametric dispersion and bounded Coefficient of Variation."
    )
    technique: DetectionTechnique = DetectionTechnique.HTTP_BEACON
    technique_name: str = "Web Protocols C2"
    default_severity: AlertSeverity = AlertSeverity.MEDIUM

    def __init__(
        self,
        min_packets: int = 6,
        cv_min: float = 0.08,
        cv_max: float = 0.40,
        mad_ratio_max: float = 0.30,
        severity_override: Optional[AlertSeverity] = None,
        enabled: bool = True,
    ):
        super().__init__(
            min_packets=min_packets,
            severity_override=severity_override,
            enabled=enabled,
        )
        self.cv_min = cv_min
        self.cv_max = cv_max
        self.mad_ratio_max = mad_ratio_max

    def evaluate(self, flow: FlowRecord) -> Optional[BeaconAlert]:
        """Evaluates flow inter-arrival times against sleep-jitter dispersion models."""
        if not self.enabled or flow.packet_count < self.min_packets:
            return None

        deltas = calculate_iat(flow.timestamps)
        if len(deltas) < 5:
            return None

        median_iat = float(np.median(deltas))
        if median_iat <= 1e-4:
            return None

        cv = calculate_coefficient_of_variation(deltas)
        mad = calculate_median_absolute_deviation(deltas)
        mad_ratio = mad / median_iat

        # Must fall within the jittered beacon band and maintain strong median clustering
        if (self.cv_min <= cv <= self.cv_max) and (mad_ratio <= self.mad_ratio_max):
            iat_mean = float(np.mean(deltas))
            iat_std = float(np.std(deltas, ddof=1))
            jitter_pct = estimate_jitter_percentage(deltas)

            # Escalate severity for long-lived persistent channels
            severity = (
                AlertSeverity.HIGH
                if flow.packet_count >= 15
                else self.severity
            )

            anomaly_score = round(float(-1.0 / (cv + 1e-3)), 2)

            metrics = JitterMetrics(
                iat_mean=round(iat_mean, 4),
                iat_std=round(iat_std, 4),
                coefficient_of_variation=round(cv, 4),
                median_absolute_deviation=round(mad, 4),
                shannon_entropy=0.0,
            )

            description = (
                f"Jitter-tolerant C2 beaconing detected on {flow.flow_id}: "
                f"{flow.packet_count} packets, median IAT={median_iat:.2f}s, "
                f"estimated jitter={jitter_pct:.1f}%, Cv={cv:.4f}, MAD ratio={mad_ratio:.4f}."
            )

            return self.create_alert(
                flow=flow,
                anomaly_score=anomaly_score,
                jitter_metrics=metrics,
                description=description,
                severity=severity,
            )

        return None
    