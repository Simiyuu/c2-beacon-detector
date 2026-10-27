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
    calculate_regularity_score,
)


class PeriodicBeaconRule(BaseRule):
    """Detection rule identifying periodic, low-jitter network beacons matching MITRE ATT&CK T1071."""

    rule_id: str = "NET-RULE-001"
    name: str = "Periodic Low-Jitter C2 Beacon"
    description: str = (
        "Detects recurring network sessions exhibiting deterministic inter-arrival times "
        "and low coefficient of variation characteristic of automated C2 polling."
    )
    technique: DetectionTechnique = DetectionTechnique.PERIODIC_BEACON
    technique_name: str = "Application Layer Protocol"
    default_severity: AlertSeverity = AlertSeverity.HIGH

    def __init__(
        self,
        min_packets: int = 5,
        cv_threshold: float = 0.15,
        severity_override: Optional[AlertSeverity] = None,
        enabled: bool = True,
    ):
        super().__init__(
            min_packets=min_packets,
            severity_override=severity_override,
            enabled=enabled,
        )
        self.cv_threshold = cv_threshold

    def evaluate(self, flow: FlowRecord) -> Optional[BeaconAlert]:
        """Evaluates flow inter-arrival times against periodic beaconing thresholds."""
        if not self.enabled or flow.packet_count < self.min_packets:
            return None

        deltas = calculate_iat(flow.timestamps)
        if len(deltas) < 3:
            return None

        cv = calculate_coefficient_of_variation(deltas)

        if cv <= self.cv_threshold:
            iat_mean = float(np.mean(deltas))
            iat_std = float(np.std(deltas, ddof=1))
            mad = calculate_median_absolute_deviation(deltas)
            regularity = calculate_regularity_score(deltas)

            # Inversely scaled anomaly score: tighter clustering produces stronger negative score
            anomaly_score = round(float(-1.0 / (cv + 1e-3)), 2)

            metrics = JitterMetrics(
                iat_mean=round(iat_mean, 4),
                iat_std=round(iat_std, 4),
                coefficient_of_variation=round(cv, 4),
                median_absolute_deviation=round(mad, 4),
                shannon_entropy=0.0,
            )

            description = (
                f"Periodic C2 beaconing identified on {flow.flow_id}: "
                f"{flow.packet_count} packets with mean IAT={iat_mean:.2f}s, "
                f"Cv={cv:.4f} (<= {self.cv_threshold}), regularity={regularity:.2f}."
            )

            return self.create_alert(
                flow=flow,
                anomaly_score=anomaly_score,
                jitter_metrics=metrics,
                description=description,
            )

        return None

    