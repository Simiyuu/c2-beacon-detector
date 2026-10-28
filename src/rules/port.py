from typing import Optional, Set
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

STANDARD_EGRESS_PORTS: Set[int] = {
    20, 21,    # FTP
    22,        # SSH
    25, 587,   # SMTP
    53,        # DNS
    80,        # HTTP
    123,       # NTP
    389, 636,  # LDAP / LDAPS
    443,       # HTTPS
    853,       # DNS-over-TLS
}

SUSPICIOUS_C2_PORTS: Set[int] = {
    1337,      # Elite / custom reverse shells
    4444,      # Metasploit default
    6667,      # IRC C2
    8000, 8080,# Alternate HTTP
    8443, 8888,# Alternate HTTPS / proxy
    9001,      # Tor / default reverse shell
}


class NonStandardPortRule(BaseRule):
    """Detection rule identifying periodic or persistent C2 beacons over non-standard egress ports."""

    rule_id: str = "NET-RULE-004"
    name: str = "Non-Standard Port Beaconing Channel"
    description: str = (
        "Detects automated or periodic communication traversing unexpected or non-standard "
        "egress destination ports per MITRE ATT&CK T1571."
    )
    technique: DetectionTechnique = DetectionTechnique.NON_STANDARD_PORT
    technique_name: str = "Non-Standard Port"
    default_severity: AlertSeverity = AlertSeverity.MEDIUM

    def __init__(
        self,
        min_packets: int = 5,
        cv_threshold: float = 0.40,
        standard_ports: Optional[Set[int]] = None,
        severity_override: Optional[AlertSeverity] = None,
        enabled: bool = True,
    ):
        super().__init__(
            min_packets=min_packets,
            severity_override=severity_override,
            enabled=enabled,
        )
        self.cv_threshold = cv_threshold
        self.standard_ports = standard_ports or STANDARD_EGRESS_PORTS

    def evaluate(self, flow: FlowRecord) -> Optional[BeaconAlert]:
        """Evaluates destination port and timing dispersion."""
        if not self.enabled or flow.packet_count < self.min_packets:
            return None

        # Standard ports are cleared
        if flow.dst_port in self.standard_ports:
            return None

        deltas = calculate_iat(flow.timestamps)
        if len(deltas) < 3:
            return None

        cv = calculate_coefficient_of_variation(deltas)

        # Confirm the non-standard port traffic exhibits automated beaconing characteristics
        if cv <= self.cv_threshold:
            iat_mean = float(np.mean(deltas))
            iat_std = float(np.std(deltas, ddof=1))
            mad = calculate_median_absolute_deviation(deltas)
            regularity = calculate_regularity_score(deltas)

            is_known_c2_port = flow.dst_port in SUSPICIOUS_C2_PORTS
            severity = AlertSeverity.CRITICAL if is_known_c2_port else AlertSeverity.HIGH

            anomaly_score = round(float(-2.0 / (cv + 1e-3)), 2)
            if is_known_c2_port:
                anomaly_score -= 5.0

            metrics = JitterMetrics(
                iat_mean=round(iat_mean, 4),
                iat_std=round(iat_std, 4),
                coefficient_of_variation=round(cv, 4),
                median_absolute_deviation=round(mad, 4),
                shannon_entropy=0.0,
            )

            port_context = "known high-risk C2 port" if is_known_c2_port else "non-standard egress port"
            description = (
                f"Automated beaconing to {port_context} (port {flow.dst_port}) on {flow.flow_id}: "
                f"{flow.packet_count} packets with mean IAT={iat_mean:.2f}s, "
                f"Cv={cv:.4f} (<= {self.cv_threshold}), regularity={regularity:.2f}."
            )

            return self.create_alert(
                flow=flow,
                anomaly_score=anomaly_score,
                jitter_metrics=metrics,
                description=description,
                severity=severity,
            )

        return None
    