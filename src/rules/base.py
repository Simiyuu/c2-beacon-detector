from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import uuid

from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    FlowRecord,
    JitterMetrics,
    MITREAttackMetadata,
)


class BaseRule(ABC):
    """Abstract contract for stateful and statistical network detection rules."""

    rule_id: str = "NET-RULE-BASE"
    name: str = "Base Detection Rule"
    description: str = "Abstract base rule contract."
    technique: DetectionTechnique = DetectionTechnique.PERIODIC_BEACON
    technique_name: str = "Application Layer Protocol"
    default_severity: AlertSeverity = AlertSeverity.MEDIUM

    def __init__(
        self,
        min_packets: int = 4,
        severity_override: Optional[AlertSeverity] = None,
        enabled: bool = True,
    ):
        self.min_packets = min_packets
        self.severity = severity_override or self.default_severity
        self.enabled = enabled

    @abstractmethod
    def evaluate(self, flow: FlowRecord) -> Optional[BeaconAlert]:
        """Evaluates a completed FlowRecord and returns a BeaconAlert if anomalous behavior is confirmed."""
        pass

    def create_alert(
        self,
        flow: FlowRecord,
        anomaly_score: float,
        jitter_metrics: JitterMetrics,
        description: str,
        severity: Optional[AlertSeverity] = None,
    ) -> BeaconAlert:
        """Helper factory constructing a validated BeaconAlert matching rule metadata."""
        alert_id = f"ALT-{self.rule_id}-{uuid.uuid4().hex[:8].upper()}"
        return BeaconAlert(
            alert_id=alert_id,
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            severity=severity or self.severity,
            mitre_attack=MITREAttackMetadata(
                technique_id=self.technique,
                technique_name=self.technique_name,
            ),
            jitter_metrics=jitter_metrics,
            anomaly_score=anomaly_score,
            description=description,
        )
    