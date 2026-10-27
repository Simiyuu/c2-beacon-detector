from typing import Optional
import pytest
from src.models import AlertSeverity, BeaconAlert, DetectionTechnique, FlowRecord, JitterMetrics
from src.rules.base import BaseRule


class DummyPassingRule(BaseRule):
    rule_id = "TEST-001"
    name = "Dummy Passing Rule"
    technique = DetectionTechnique.PERIODIC_BEACON
    technique_name = "Application Layer Protocol"
    default_severity = AlertSeverity.LOW

    def evaluate(self, flow: FlowRecord) -> Optional[BeaconAlert]:
        if flow.packet_count >= self.min_packets:
            metrics = JitterMetrics(iat_mean=5.0, iat_std=0.01)
            return self.create_alert(
                flow=flow,
                anomaly_score=-1.5,
                jitter_metrics=metrics,
                description="Dummy alert triggered",
            )
        return None


def test_cannot_instantiate_abstract_base_rule():
    with pytest.raises(TypeError):
        BaseRule()  # Can't instantiate abstract class without evaluate()


def test_dummy_rule_alert_generation():
    rule = DummyPassingRule(min_packets=3, severity_override=AlertSeverity.HIGH)
    flow = FlowRecord(
        flow_id="10.0.0.1:1234->198.51.100.2:80:tcp",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.2",
        src_port=1234,
        dst_port=80,
        protocol="tcp",
        packet_count=4,
        timestamps=[1.0, 6.0, 11.0, 16.0],
    )

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert alert.flow_id == flow.flow_id
    assert alert.mitre_attack.technique_id == DetectionTechnique.PERIODIC_BEACON
    assert alert.anomaly_score == -1.5


def test_dummy_rule_skips_insufficient_packets():
    rule = DummyPassingRule(min_packets=5)
    flow = FlowRecord(
        flow_id="10.0.0.1:1234->198.51.100.2:80:tcp",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.2",
        src_port=1234,
        dst_port=80,
        protocol="tcp",
        packet_count=2,
    )
    assert rule.evaluate(flow) is None
    