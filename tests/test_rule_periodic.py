import numpy as np
import pytest
from src.models import AlertSeverity, DetectionTechnique, FlowRecord
from src.rules.periodic import PeriodicBeaconRule


def test_periodic_rule_flags_clockwork_beacon():
    """Verify deterministic 5s heartbeat triggers HIGH severity alert."""
    rule = PeriodicBeaconRule(min_packets=5, cv_threshold=0.15)
    flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=8443,
        protocol="tcp",
        packet_count=6,
        timestamps=[10.0, 15.0, 20.0, 25.0, 30.0, 35.0],
    )

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert alert.mitre_attack.technique_id == DetectionTechnique.PERIODIC_BEACON
    assert alert.jitter_metrics.coefficient_of_variation == 0.0
    assert alert.jitter_metrics.iat_mean == 5.0
    assert alert.anomaly_score < 0.0


def test_periodic_rule_clears_bursty_web_traffic():
    """Verify high-variance Poisson web session is cleared without alert."""
    rule = PeriodicBeaconRule(min_packets=5, cv_threshold=0.15)
    flow = FlowRecord(
        flow_id="10.0.0.15:49152->142.250.190.46:443:tcp",
        src_ip="10.0.0.15",
        dst_ip="142.250.190.46",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
        packet_count=6,
        # Irregular web arrival deltas: 0.1s, 2.5s, 0.05s, 8.0s, 1.2s
        timestamps=[10.0, 10.1, 12.6, 12.65, 20.65, 21.85],
    )

    alert = rule.evaluate(flow)
    assert alert is None


def test_periodic_rule_respects_min_packets():
    """Verify flows below min_packets boundary return None."""
    rule = PeriodicBeaconRule(min_packets=5)
    flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=8443,
        protocol="tcp",
        packet_count=3,
        timestamps=[0.0, 5.0, 10.0],
    )

    alert = rule.evaluate(flow)
    assert alert is None

    