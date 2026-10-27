import numpy as np
import pytest
from src.models import AlertSeverity, DetectionTechnique, FlowRecord
from src.rules.jitter import JitterBeaconRule


def test_jitter_rule_flags_twenty_percent_jitter_beacon():
    """Verify beacon with 20% sleep jitter is detected and attributed to T1071.001."""
    rng = np.random.default_rng(seed=42)
    base_interval = 10.0
    # Jitter of +- 2.0s around 10.0s baseline (20% jitter)
    noise = rng.uniform(-2.0, 2.0, size=15)
    deltas = base_interval + noise
    timestamps = [0.0] + list(np.cumsum(deltas))

    flow = FlowRecord(
        flow_id="10.0.0.15:54321->198.51.100.24:443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        packet_count=len(timestamps),
        timestamps=timestamps,
    )

    rule = JitterBeaconRule(min_packets=6)
    alert = rule.evaluate(flow)

    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH  # Escalated due to 16 packets
    assert alert.mitre_attack.technique_id == DetectionTechnique.HTTP_BEACON
    assert 0.08 <= alert.jitter_metrics.coefficient_of_variation <= 0.40
    assert "estimated jitter=" in alert.description



def test_jitter_rule_clears_clockwork_beacon():
    """Verify clockwork beacons (Cv near 0) are bypassed (delegated to PeriodicBeaconRule)."""
    timestamps = [float(i * 5.0) for i in range(10)]
    flow = FlowRecord(
        flow_id="10.0.0.15:54321->198.51.100.24:443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        packet_count=len(timestamps),
        timestamps=timestamps,
    )

    rule = JitterBeaconRule(min_packets=6)
    alert = rule.evaluate(flow)
    assert alert is None


def test_jitter_rule_clears_erratic_traffic():
    """Verify erratic web browsing (Cv > 0.60) produces no alert."""
    timestamps = [1.0, 1.2, 5.0, 5.1, 19.0, 20.0, 55.0, 55.2]
    flow = FlowRecord(
        flow_id="10.0.0.15:54321->142.250.190.46:443:tcp",
        src_ip="10.0.0.15",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        packet_count=len(timestamps),
        timestamps=timestamps,
    )

    rule = JitterBeaconRule(min_packets=6)
    alert = rule.evaluate(flow)
    assert alert is None
