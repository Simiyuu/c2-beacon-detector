import pytest
from src.models import AlertSeverity, DetectionTechnique, FlowRecord
from src.rules.entropy import HighEntropyChannelRule


def test_entropy_rule_flags_encrypted_c2_stream():
    """Verify flow with sustained ~7.8 bit Shannon entropy triggers T1573 alert."""
    flow = FlowRecord(
        flow_id="10.0.0.15:52341->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=52341,
        dst_port=8443,
        protocol="tcp",
        packet_count=6,
        timestamps=[1.0, 6.0, 11.0, 16.0, 21.0, 26.0],
        packet_lengths=[128, 128, 128, 128, 128, 128],
        payload_entropies=[7.82, 7.91, 7.79, 7.88, 7.85, 7.90],
    )

    rule = HighEntropyChannelRule(min_packets=5, entropy_threshold=7.0)
    alert = rule.evaluate(flow)

    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert alert.mitre_attack.technique_id == DetectionTechnique.HIGH_ENTROPY_CHANNEL
    assert alert.jitter_metrics.shannon_entropy >= 7.8
    assert alert.anomaly_score <= -9.0


def test_entropy_rule_clears_plaintext_stream():
    """Verify low-entropy plaintext flows (H ~ 3.3) are cleared."""
    flow = FlowRecord(
        flow_id="10.0.0.15:52341->198.51.100.24:80:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=52341,
        dst_port=80,
        protocol="tcp",
        packet_count=5,
        timestamps=[1.0, 2.0, 3.0, 4.0, 5.0],
        packet_lengths=[200, 250, 300, 210, 220],
        payload_entropies=[3.2, 3.4, 3.1, 3.5, 3.3],
    )

    rule = HighEntropyChannelRule(min_packets=5, entropy_threshold=7.0)
    alert = rule.evaluate(flow)
    assert alert is None


def test_entropy_rule_ignores_pure_ack_traffic():
    """Verify control/ACK flows with zero payload entropy are ignored."""
    flow = FlowRecord(
        flow_id="10.0.0.15:52341->198.51.100.24:80:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=52341,
        dst_port=80,
        protocol="tcp",
        packet_count=5,
        timestamps=[1.0, 2.0, 3.0, 4.0, 5.0],
        packet_lengths=[54, 54, 54, 54, 54],
        payload_entropies=[0.0, 0.0, 0.0, 0.0, 0.0],
    )

    rule = HighEntropyChannelRule(min_packets=5, entropy_threshold=7.0)
    alert = rule.evaluate(flow)
    assert alert is None
    