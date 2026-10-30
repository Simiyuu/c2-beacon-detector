import pytest
from src.models import AlertSeverity, DetectionTechnique, FlowRecord
from src.rules.entropy import HighEntropyChannelRule, HighEntropyRule


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


def test_entropy_rule_sliding_window_capacity_pruning():
    """Verify capacity pruning discards historical plaintext packets and detects encrypted stream."""
    rule = HighEntropyChannelRule(min_packets=5, entropy_threshold=7.0)
    flow = FlowRecord(
        flow_id="10.0.0.15:52341->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=52341,
        dst_port=8443,
        protocol="tcp",
        max_window_packets=6,
        window_duration_seconds=1000.0,
    )

    # 1. Ingest 4 low-entropy plaintext packets
    for i in range(4):
        flow.add_packet(timestamp=10.0 + i, length=120, payload_entropy=3.1, auto_prune=True)

    # 2. Ingest 6 high-entropy encrypted packets (H ~ 7.85)
    for i in range(6):
        flow.add_packet(timestamp=20.0 + i, length=120, payload_entropy=7.85, auto_prune=True)

    # Window capacity of 6 should prune all 4 initial plaintext packets
    assert flow.packet_count == 10
    assert flow.window_size == 6
    assert flow.pruned_packet_count == 4
    assert all(e >= 7.8 for e in flow.payload_entropies)

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.mitre_attack.technique_id == DetectionTechnique.HIGH_ENTROPY_CHANNEL
    assert alert.jitter_metrics.shannon_entropy >= 7.8
    assert "High-entropy C2 channel detected" in alert.description


def test_entropy_rule_sliding_window_temporal_pruning():
    """Verify temporal eviction clears historical unencrypted sessions and detects current encrypted burst."""
    rule = HighEntropyChannelRule(min_packets=5, entropy_threshold=7.0)
    flow = FlowRecord(
        flow_id="10.0.0.22:49152->203.0.113.88:443:tcp",
        src_ip="10.0.0.22",
        dst_ip="203.0.113.88",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
        max_window_packets=50,
        window_duration_seconds=60.0,
    )

    # Historical unencrypted packets at t=100
    flow.add_packet(timestamp=100.0, length=200, payload_entropy=2.8, auto_prune=True)
    flow.add_packet(timestamp=101.0, length=200, payload_entropy=2.9, auto_prune=True)

    # Active encrypted session at t=3600
    for i in range(6):
        flow.add_packet(timestamp=3600.0 + (i * 2.0), length=256, payload_entropy=7.80, auto_prune=True)

    assert flow.pruned_packet_count == 2
    assert flow.window_size == 6

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.jitter_metrics.shannon_entropy >= 7.7
    assert alert.severity == AlertSeverity.HIGH


def test_entropy_rule_alias_and_insufficient_samples():
    """Verify HighEntropyRule alias and sample boundary enforcement in window."""
    rule = HighEntropyRule(min_packets=5, entropy_threshold=7.0)
    flow = FlowRecord(
        flow_id="10.0.0.22:49152->203.0.113.88:443:tcp",
        src_ip="10.0.0.22",
        dst_ip="203.0.113.88",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
        max_window_packets=2,  # Insufficient window size
    )

    flow.add_packet(timestamp=10.0, length=256, payload_entropy=7.9, auto_prune=True)
    flow.add_packet(timestamp=12.0, length=256, payload_entropy=7.9, auto_prune=True)

    alert = rule.evaluate(flow)
    assert alert is None

    