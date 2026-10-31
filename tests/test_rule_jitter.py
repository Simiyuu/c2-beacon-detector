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


def test_jitter_beacon_sliding_window_capacity_pruning():
    """Verifies that capacity eviction purges historical bursts and flags the active jittered window."""
    rule = JitterBeaconRule(min_packets=6)
    flow = FlowRecord(
        flow_id="10.0.0.18:50000->198.51.100.30:443:tcp",
        src_ip="10.0.0.18",
        dst_ip="198.51.100.30",
        src_port=50000,
        dst_port=443,
        protocol="tcp",
        max_window_packets=8,
        window_duration_seconds=1000.0,
    )

    # 1. Ingest 4 erratic packets
    for ts in [1.0, 1.2, 15.0, 40.0]:
        flow.add_packet(timestamp=ts, length=64, auto_prune=True)

    # 2. Ingest 8 jittered beacon packets (7 deltas around 10s +- 1.5s)
    rng = np.random.default_rng(seed=42)
    deltas = list(10.0 + rng.uniform(-1.5, 1.5, size=7))
    current_ts = 100.0
    flow.add_packet(timestamp=current_ts, length=128, auto_prune=True)
    for d in deltas:
        current_ts += float(d)
        flow.add_packet(timestamp=current_ts, length=128, auto_prune=True)

    # All 4 erratic packets should be evicted from the 8-packet window
    assert flow.packet_count == 12
    assert flow.window_size == 8
    assert flow.pruned_packet_count == 4

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.mitre_attack.technique_id == DetectionTechnique.HTTP_BEACON
    assert 0.08 <= alert.jitter_metrics.coefficient_of_variation <= 0.40
    assert "Jitter-tolerant C2 beaconing detected" in alert.description


def test_jitter_beacon_sliding_window_temporal_pruning():
    """Verifies temporal eviction clears ancient bursts, detecting a new jittered beacon window."""
    rule = JitterBeaconRule(min_packets=6)
    flow = FlowRecord(
        flow_id="10.0.0.25:49160->203.0.113.77:8080:tcp",
        src_ip="10.0.0.25",
        dst_ip="203.0.113.77",
        src_port=49160,
        dst_port=8080,
        protocol="tcp",
        max_window_packets=50,
        window_duration_seconds=60.0,
    )

    # Ancient burst from t=100.0
    flow.add_packet(timestamp=100.0, length=200, auto_prune=True)
    flow.add_packet(timestamp=100.1, length=200, auto_prune=True)

    # New jittered beacon session starting at t=3600.0
    rng = np.random.default_rng(seed=99)
    deltas = list(6.0 + rng.uniform(-1.0, 1.0, size=7))
    current_ts = 3600.0
    flow.add_packet(timestamp=current_ts, length=120, auto_prune=True)
    for d in deltas:
        current_ts += float(d)
        flow.add_packet(timestamp=current_ts, length=120, auto_prune=True)

    assert flow.pruned_packet_count == 2
    assert flow.window_size == 8

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.mitre_attack.technique_id == DetectionTechnique.HTTP_BEACON
    assert 0.08 <= alert.jitter_metrics.coefficient_of_variation <= 0.40

def test_jitter_beacon_sliding_window_temporal_pruning():
    """Verifies temporal eviction clears ancient bursts, detecting a new jittered beacon window."""
    rule = JitterBeaconRule(min_packets=6)
    flow = FlowRecord(
        flow_id="10.0.0.25:49160->203.0.113.77:8080:tcp",
        src_ip="10.0.0.25",
        dst_ip="203.0.113.77",
        src_port=49160,
        dst_port=8080,
        protocol="tcp",
        max_window_packets=50,
        window_duration_seconds=100.0,
    )

    # Ancient burst from t=100.0
    flow.add_packet(timestamp=100.0, length=200, auto_prune=True)
    flow.add_packet(timestamp=100.1, length=200, auto_prune=True)

    # Deterministic ~15% sleep jitter deltas around 10.0s baseline:
    # Cv ≈ 0.152, MAD ratio ≈ 0.150, strictly within [0.08, 0.40] and <= 0.30
    deltas = [8.2, 11.8, 8.5, 11.5, 8.8, 11.2, 10.0]
    current_ts = 3600.0
    flow.add_packet(timestamp=current_ts, length=120, auto_prune=True)
    for d in deltas:
        current_ts += float(d)
        flow.add_packet(timestamp=current_ts, length=120, auto_prune=True)

    # 100s window at t=3670 evicts packets prior to t=3570, retaining all 8 beacon packets
    assert flow.pruned_packet_count == 2
    assert flow.window_size == 8

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.mitre_attack.technique_id == DetectionTechnique.HTTP_BEACON
    assert 0.08 <= alert.jitter_metrics.coefficient_of_variation <= 0.40
    