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


def test_periodic_beacon_detection_with_capacity_pruned_window():
    """Verifies that low-jitter beaconing is detected once historical noise is pruned by capacity bounds."""
    rule = PeriodicBeaconRule(min_packets=5, cv_threshold=0.15)
    flow = FlowRecord(
        flow_id="10.0.0.5:52000->198.51.100.2:443:tcp",
        src_ip="10.0.0.5",
        dst_ip="198.51.100.2",
        src_port=52000,
        dst_port=443,
        protocol="tcp",
        max_window_packets=6,  # Cap sliding buffer to 6 packets
        window_duration_seconds=1000.0,
    )

    # 1. Ingest erratic historical packets (high variance)
    erratic_timestamps = [10.0, 14.2, 35.1, 80.0]
    for ts in erratic_timestamps:
        flow.add_packet(timestamp=ts, length=64, auto_prune=True)

    # 2. Ingest 6 deterministic beacon packets (constant 5.0s delta)
    beacon_start = 100.0
    for i in range(6):
        flow.add_packet(timestamp=beacon_start + (i * 5.0), length=64, auto_prune=True)

    # Active window should have evicted the erratic packets, keeping only the 6 beacon packets
    assert flow.window_size == 6
    assert flow.packet_count == 10
    assert flow.pruned_packet_count == 4

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.mitre_attack.technique_id == DetectionTechnique.PERIODIC_BEACON
    assert alert.jitter_metrics.iat_mean == 5.0
    assert alert.jitter_metrics.coefficient_of_variation <= 0.05
    assert "Periodic C2 beaconing identified" in alert.description


def test_periodic_beacon_detection_with_temporal_pruned_window():
    """Verifies that temporal eviction clears old bursts, detecting a new regular beacon window."""
    rule = PeriodicBeaconRule(min_packets=5, cv_threshold=0.15)
    flow = FlowRecord(
        flow_id="10.0.0.12:49152->203.0.113.10:8080:tcp",
        src_ip="10.0.0.12",
        dst_ip="203.0.113.10",
        src_port=49152,
        dst_port=8080,
        protocol="tcp",
        max_window_packets=50,
        window_duration_seconds=60.0,  # 60-second temporal horizon
    )

    # Burst from an hour ago
    flow.add_packet(timestamp=100.0, length=120, auto_prune=True)
    flow.add_packet(timestamp=101.0, length=120, auto_prune=True)

    # Current periodic beacon at t=3600 (10.0s interval)
    current_time = 3600.0
    for i in range(6):
        flow.add_packet(timestamp=current_time + (i * 10.0), length=120, auto_prune=True)

    # The 2 old packets from t=100 are well outside the 60s window (cutoff = 3650 - 60 = 3590)
    assert flow.pruned_packet_count == 2
    assert flow.window_size == 6

    alert = rule.evaluate(flow)
    assert alert is not None
    assert alert.jitter_metrics.iat_mean == 10.0
    assert alert.jitter_metrics.coefficient_of_variation <= 0.05


def test_periodic_beacon_insufficient_samples_in_window_returns_none():
    """Verifies that when pruning reduces active window size below min_packets, no alert is emitted."""
    rule = PeriodicBeaconRule(min_packets=5, cv_threshold=0.15)
    flow = FlowRecord(
        flow_id="10.0.0.9:4444->198.51.100.9:443:tcp",
        src_ip="10.0.0.9",
        dst_ip="198.51.100.9",
        src_port=4444,
        dst_port=443,
        protocol="tcp",
        max_window_packets=3,  # Window constrained to 3 packets (< min_packets 5)
    )

    # Ingest 3 periodic packets
    for i in range(3):
        flow.add_packet(timestamp=100.0 + (i * 5.0), length=64, auto_prune=True)

    alert = rule.evaluate(flow)
    assert alert is None
    