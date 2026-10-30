import pytest
from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    FlowRecord,
    JitterMetrics,
    MITREAttackMetadata,
    PacketEvent,
)


def test_packet_event_flow_key_normalization():
    """Verifies that reverse packet directions generate identical bi-directional flow keys."""
    fwd = PacketEvent(
        timestamp=100.0,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=443,
        protocol="TCP",
        length=64,
        payload_entropy=3.5,
    )
    rev = PacketEvent(
        timestamp=100.1,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=49152,
        protocol="tcp",
        length=128,
        payload_entropy=4.2,
    )
    assert fwd.flow_key == rev.flow_key
    assert "tcp" in fwd.flow_key


def test_flow_record_add_packet_event():
    """Verifies ingestion of PacketEvent instances and metric tracking."""
    flow = FlowRecord(
        flow_id="test-flow",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=5000,
        dst_port=80,
        protocol="tcp",
    )
    pkt = PacketEvent(
        timestamp=1000.0,
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=5000,
        dst_port=80,
        protocol="tcp",
        length=120,
        payload_entropy=2.1,
    )

    flow.add_packet(packet=pkt)
    assert flow.packet_count == 1
    assert flow.total_bytes == 120
    assert flow.byte_count == 120
    assert flow.start_time == 1000.0
    assert flow.last_seen == 1000.0
    assert flow.timestamps == [1000.0]
    assert flow.payload_entropies == [2.1]


def test_flow_record_capacity_pruning():
    """Verifies that exceeding max_window_packets evicts oldest entries."""
    flow = FlowRecord(
        flow_id="test-cap",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=5000,
        dst_port=443,
        protocol="tcp",
        max_window_packets=5,
        window_duration_seconds=1000.0,
    )

    for i in range(8):
        flow.add_packet(timestamp=100.0 + i, length=50, payload_entropy=1.0, auto_prune=True)

    assert flow.packet_count == 8
    assert flow.window_size == 5
    assert flow.pruned_packet_count == 3
    assert flow.timestamps == [103.0, 104.0, 105.0, 106.0, 107.0]
    assert flow.inter_arrival_times == [1.0, 1.0, 1.0, 1.0]


def test_flow_record_temporal_pruning():
    """Verifies that timestamps older than window_duration_seconds are evicted."""
    flow = FlowRecord(
        flow_id="test-time",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=5000,
        dst_port=443,
        protocol="tcp",
        max_window_packets=50,
        window_duration_seconds=10.0,
    )

    flow.add_packet(timestamp=100.0, length=60, auto_prune=True)
    flow.add_packet(timestamp=102.0, length=60, auto_prune=True)
    flow.add_packet(timestamp=104.0, length=60, auto_prune=True)
    assert flow.window_size == 3

    # Packet at t=113 establishes a 103.0s cutoff (113 - 10 = 103).
    # t=100.0 and t=102.0 are pruned; t=104.0 is preserved (113 - 104 = 9s <= 10s).
    flow.add_packet(timestamp=113.0, length=60, auto_prune=True)
    assert flow.packet_count == 4
    assert flow.pruned_packet_count == 2
    assert flow.timestamps == [104.0, 113.0]
    assert flow.window_duration == 9.0
    


def test_beacon_alert_serialization():
    """Verifies schema validation and serialization of BeaconAlert."""
    alert = BeaconAlert(
        alert_id="ALT-V2-001",
        flow_id="10.0.0.1:5000->198.51.100.1:443:tcp",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=5000,
        dst_port=443,
        protocol="tcp",
        severity=AlertSeverity.HIGH,
        mitre_attack=MITREAttackMetadata(
            technique_id=DetectionTechnique.PERIODIC_BEACON,
            technique_name="Application Layer Protocol",
        ),
        jitter_metrics=JitterMetrics(
            iat_mean=5.0,
            iat_std=0.1,
            coefficient_of_variation=0.02,
            median_absolute_deviation=0.05,
            shannon_entropy=4.5,
        ),
        anomaly_score=0.95,
        description="Low jitter periodic beaconing detected",
    )

    dumped = alert.model_dump()
    assert dumped["alert_id"] == "ALT-V2-001"
    assert dumped["severity"] == "HIGH"
    assert dumped["mitre_attack"]["technique_id"] == "T1071"

