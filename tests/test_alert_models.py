from datetime import datetime
from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    JitterMetrics,
    MITREAttackMetadata,
    PacketEvent,
)


def test_packet_event_flow_key_bidirectional():
    pkt1 = PacketEvent(
        timestamp=100.0,
        src_ip="10.0.0.5",
        dst_ip="198.51.100.24",
        src_port=49152,
        dst_port=8443,
        protocol="tcp",
        length=64,
    )
    pkt2 = PacketEvent(
        timestamp=100.1,
        src_ip="198.51.100.24",
        dst_ip="10.0.0.5",
        src_port=8443,
        dst_port=49152,
        protocol="tcp",
        length=128,
    )
    assert pkt1.flow_key == pkt2.flow_key


def test_beacon_alert_serialization():
    metrics = JitterMetrics(
        iat_mean=5.0,
        iat_std=0.02,
        coefficient_of_variation=0.004,
        median_absolute_deviation=0.01,
        shannon_entropy=4.2,
    )
    alert = BeaconAlert(
        alert_id="ALT-2026-001",
        flow_id="10.0.0.5:49152->198.51.100.24:8443:tcp",
        src_ip="10.0.0.5",
        dst_ip="198.51.100.24",
        src_port=49152,
        dst_port=8443,
        protocol="tcp",
        severity=AlertSeverity.CRITICAL,
        mitre_attack=MITREAttackMetadata(
            technique_id=DetectionTechnique.HTTP_BEACON,
            technique_name="Web Protocols C2",
        ),
        jitter_metrics=metrics,
        anomaly_score=-2.45,
        description="Persistent low-jitter HTTP beaconing pattern detected",
    )
    dumped = alert.model_dump()
    assert dumped["severity"] == "CRITICAL"
    assert dumped["mitre_attack"]["technique_id"] == "T1071.001"
    assert dumped["jitter_metrics"]["coefficient_of_variation"] == 0.004
    