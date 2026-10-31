import os
from typing import List
import pytest

from sample_data.generate_traffic import generate_synthetic_pcap
from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    PacketEvent,
)
from src.pipeline import DetectionPipeline, StreamingBeaconDetector


def test_end_to_end_pipeline_identifies_c2_flow(tmp_path):
    """Verify raw PCAP ingestion produces accurate beacon alerts end-to-end."""
    pcap_file = str(tmp_path / "synthetic_test.pcap")

    # Generate 50-packet trace (30 bursty web packets, 20 fixed 5.0s C2 beacons)
    generate_synthetic_pcap(output_path=pcap_file, c2_jitter_pct=0.0)
    assert os.path.exists(pcap_file)

    # Execute full detection pipeline
    pipeline = DetectionPipeline(contamination=0.10)
    alerts = pipeline.run(pcap_file)

    # Validate alert structure and target identification
    assert len(alerts) > 0, "Pipeline failed to detect any anomalies in synthetic trace"

    # Verify the C2 destination IP and port were accurately isolated
    flagged_keys = [alert["flow_id"] for alert in alerts]
    assert any("198.51.100.24" in key and "8443" in key for key in flagged_keys), (
        f"C2 flow was not flagged. Detected flows: {flagged_keys}"
    )


def test_streaming_pipeline_detects_periodic_beacon():
    """Verify StreamingBeaconDetector flags periodic beacon streams and triggers alert callbacks."""
    captured_callback_alerts: List[BeaconAlert] = []

    def on_alert(alert: BeaconAlert):
        captured_callback_alerts.append(alert)

    detector = StreamingBeaconDetector(alert_callback=on_alert)

    # Ingest 6 periodic packets (10.0s intervals)
    base_time = 1000.0
    all_emitted: List[BeaconAlert] = []
    for i in range(6):
        pkt = PacketEvent(
            timestamp=base_time + (i * 10.0),
            src_ip="10.0.0.45",
            dst_ip="198.51.100.99",
            src_port=51200,
            dst_port=443,
            protocol="tcp",
            length=128,
            payload_entropy=0.0,
        )
        emitted = detector.process_packet(pkt)
        all_emitted.extend(emitted)

    # Exactly 1 alert emitted across the stream (fired at packet 5, deduplicated on packet 6)
    assert len(all_emitted) == 1
    assert all_emitted[0].mitre_attack.technique_id == DetectionTechnique.PERIODIC_BEACON
    assert all_emitted[0].dst_ip == "198.51.100.99"
    assert len(detector.alerts) == 1
    assert len(captured_callback_alerts) == 1
    assert captured_callback_alerts[0].flow_id == detector.alerts[0].flow_id


def test_streaming_pipeline_alert_deduplication():
    """Verify that subsequent packets in an already flagged flow do not produce duplicate alerts."""
    detector = StreamingBeaconDetector()
    base_time = 2000.0

    # Ingest 10 deterministic beacon packets
    for i in range(10):
        pkt = PacketEvent(
            timestamp=base_time + (i * 5.0),
            src_ip="10.0.0.50",
            dst_ip="198.51.100.77",
            src_port=51500,
            dst_port=8443,
            protocol="tcp",
            length=100,
            payload_entropy=0.0,
        )
        detector.process_packet(pkt)

    # Exactly 1 periodic alert must be stored despite receiving additional matching packets
    periodic_alerts = [
        a for a in detector.alerts if a.mitre_attack.technique_id == DetectionTechnique.PERIODIC_BEACON
    ]
    assert len(periodic_alerts) == 1


def test_streaming_pipeline_tick_evicts_idle_flows():
    """Verify detector tick cleans up dormant sessions from the sessionizer."""
    detector = StreamingBeaconDetector()

    # Ingest a single packet at t=100.0
    pkt = PacketEvent(
        timestamp=100.0,
        src_ip="10.0.0.10",
        dst_ip="198.51.100.10",
        src_port=49152,
        dst_port=80,
        protocol="tcp",
        length=64,
        payload_entropy=0.0,
    )
    detector.process_packet(pkt)
    assert detector.stats()["sessionizer"]["active_flows"] == 1

    # Advance clock past default 120s idle timeout (100.0 + 130.0 = 230.0)
    closing = detector.tick(current_time=230.0)
    assert detector.stats()["sessionizer"]["active_flows"] == 0
    assert len(closing) == 0  # 1-packet flow does not meet minimum packets for rule alert


def test_streaming_pipeline_ids_rule_export():
    """Verify detected alerts can be exported directly into Suricata and Snort syntax."""
    detector = StreamingBeaconDetector()

    # Ingest periodic stream to generate an alert
    for i in range(6):
        pkt = PacketEvent(
            timestamp=100.0 + (i * 10.0),
            src_ip="192.168.1.15",
            dst_ip="203.0.113.5",
            src_port=55000,
            dst_port=443,
            protocol="tcp",
            length=128,
            payload_entropy=0.0,
        )
        detector.process_packet(pkt)

    assert len(detector.alerts) >= 1

    suricata_rules = detector.export_ids_rules(engine="suricata")
    assert "alert tcp $HOME_NET any -> 203.0.113.5 443" in suricata_rules
    assert "classtype:trojan-activity;" in suricata_rules
    assert "sid:1000001;" in suricata_rules

    snort_rules = detector.export_ids_rules(engine="snort")
    assert "alert tcp $HOME_NET any -> 203.0.113.5 443" in snort_rules
    assert "detection_filter:track by_src" in snort_rules


def test_streaming_pipeline_stats_and_reset():
    """Verify stats telemetry counters and clean state resets."""
    detector = StreamingBeaconDetector()

    packets = [
        PacketEvent(
            timestamp=10.0 + i,
            src_ip="10.0.0.8",
            dst_ip="198.51.100.8",
            src_port=40000,
            dst_port=80,
            protocol="tcp",
            length=64,
            payload_entropy=0.0,
        )
        for i in range(4)
    ]
    detector.process_packet_events(packets)

    st = detector.stats()
    assert st["total_packets_processed"] == 4
    assert st["active_rules_count"] == 3
    assert st["sessionizer"]["active_flows"] == 1

    detector.reset()
    st_reset = detector.stats()
    assert st_reset["total_packets_processed"] == 0
    assert st_reset["total_alerts_emitted"] == 0
    assert st_reset["sessionizer"]["active_flows"] == 0
    