import pytest
from scapy.all import IP, Raw, TCP, wrpcap
from src.hunter import C2Hunter
from src.models import AlertSeverity


def test_hunter_detects_periodic_c2_in_pcap(tmp_path):
    """Verifies that C2Hunter streams a PCAP, groups the flow,

    and generates a correlated alert for a clockwork beacon on port 8443.
    """
    pcap_file = tmp_path / "c2_periodic_test.pcap"
    packets = []
    base_time = 1700000000.0

    # 8 packets exactly 5.0 seconds apart targeting non-standard port 8443
    for i in range(8):
        pkt = (
            IP(src="10.0.0.25", dst="198.51.100.50")
            / TCP(sport=49152, dport=8443)
            / Raw(load=b"POST /api/heartbeat HTTP/1.1\r\n\r\n")
        )
        pkt.time = base_time + (i * 5.0)
        packets.append(pkt)

    wrpcap(str(pcap_file), packets)

    hunter = C2Hunter()
    alerts = hunter.hunt(str(pcap_file))

    assert len(alerts) >= 1
    top_alert = alerts[0]
    assert top_alert.dst_port == 8443
    assert top_alert.src_ip == "10.0.0.25"
    assert top_alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]

    summary = hunter.get_summary()
    assert summary["packets_analyzed"] == 8
    assert summary["flows_assembled"] == 1
    assert summary["alerts_identified"] == len(alerts)
    assert summary["duration_seconds"] >= 0.0


def test_hunter_clears_benign_traffic(tmp_path):
    """Verifies that normal, irregular web browsing produces zero alerts."""
    pcap_file = tmp_path / "benign_traffic_test.pcap"
    packets = []
    base_time = 1700000000.0
    delays = [0.0, 0.15, 2.40, 2.55, 14.20]

    for delay in delays:
        pkt = (
            IP(src="10.0.0.25", dst="142.250.190.46")
            / TCP(sport=50000, dport=443)
            / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: google.com\r\n\r\n")
        )
        pkt.time = base_time + delay
        packets.append(pkt)

    wrpcap(str(pcap_file), packets)

    hunter = C2Hunter()
    alerts = hunter.hunt(str(pcap_file))

    assert len(alerts) == 0

    summary = hunter.get_summary()
    assert summary["packets_analyzed"] == 5
    assert summary["alerts_identified"] == 0
    