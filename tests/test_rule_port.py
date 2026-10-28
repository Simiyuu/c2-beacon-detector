import pytest
from src.models import AlertSeverity, DetectionTechnique, FlowRecord
from src.rules.port import NonStandardPortRule


def test_port_rule_flags_c2_on_port_8443():
    """Verify beacon on known suspicious port 8443 triggers CRITICAL alert."""
    flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=8443,
        protocol="tcp",
        packet_count=6,
        timestamps=[0.0, 5.0, 10.0, 15.0, 20.0, 25.0],
    )

    rule = NonStandardPortRule(min_packets=5)
    alert = rule.evaluate(flow)

    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.mitre_attack.technique_id == DetectionTechnique.NON_STANDARD_PORT
    assert "known high-risk C2 port" in alert.description


def test_port_rule_flags_high_random_port():
    """Verify periodic flow targeting unassigned port 31337 flags with HIGH severity."""
    flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:31337:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=31337,
        protocol="tcp",
        packet_count=5,
        timestamps=[0.0, 10.0, 20.0, 30.0, 40.0],
    )

    rule = NonStandardPortRule(min_packets=5)
    alert = rule.evaluate(flow)

    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert alert.dst_port == 31337


def test_port_rule_clears_standard_https_port_443():
    """Verify standard HTTPS port 443 is ignored by port rule."""
    flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=443,
        protocol="tcp",
        packet_count=6,
        timestamps=[0.0, 5.0, 10.0, 15.0, 20.0, 25.0],
    )

    rule = NonStandardPortRule(min_packets=5)
    alert = rule.evaluate(flow)
    assert alert is None


def test_port_rule_clears_erratic_traffic_on_high_port():
    """Verify erratic browsing traffic on non-standard port does not alert."""
    flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:8080:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=8080,
        protocol="tcp",
        packet_count=5,
        timestamps=[0.0, 0.2, 5.8, 6.1, 40.0],
    )

    rule = NonStandardPortRule(min_packets=5)
    alert = rule.evaluate(flow)
    assert alert is None
    