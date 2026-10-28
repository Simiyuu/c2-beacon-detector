import pytest
from src.engine import RuleEngine
from src.models import AlertSeverity, DetectionTechnique, FlowRecord


def test_rule_engine_registers_default_rules():
    """Verify engine initializes with all core detection rules active."""
    engine = RuleEngine(register_defaults=True)
    assert len(engine.rules) == 4
    rule_types = {type(rule).__name__ for rule in engine.rules}
    assert "PeriodicBeaconRule" in rule_types
    assert "JitterBeaconRule" in rule_types
    assert "HighEntropyChannelRule" in rule_types
    assert "NonStandardPortRule" in rule_types


def test_rule_engine_evaluates_multi_vector_c2_and_deduplicates():
    """Verify a flow matching periodic timing and non-standard port 8443

    is deduplicated with CRITICAL severity and enriched context.
    """
    engine = RuleEngine(register_defaults=True)

    # Synthetic C2 flow: Clockwork 5s interval on port 8443
    c2_flow = FlowRecord(
        flow_id="10.0.0.15:51234->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=51234,
        dst_port=8443,
        protocol="tcp",
        packet_count=6,
        timestamps=[0.0, 5.0, 10.0, 15.0, 20.0, 25.0],
        packet_lengths=[128, 128, 128, 128, 128, 128],
        payload_entropies=[0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    )

    # Raw multi-rule evaluation without deduplication produces 2 alerts (Periodic + Port)
    raw_alerts = engine.evaluate_flow(c2_flow)
    assert len(raw_alerts) == 2

    # Deduplication elevates to CRITICAL and retains correlated technique
    deduped = engine.evaluate_flows([c2_flow], deduplicate=True)
    assert len(deduped) == 1
    alert = deduped[0]
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.dst_port == 8443
    assert "Correlated technique: T1071" in alert.description


def test_rule_engine_clears_benign_flows():
    """Verify erratic web flow yields zero alerts."""
    engine = RuleEngine(register_defaults=True)

    benign_flow = FlowRecord(
        flow_id="10.0.0.15:49152->142.250.190.46:443:tcp",
        src_ip="10.0.0.15",
        dst_ip="142.250.190.46",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
        packet_count=6,
        timestamps=[0.0, 0.1, 2.5, 2.6, 15.0, 15.2],
        packet_lengths=[1200, 300, 1400, 250, 1500, 400],
        payload_entropies=[4.1, 3.8, 4.5, 3.9, 4.2, 3.7],
    )

    alerts = engine.evaluate_flows([benign_flow], deduplicate=True)
    assert len(alerts) == 0
    