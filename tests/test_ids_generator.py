import pytest
from src.ids_generator import IDSRuleGenerator, IDSRuleGeneratorError
from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    JitterMetrics,
    MITREAttackMetadata,
)


@pytest.fixture
def sample_beacon_alert():
    """Generates a standardized sample BeaconAlert instance for rule testing."""
    return BeaconAlert(
        alert_id="ALT-IDS-001",
        flow_id="192.168.1.105:51234->198.51.100.50:443:tcp",
        src_ip="192.168.1.105",
        dst_ip="198.51.100.50",
        src_port=51234,
        dst_port=443,
        protocol="tcp",
        severity=AlertSeverity.HIGH,
        mitre_attack=MITREAttackMetadata(
            technique_id=DetectionTechnique.PERIODIC_BEACON,
            technique_name="Application Layer Protocol",
        ),
        jitter_metrics=JitterMetrics(
            iat_mean=10.0,
            iat_std=0.05,
            coefficient_of_variation=0.005,
            median_absolute_deviation=0.02,
            shannon_entropy=4.2,
        ),
        anomaly_score=-200.0,
        description="Periodic C2 beaconing identified on 192.168.1.105 with mean IAT=10.00s",
    )


def test_generator_initialization_defaults():
    """Verifies default generator configuration."""
    generator = IDSRuleGenerator()
    assert generator.base_sid == 1000001
    assert generator.current_sid == 1000001
    assert generator.default_action == "alert"
    assert generator.home_net == "$HOME_NET"


def test_generate_suricata_rule_structure(sample_beacon_alert):
    """Verifies Suricata rule format, keywords, and metadata alignment."""
    generator = IDSRuleGenerator(base_sid=1000001)
    rule = generator.generate_suricata_rule(sample_beacon_alert)

    assert rule.startswith("alert tcp $HOME_NET any -> 198.51.100.50 443")
    assert 'msg:"C2-DETECTOR [T1071] Periodic C2 beaconing identified on 192.168.1.105 with mean IAT=10.00s";' in rule
    assert "flow:established,to_server;" in rule
    assert "threshold:type limit, track by_src, count 1, seconds 60;" in rule
    assert "classtype:trojan-activity;" in rule
    assert "sid:1000001; rev:1;" in rule
    assert "metadata:mitre_technique_id T1071, anomaly_score -200.0;" in rule


def test_generate_snort_rule_structure(sample_beacon_alert):
    """Verifies Snort rule format and detection_filter option."""
    generator = IDSRuleGenerator(base_sid=2000001, default_action="drop")
    rule = generator.generate_snort_rule(sample_beacon_alert)

    assert rule.startswith("drop tcp $HOME_NET any -> 198.51.100.50 443")
    assert 'msg:"C2-DETECTOR [T1071] Periodic C2 beaconing identified on 192.168.1.105 with mean IAT=10.00s";' in rule
    assert "flow:established,to_server;" in rule
    assert "detection_filter:track by_src, count 3, seconds 60;" in rule
    assert "sid:2000001; rev:1;" in rule


def test_sid_sequential_incrementing(sample_beacon_alert):
    """Verifies sequential SID assignment across multiple rule generations."""
    generator = IDSRuleGenerator(base_sid=1000001)
    rule_1 = generator.generate_suricata_rule(sample_beacon_alert)
    rule_2 = generator.generate_suricata_rule(sample_beacon_alert)

    assert "sid:1000001;" in rule_1
    assert "sid:1000002;" in rule_2
    assert generator.current_sid == 1000003


def test_duplicate_sid_request_raises_error(sample_beacon_alert):
    """Verifies error handling when a caller requests an already allocated SID."""
    generator = IDSRuleGenerator(base_sid=1000001)
    generator.generate_suricata_rule(sample_beacon_alert, sid=1000050)

    with pytest.raises(IDSRuleGeneratorError) as exc_info:
        generator.generate_suricata_rule(sample_beacon_alert, sid=1000050)

    assert "Duplicate SID requested: 1000050" in str(exc_info.value)


def test_description_sanitization(sample_beacon_alert):
    """Verifies that quotes, semicolons, and backslashes in descriptions are stripped."""
    sample_beacon_alert.description = 'Malicious "Payload"; C2\\channel detected;'
    generator = IDSRuleGenerator()
    rule = generator.generate_suricata_rule(sample_beacon_alert)

    assert 'msg:"C2-DETECTOR [T1071] Malicious Payload C2channel detected";' in rule


def test_batch_rule_generation_and_export(sample_beacon_alert):
    """Verifies batch generation and text export formatting."""
    alert_2 = sample_beacon_alert.model_copy(deep=True)
    alert_2.dst_ip = "203.0.113.88"
    alert_2.dst_port = 8443

    generator = IDSRuleGenerator(base_sid=1000001)
    exported = generator.export_rules_text([sample_beacon_alert, alert_2], engine="suricata")

    lines = exported.strip().split("\n")
    assert len(lines) == 2
    assert "198.51.100.50 443" in lines[0]
    assert "sid:1000001;" in lines[0]
    assert "203.0.113.88 8443" in lines[1]
    assert "sid:1000002;" in lines[1]


def test_unsupported_ids_engine_raises_error(sample_beacon_alert):
    """Verifies that requesting an unsupported IDS engine raises IDSRuleGeneratorError."""
    generator = IDSRuleGenerator()
    with pytest.raises(IDSRuleGeneratorError) as exc_info:
        generator.generate_rules([sample_beacon_alert], engine="zeek")

    assert "Unsupported IDS engine: 'zeek'" in str(exc_info.value)


def test_generator_reset(sample_beacon_alert):
    """Verifies resetting the SID allocator to base_sid."""
    generator = IDSRuleGenerator(base_sid=1000001)
    generator.generate_suricata_rule(sample_beacon_alert)
    generator.generate_suricata_rule(sample_beacon_alert)
    assert generator.current_sid == 1000003

    generator.reset()
    assert generator.current_sid == 1000001
    rule_after_reset = generator.generate_suricata_rule(sample_beacon_alert)
    assert "sid:1000001;" in rule_after_reset

    