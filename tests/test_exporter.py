import json
import pytest
from src.exporter import AlertExporter
from src.models import (
    AlertSeverity,
    BeaconAlert,
    DetectionTechnique,
    JitterMetrics,
    MITREAttackMetadata,
)


@pytest.fixture
def sample_alert() -> BeaconAlert:
    """Provides a synthetic BeaconAlert instance for export testing."""
    metrics = JitterMetrics(
        iat_mean=5.0,
        iat_std=0.015,
        coefficient_of_variation=0.003,
        median_absolute_deviation=0.01,
        shannon_entropy=7.82,
    )
    mitre = MITREAttackMetadata(
        technique_id=DetectionTechnique.PERIODIC_BEACON,
        technique_name="Application Layer Protocol",
        tactic="Command and Control",
        reference_url="https://attack.mitre.org/techniques/T1071/",
    )
    return BeaconAlert(
        alert_id="ALT-NET-001-A1B2C3D4",
        flow_id="10.0.0.15:49152->198.51.100.24:8443:tcp",
        src_ip="10.0.0.15",
        dst_ip="198.51.100.24",
        src_port=49152,
        dst_port=8443,
        protocol="tcp",
        severity=AlertSeverity.CRITICAL,
        mitre_attack=mitre,
        jitter_metrics=metrics,
        anomaly_score=-9.85,
        description="Clockwork periodic beaconing on non-standard port 8443",
    )


def test_exporter_to_json(sample_alert):
    """Verifies that to_json serializes alerts into valid, well-structured JSON."""
    json_str = AlertExporter.to_json([sample_alert])
    data = json.loads(json_str)

    assert isinstance(data, list)
    assert len(data) == 1
    record = data[0]
    assert record["alert_id"] == "ALT-NET-001-A1B2C3D4"
    assert record["severity"] == "CRITICAL"
    assert record["dst_port"] == 8443
    assert record["mitre_attack"]["technique_id"] == "T1071"


def test_exporter_to_jsonl(sample_alert):
    """Verifies that to_jsonl outputs newline-delimited JSON suitable for log shipping."""
    jsonl_str = AlertExporter.to_jsonl([sample_alert, sample_alert])
    lines = [line.strip() for line in jsonl_str.strip().split("\n")]

    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert parsed["src_ip"] == "10.0.0.15"
        assert parsed["severity"] == "CRITICAL"


def test_exporter_to_csv(sample_alert):
    """Verifies that to_csv generates a flattened tabular format with expected headers."""
    csv_str = AlertExporter.to_csv([sample_alert])
    lines = csv_str.strip().splitlines()

    assert len(lines) == 2  # Header + 1 data row
    headers = lines[0].split(",")
    assert "alert_id" in headers
    assert "mitre_technique_id" in headers
    assert "entropy" in headers

    data_row = lines[1]
    assert "ALT-NET-001-A1B2C3D4" in data_row
    assert "T1071" in data_row
    assert "CRITICAL" in data_row


def test_exporter_save_to_file(sample_alert, tmp_path):
    """Verifies automatic format inference and disk persistence."""
    json_path = tmp_path / "hunt_output.json"
    csv_path = tmp_path / "hunt_output.csv"
    jsonl_path = tmp_path / "hunt_output.jsonl"

    AlertExporter.save_to_file([sample_alert], str(json_path))
    AlertExporter.save_to_file([sample_alert], str(csv_path))
    AlertExporter.save_to_file([sample_alert], str(jsonl_path))

    assert json_path.exists()
    assert csv_path.exists()
    assert jsonl_path.exists()

    assert json.loads(json_path.read_text(encoding="utf-8"))[0]["alert_id"] == "ALT-NET-001-A1B2C3D4"
    assert "ALT-NET-001-A1B2C3D4" in csv_path.read_text(encoding="utf-8")


def test_exporter_unsupported_format(sample_alert, tmp_path):
    """Verifies that unknown file formats raise an explicit ValueError."""
    invalid_path = tmp_path / "hunt_output.yaml"
    with pytest.raises(ValueError, match="Unsupported export format"):
        AlertExporter.save_to_file([sample_alert], str(invalid_path))
        