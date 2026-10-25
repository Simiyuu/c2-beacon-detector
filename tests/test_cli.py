import json
import subprocess
import sys
from sample_data.generate_traffic import generate_synthetic_pcap


def test_cli_execution_with_json_output(tmp_path):
    """Verify CLI parses pcap flag and outputs valid JSON alerts to stdout."""
    pcap_path = str(tmp_path / "cli_test.pcap")
    generate_synthetic_pcap(output_path=pcap_path, c2_jitter_pct=0.0)

    cmd = [
        sys.executable,
        "-m",
        "src.cli",
        "--pcap",
        pcap_path,
        "--json",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    assert result.returncode == 0, f"CLI exited with error: {result.stderr}"
    
    # Verify stdout parses cleanly as JSON
    alerts = json.loads(result.stdout.strip())
    assert isinstance(alerts, list)
    assert len(alerts) > 0
    assert any("198.51.100.24" in alert["flow_id"] for alert in alerts)


def test_cli_missing_pcap_argument_exits_with_error():
    """Verify running the CLI without mandatory --pcap argument returns non-zero code."""
    cmd = [sys.executable, "-m", "src.cli"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    assert result.returncode != 0