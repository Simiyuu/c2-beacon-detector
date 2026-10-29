import json
from pathlib import Path
import pytest
from scapy.all import IP, Raw, TCP, wrpcap

from src.cli import build_parser, main


@pytest.fixture
def c2_pcap_path(tmp_path: Path) -> str:
    """Generates a synthetic PCAP with a clockwork periodic beacon on port 8443."""
    pcap_file = tmp_path / "c2_traffic.pcap"
    packets = []
    base_time = 1700000000.0

    for i in range(8):
        pkt = (
            IP(src="10.0.0.45", dst="198.51.100.99")
            / TCP(sport=51234, dport=8443)
            / Raw(load=b"POST /heartbeat HTTP/1.1\r\n\r\n")
        )
        pkt.time = base_time + (i * 5.0)
        packets.append(pkt)

    wrpcap(str(pcap_file), packets)
    return str(pcap_file)


@pytest.fixture
def benign_pcap_path(tmp_path: Path) -> str:
    """Generates a synthetic PCAP with irregular web browsing packets."""
    pcap_file = tmp_path / "benign_traffic.pcap"
    packets = []
    base_time = 1700000000.0
    intervals = [0.0, 0.22, 3.41, 3.55, 18.2]

    for delay in intervals:
        pkt = (
            IP(src="10.0.0.45", dst="93.184.216.34")
            / TCP(sport=51234, dport=443)
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        pkt.time = base_time + delay
        packets.append(pkt)

    wrpcap(str(pcap_file), packets)
    return str(pcap_file)


def test_cli_parser_defaults():
    """Verifies default argument parsing structure."""
    parser = build_parser()
    args = parser.parse_args(["--pcap", "sample.pcap"])
    assert args.pcap == "sample.pcap"
    assert args.output is None
    assert args.format is None
    assert args.no_dedup is False
    assert args.strict is False


def test_cli_missing_pcap_returns_error_code(capsys):
    """Verifies that referencing a non-existent PCAP yields exit code 2."""
    ret = main(["--pcap", "does_not_exist_file.pcap"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "Target PCAP file not found" in captured.err


def test_cli_benign_traffic_returns_clean(benign_pcap_path, capsys):
    """Verifies that clean traffic reports zero incidents with exit code 0."""
    ret = main(["--pcap", benign_pcap_path])
    assert ret == 0
    captured = capsys.readouterr()
    assert "0 C2 beaconing anomalies detected" in captured.out
    assert "Telemetry:" in captured.out


def test_cli_detects_c2_and_exports_json(c2_pcap_path, tmp_path, capsys):
    """Verifies detection of C2 beacon and successful export to JSON file."""
    output_json = tmp_path / "hunt_alerts.json"
    ret = main([
        "--pcap", c2_pcap_path,
        "--output", str(output_json),
    ])

    assert ret == 0
    captured = capsys.readouterr()
    assert "ALERT SUMMARY" in captured.out
    assert "8443" in captured.out
    assert output_json.exists()

    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert len(data) >= 1
    assert data[0]["dst_port"] == 8443


def test_cli_strict_mode_exits_with_code_one(c2_pcap_path):
    """Verifies that --strict returns exit code 1 when threats are flagged."""
    ret = main(["--pcap", c2_pcap_path, "--strict"])
    assert ret == 1


def test_cli_exports_csv_format(c2_pcap_path, tmp_path):
    """Verifies that export in CSV format writes valid tabular data."""
    output_csv = tmp_path / "hunt_alerts.csv"
    ret = main([
        "--pcap", c2_pcap_path,
        "--output", str(output_csv),
        "--format", "csv",
    ])

    assert ret == 0
    assert output_csv.exists()
    content = output_csv.read_text(encoding="utf-8")
    assert "alert_id,timestamp,flow_id" in content
    assert "8443" in content
    