import json
from pathlib import Path
import queue
import time
from unittest.mock import MagicMock, patch
import pytest
from scapy.all import IP, Raw, TCP, wrpcap

from src.cli import build_parser, main
from src.sniffer import PacketSnifferError


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
    """Verifies default argument parsing structure and v2 sliding window parameters."""
    parser = build_parser()
    args = parser.parse_args(["--pcap", "sample.pcap"])
    assert args.pcap == "sample.pcap"
    assert args.interface is None
    assert args.bpf == "ip and (tcp or udp)"
    assert args.packet_count is None
    assert args.timeout is None
    assert args.window_duration == 300.0
    assert args.max_window_packets == 100
    assert args.idle_timeout == 120.0
    assert args.output is None
    assert args.format is None
    assert args.export_ids is None
    assert args.ids_engine == "suricata"
    assert args.no_dedup is False
    assert args.strict is False


def test_cli_neither_pcap_nor_interface_returns_error(capsys):
    """Verifies that omitting both --pcap and --interface yields exit code 2."""
    ret = main([])
    assert ret == 2
    captured = capsys.readouterr()
    assert "Either --pcap (-p) or --interface (-i) must be specified." in captured.err


def test_cli_both_pcap_and_interface_returns_error(capsys):
    """Verifies that passing both --pcap and --interface simultaneously yields exit code 2."""
    ret = main(["--pcap", "sample.pcap", "--interface", "eth0"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "Cannot specify both --pcap and --interface simultaneously." in captured.err


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


def test_cli_pcap_export_ids_rules_suricata_and_snort(c2_pcap_path, tmp_path):
    """Verifies automated Suricata and Snort rule export from PCAP hunting."""
    suricata_file = tmp_path / "suricata.rules"
    ret_suricata = main([
        "--pcap", c2_pcap_path,
        "--export-ids", str(suricata_file),
        "--ids-engine", "suricata",
    ])
    assert ret_suricata == 0
    assert suricata_file.exists()
    suricata_content = suricata_file.read_text(encoding="utf-8")
    assert "alert tcp $HOME_NET any -> 198.51.100.99 8443" in suricata_content
    assert "classtype:trojan-activity;" in suricata_content

    snort_file = tmp_path / "snort.rules"
    ret_snort = main([
        "--pcap", c2_pcap_path,
        "--export-ids", str(snort_file),
        "--ids-engine", "snort",
    ])
    assert ret_snort == 0
    assert snort_file.exists()
    snort_content = snort_file.read_text(encoding="utf-8")
    assert "alert tcp $HOME_NET any -> 198.51.100.99 8443" in snort_content
    assert "detection_filter:track by_src" in snort_content


@patch("src.cli.LivePacketSniffer")
def test_cli_live_sniff_sniffer_error_returns_exit_code_2(mock_sniffer_cls, capsys):
    """Verifies that sniffer initialization errors return exit code 2."""
    mock_sniffer_cls.side_effect = PacketSnifferError("Permission denied on raw socket")
    ret = main(["--interface", "eth0"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "Error initializing packet sniffer" in captured.err


@patch("src.cli.LivePacketSniffer")
def test_cli_live_sniff_processes_packets_and_exports_ids(mock_sniffer_cls, tmp_path):
    """Verifies live interface capture pipeline, packet limit termination, and IDS export."""
    mock_instance = MagicMock()
    q = queue.Queue()
    base_time = time.time()

    # Ingest 6 periodic packets (10.0s intervals) to trigger PeriodicBeaconRule
    for i in range(6):
        pkt = (
            IP(src="10.0.0.45", dst="198.51.100.99")
            / TCP(sport=51234, dport=8443)
            / Raw(load=b"BEACON")
        )
        pkt.time = base_time + (i * 10.0)
        q.put(pkt)

    mock_instance._queue = q
    mock_instance.stats = {"running": True}
    mock_sniffer_cls.return_value = mock_instance

    ids_out = tmp_path / "live_suricata.rules"
    ret = main([
        "--interface", "eth0",
        "--packet-count", "6",
        "--export-ids", str(ids_out),
    ])

    assert ret == 0
    assert ids_out.exists()
    content = ids_out.read_text(encoding="utf-8")
    assert "198.51.100.99 8443" in content
    mock_instance.start.assert_called_once()
    mock_instance.stop.assert_called_once()

    