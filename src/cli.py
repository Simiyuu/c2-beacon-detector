import argparse
from collections import Counter
import math
from pathlib import Path
import queue
import sys
import time
from typing import List, Optional

from scapy.all import IP, TCP, UDP, Packet

from src.exporter import AlertExporter
from src.hunter import C2Hunter
from src.ids_generator import IDSRuleGenerator
from src.models import AlertSeverity, BeaconAlert, PacketEvent
from src.pipeline import StreamingBeaconDetector
from src.sniffer import LivePacketSniffer, PacketSnifferError
from src.windowed_sessionizer import WindowedFlowSessionizer


def _calculate_payload_entropy(payload: bytes) -> float:
    """Calculates Shannon entropy in bits per byte for payload data."""
    if not payload:
        return 0.0
    length = len(payload)
    counts = Counter(payload)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def _scapy_to_packet_event(raw_pkt: Packet) -> Optional[PacketEvent]:
    """Translates a live captured Scapy IP frame into a normalized PacketEvent."""
    if not raw_pkt.haslayer(IP):
        return None

    ip_layer = raw_pkt[IP]
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    timestamp = float(getattr(raw_pkt, "time", time.time()))
    length = len(raw_pkt)

    if raw_pkt.haslayer(TCP):
        tcp_layer = raw_pkt[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        protocol = "tcp"
        payload = bytes(tcp_layer.payload)
    elif raw_pkt.haslayer(UDP):
        udp_layer = raw_pkt[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        protocol = "udp"
        payload = bytes(udp_layer.payload)
    else:
        src_port = 0
        dst_port = 0
        protocol = "ip"
        payload = b""

    entropy = _calculate_payload_entropy(payload)

    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        payload_entropy=entropy,
    )


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser for the C2 beacon detector."""
    parser = argparse.ArgumentParser(
        prog="c2-beacon-detector",
        description="Enterprise network threat hunting engine for C2 beacon detection.",
    )

    # Ingestion sources (Offline PCAP vs Live Interface)
    input_group = parser.add_argument_group("Capture Input Options")
    input_group.add_argument(
        "--pcap",
        "-p",
        type=str,
        default=None,
        help="Path to the target PCAP file for offline analysis.",
    )
    input_group.add_argument(
        "--interface",
        "-i",
        type=str,
        default=None,
        help="Network interface name for live streaming packet capture.",
    )
    input_group.add_argument(
        "--bpf",
        type=str,
        default="ip and (tcp or udp)",
        help="Berkeley Packet Filter (BPF) expression for live sniffing (default: 'ip and (tcp or udp)').",
    )
    input_group.add_argument(
        "--packet-count",
        "-c",
        type=int,
        default=None,
        help="Maximum packet count to capture in live streaming mode.",
    )
    input_group.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=None,
        help="Maximum capture duration in seconds for live mode.",
    )

    # Sliding-window parameters
    window_group = parser.add_argument_group("Sliding-Window Parameters")
    window_group.add_argument(
        "--window-duration",
        "-w",
        type=float,
        default=300.0,
        help="Sliding-window duration in seconds for time-slice eviction (default: 300.0s).",
    )
    window_group.add_argument(
        "--max-window-packets",
        type=int,
        default=100,
        help="Maximum packet buffer capacity per flow record (default: 100 packets).",
    )
    window_group.add_argument(
        "--idle-timeout",
        type=float,
        default=120.0,
        help="Inactivity timeout in seconds before dormant flows are evicted (default: 120.0s).",
    )

    # Export & IDS options
    export_group = parser.add_argument_group("Export & IDS Options")
    export_group.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional path to write exported alerts (e.g., alerts.json, alerts.csv).",
    )
    export_group.add_argument(
        "--format",
        "-f",
        choices=["json", "jsonl", "csv"],
        default=None,
        help="Explicit export format (inferred from --output extension if omitted).",
    )
    export_group.add_argument(
        "--export-ids",
        type=str,
        default=None,
        help="Optional file path to export generated Suricata or Snort IDS rules.",
    )
    export_group.add_argument(
        "--ids-engine",
        choices=["suricata", "snort"],
        default="suricata",
        help="Target IDS engine syntax for rule export (default: suricata).",
    )

    # Execution controls
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable alert deduplication to view all raw detection rule triggers.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 if any HIGH or CRITICAL severity alerts are detected.",
    )
    return parser


def print_alert_table(alerts: List[BeaconAlert]) -> None:
    """Renders an ASCII summary table of detected C2 alerts to stdout."""
    if not alerts:
        print("\n[+] Hunt complete: 0 C2 beaconing anomalies detected.")
        return

    print(f"\n[!] ALERT SUMMARY: {len(alerts)} incident(s) flagged\n")
    header = f"{'SEVERITY':<10} | {'FLOW ID':<42} | {'TECHNIQUE':<8} | {'ANOMALY SCORE'}"
    print(header)
    print("-" * len(header))

    for alert in alerts:
        tech_id = (
            alert.mitre_attack.technique_id.value
            if hasattr(alert.mitre_attack.technique_id, "value")
            else str(alert.mitre_attack.technique_id)
        )
        print(
            f"{alert.severity.value:<10} | "
            f"{alert.flow_id:<42} | "
            f"{tech_id:<8} | "
            f"{alert.anomaly_score:.2f}"
        )
    print()


def _run_pcap_hunt(args: argparse.Namespace) -> int:
    """Executes offline PCAP threat hunt."""
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[-] Error: Target PCAP file not found: {args.pcap}", file=sys.stderr)
        return 2

    hunter = C2Hunter()
    deduplicate = not args.no_dedup
    alerts = hunter.hunt(str(pcap_path), deduplicate=deduplicate)

    print_alert_table(alerts)

    if args.output:
        try:
            AlertExporter.save_to_file(alerts, args.output, fmt=args.format)
            print(f"[+] Successfully exported {len(alerts)} alert(s) to: {args.output}")
        except Exception as e:
            print(f"[-] Error writing output file: {e}", file=sys.stderr)
            return 2

    if args.export_ids:
        try:
            ids_gen = IDSRuleGenerator()
            rules_text = ids_gen.export_rules_text(alerts, engine=args.ids_engine)
            Path(args.export_ids).write_text(rules_text, encoding="utf-8")
            print(
                f"[+] Successfully exported {len(alerts)} {args.ids_engine.capitalize()} rule(s) to: {args.export_ids}"
            )
        except Exception as e:
            print(f"[-] Error exporting IDS rules: {e}", file=sys.stderr)
            return 2

    summary = hunter.get_summary()
    print(
        f"[*] Telemetry: {summary.get('packets_analyzed', 0)} packets analyzed | "
        f"{summary.get('flows_assembled', 0)} flows evaluated in "
        f"{summary.get('duration_seconds', 0.0):.3f}s"
    )

    if args.strict:
        has_critical_or_high = any(
            a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL) for a in alerts
        )
        if has_critical_or_high:
            return 1

    return 0


def _run_live_sniff(args: argparse.Namespace) -> int:
    """Executes live wire sniffing and streaming beacon detection."""
    print(f"[*] Initializing live sniffing on interface '{args.interface}'...")
    if args.bpf:
        print(f"[*] Applied BPF filter: {args.bpf}")

    sessionizer = WindowedFlowSessionizer(
        idle_timeout=args.idle_timeout,
        window_duration=args.window_duration,
        max_window_packets=args.max_window_packets,
    )
    ids_gen = IDSRuleGenerator()

    def on_live_alert(alert: BeaconAlert) -> None:
        tech_id = (
            alert.mitre_attack.technique_id.value
            if hasattr(alert.mitre_attack.technique_id, "value")
            else str(alert.mitre_attack.technique_id)
        )
        print(
            f"[!] LIVE ALERT [{alert.severity.value}] {alert.flow_id} ({tech_id}) - Score: {alert.anomaly_score:.2f}"
        )

    detector = StreamingBeaconDetector(
        sessionizer=sessionizer,
        ids_generator=ids_gen,
        alert_callback=on_live_alert,
    )

    try:
        sniffer = LivePacketSniffer(
            interface=args.interface,
            bpf_filter=args.bpf,
        )
        sniffer.start()
    except PacketSnifferError as e:
        print(f"[-] Error initializing packet sniffer: {e}", file=sys.stderr)
        return 2

    start_time = time.time()
    packet_count = 0
    print("[*] Sniffer active. Press Ctrl+C to terminate live capture.\n")

    try:
        while sniffer.stats["running"]:
            if args.timeout and (time.time() - start_time) >= args.timeout:
                break
            try:
                raw_pkt = sniffer._queue.get(timeout=0.2)
                event = _scapy_to_packet_event(raw_pkt)
                if event:
                    detector.process_packet(event)
                    packet_count += 1
                    if args.packet_count and packet_count >= args.packet_count:
                        break
                sniffer._queue.task_done()
            except queue.Empty:
                pass
            detector.tick(current_time=time.time())
    except KeyboardInterrupt:
        print("\n[*] Stopping capture (SIGINT received)...")
    finally:
        sniffer.stop()

    duration = time.time() - start_time
    alerts = detector.alerts
    print_alert_table(alerts)

    if args.output:
        try:
            AlertExporter.save_to_file(alerts, args.output, fmt=args.format)
            print(f"[+] Successfully exported {len(alerts)} alert(s) to: {args.output}")
        except Exception as e:
            print(f"[-] Error writing output file: {e}", file=sys.stderr)
            return 2

    if args.export_ids:
        try:
            rules_text = detector.export_ids_rules(engine=args.ids_engine)
            Path(args.export_ids).write_text(rules_text, encoding="utf-8")
            print(
                f"[+] Successfully exported {len(alerts)} {args.ids_engine.capitalize()} rule(s) to: {args.export_ids}"
            )
        except Exception as e:
            print(f"[-] Error exporting IDS rules: {e}", file=sys.stderr)
            return 2

    st = detector.stats()
    print(
        f"[*] Telemetry: {st.get('total_packets_processed', 0)} packets analyzed | "
        f"{st.get('sessionizer', {}).get('active_flows', 0)} active flows remaining in "
        f"{duration:.3f}s"
    )

    if args.strict:
        has_critical_or_high = any(
            a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL) for a in alerts
        )
        if has_critical_or_high:
            return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint orchestrating input parsing, capture routing, and reporting."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.pcap and not args.interface:
        print(
            "[-] Error: Either --pcap (-p) or --interface (-i) must be specified.",
            file=sys.stderr,
        )
        return 2

    if args.pcap and args.interface:
        print(
            "[-] Error: Cannot specify both --pcap and --interface simultaneously.",
            file=sys.stderr,
        )
        return 2

    if args.pcap:
        return _run_pcap_hunt(args)
    else:
        return _run_live_sniff(args)


if __name__ == "__main__":
    sys.exit(main())
    