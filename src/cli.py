import argparse
import sys
from pathlib import Path
from typing import List, Optional

from src.exporter import AlertExporter
from src.hunter import C2Hunter
from src.models import AlertSeverity, BeaconAlert


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser for the C2 beacon detector."""
    parser = argparse.ArgumentParser(
        prog="c2-beacon-detector",
        description="Enterprise network threat hunting engine for C2 beacon detection.",
    )
    parser.add_argument(
        "--pcap",
        "-p",
        required=True,
        type=str,
        help="Path to the target PCAP file for analysis.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional path to write exported alerts (e.g., alerts.json, alerts.csv).",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "jsonl", "csv"],
        default=None,
        help="Explicit export format (inferred from --output extension if omitted).",
    )
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


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint orchestrating PCAP loading, hunting, and report export."""
    parser = build_parser()
    args = parser.parse_args(argv)

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


if __name__ == "__main__":
    sys.exit(main())
    