import argparse
import json
import os
import sys
from typing import List

from src.pipeline import DetectionPipeline


def parse_args(args: List[str] = None) -> argparse.Namespace:
    """Parses command-line arguments for the beacon detection CLI."""
    parser = argparse.ArgumentParser(
        description="Behavioral C2 Beacon Detector for promiscous PCAP network telemetry.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        help="Path to the target PCAP file for analysis.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected proportion of anomalous beacon flows in the capture.",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=3,
        help="Minimum packet threshold required to evaluate a session flow.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output detected alerts strictly as formatted JSON to stdout.",
    )
    return parser.parse_args(args)


def main() -> None:
    """CLI entrypoint orchestrating PCAP ingestion and detection reporting."""
    args = parse_args()

    if not os.path.isfile(args.pcap):
        sys.stderr.write(f"Error: Target PCAP file not found: {args.pcap}\n")
        sys.exit(1)

    pipeline = DetectionPipeline(
        contamination=args.contamination,
        min_packets=args.min_packets,
    )

    alerts = pipeline.run(args.pcap)

    if args.json:
        sys.stdout.write(json.dumps(alerts, indent=2) + "\n")
        sys.exit(0)

    # Human-readable console reporting
    print("=" * 80)
    print(f"[*] C2 BEACON DETECTION REPORT: {args.pcap}")
    print(f"[*] Total Anomalous Flows Flagged: {len(alerts)}")
    print("=" * 80)

    if not alerts:
        print("[+] No anomalous beaconing patterns identified.")
        sys.exit(0)

    for alert in alerts:
        print(f"[!] THREAT DETECTED: {alert['flow_id']}")
        print(
            f"    Packets: {alert['packet_count']} | Bytes: {alert['total_bytes']} | "
            f"Mean IAT: {alert['iat_mean']:.3f}s | Std IAT: {alert['iat_std']:.3f}s"
        )
        print(f"    Anomaly Score: {alert['anomaly_score']:.4f}")
        print("-" * 80)

    sys.exit(0)


if __name__ == "__main__":
    main()