import argparse
import json
import math
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from scapy.all import IP, Raw, TCP, UDP, wrpcap
from src.hunter import C2Hunter
from src.models import BeaconAlert


def generate_benchmark_trace(output_pcap: str) -> Dict[str, bool]:
    """Synthesizes a labeled ground-truth PCAP containing distinct C2 flows and benign noise.

    Returns a mapping of flow_key (src_ip->dst_ip:dst_port:proto) to is_malicious (bool).
    """
    packets = []
    base_time = 1700000000.0
    ground_truth: Dict[str, bool] = {}

    # 1. Malicious Flow A: Clockwork Periodic Beacon (T1071)
    flow_a = "10.0.1.10->198.51.100.10:8080:tcp"
    ground_truth[flow_a] = True
    for i in range(12):
        pkt = (
            IP(src="10.0.1.10", dst="198.51.100.10")
            / TCP(sport=49200, dport=8080)
            / Raw(load=b"POST /api/v1/ping HTTP/1.1\r\n\r\n")
        )
        pkt.time = base_time + (i * 3.0)
        packets.append(pkt)

    # 2. Malicious Flow B: Jittered Beacon with Sleep Variance (T1071.001)
    flow_b = "10.0.1.20->198.51.100.20:8443:tcp"
    ground_truth[flow_b] = True
    rng = random.Random(42)
    cur_time = base_time + 0.5
    for _ in range(12):
        pkt = (
            IP(src="10.0.1.20", dst="198.51.100.20")
            / TCP(sport=49300, dport=8443)
            / Raw(load=b"CHECKIN")
        )
        pkt.time = cur_time
        packets.append(pkt)
        cur_time += 4.0 + rng.uniform(-0.4, 0.4)

    # 3. Malicious Flow C: Encrypted High-Entropy Tunnel (T1573)
    flow_c = "10.0.1.30->198.51.100.30:443:tcp"
    ground_truth[flow_c] = True
    high_entropy_bytes = bytes([rng.randint(0, 255) for _ in range(256)])
    for i in range(10):
        pkt = (
            IP(src="10.0.1.30", dst="198.51.100.30")
            / TCP(sport=49400, dport=443)
            / Raw(load=high_entropy_bytes)
        )
        pkt.time = base_time + 1.0 + (i * 2.5)
        packets.append(pkt)

    # 4. Benign Flow D: Irregular Interactive Web Traffic
    flow_d = "10.0.1.50->142.250.190.46:443:tcp"
    ground_truth[flow_d] = False
    web_delays = [0.0, 0.12, 1.85, 2.10, 8.40, 8.55, 22.1, 22.3]
    for delay in web_delays:
        pkt = (
            IP(src="10.0.1.50", dst="142.250.190.46")
            / TCP(sport=51000, dport=443)
            / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: google.com\r\n\r\n")
        )
        pkt.time = base_time + delay
        packets.append(pkt)

    # 5. Benign Flow E: Sporadic DNS Lookups
    flow_e = "10.0.1.50->8.8.8.8:53:udp"
    ground_truth[flow_e] = False
    dns_delays = [0.05, 5.20, 19.80, 45.0]
    for delay in dns_delays:
        pkt = (
            IP(src="10.0.1.50", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        )
        pkt.time = base_time + delay
        packets.append(pkt)

    # Sort all packets chronologically to simulate physical capture wire order
    packets.sort(key=lambda p: float(p.time))
    Path(output_pcap).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_pcap, packets)

    return ground_truth


def evaluate_c2_detector(
    pcap_path: str, ground_truth: Dict[str, bool]
) -> Dict[str, Any]:
    """Runs C2Hunter on target PCAP and calculates precision, recall, F1, and FPR."""
    hunter = C2Hunter()
    start_eval = time.perf_counter()
    alerts: List[BeaconAlert] = hunter.hunt(pcap_path, deduplicate=True)
    elapsed = time.perf_counter() - start_eval

    # Normalize alert keys to match ground truth format (src->dst:port:proto)
    flagged_flow_keys = set()
    for alert in alerts:
        key = f"{alert.src_ip}->{alert.dst_ip}:{alert.dst_port}:{alert.protocol.lower()}"
        flagged_flow_keys.add(key)

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for flow_key, is_malicious in ground_truth.items():
        flagged = flow_key in flagged_flow_keys
        if is_malicious and flagged:
            tp += 1
        elif not is_malicious and flagged:
            fp += 1
        elif is_malicious and not flagged:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    telemetry = hunter.get_summary()
    total_packets = telemetry.get("packets_analyzed", 0)
    throughput_pps = (total_packets / elapsed) if elapsed > 0 else 0.0

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
        },
        "performance": {
            "total_packets": total_packets,
            "evaluation_time_sec": round(elapsed, 4),
            "throughput_pps": round(throughput_pps, 2),
            "alerts_generated": len(alerts),
        },
    }


def print_benchmark_report(results: Dict[str, Any]) -> None:
    """Formats and prints the detection evaluation scorecard."""
    cm = results["confusion_matrix"]
    m = results["metrics"]
    p = results["performance"]

    print("\n" + "=" * 62)
    print("       C2-BEACON-DETECTOR EVALUATION BENCHMARK SCORECARD       ")
    print("=" * 62)
    print(f" True Positives (TP):  {cm['tp']:<5} | False Positives (FP): {cm['fp']:<5}")
    print(f" False Negatives (FN): {cm['fn']:<5} | True Negatives (TN):  {cm['tn']:<5}")
    print("-" * 62)
    print(f" Precision:            {m['precision'] * 100:>6.2f}%")
    print(f" Recall (Sensitivity): {m['recall'] * 100:>6.2f}%")
    print(f" F1-Score:             {m['f1_score']:>7.4f}")
    print(f" False Positive Rate:  {m['false_positive_rate'] * 100:>6.2f}%")
    print("-" * 62)
    print(f" Total Packets:        {p['total_packets']}")
    print(f" Evaluation Latency:   {p['evaluation_time_sec']:.4f}s")
    print(f" Ingestion Throughput: {p['throughput_pps']} packets/sec")
    print("=" * 62 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run C2 detection benchmark against synthetic ground-truth traces."
    )
    parser.add_argument(
        "--output-pcap",
        type=str,
        default="tests/data/benchmark_ground_truth.pcap",
        help="Path to generate the evaluation PCAP file.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Optional path to output JSON benchmark scorecard.",
    )
    args = parser.parse_args()

    print("[*] Synthesizing labeled benchmark ground truth trace...")
    ground_truth = generate_benchmark_trace(args.output_pcap)

    print(f"[*] Running C2Hunter against {args.output_pcap}...")
    results = evaluate_c2_detector(args.output_pcap, ground_truth)

    print_benchmark_report(results)

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Saved JSON benchmark report to: {args.json_out}")

    # Enforce minimum detection thresholds for automated checks
    if results["metrics"]["recall"] < 0.90 or results["metrics"]["precision"] < 0.90:
        print("[-] Failure: Engine did not meet the 90% benchmark accuracy threshold.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
    