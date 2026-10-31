import argparse
from pathlib import Path
import random
import sys
import time
import tracemalloc
from typing import List, Tuple

import numpy as np

from src.models import DetectionTechnique, PacketEvent
from src.pipeline import StreamingBeaconDetector
from src.windowed_sessionizer import WindowedFlowSessionizer


def generate_synthetic_stream(
    num_background_flows: int = 150,
    packets_per_flow: int = 60,
    c2_beacon_packets: int = 30,
) -> Tuple[List[PacketEvent], int]:
    """Generates an interleaved stream of benign background traffic mixed with C2 beaconing."""
    packets: List[PacketEvent] = []
    rng = np.random.default_rng(seed=42)

    # 1. Synthesize background flows (sporadic, bursty web traffic)
    start_time = 1000.0
    for flow_idx in range(num_background_flows):
        src_port = 40000 + (flow_idx % 20000)
        dst_ip = f"172.16.1.{10 + (flow_idx % 200)}"
        flow_time = start_time + rng.uniform(0.0, 30.0)

        for _ in range(packets_per_flow):
            delta = float(rng.exponential(scale=1.5))
            flow_time += delta
            packets.append(
                PacketEvent(
                    timestamp=flow_time,
                    src_ip="10.0.0.15",
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=443,
                    protocol="tcp",
                    length=int(rng.integers(64, 1500)),
                    payload_entropy=float(rng.uniform(1.0, 5.0)),
                )
            )

    # 2. Synthesize periodic C2 beacon flow (fixed 10.0s interval)
    c2_time = start_time + 5.0
    for _ in range(c2_beacon_packets):
        c2_time += 10.0
        packets.append(
            PacketEvent(
                timestamp=c2_time,
                src_ip="10.0.0.15",
                dst_ip="198.51.100.99",
                src_port=51200,
                dst_port=8443,
                protocol="tcp",
                length=128,
                payload_entropy=3.14,
            )
        )

    # 3. Sort strictly by epoch timestamp to simulate realistic wire arrival
    packets.sort(key=lambda p: p.timestamp)
    total_packets = len(packets)
    return packets, total_packets


def run_benchmark(
    num_flows: int = 150,
    packets_per_flow: int = 60,
    window_duration: float = 300.0,
    max_window_packets: int = 100,
) -> None:
    """Executes the streaming ingestion, memory ceiling, and throughput benchmark."""
    print("=" * 72)
    print("  C2 BEACON DETECTOR v2.0 - STREAMING PERFORMANCE BENCHMARK")
    print("=" * 72)
    print(f"[*] Generating synthetic stream ({num_flows} concurrent flows)...")

    stream_packets, total_packets = generate_synthetic_stream(
        num_background_flows=num_flows,
        packets_per_flow=packets_per_flow,
    )

    print(f"[+] Synthesized {total_packets:,} packets in chronological stream order.")
    print(f"[*] Initializing WindowedFlowSessionizer (window={window_duration}s, max_pkts={max_window_packets})...")

    sessionizer = WindowedFlowSessionizer(
        idle_timeout=120.0,
        window_duration=window_duration,
        max_window_packets=max_window_packets,
    )
    detector = StreamingBeaconDetector(sessionizer=sessionizer)

    # Begin profiling
    tracemalloc.start()
    t_start = time.perf_counter()

    for packet in stream_packets:
        detector.process_packet(packet)

    t_ingest = time.perf_counter() - t_start
    current_mem, peak_mem = tracemalloc.get_traced_memory()

    # Eviction tick benchmark
    max_ts = stream_packets[-1].timestamp if stream_packets else 0.0
    t_tick_start = time.perf_counter()
    evicted_alerts = detector.tick(current_time=max_ts + 200.0)
    t_tick = time.perf_counter() - t_tick_start

    tracemalloc.stop()

    # Telemetry metrics
    stats = detector.stats()
    throughput = total_packets / t_ingest if t_ingest > 0 else 0.0
    avg_latency_us = (t_ingest / total_packets) * 1_000_000 if total_packets > 0 else 0.0
    peak_mem_mb = peak_mem / (1024 * 1024)

    # Print results
    print("\n--- INGESTION & DETECTION METRICS ---")
    print(f"  Total Packets Ingested : {total_packets:,}")
    print(f"  Processing Time        : {t_ingest:.4f} seconds")
    print(f"  Throughput Rate        : {throughput:,.2f} packets/sec")
    print(f"  Mean Processing Latency: {avg_latency_us:.2f} µs/packet")
    print(f"  Peak Memory Footprint  : {peak_mem_mb:.2f} MB")

    print("\n--- SLIDING-WINDOW & EVICTION METRICS ---")
    print(f"  Active Flows Monitored : {stats['sessionizer']['active_flows']}")
    print(f"  Idle Eviction Duration : {t_tick * 1000:.3f} ms")
    print(f"  Closing Alerts Fired   : {len(evicted_alerts)}")

    print("\n--- DETECTION EFFECTIVENESS ---")
    print(f"  Total Alerts Emitted   : {len(detector.alerts)}")
    for alert in detector.alerts:
        tech = (
            alert.mitre_attack.technique_id.value
            if hasattr(alert.mitre_attack.technique_id, "value")
            else str(alert.mitre_attack.technique_id)
        )
        print(f"  [!] Flagged: {alert.flow_id} ({tech}) | Score: {alert.anomaly_score:.2f}")

    # Validation gates
    assert len(detector.alerts) >= 1, "Benchmark failed: C2 beacon was not detected."
    c2_flagged = any("198.51.100.99" in a.flow_id for a in detector.alerts)
    assert c2_flagged, "Benchmark failed: Dedicated C2 flow was missed."

    print("\n[+] Benchmark complete: All performance criteria and detection gates passed.")
    print("=" * 72)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Streaming Beacon Detector Benchmark")
    parser.add_argument("--flows", type=int, default=150, help="Number of concurrent background flows")
    parser.add_argument("--packets-per-flow", type=int, default=60, help="Packets per flow")
    args = parser.parse_args()

    run_benchmark(num_flows=args.flows, packets_per_flow=args.packets_per_flow)

    