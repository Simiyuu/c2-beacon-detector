import os
import random
import time
from typing import List
from scapy.all import IP, TCP, Raw, wrpcap


def inject_jitter(base_interval: float, jitter_pct: float) -> float:
    """Calculates a randomized interval bounded strictly within base_interval +/- jitter_pct."""
    if jitter_pct <= 0.0:
        return float(base_interval)

    low = base_interval * (1.0 - jitter_pct)
    high = base_interval * (1.0 + jitter_pct)
    return random.uniform(low, high)


def generate_jittered_intervals(
    count: int,
    base_interval: float,
    jitter_pct: float,
    start_time: float = 0.0,
) -> List[float]:
    """Generates a strictly increasing series of timestamps simulated with sleep jitter."""
    timestamps: List[float] = []
    current_time = float(start_time)

    for _ in range(count):
        delta = inject_jitter(base_interval, jitter_pct)
        current_time += delta
        timestamps.append(current_time)

    return timestamps


def generate_synthetic_pcap(
    output_path: str = "sample_data/traffic.pcap",
    c2_jitter_pct: float = 0.0,
):
    packets = []
    base_time = time.time() - 3600

    client_ip = "192.168.1.50"
    web_server_ip = "93.184.216.34"
    c2_server_ip = "198.51.100.24"

    # 1. Bursty Web Traffic (variable IAT, variable payload sizes)
    current_time = base_time
    for _ in range(30):
        current_time += random.uniform(0.05, 3.0)
        payload_len = random.randint(64, 1400)
        pkt = (
            IP(src=client_ip, dst=web_server_ip)
            / TCP(sport=54321, dport=443)
            / Raw(load=b"X" * payload_len)
        )
        pkt.time = current_time
        packets.append(pkt)

    # 2. C2 Beacon Traffic (supports fixed or jittered intervals)
    c2_timestamps = generate_jittered_intervals(
        count=20,
        base_interval=5.0,
        jitter_pct=c2_jitter_pct,
        start_time=base_time,
    )

    for ts in c2_timestamps:
        pkt = (
            IP(src=client_ip, dst=c2_server_ip)
            / TCP(sport=49822, dport=8443)
            / Raw(load=b"BEACON_HEARTBEAT_DATA")
        )
        pkt.time = ts
        packets.append(pkt)

    # Sort packets chronologically by timestamp
    packets.sort(key=lambda p: p.time)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)


if __name__ == "__main__":
    generate_synthetic_pcap()