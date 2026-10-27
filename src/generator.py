import os
import random
from typing import Optional
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap


class SyntheticTrafficGenerator:
    """Deterministic synthetic PCAP generator for testing periodic and jittered network beaconing."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)
        self.np_rng = np.random.default_rng(seed)

    def generate_c2_trace(
        self,
        output_pcap_path: str,
        beacon_count: int = 25,
        base_interval: float = 5.0,
        jitter_pct: float = 0.0,
        high_entropy: bool = True,
        background_flow_count: int = 15,
        c2_src_ip: str = "10.0.0.15",
        c2_dst_ip: str = "198.51.100.24",
        c2_dst_port: int = 8443,
    ) -> str:
        """Generates a synthetic PCAP combining background benign traffic and C2 beaconing."""
        packets = []
        current_time = 1700000000.0  # Deterministic base epoch

        # 1. Generate Benign Background Traffic (Bursty, Variable Intervals)
        bg_ips = ["93.184.216.34", "151.101.1.69", "172.217.16.206", "142.250.190.46"]
        for _ in range(background_flow_count):
            flow_src_port = self.rng.randint(49152, 65535)
            flow_dst_ip = self.rng.choice(bg_ips)
            flow_dst_port = self.rng.choice([80, 443])
            burst_size = self.rng.randint(2, 6)

            flow_time = current_time + self.rng.uniform(0.0, 30.0)
            for _ in range(burst_size):
                flow_time += self.rng.uniform(0.05, 0.4)
                payload_len = self.rng.randint(64, 1400)
                payload = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n" + b"A" * max(0, payload_len - 38)
                pkt = (
                    IP(src="10.0.0.15", dst=flow_dst_ip)
                    / TCP(sport=flow_src_port, dport=flow_dst_port, flags="PA")
                    / Raw(load=payload)
                )
                pkt.time = flow_time
                packets.append(pkt)

        # 2. Generate Simulated C2 Beacon Traffic (Periodic with Parameterized Jitter)
        beacon_time = current_time + 1.0
        c2_sport = 51234

        for seq in range(beacon_count):
            if seq > 0:
                if jitter_pct > 0.0:
                    delta_limit = base_interval * (jitter_pct / 100.0)
                    interval_noise = self.rng.uniform(-delta_limit, delta_limit)
                    delta = max(0.1, base_interval + interval_noise)
                else:
                    delta = base_interval
                beacon_time += delta

            # Generate C2 Payload (Encrypted High-Entropy vs Plaintext)
            if high_entropy:
                # Pseudorandom bytes simulate AES / Cobalt Strike Malleable C2 payload
                payload = self.np_rng.bytes(128)
            else:
                payload = f"status=heartbeat&seq={seq}".encode("utf-8")

            beacon_pkt = (
                IP(src=c2_src_ip, dst=c2_dst_ip)
                / TCP(sport=c2_sport, dport=c2_dst_port, flags="PA")
                / Raw(load=payload)
            )
            beacon_pkt.time = beacon_time
            packets.append(beacon_pkt)

        # Sort all packets chronologically by timestamp
        packets.sort(key=lambda pkt: float(pkt.time))

        os.makedirs(os.path.dirname(os.path.abspath(output_pcap_path)), exist_ok=True)
        wrpcap(output_pcap_path, packets)
        return output_pcap_path
    