import time
from scapy.all import IP, TCP, UDP, Raw, wrpcap

def generate_synthetic_pcap(output_path: str = "sample_data/traffic.pcap"):
    """
    Generates synthetic network traffic:
    1. Legitimate background traffic: Random intervals, random payload sizes.
    2. C2 Beaconing traffic: Fixed periodic intervals (heartbeats) to an external IP.
    """
    packets = []
    base_time = time.time()

    # 1. Normal HTTP/HTTPS web traffic (irregular bursts)
    client_ip = "192.168.1.100"
    web_server_ip = "142.250.180.206"
    current_time = base_time

    for _ in range(30):
        # Burst of packets with slight jitter
        current_time += 0.05 + (_ % 3) * 0.12
        pkt = IP(src=client_ip, dst=web_server_ip, time=current_time) / \
              TCP(sport=51234, dport=443) / \
              Raw(load=b"X" * (50 + (_ * 17) % 300))
        packets.append(pkt)

    # 2. Covert C2 Beaconing traffic (strict periodic rhythm: every 5.0 seconds)
    c2_ip = "45.33.32.156"
    beacon_time = base_time

    for _ in range(15):
        beacon_time += 5.0  # Periodic heartbeat
        pkt = IP(src=client_ip, dst=c2_ip, time=beacon_time) / \
              TCP(sport=49888, dport=8443) / \
              Raw(load=b"HEARTBEAT_CHECKIN_DATA")
        packets.append(pkt)

    # Sort packets chronologically
    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)
    print(f"Generated {len(packets)} synthetic packets -> {output_path}")

if __name__ == "__main__":
    generate_synthetic_pcap()