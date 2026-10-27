import math
import os
from collections import Counter
from typing import Iterator, Optional
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw
from scapy.utils import PcapReader

from src.models import PacketEvent


def calculate_entropy(data: bytes) -> float:
    """Calculates byte-level Shannon entropy (0.0 to 8.0 bits)."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


class StreamingPacketReader:
    """Memory-efficient lazy streaming reader for PCAP and PCAPNG files."""

    def __init__(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Packet capture file not found: {pcap_path}")
        self.pcap_path = pcap_path

    def __iter__(self) -> Iterator[PacketEvent]:
        """Yields PacketEvent instances sequentially with O(1) memory overhead."""
        return self.stream()

    def stream(self) -> Iterator[PacketEvent]:
        """Streams and parses frames from PCAP storage."""
        with PcapReader(self.pcap_path) as pcap_reader:
            for raw_pkt in pcap_reader:
                event = self._parse_packet(raw_pkt)
                if event is not None:
                    yield event

    def _parse_packet(self, pkt: Packet) -> Optional[PacketEvent]:
        """Extracts layer-3 and layer-4 metadata into a validated PacketEvent."""
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = float(pkt.time)
        length = len(pkt)

        # Layer 4 identification
        if pkt.haslayer(TCP):
            proto = "tcp"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto = "udp"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            proto = ip_layer.proto
            sport = 0
            dport = 0

        # Calculate payload entropy if application payload exists
        payload_entropy = 0.0
        if pkt.haslayer(Raw):
            payload_data = bytes(pkt[Raw].load)
            payload_entropy = calculate_entropy(payload_data)

        return PacketEvent(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=str(proto),
            length=length,
            payload_entropy=payload_entropy,
        )
    