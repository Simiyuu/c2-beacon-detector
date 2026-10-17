from typing import Dict, List
from scapy.all import rdpcap, IP, TCP, UDP
from src.models import PacketEvent, FlowRecord

class PCAPParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def parse_packets(self) -> List[PacketEvent]:
        """Dissects raw packets from PCAP and extracts L3/L4 telemetry."""
        packets = rdpcap(self.pcap_path)
        events = []

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            proto = "UNKNOWN"
            sport = 0
            dport = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)

            event = PacketEvent(
                timestamp=float(pkt.time),
                src_ip=str(pkt[IP].src),
                dst_ip=str(pkt[IP].dst),
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                length=len(pkt)
            )
            events.append(event)

        return events

    def aggregate_flows(self, events: List[PacketEvent]) -> Dict[str, FlowRecord]:
        """Aggregates parsed packet events into bi-directional 5-tuple flow records."""
        flows: Dict[str, FlowRecord] = {}

        for event in events:
            key = str(event.flow_key)
            if key not in flows:
                flows[key] = FlowRecord(
                    flow_id=key,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    src_port=event.src_port,
                    dst_port=event.dst_port,
                    protocol=event.protocol
                )

            flow = flows[key]
            flow.packet_count += 1
            flow.total_bytes += event.length
            flow.timestamps.append(event.timestamp)
            flow.packet_lengths.append(event.length)

        return flows