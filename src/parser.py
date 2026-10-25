from typing import Dict, List, Optional
from scapy.all import Packet, IP, TCP, Dot1Q, rdpcap
from src.models import FlowRecord, PacketEvent


class PCAPParser:
    def __init__(self, pcap_path: Optional[str] = None):
        self.pcap_path = pcap_path
        self.flows: Dict[str, FlowRecord] = {}

    def add_event(self, event: PacketEvent) -> None:
        """Normalizes bidirectional endpoints and appends packet telemetry to FlowRecord."""
        proto = getattr(event, "protocol", "TCP")
        endpoints = sorted([(event.src_ip, event.src_port), (event.dst_ip, event.dst_port)])
        flow_key = f"{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}_{proto}"

        if flow_key not in self.flows:
            self.flows[flow_key] = FlowRecord(
                flow_id=flow_key,
                src_ip=endpoints[0][0],
                dst_ip=endpoints[1][0],
                src_port=endpoints[0][1],
                dst_port=endpoints[1][1],
                protocol=proto,
                packet_count=0,
                total_bytes=0,
                timestamps=[],
                packet_lengths=[],
            )

        pkt_len = getattr(event, "length", getattr(event, "byte_length", 0))
        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.total_bytes += pkt_len
        flow.timestamps.append(event.timestamp)
        flow.packet_lengths.append(pkt_len)

    def aggregate_flows(self, events: List[PacketEvent]) -> Dict[str, FlowRecord]:
        """Aggregates a sequence of PacketEvent models into normalized FlowRecords."""
        for event in events:
            self.add_event(event)
        return self.flows

    def process_packet(self, raw_packet: Packet) -> Dict[str, FlowRecord]:
        """Dissects packet with strict validation against non-IP, non-TCP, and malformed frames."""
        if not raw_packet.haslayer(IP) or not raw_packet.haslayer(TCP):
            return self.flows

        try:
            ip_layer = raw_packet[IP]
            tcp_layer = raw_packet[TCP]

            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)

            timestamp = float(getattr(raw_packet, "time", 0.0))
            pkt_len = len(raw_packet)

            p_fields = getattr(PacketEvent, "model_fields", {})
            event_kwargs = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "timestamp": timestamp,
            }
            if "length" in p_fields:
                event_kwargs["length"] = pkt_len
            elif "byte_length" in p_fields:
                event_kwargs["byte_length"] = pkt_len
            if "protocol" in p_fields:
                event_kwargs["protocol"] = "TCP"

            event = PacketEvent(**event_kwargs)
            self.add_event(event)

        except Exception as e:
            print(f"\n[DEBUG PARSER ERROR] {type(e).__name__}: {e}")

        return self.flows

    def parse(self) -> Dict[str, FlowRecord]:
        """Parses the PCAP specified in self.pcap_path."""
        if not self.pcap_path:
            raise ValueError("No pcap_path provided during initialization.")
        return self.parse_pcap(self.pcap_path)

    def parse_pcap(self, pcap_path: Optional[str] = None) -> Dict[str, FlowRecord]:
        """Loads and processes an entire PCAP file from disk."""
        target_path = pcap_path or self.pcap_path
        if not target_path:
            raise ValueError("No PCAP file path provided to parse.")
        packets = rdpcap(target_path)
        for pkt in packets:
            self.process_packet(pkt)
        return self.flows