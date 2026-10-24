# tests/test_fuzz_parser.py
import pytest
from scapy.all import Ether, IP, TCP, ARP, Dot1Q, Raw
from src.parser import PCAPParser



def test_parser_ignores_non_ip_arp_traffic():
    """Verify ARP frames are cleanly ignored without unhandled attribute errors."""
    parser = PCAPParser()
    arp_pkt = Ether() / ARP(op=1, pdst="192.168.1.1")
    # Must not raise an exception and must not register a flow
    flows = parser.process_packet(arp_pkt)
    assert len(flows) == 0


def test_parser_handles_vlan_tagged_frames():
    """Verify 802.1Q tagged frames are unwrapped to inspect underlying IP/TCP."""
    parser = PCAPParser()
    vlan_pkt = Ether() / Dot1Q(vlan=100) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=443, dport=5555) / Raw(b"heartbeat")
    flows = parser.process_packet(vlan_pkt)
    assert len(flows) == 1
    flow_key = list(flows.keys())[0]
    assert "10.0.0.1" in flow_key and "10.0.0.2" in flow_key


def test_parser_drops_truncated_ip_header():
    """Verify malformed/truncated raw IP bytes do not crash the ingestion loop."""
    parser = PCAPParser()
    # Construct an invalid packet missing L4 transport layer
    raw_corrupted = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)  # Declares TCP but has no TCP payload/header
    flows = parser.process_packet(raw_corrupted)
    assert len(flows) == 0