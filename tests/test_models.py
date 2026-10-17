import pytest
from src.models import PacketEvent, FlowRecord

def test_packet_event_flow_key_normalization():
    pkt1 = PacketEvent(
        timestamp=100.0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=4444,
        dst_port=80,
        protocol="TCP",
        length=64
    )
    pkt2 = PacketEvent(
        timestamp=101.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=4444,
        protocol="tcp",
        length=128
    )
    # Both directions must map to the exact same 5-tuple key
    assert pkt1.flow_key == pkt2.flow_key

def test_flow_record_defaults():
    flow = FlowRecord(
        flow_id="test_flow",
        src_ip="192.168.1.5",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol="UDP"
    )
    assert flow.packet_count == 0
    assert flow.total_bytes == 0
    assert flow.timestamps == []