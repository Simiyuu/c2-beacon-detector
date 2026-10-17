import pytest
from src.models import PacketEvent
from src.parser import PCAPParser

def test_aggregate_flows_grouping():
    parser = PCAPParser(pcap_path="dummy.pcap")
    events = [
        PacketEvent(
            timestamp=10.0,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=1000,
            dst_port=80,
            protocol="TCP",
            length=100
        ),
        PacketEvent(
            timestamp=12.0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=1000,
            protocol="TCP",
            length=200
        )
    ]

    flows = parser.aggregate_flows(events)
    assert len(flows) == 1

    flow = list(flows.values())[0]
    assert flow.packet_count == 2
    assert flow.total_bytes == 300
    assert flow.timestamps == [10.0, 12.0]
    assert flow.packet_lengths == [100, 200]