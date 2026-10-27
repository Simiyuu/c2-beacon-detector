from src.models import PacketEvent
from src.sessionizer import FlowSessionizer


def _create_packet(
    timestamp: float,
    src_ip: str = "192.168.1.50",
    dst_ip: str = "198.51.100.24",
    src_port: int = 54321,
    dst_port: int = 443,
    protocol: str = "tcp",
    length: int = 100,
) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
    )


def test_bidirectional_packet_pairing():
    """Verify client-to-server and server-to-client frames merge into the same flow."""
    sessionizer = FlowSessionizer(idle_timeout=60.0)

    # Inbound client request
    pkt1 = _create_packet(timestamp=100.0, src_ip="192.168.1.50", dst_ip="198.51.100.24", src_port=54321, dst_port=443)
    # Outbound server response (reversed IP and port)
    pkt2 = _create_packet(timestamp=100.2, src_ip="198.51.100.24", dst_ip="192.168.1.50", src_port=443, dst_port=54321)

    assert sessionizer.process_packet(pkt1) is None
    assert sessionizer.process_packet(pkt2) is None

    # Should only have 1 active flow containing both packets
    flows = sessionizer.flush()
    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].total_bytes == 200
    assert flows[0].timestamps == [100.0, 100.2]


def test_idle_timeout_triggers_flush_and_split():
    """Verify an idle gap exceeding idle_timeout segments traffic into distinct sessions."""
    sessionizer = FlowSessionizer(idle_timeout=30.0, active_timeout=300.0)

    pkt1 = _create_packet(timestamp=10.0)
    pkt2 = _create_packet(timestamp=20.0)
    # 70s gap (exceeds 30s idle_timeout)
    pkt3 = _create_packet(timestamp=90.0)

    sessionizer.process_packet(pkt1)
    sessionizer.process_packet(pkt2)
    expired_flow = sessionizer.process_packet(pkt3)

    assert expired_flow is not None
    assert expired_flow.packet_count == 2
    assert expired_flow.timestamps == [10.0, 20.0]

    remaining = sessionizer.flush()
    assert len(remaining) == 1
    assert remaining[0].packet_count == 1
    assert remaining[0].timestamps == [90.0]


def test_active_timeout_segments_long_flow():
    """Verify a persistent connection exceeding active_timeout is segmented cleanly."""
    sessionizer = FlowSessionizer(idle_timeout=60.0, active_timeout=100.0)

    pkt1 = _create_packet(timestamp=0.0)
    pkt2 = _create_packet(timestamp=50.0)
    # Active duration is 110s (exceeds 100s active_timeout) even though idle gap is only 60s
    pkt3 = _create_packet(timestamp=110.0)

    sessionizer.process_packet(pkt1)
    sessionizer.process_packet(pkt2)
    expired_flow = sessionizer.process_packet(pkt3)

    assert expired_flow is not None
    assert expired_flow.packet_count == 2
    assert expired_flow.timestamps == [0.0, 50.0]

    flushed = sessionizer.flush()
    assert len(flushed) == 1
    assert flushed[0].timestamps == [110.0]


def test_process_stream_generator_e2e():
    """Verify process_stream yields expired flows sequentially and flushes remaining state."""
    sessionizer = FlowSessionizer(idle_timeout=10.0)
    packets = [
        _create_packet(timestamp=1.0),
        _create_packet(timestamp=5.0),
        _create_packet(timestamp=25.0),  # Expires session 1 (gap = 20s)
        _create_packet(timestamp=28.0),
    ]

    flows = list(sessionizer.process_stream(iter(packets)))

    assert len(flows) == 2
    assert flows[0].packet_count == 2
    assert flows[0].timestamps == [1.0, 5.0]
    assert flows[1].packet_count == 2
    assert flows[1].timestamps == [25.0, 28.0]
    