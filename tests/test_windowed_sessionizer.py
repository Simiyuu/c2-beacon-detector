import pytest
from src.models import PacketEvent
from src.windowed_sessionizer import WindowedFlowSessionizer


@pytest.fixture
def sample_packet_fwd():
    """Client to server packet."""
    return PacketEvent(
        timestamp=100.0,
        src_ip="192.168.1.10",
        dst_ip="198.51.100.20",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
        length=64,
        payload_entropy=3.1,
    )


@pytest.fixture
def sample_packet_rev():
    """Server to client reverse packet."""
    return PacketEvent(
        timestamp=101.5,
        src_ip="198.51.100.20",
        dst_ip="192.168.1.10",
        src_port=443,
        dst_port=49152,
        protocol="tcp",
        length=128,
        payload_entropy=4.5,
    )


def test_sessionizer_initialization_defaults():
    """Verifies default settings and operational telemetry."""
    sessionizer = WindowedFlowSessionizer()
    assert sessionizer.idle_timeout == 120.0
    assert sessionizer.window_duration == 300.0
    assert sessionizer.max_window_packets == 100
    assert sessionizer.flow_count == 0
    assert sessionizer.active_flows == {}

    stats = sessionizer.stats()
    assert stats["active_flows"] == 0
    assert stats["total_packets_processed"] == 0
    assert stats["idle_timeout"] == 120.0


def test_bidirectional_packet_pairing(sample_packet_fwd, sample_packet_rev):
    """Verifies that forward and reverse packets resolve to the same flow record."""
    sessionizer = WindowedFlowSessionizer()

    flow_1 = sessionizer.add_packet(sample_packet_fwd)
    assert sessionizer.flow_count == 1
    assert flow_1.packet_count == 1
    assert flow_1.total_bytes == 64

    # Reverse packet should update the existing flow
    flow_2 = sessionizer.add_packet(sample_packet_rev)
    assert sessionizer.flow_count == 1
    assert flow_1.flow_id == flow_2.flow_id
    assert flow_2.packet_count == 2
    assert flow_2.total_bytes == 192
    assert flow_2.last_seen == 101.5
    assert flow_2.inter_arrival_times == [1.5]


def test_parameter_propagation_to_flow_records(sample_packet_fwd):
    """Verifies that custom window parameters cascade to instantiated flows."""
    sessionizer = WindowedFlowSessionizer(
        idle_timeout=60.0,
        window_duration=45.0,
        max_window_packets=25,
    )
    flow = sessionizer.add_packet(sample_packet_fwd)

    assert flow.window_duration_seconds == 45.0
    assert flow.max_window_packets == 25


def test_idle_flow_eviction(sample_packet_fwd):
    """Verifies that flows inactive beyond idle_timeout are evicted."""
    sessionizer = WindowedFlowSessionizer(idle_timeout=10.0)

    # Ingest flow A at t=100
    sessionizer.add_packet(sample_packet_fwd)

    # Ingest flow B at t=105
    pkt_b = PacketEvent(
        timestamp=105.0,
        src_ip="10.0.0.5",
        dst_ip="172.16.0.1",
        src_port=52000,
        dst_port=80,
        protocol="tcp",
        length=100,
    )
    sessionizer.add_packet(pkt_b)
    assert sessionizer.flow_count == 2

    # At t=112:
    # flow A: 112 - 100 = 12s inactive (> 10s timeout) -> EVICTED
    # flow B: 112 - 105 = 7s inactive (<= 10s timeout) -> RETAINED
    evicted = sessionizer.evict_idle_flows(current_time=112.0)

    assert len(evicted) == 1
    assert evicted[0].flow_id == sample_packet_fwd.flow_key
    assert sessionizer.flow_count == 1
    assert pkt_b.flow_key in sessionizer.active_flows


def test_sessionizer_flush(sample_packet_fwd, sample_packet_rev):
    """Verifies that flush() extracts all active flows and empties the session table."""
    sessionizer = WindowedFlowSessionizer()
    sessionizer.add_packet(sample_packet_fwd)

    # Add a second distinct flow
    pkt_distinct = PacketEvent(
        timestamp=102.0,
        src_ip="192.168.1.99",
        dst_ip="8.8.8.8",
        src_port=34567,
        dst_port=53,
        protocol="udp",
        length=48,
    )
    sessionizer.add_packet(pkt_distinct)
    assert sessionizer.flow_count == 2

    flushed = sessionizer.flush()
    assert len(flushed) == 2
    assert sessionizer.flow_count == 0
    assert sessionizer.active_flows == {}

    