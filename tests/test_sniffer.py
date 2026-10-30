from unittest.mock import MagicMock, patch
import pytest
from scapy.all import IP, TCP

from src.sniffer import LivePacketSniffer, PacketSnifferError


@pytest.fixture
def sample_packet():
    """Generates a synthetic IP/TCP frame for mock ingestion."""
    return IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=54321, dport=443)


def test_sniffer_initialization_defaults():
    """Verifies default initialization settings and state telemetry."""
    sniffer = LivePacketSniffer(interface="eth0")
    assert sniffer.interface == "eth0"
    assert sniffer.bpf_filter == "ip and (tcp or udp)"
    assert sniffer.max_queue_size == 10000
    assert sniffer.stats == {
        "captured": 0,
        "dropped": 0,
        "queue_depth": 0,
        "running": False,
    }


def test_packet_callback_enqueues_packet_and_tracks_stats(sample_packet):
    """Verifies that received frames are queued and telemetry updates accurately."""
    sniffer = LivePacketSniffer(max_queue_size=10)
    sniffer._packet_callback(sample_packet)

    assert sniffer.stats["captured"] == 1
    assert sniffer.stats["dropped"] == 0
    assert sniffer.stats["queue_depth"] == 1

    packet_out = sniffer._queue.get_nowait()
    assert packet_out[IP].src == "192.168.1.100"
    assert packet_out[TCP].dport == 443


def test_packet_callback_drops_packet_when_queue_full(sample_packet):
    """Verifies backpressure handling when queue reaches capacity."""
    sniffer = LivePacketSniffer(max_queue_size=2)

    # Fill queue to capacity
    sniffer._packet_callback(sample_packet)
    sniffer._packet_callback(sample_packet)
    assert sniffer.stats["queue_depth"] == 2
    assert sniffer.stats["dropped"] == 0

    # Trigger queue overflow
    sniffer._packet_callback(sample_packet)
    assert sniffer.stats["captured"] == 3
    assert sniffer.stats["dropped"] == 1
    assert sniffer.stats["queue_depth"] == 2


def test_iter_packets_drains_queue_after_stop(sample_packet):
    """Verifies that iter_packets drains buffered items after stop() is called."""
    sniffer = LivePacketSniffer(max_queue_size=10)
    sniffer._is_running.set()

    # Preload packets
    for _ in range(3):
        sniffer._packet_callback(sample_packet)

    # Signal stop while queue still has items
    sniffer.stop()

    yielded_packets = list(sniffer.iter_packets(timeout=0.1))
    assert len(yielded_packets) == 3
    assert sniffer.stats["queue_depth"] == 0


@patch("src.sniffer.AsyncSniffer")
def test_start_spawns_async_sniffer(mock_async_sniffer_cls):
    """Verifies that start() configures and initiates the background Scapy worker."""
    mock_instance = MagicMock()
    mock_async_sniffer_cls.return_value = mock_instance

    sniffer = LivePacketSniffer(interface="wlan0", bpf_filter="tcp port 80")
    sniffer.start()

    assert sniffer.stats["running"] is True
    mock_async_sniffer_cls.assert_called_once_with(
        iface="wlan0",
        filter="tcp port 80",
        prn=sniffer._packet_callback,
        store=False,
    )
    mock_instance.start.assert_called_once()


@patch("src.sniffer.AsyncSniffer")
def test_start_failure_raises_packet_sniffer_error(mock_async_sniffer_cls):
    """Verifies that socket or interface failures raise PacketSnifferError."""
    mock_instance = MagicMock()
    mock_instance.start.side_effect = PermissionError("Operation not permitted")
    mock_async_sniffer_cls.return_value = mock_instance

    sniffer = LivePacketSniffer(interface="eth99")
    with pytest.raises(PacketSnifferError) as exc_info:
        sniffer.start()

    assert "Failed to start sniffer on interface 'eth99'" in str(exc_info.value)
    assert sniffer.stats["running"] is False


@patch("src.sniffer.AsyncSniffer")
def test_stop_terminates_running_sniffer(mock_async_sniffer_cls):
    """Verifies clean shutdown of active capture threads."""
    mock_instance = MagicMock()
    mock_instance.running = True
    mock_async_sniffer_cls.return_value = mock_instance

    sniffer = LivePacketSniffer()
    sniffer.start()
    assert sniffer.stats["running"] is True

    sniffer.stop()
    assert sniffer.stats["running"] is False
    mock_instance.stop.assert_called_once()
    