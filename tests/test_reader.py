import pytest
from src.generator import SyntheticTrafficGenerator
from src.reader import StreamingPacketReader, calculate_entropy


def test_entropy_bounds():
    # Empty payload
    assert calculate_entropy(b"") == 0.0

    # Low entropy (all identical bytes)
    assert calculate_entropy(b"AAAAAAAAAAAAAAAAAAAA") == 0.0

    # High entropy (diverse randomized byte sequence)
    high_entropy_bytes = bytes(range(256))
    assert calculate_entropy(high_entropy_bytes) == 8.0


def test_streaming_reader_lazy_iteration(tmp_path):
    pcap_path = str(tmp_path / "streaming_test.pcap")
    gen = SyntheticTrafficGenerator(seed=42)
    gen.generate_c2_trace(
        output_pcap_path=pcap_path,
        beacon_count=15,
        base_interval=2.0,
        background_flow_count=5,
    )

    reader = StreamingPacketReader(pcap_path)
    stream = iter(reader)

    # Verify lazy consumption: fetch first 3 packets without iterating the entire file
    first_pkt = next(stream)
    second_pkt = next(stream)
    third_pkt = next(stream)

    assert first_pkt.timestamp <= second_pkt.timestamp <= third_pkt.timestamp
    assert first_pkt.protocol in ["tcp", "udp"]
    assert first_pkt.src_ip == "10.0.0.15"


def test_streaming_reader_file_not_found():
    with pytest.raises(FileNotFoundError):
        StreamingPacketReader("non_existent_capture.pcap")
        