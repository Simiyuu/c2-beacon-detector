import os
from scapy.utils import rdpcap
from src.generator import SyntheticTrafficGenerator


def test_generator_creates_valid_pcap(tmp_path):
    pcap_path = str(tmp_path / "test_beacon.pcap")
    gen = SyntheticTrafficGenerator(seed=1337)
    gen.generate_c2_trace(
        output_pcap_path=pcap_path,
        beacon_count=10,
        base_interval=3.0,
        jitter_pct=0.0,
        background_flow_count=5,
    )

    assert os.path.exists(pcap_path)
    packets = rdpcap(pcap_path)
    assert len(packets) >= 10

    # Ensure packets are ordered chronologically
    timestamps = [float(p.time) for p in packets]
    assert timestamps == sorted(timestamps)


def test_generator_jitter_bounds(tmp_path):
    pcap_path = str(tmp_path / "jitter_test.pcap")
    gen = SyntheticTrafficGenerator(seed=999)
    gen.generate_c2_trace(
        output_pcap_path=pcap_path,
        beacon_count=10,
        base_interval=10.0,
        jitter_pct=20.0,  # Intervals must strictly fall within [8.0, 12.0]
        background_flow_count=0,
    )

    packets = rdpcap(pcap_path)
    c2_times = [float(p.time) for p in packets]
    deltas = [c2_times[i] - c2_times[i - 1] for i in range(1, len(c2_times))]

    for delta in deltas:
        assert 8.0 <= delta <= 12.0
        