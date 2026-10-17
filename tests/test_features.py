import pytest
from src.models import FlowRecord
from src.features import FeatureExtractor

def test_feature_extraction_single_packet():
    flow = FlowRecord(
        flow_id="single_packet_flow",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        packet_count=1,
        total_bytes=100,
        timestamps=[1000.0],
        packet_lengths=[100]
    )
    features = FeatureExtractor.extract_from_flow(flow)
    assert features.packet_count == 1
    assert features.duration_seconds == 0.0
    assert features.iat_mean == 0.0
    assert features.iat_std == 0.0
    assert features.byte_mean == 100.0
    assert features.byte_std == 0.0

def test_feature_extraction_multi_packet_iat():
    flow = FlowRecord(
        flow_id="beacon_flow",
        src_ip="192.168.1.50",
        dst_ip="1.1.1.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_count=3,
        total_bytes=300,
        timestamps=[10.0, 15.0, 20.0],  # Exactly 5.0s delta (0 std dev)
        packet_lengths=[100, 100, 100]
    )
    features = FeatureExtractor.extract_from_flow(flow)
    assert features.packet_count == 3
    assert features.duration_seconds == 10.0
    assert features.iat_mean == 5.0
    assert features.iat_std == 0.0
    assert features.byte_mean == 100.0
    assert features.byte_std == 0.0