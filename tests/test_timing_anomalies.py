import pytest
from src.features import FeatureExtractor
from src.models import FlowRecord


def _get_val(obj, key):
    """Helper to extract metric whether return type is a dict or a Pydantic model."""
    if isinstance(obj, dict):
        return obj[key]
    return getattr(obj, key)


def test_zero_delta_inter_arrival_time():
    """Verify identical timestamps (delta-t = 0) do not cause division by zero or NaN values."""
    flow = FlowRecord(
        flow_id="10.0.0.1:443<->10.0.0.2:5000_TCP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=443,
        dst_port=5000,
        protocol="TCP",
        packet_count=3,
        total_bytes=192,
        timestamps=[100.0, 100.0, 100.0],
        packet_lengths=[64, 64, 64],
    )
    extractor = FeatureExtractor()
    features = extractor.extract_from_flow(flow)

    assert _get_val(features, "iat_mean") == 0.0
    assert _get_val(features, "iat_std") == 0.0
    assert _get_val(features, "duration_seconds") == 0.0


def test_out_of_order_packets_are_sorted_chronologically():
    """Verify non-chronological timestamps are sorted to prevent negative delta-t intervals."""
    flow = FlowRecord(
        flow_id="10.0.0.1:443<->10.0.0.2:5000_TCP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=443,
        dst_port=5000,
        protocol="TCP",
        packet_count=3,
        total_bytes=300,
        timestamps=[105.0, 101.0, 110.0],  # Out of order arrival
        packet_lengths=[100, 100, 100],
    )
    extractor = FeatureExtractor()
    features = extractor.extract_from_flow(flow)

    # Sorted: [101.0, 105.0, 110.0] -> deltas: [4.0, 5.0] -> mean: 4.5, duration: 9.0
    assert _get_val(features, "iat_mean") == pytest.approx(4.5, 0.01)
    assert _get_val(features, "duration_seconds") == pytest.approx(9.0, 0.01)