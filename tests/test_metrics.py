import numpy as np
import pytest
from src.metrics import (
    calculate_iat,
    compute_distribution_stats,
    extract_flow_distribution_metrics,
)


def test_calculate_iat_ordered():
    timestamps = [10.0, 15.0, 25.0, 30.0]
    deltas = calculate_iat(timestamps)
    assert np.array_equal(deltas, np.array([5.0, 10.0, 5.0]))


def test_calculate_iat_out_of_order():
    timestamps = [30.0, 10.0, 25.0, 15.0]
    deltas = calculate_iat(timestamps)
    # Automatically sorts to [10, 15, 25, 30] -> deltas [5, 10, 5]
    assert np.array_equal(deltas, np.array([5.0, 10.0, 5.0]))


def test_calculate_iat_empty_and_single():
    assert calculate_iat([]).size == 0
    assert calculate_iat([100.0]).size == 0


def test_compute_distribution_stats_empty():
    stats = compute_distribution_stats([])
    assert stats["count"] == 0.0
    assert stats["mean"] == 0.0
    assert stats["std"] == 0.0
    assert stats["iqr"] == 0.0


def test_compute_distribution_stats_single():
    stats = compute_distribution_stats([42.0])
    assert stats["count"] == 1.0
    assert stats["mean"] == 42.0
    assert stats["std"] == 0.0
    assert stats["min"] == 42.0
    assert stats["max"] == 42.0


def test_compute_distribution_stats_known_values():
    # Sequence with known mean = 10, ddof=1 std, IQR
    values = [5.0, 10.0, 15.0]
    stats = compute_distribution_stats(values)
    assert stats["count"] == 3.0
    assert stats["mean"] == 10.0
    assert stats["min"] == 5.0
    assert stats["max"] == 15.0
    assert stats["median"] == 10.0
    assert stats["std"] == 5.0


def test_extract_flow_distribution_metrics_e2e():
    timestamps = [1.0, 6.0, 11.0, 16.0]  # Exact 5.0s interval
    packet_lengths = [128, 128, 128, 128]  # Constant size

    metrics = extract_flow_distribution_metrics(timestamps, packet_lengths)
    assert metrics["packet_count"] == 4
    assert metrics["duration"] == 15.0
    assert metrics["iat"]["mean"] == 5.0
    assert metrics["iat"]["std"] == 0.0  # Perfect periodicity
    assert metrics["size"]["mean"] == 128.0
    assert metrics["size"]["std"] == 0.0
    