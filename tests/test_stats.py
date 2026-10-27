import numpy as np
import pytest
from src.stats import (
    calculate_coefficient_of_variation,
    calculate_median_absolute_deviation,
    calculate_regularity_score,
    estimate_jitter_percentage,
)


def test_zero_jitter_clockwork_beacon():
    """Verify perfect periodicity produces Cv=0 and regularity=1.0."""
    intervals = [10.0, 10.0, 10.0, 10.0, 10.0]
    assert calculate_coefficient_of_variation(intervals) == 0.0
    assert calculate_median_absolute_deviation(intervals) == 0.0
    assert calculate_regularity_score(intervals) == 1.0
    assert estimate_jitter_percentage(intervals) == 0.0


def test_ten_percent_jitter_distribution():
    """Verify 10% uniform jitter falls into high regularity bracket."""
    rng = np.random.default_rng(seed=42)
    base_interval = 10.0
    # Uniform noise between -1.0s and +1.0s (10% of 10s)
    noise = rng.uniform(-1.0, 1.0, size=50)
    intervals = base_interval + noise

    cv = calculate_coefficient_of_variation(intervals)
    regularity = calculate_regularity_score(intervals)

    assert cv <= 0.08
    assert regularity >= 0.90


def test_twenty_five_percent_jitter_distribution():
    """Verify 25% uniform jitter remains well below Poisson web noise."""
    rng = np.random.default_rng(seed=42)
    base_interval = 20.0
    # Uniform noise between -5.0s and +5.0s (25% of 20s)
    noise = rng.uniform(-5.0, 5.0, size=50)
    intervals = base_interval + noise

    cv = calculate_coefficient_of_variation(intervals)
    regularity = calculate_regularity_score(intervals)
    estimated_jitter = estimate_jitter_percentage(intervals)

    # Theoretical uniform std for width 10 is ~2.88 -> Cv ~ 0.144
    assert 0.10 <= cv <= 0.20
    assert regularity >= 0.80
    assert 20.0 <= estimated_jitter <= 26.0


def test_fifty_percent_high_jitter_beacon():
    """Verify 50% high-jitter C2 remains within identifiable beacon bounds."""
    rng = np.random.default_rng(seed=42)
    base_interval = 30.0
    # Uniform noise between -15.0s and +15.0s
    noise = rng.uniform(-15.0, 15.0, size=60)
    intervals = base_interval + noise

    cv = calculate_coefficient_of_variation(intervals)
    assert cv <= 0.35
    # Normal web browsing Cv typically exceeds 0.80
    assert cv < 0.50


def test_mad_resilience_to_latency_spikes():
    """Verify MAD resists a single network dropout spike that corrupts sample std."""
    regular_intervals = [5.0] * 20
    clean_mad = calculate_median_absolute_deviation(regular_intervals)

    # Inject a 120-second network dropout / TCP stall
    polluted_intervals = regular_intervals.copy()
    polluted_intervals[10] = 120.0

    polluted_mad = calculate_median_absolute_deviation(polluted_intervals)

    # Standard deviation spikes from 0 to >25, but MAD remains 0.0
    assert polluted_mad == clean_mad == 0.0
    