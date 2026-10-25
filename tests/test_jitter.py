import pytest
import numpy as np
from sample_data.generate_traffic import inject_jitter, generate_jittered_intervals


def test_zero_jitter_returns_fixed_interval():
    """Verify 0% jitter always returns the exact base interval."""
    base = 5.0
    samples = [inject_jitter(base_interval=base, jitter_pct=0.0) for _ in range(50)]
    assert all(s == base for s in samples)


def test_jitter_stays_strictly_within_bounds():
    """Verify +/- 20% jitter on a 10s sleep stays strictly between 8.0s and 12.0s."""
    base = 10.0
    jitter = 0.20  # Bounds: [8.0, 12.0]
    samples = [inject_jitter(base_interval=base, jitter_pct=jitter) for _ in range(500)]

    assert min(samples) >= 8.0, "Sample fell below lower jitter bound"
    assert max(samples) <= 12.0, "Sample exceeded upper jitter bound"
    # Sample mean must converge near the expected base interval
    assert np.mean(samples) == pytest.approx(base, abs=0.25)


def test_generate_jittered_intervals_monotonic_progression():
    """Verify generated timestamps progress forward in time with no negative deltas."""
    timestamps = generate_jittered_intervals(count=20, base_interval=3.0, jitter_pct=0.15, start_time=1000.0)
    deltas = np.diff(timestamps)

    assert len(timestamps) == 20
    assert np.all(deltas > 0), "Timestamps must be strictly increasing"
    assert np.all((deltas >= 2.55) & (deltas <= 3.45)), "Intervals violated +/- 15% range"