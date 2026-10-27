from typing import Dict, List, Union
import numpy as np


def calculate_coefficient_of_variation(data: Union[np.ndarray, List[float]]) -> float:
    """Computes the Coefficient of Variation (Cv = sigma / mu).

    Cv thresholds:
    - Cv < 0.15: Highly periodic (default Cobalt Strike / automated beacon)
    - 0.15 <= Cv <= 0.40: Jitter-tolerant beacon (20-40% configured sleep jitter)
    - 0.8 <= Cv <= 1.2: Poisson process / normal interactive user web browsing
    - Cv > 1.2: Bursty traffic (concurrent assets, file transfers)
    """
    arr = np.asarray(data, dtype=np.float64)
    if arr.size < 2:
        return 0.0

    mean_val = float(np.mean(arr))
    if mean_val <= 1e-9:
        return 0.0

    std_val = float(np.std(arr, ddof=1))
    return round(float(std_val / mean_val), 6)


def calculate_median_absolute_deviation(data: Union[np.ndarray, List[float]]) -> float:
    """Computes Median Absolute Deviation (MAD = median(|X - median(X)|)).

    A robust non-parametric measure of dispersion resistant to single network latency spikes.
    """
    arr = np.asarray(data, dtype=np.float64)
    if arr.size < 2:
        return 0.0

    median_val = np.median(arr)
    absolute_deviations = np.abs(arr - median_val)
    mad = float(np.median(absolute_deviations))
    return round(mad, 6)


def calculate_regularity_score(data: Union[np.ndarray, List[float]]) -> float:
    """Computes a normalized beacon regularity score bounded in range [0.0, 1.0].

    1.0 = absolute clockwork periodicity (0% jitter).
    0.0 = completely erratic or Poisson-distributed background traffic.
    """
    arr = np.asarray(data, dtype=np.float64)
    if arr.size < 3:
        return 0.0

    cv = calculate_coefficient_of_variation(arr)
    regularity = 1.0 / (1.0 + cv)
    return round(float(np.clip(regularity, 0.0, 1.0)), 4)


def estimate_jitter_percentage(data: Union[np.ndarray, List[float]]) -> float:
    """Estimates adversary-configured sleep jitter percentage based on observed IAT distribution."""
    arr = np.asarray(data, dtype=np.float64)
    if arr.size < 3:
        return 0.0

    median_iat = float(np.median(arr))
    if median_iat <= 1e-9:
        return 0.0

    max_dev = float(np.max(np.abs(arr - median_iat)))
    jitter_pct = (max_dev / median_iat) * 100.0
    return round(float(min(jitter_pct, 100.0)), 2)
