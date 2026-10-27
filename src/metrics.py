from typing import Any, Dict, List, Union
import numpy as np


def calculate_iat(timestamps: List[float]) -> np.ndarray:
    """Computes inter-arrival time (IAT) deltas between consecutive packet timestamps.

    Returns an empty 1D array if fewer than 2 timestamps are provided.
    """
    if len(timestamps) < 2:
        return np.empty(0, dtype=np.float64)

    ts_array = np.asarray(timestamps, dtype=np.float64)
    # Ensure chronological order
    if not np.all(ts_array[:-1] <= ts_array[1:]):
        ts_array = np.sort(ts_array)

    deltas = np.diff(ts_array)
    # Clamp negative floating point inaccuracies to 0.0
    return np.maximum(deltas, 0.0)


def compute_distribution_stats(series: Union[np.ndarray, List[float]]) -> Dict[str, float]:
    """Computes parametric and non-parametric statistical descriptors for a numerical series.

    Guarantees finite float outputs with zeroed fallbacks for empty or single-value arrays.
    """
    arr = np.asarray(series, dtype=np.float64)

    if arr.size == 0:
        return {
            "count": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "median": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "iqr": 0.0,
        }

    if arr.size == 1:
        val = float(arr[0])
        return {
            "count": 1.0,
            "mean": val,
            "std": 0.0,
            "min": val,
            "max": val,
            "median": val,
            "p25": val,
            "p75": val,
            "iqr": 0.0,
        }

    mean_val = float(np.mean(arr))
    # ddof=1 for sample standard deviation
    std_val = float(np.std(arr, ddof=1))
    min_val = float(np.min(arr))
    max_val = float(np.max(arr))
    p25 = float(np.percentile(arr, 25))
    median_val = float(np.median(arr))
    p75 = float(np.percentile(arr, 75))
    iqr_val = float(max(0.0, p75 - p25))

    return {
        "count": float(arr.size),
        "mean": round(mean_val, 6),
        "std": round(std_val, 6),
        "min": round(min_val, 6),
        "max": round(max_val, 6),
        "median": round(median_val, 6),
        "p25": round(p25, 6),
        "p75": round(p75, 6),
        "iqr": round(iqr_val, 6),
    }


def extract_flow_distribution_metrics(
    timestamps: List[float], packet_lengths: List[int]
) -> Dict[str, Any]:
    """Combines timing and frame size dispersion metrics for a network flow."""
    iat_deltas = calculate_iat(timestamps)
    iat_stats = compute_distribution_stats(iat_deltas)
    size_stats = compute_distribution_stats(packet_lengths)

    return {
        "iat": iat_stats,
        "size": size_stats,
        "packet_count": len(timestamps),
        "duration": float(timestamps[-1] - timestamps[0]) if len(timestamps) >= 2 else 0.0,
    }
