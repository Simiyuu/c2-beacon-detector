from enum import Enum
from typing import List, Union
import numpy as np


class EntropyProfile(str, Enum):
    ZERO = "ZERO"
    PLAINTEXT = "PLAINTEXT"
    STRUCTURED = "STRUCTURED"
    ENCODED = "ENCODED"
    ENCRYPTED_OR_RANDOM = "ENCRYPTED_OR_RANDOM"


def calculate_shannon_entropy(data: Union[bytes, bytearray, np.ndarray]) -> float:
    """Calculates byte-level Shannon entropy across the 0-255 byte spectrum in bits (0.0 to 8.0).

    Uses vectorized numpy bincount for O(N) execution speed.
    """
    if not data:
        return 0.0

    if isinstance(data, (bytes, bytearray)):
        byte_arr = np.frombuffer(data, dtype=np.uint8)
    else:
        byte_arr = np.asarray(data, dtype=np.uint8)

    if byte_arr.size == 0:
        return 0.0

    counts = np.bincount(byte_arr, minlength=256)
    non_zero_counts = counts[counts > 0]
    probabilities = non_zero_counts / byte_arr.size

    entropy = -float(np.sum(probabilities * np.log2(probabilities)))
    return round(float(np.clip(entropy, 0.0, 8.0)), 4)


def sliding_window_entropy(
    data: bytes, window_size: int = 64, step: int = 32
) -> List[float]:
    """Computes Shannon entropy across overlapping windows to detect localized high-entropy payloads."""
    if not data or len(data) < window_size:
        return [calculate_shannon_entropy(data)]

    scores: List[float] = []
    total_len = len(data)

    for offset in range(0, total_len - window_size + 1, step):
        chunk = data[offset : offset + window_size]
        scores.append(calculate_shannon_entropy(chunk))

    # Catch remaining trailing slice if any
    if (total_len - window_size) % step != 0:
        chunk = data[total_len - window_size : total_len]
        scores.append(calculate_shannon_entropy(chunk))

    return scores


def classify_payload_entropy(entropy_score: float) -> EntropyProfile:
    """Classifies an entropy score into operational risk categories."""
    if entropy_score <= 0.05:
        return EntropyProfile.ZERO
    if entropy_score < 3.5:
        return EntropyProfile.PLAINTEXT
    if entropy_score < 5.5:
        return EntropyProfile.STRUCTURED
    if entropy_score < 7.0:
        return EntropyProfile.ENCODED
    return EntropyProfile.ENCRYPTED_OR_RANDOM
