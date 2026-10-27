import base64
import numpy as np
import pytest
from src.entropy import (
    EntropyProfile,
    calculate_shannon_entropy,
    classify_payload_entropy,
    sliding_window_entropy,
)


def test_entropy_mathematical_bounds():
    assert calculate_shannon_entropy(b"") == 0.0
    assert calculate_shannon_entropy(b"0" * 512) == 0.0

    uniform_bytes = bytes(range(256)) * 4
    assert calculate_shannon_entropy(uniform_bytes) == 8.0


def test_plaintext_http_payload_classification():
    http_get = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: internal-portal.corp.local\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    score = calculate_shannon_entropy(http_get)
    # Plaintext ASCII with protocol headers falls between 2.0 and 5.3 bits
    assert 2.0 <= score <= 5.3
    profile = classify_payload_entropy(score)
    assert profile in [EntropyProfile.PLAINTEXT, EntropyProfile.STRUCTURED]


def test_base64_encoded_payload_classification():
    # Base64 encoded exfiltration buffer (high-entropy payload transported via Base64)
    rng = np.random.default_rng(seed=42)
    raw_payload = rng.bytes(512)
    b64_payload = base64.b64encode(raw_payload)
    score = calculate_shannon_entropy(b64_payload)

    # Base64 distributions over 64 symbols hover near log2(64) = 6.0 bits
    assert 5.5 <= score <= 6.0
    profile = classify_payload_entropy(score)
    assert profile == EntropyProfile.ENCODED


def test_encrypted_pseudo_random_stream_classification():
    rng = np.random.default_rng(seed=1337)
    random_bytes = rng.bytes(1024)
    score = calculate_shannon_entropy(random_bytes)

    assert score >= 7.6
    profile = classify_payload_entropy(score)
    assert profile == EntropyProfile.ENCRYPTED_OR_RANDOM


def test_sliding_window_detects_embedded_high_entropy_blob():
    rng = np.random.default_rng(seed=42)
    carrier = b"A" * 200 + rng.bytes(80) + b"B" * 200

    window_scores = sliding_window_entropy(carrier, window_size=64, step=32)

    assert window_scores[0] == 0.0
    assert any(s >= 5.0 for s in window_scores)
    