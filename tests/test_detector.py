import pytest
import numpy as np
from src.detector import BeaconDetector


def test_detector_flags_periodic_beacon_flow():
    """Verify low-variance IAT flows are flagged as anomalies (-1) against noisy background."""
    # Synthetic feature matrix: [iat_mean, iat_std, bytes_mean, bytes_std]
    # 20 background flows (high timing variance, variable sizes)
    rng = np.random.default_rng(seed=42)
    background_flows = rng.uniform(low=[0.1, 1.5, 200, 100], high=[10.0, 5.0, 1200, 400], size=(30, 4))

    # 1 beacon flow (tight timing around 5s, near-zero std dev, fixed size)
    beacon_flow = np.array([[5.0, 0.05, 128.0, 2.0]])

    train_data = np.vstack([background_flows, beacon_flow])

    detector = BeaconDetector(contamination=0.05)
    detector.fit(train_data)

    pred = detector.predict(beacon_flow)
    assert pred[0] == -1, "Detector failed to classify periodic beacon flow as anomalous"


def test_detector_clears_benign_bursty_flow():
    """Verify high-variance browsing flows are classified as benign inliers (1)."""
    rng = np.random.default_rng(seed=42)
    background_flows = rng.uniform(low=[0.1, 1.5, 200, 100], high=[10.0, 5.0, 1200, 400], size=(30, 4))
    benign_flow = np.array([[2.5, 2.8, 800.0, 350.0]])

    detector = BeaconDetector(contamination=0.05)
    detector.fit(background_flows)

    pred = detector.predict(benign_flow)
    assert pred[0] == 1, "Detector falsely flagged high-variance web traffic"