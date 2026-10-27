from typing import Union
import numpy as np


class BeaconDetector:
    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        """Pure-NumPy statistical beaconing detector based on timing consistency and jitter analysis.

        Zero C-extension DLLs to avoid Windows AppLocker and container runtime blocks.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.threshold: float = 0.0
        self.is_fitted: bool = False

    def _calculate_anomaly_metric(self, data: np.ndarray) -> np.ndarray:
        """Calculates a timing irregularity score.

        Lower score = low jitter, highly periodic (anomalous C2 beacon).
        Higher score = high jitter, bursty browsing (benign inlier).
        Feature columns expected: [iat_mean, iat_std, bytes_mean, bytes_std]
        """
        iat_mean = data[:, 0]
        iat_std = data[:, 1]
        bytes_std = data[:, 3]

        # Regularity score combines IAT variance and payload size stability
        score = np.log1p(np.maximum(iat_std, 1e-4)) + 0.05 * np.log1p(np.maximum(bytes_std, 1e-4))

        # Heavily penalize flows with near-zero timing variance
        low_jitter_mask = iat_std < 0.25
        score[low_jitter_mask] -= 2.0

        return score

    def fit(self, X: Union[np.ndarray, list]) -> "BeaconDetector":
        """Fits baseline threshold from background traffic distributions."""
        data = np.asarray(X, dtype=np.float64)
        if data.ndim == 1:
            data = data.reshape(1, -1)

        scores = self._calculate_anomaly_metric(data)
        # Threshold at the contamination quantile
        self.threshold = float(np.quantile(scores, self.contamination))
        self.is_fitted = True
        return self

    def predict(self, X: Union[np.ndarray, list]) -> np.ndarray:
        """Predicts anomaly status: -1 for beacon/outlier, 1 for benign inlier."""
        if not self.is_fitted:
            raise RuntimeError("BeaconDetector must be fitted before running predictions.")

        scores = self.score_samples(X)
        preds = np.where(scores <= self.threshold, -1, 1)
        return preds

    def score_samples(self, X: Union[np.ndarray, list]) -> np.ndarray:
        """Returns anomaly scores. Lower score = more anomalous."""
        if not self.is_fitted:
            raise RuntimeError("BeaconDetector must be fitted before scoring samples.")

        data = np.asarray(X, dtype=np.float64)
        if data.ndim == 1:
            data = data.reshape(1, -1)

        return self._calculate_anomaly_metric(data)
        