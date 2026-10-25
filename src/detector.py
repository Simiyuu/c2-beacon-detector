from typing import Optional, Union
import numpy as np
from sklearn.ensemble import IsolationForest


class BeaconDetector:
    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        """Unsupervised network beaconing anomaly detector based on Isolation Forests."""
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        self.is_fitted: bool = False

    def fit(self, X: Union[np.ndarray, list]) -> "BeaconDetector":
        """Fits isolation trees on extracted flow feature vectors."""
        data = np.asarray(X, dtype=np.float64)
        if data.ndim == 1:
            data = data.reshape(-1, 1)

        self.model.fit(data)
        self.is_fitted = True
        return self

    def predict(self, X: Union[np.ndarray, list]) -> np.ndarray:
        """Predicts anomaly status: -1 for beacon/outlier, 1 for benign inlier."""
        if not self.is_fitted:
            raise RuntimeError("BeaconDetector must be fitted before running predictions.")

        data = np.asarray(X, dtype=np.float64)
        if data.ndim == 1:
            data = data.reshape(1, -1)

        return self.model.predict(data)

    def score_samples(self, X: Union[np.ndarray, list]) -> np.ndarray:
        """Returns anomaly scores. The lower the score, the more anomalous the flow."""
        if not self.is_fitted:
            raise RuntimeError("BeaconDetector must be fitted before scoring samples.")

        data = np.asarray(X, dtype=np.float64)
        if data.ndim == 1:
            data = data.reshape(1, -1)

        return self.model.score_samples(data)