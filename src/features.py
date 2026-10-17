import numpy as np
from pydantic import BaseModel
from typing import Dict, List
from src.models import FlowRecord

class FlowFeatures(BaseModel):
    flow_id: str
    packet_count: int
    duration_seconds: float
    iat_mean: float
    iat_std: float
    iat_min: float
    iat_max: float
    byte_mean: float
    byte_std: float

class FeatureExtractor:
    @staticmethod
    def extract_from_flow(flow: FlowRecord) -> FlowFeatures:
        """Computes statistical metrics (IAT and byte variance) for a flow."""
        timestamps = sorted(flow.timestamps)
        lengths = flow.packet_lengths

        if len(timestamps) > 1:
            iats = np.diff(timestamps)
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
            duration = float(timestamps[-1] - timestamps[0])
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_min = 0.0
            iat_max = 0.0
            duration = 0.0

        byte_mean = float(np.mean(lengths)) if lengths else 0.0
        byte_std = float(np.std(lengths)) if lengths else 0.0

        return FlowFeatures(
            flow_id=flow.flow_id,
            packet_count=flow.packet_count,
            duration_seconds=duration,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max,
            byte_mean=byte_mean,
            byte_std=byte_std
        )

    @classmethod
    def extract_all(cls, flows: Dict[str, FlowRecord]) -> List[FlowFeatures]:
        return [cls.extract_from_flow(flow) for flow in flows.values()]