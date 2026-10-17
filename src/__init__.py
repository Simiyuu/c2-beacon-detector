from pydantic import BaseModel, Field
from typing import Tuple, List

class PacketEvent(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int

    @property
    def flow_key(self) -> Tuple[str, str, int, int, str]:
        """Returns normalized bi-directional 5-tuple."""
        endpoints = sorted([(self.src_ip, self.src_port), (self.dst_ip, self.dst_port)])
        return (
            endpoints[0][0],
            endpoints[1][0],
            endpoints[0][1],
            endpoints[1][1],
            self.protocol.upper()
        )

class FlowRecord(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 0
    total_bytes: int = 0
    timestamps: List[float] = Field(default_factory=list)
    packet_lengths: List[int] = Field(default_factory=list)