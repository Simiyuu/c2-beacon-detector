from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionTechnique(str, Enum):
    PERIODIC_BEACON = "T1071"
    HTTP_BEACON = "T1071.001"
    DNS_TUNNELING = "T1572"
    NON_STANDARD_PORT = "T1571"
    HIGH_ENTROPY_CHANNEL = "T1573"


class MITREAttackMetadata(BaseModel):
    technique_id: DetectionTechnique = DetectionTechnique.PERIODIC_BEACON
    technique_name: str = "Application Layer Protocol"
    tactic: str = "Command and Control"
    reference_url: str = "https://attack.mitre.org/techniques/T1071/"


class JitterMetrics(BaseModel):
    iat_mean: float = Field(..., ge=0.0, description="Mean Inter-Arrival Time in seconds")
    iat_std: float = Field(..., ge=0.0, description="Standard deviation of IAT")
    coefficient_of_variation: float = Field(
        default=0.0, ge=0.0, description="Cv = std / mean ratio indicating relative jitter"
    )
    median_absolute_deviation: float = Field(
        default=0.0, ge=0.0, description="MAD metric for non-parametric dispersion"
    )
    shannon_entropy: float = Field(
        default=0.0, ge=0.0, le=8.0, description="Bitwise entropy of packet payloads (0-8 bits)"
    )


class PacketEvent(BaseModel):
    timestamp: float = Field(..., description="Epoch timestamp of packet capture")
    src_ip: str
    dst_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str
    length: int = Field(..., ge=0)
    payload_entropy: float = Field(default=0.0, ge=0.0, le=8.0)

    @property
    def flow_key(self) -> str:
        """Normalized 5-tuple key ensuring bi-directional packet pairing."""
        proto = self.protocol.lower()
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port):
            return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{proto}"
        return f"{self.dst_ip}:{self.dst_port}->{self.src_ip}:{self.src_port}:{proto}"


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

    def add_packet(self, packet: PacketEvent) -> None:
        self.packet_count += 1
        self.total_bytes += packet.length
        self.timestamps.append(packet.timestamp)
        self.packet_lengths.append(packet.length)


class BeaconAlert(BaseModel):
    alert_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    severity: AlertSeverity = AlertSeverity.HIGH
    mitre_attack: MITREAttackMetadata = Field(default_factory=MITREAttackMetadata)
    jitter_metrics: JitterMetrics
    anomaly_score: float
    description: str
    