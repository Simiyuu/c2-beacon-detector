from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Backward compatibility alias
Severity = AlertSeverity


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


# Backward compatibility alias
MitreAttack = MITREAttackMetadata


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
    payload_entropies: List[float] = Field(default_factory=list)

    # Sliding-window parameters & eviction telemetry
    start_time: float = 0.0
    last_seen: float = 0.0
    max_window_packets: int = 100
    window_duration_seconds: float = 300.0
    pruned_packet_count: int = 0

    def add_packet(
        self,
        packet: Optional[PacketEvent] = None,
        timestamp: Optional[float] = None,
        length: int = 0,
        payload_entropy: float = 0.0,
        auto_prune: bool = False,
    ) -> None:
        self.packet_count += 1
        if packet is not None:
            ts = packet.timestamp
            pkt_len = packet.length
            entropy = packet.payload_entropy
        else:
            ts = timestamp if timestamp is not None else 0.0
            pkt_len = length
            entropy = payload_entropy

        if self.packet_count == 1:
            self.start_time = ts
        self.last_seen = max(self.last_seen, ts)

        self.total_bytes += pkt_len
        self.timestamps.append(ts)
        self.packet_lengths.append(pkt_len)
        self.payload_entropies.append(entropy)

        if auto_prune:
            self.prune_window(reference_time=ts)

    def prune_window(self, reference_time: Optional[float] = None) -> int:
        """Evicts timestamps and length entries outside the sliding temporal or capacity bounds.

        Returns:
            int: The number of packet events evicted during this call.
        """
        if not self.timestamps:
            return 0

        ref_time = reference_time if reference_time is not None else self.last_seen
        cutoff_time = ref_time - self.window_duration_seconds

        # 1. Temporal boundary eviction (chronological)
        keep_idx = 0
        while keep_idx < len(self.timestamps) and self.timestamps[keep_idx] < cutoff_time:
            keep_idx += 1

        # 2. Capacity constraint eviction
        capacity_overflow = (len(self.timestamps) - keep_idx) - self.max_window_packets
        if capacity_overflow > 0:
            keep_idx += capacity_overflow

        if keep_idx > 0:
            self.pruned_packet_count += keep_idx
            self.timestamps = self.timestamps[keep_idx:]
            self.packet_lengths = self.packet_lengths[keep_idx:]
            self.payload_entropies = self.payload_entropies[keep_idx:]
            return keep_idx

        return 0

    @property
    def byte_count(self) -> int:
        return self.total_bytes

    @property
    def window_size(self) -> int:
        return len(self.timestamps)

    @property
    def window_duration(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        return self.timestamps[-1] - self.timestamps[0]

    @property
    def inter_arrival_times(self) -> List[float]:
        if len(self.timestamps) < 2:
            return []
        return [
            round(self.timestamps[i] - self.timestamps[i - 1], 6)
            for i in range(1, len(self.timestamps))
        ]


# Backward compatibility alias
FlowSession = FlowRecord


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
    