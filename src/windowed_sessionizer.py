from typing import Dict, List, Optional
from src.models import FlowRecord, PacketEvent


class WindowedFlowSessionizer:
    """Stateful stream sessionizer maintaining sliding-window flow records with idle eviction."""

    def __init__(
        self,
        idle_timeout: float = 120.0,
        window_duration: float = 300.0,
        max_window_packets: int = 100,
    ) -> None:
        self.idle_timeout = idle_timeout
        self.window_duration = window_duration
        self.max_window_packets = max_window_packets
        self._flows: Dict[str, FlowRecord] = {}
        self._total_packets_processed = 0

    @property
    def active_flows(self) -> Dict[str, FlowRecord]:
        """Returns the dictionary of currently active flows."""
        return self._flows

    @property
    def flow_count(self) -> int:
        """Current number of active sessions in memory."""
        return len(self._flows)

    def add_packet(self, packet: PacketEvent) -> FlowRecord:
        """Ingests a PacketEvent into its corresponding bi-directional flow record."""
        self._total_packets_processed += 1
        flow_key = packet.flow_key

        if flow_key not in self._flows:
            flow = FlowRecord(
                flow_id=flow_key,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                last_seen=packet.timestamp,
                max_window_packets=self.max_window_packets,
                window_duration_seconds=self.window_duration,
            )
            self._flows[flow_key] = flow

        flow = self._flows[flow_key]
        flow.add_packet(packet=packet, auto_prune=True)
        return flow

    def evict_idle_flows(self, current_time: float) -> List[FlowRecord]:
        """Evicts and returns flows whose inactivity delta exceeds idle_timeout.

        Args:
            current_time: The current stream or system epoch timestamp.

        Returns:
            List[FlowRecord]: Flows removed from the active session table.
        """
        cutoff = current_time - self.idle_timeout
        expired_keys = [
            key for key, flow in self._flows.items() if flow.last_seen < cutoff
        ]

        evicted: List[FlowRecord] = []
        for key in expired_keys:
            evicted.append(self._flows.pop(key))

        return evicted

    def flush(self) -> List[FlowRecord]:
        """Drains and returns all active flows from the session table."""
        flushed = list(self._flows.values())
        self._flows.clear()
        return flushed

    def stats(self) -> dict:
        """Returns operational metrics for telemetry and health checking."""
        return {
            "active_flows": len(self._flows),
            "total_packets_processed": self._total_packets_processed,
            "idle_timeout": self.idle_timeout,
            "window_duration": self.window_duration,
            "max_window_packets": self.max_window_packets,
        }
    

    