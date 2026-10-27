from typing import Dict, Iterator, List, Optional
from src.models import FlowRecord, PacketEvent


class FlowSessionizer:
    """Stateful 5-tuple network flow sessionizer with idle and active window boundary controls."""

    def __init__(
        self,
        idle_timeout: float = 60.0,
        active_timeout: float = 300.0,
    ):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        # Active sessions keyed by canonical bidirectional flow_key
        self.active_flows: Dict[str, FlowRecord] = {}

    def process_packet(self, packet: PacketEvent) -> Optional[FlowRecord]:
        """Ingests a PacketEvent.

        If the packet triggers an idle or active timeout on an existing session,
        the expired FlowRecord is returned, and a new session begins.
        """
        key = packet.flow_key
        expired_flow: Optional[FlowRecord] = None

        if key in self.active_flows:
            current_flow = self.active_flows[key]
            last_timestamp = current_flow.timestamps[-1]
            first_timestamp = current_flow.timestamps[0]

            # Check idle timeout (gap between last packet and current)
            idle_delta = packet.timestamp - last_timestamp
            # Check active timeout (total lifespan of current session)
            active_duration = packet.timestamp - first_timestamp

            if idle_delta > self.idle_timeout or active_duration > self.active_timeout:
                expired_flow = current_flow
                # Start new flow session for this 5-tuple
                new_flow = FlowRecord(
                    flow_id=key,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                )
                new_flow.add_packet(packet)
                self.active_flows[key] = new_flow
            else:
                current_flow.add_packet(packet)
        else:
            # Initialize new flow session
            new_flow = FlowRecord(
                flow_id=key,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
            )
            new_flow.add_packet(packet)
            self.active_flows[key] = new_flow

        return expired_flow

    def process_stream(self, packets: Iterator[PacketEvent]) -> Iterator[FlowRecord]:
        """Processes a packet iterator, yielding expired flows as they timeout, and all remaining flows at completion."""
        for packet in packets:
            expired = self.process_packet(packet)
            if expired is not None:
                yield expired

        # Flush any remaining active flows upon stream end
        yield from self.flush()

    def flush(self) -> List[FlowRecord]:
        """Flushes and clears all currently active flows."""
        flushed_flows = list(self.active_flows.values())
        self.active_flows.clear()
        return flushed_flows
    