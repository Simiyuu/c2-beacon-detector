import time
from typing import Any, Dict, List, Optional

from src.engine import RuleEngine
from src.models import BeaconAlert, FlowRecord
from src.reader import StreamingPacketReader
from src.sessionizer import FlowSessionizer


class C2Hunter:
    """Enterprise streaming threat hunter orchestrating packet ingestion,

    stateful session tracking, and multi-rule C2 beacon detection.
    """

    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        idle_timeout: float = 60.0,
        active_timeout: float = 300.0,
    ):
        self.engine = rule_engine or RuleEngine(register_defaults=True)
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.sessionizer = FlowSessionizer(
            idle_timeout=self.idle_timeout,
            active_timeout=self.active_timeout,
        )
        self.last_hunt_stats: Dict[str, Any] = {}

    def hunt(self, pcap_path: str, deduplicate: bool = True) -> List[BeaconAlert]:
        """Executes an end-to-end hunt against a target PCAP file.

        Streams packets, tracks stateful flows, flushes on EOF, and evaluates detection rules.
        """
        start_time = time.perf_counter()
        completed_flows: List[FlowRecord] = []
        packet_count = 0

        reader = StreamingPacketReader(pcap_path)

        for packet in reader:
            packet_count += 1
            evicted = self.sessionizer.process_packet(packet)
            if evicted is not None:
                completed_flows.append(evicted)

        # Drain remaining active sessions upon reaching EOF
        flushed_flows = self.sessionizer.flush_all()
        completed_flows.extend(flushed_flows)

        # Run multi-rule evaluation and deduplication
        alerts = self.engine.evaluate_flows(completed_flows, deduplicate=deduplicate)
        elapsed = round(time.perf_counter() - start_time, 4)

        self.last_hunt_stats = {
            "pcap_path": pcap_path,
            "packets_analyzed": packet_count,
            "flows_assembled": len(completed_flows),
            "alerts_identified": len(alerts),
            "duration_seconds": elapsed,
        }

        return alerts

    def get_summary(self) -> Dict[str, Any]:
        """Returns diagnostic metrics from the most recent hunt."""
        return self.last_hunt_stats.copy()
    