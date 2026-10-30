import queue
import threading
import time
from typing import Generator, Optional
from scapy.all import AsyncSniffer, Packet


class PacketSnifferError(Exception):
    """Raised when interface sniffing fails or parameters are invalid."""


class LivePacketSniffer:
    """Thread-safe asynchronous packet capture engine backed by a bounded ring buffer queue."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip and (tcp or udp)",
        max_queue_size: int = 10000,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.max_queue_size = max_queue_size
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=max_queue_size)
        self._sniffer: Optional[AsyncSniffer] = None
        self._is_running = threading.Event()
        self._packets_captured = 0
        self._packets_dropped = 0

    def _packet_callback(self, pkt: Packet) -> None:
        """Invoked by AsyncSniffer thread for each captured raw frame."""
        self._packets_captured += 1
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._packets_dropped += 1

    def start(self) -> None:
        """Starts the underlying background sniffer thread."""
        if self._is_running.is_set():
            return

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=False,
            )
            self._sniffer.start()
            self._is_running.set()
        except Exception as e:
            raise PacketSnifferError(f"Failed to start sniffer on interface '{self.interface}': {e}") from e

    def stop(self) -> None:
        """Stops background packet capture and clears running flags."""
        if not self._is_running.is_set():
            return

        self._is_running.clear()
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()

    def iter_packets(self, timeout: float = 0.5) -> Generator[Packet, None, None]:
        """Yields packets from the queue until stopped and drained."""
        while self._is_running.is_set() or not self._queue.empty():
            try:
                pkt = self._queue.get(timeout=timeout)
                yield pkt
                self._queue.task_done()
            except queue.Empty:
                if not self._is_running.is_set():
                    break
                continue

    @property
    def stats(self) -> dict:
        """Returns runtime packet capture statistics."""
        return {
            "captured": self._packets_captured,
            "dropped": self._packets_dropped,
            "queue_depth": self._queue.qsize(),
            "running": self._is_running.is_set(),
        }

    