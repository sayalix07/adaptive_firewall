# layer1/queue_manager.py
# ─────────────────────────────────────────────────────────────────────────────
# Flow Queue Manager
#
# A thin wrapper around Python's thread-safe queue.Queue.
# Sits between Layer 1 (producer) and Layer 2 (consumer).
#
# Why wrap Queue at all?
#   - Adds a size cap so a slow Layer 2 doesn't let memory grow unbounded.
#   - Provides drop_count telemetry so we know if we're falling behind.
#   - Gives Layer 2 a clean get_flow() interface instead of raw queue calls.
# ─────────────────────────────────────────────────────────────────────────────

import queue
from dataclasses import dataclass, field


@dataclass
class QueueStats:
    enqueued: int = 0
    dequeued: int = 0
    dropped:  int = 0

    @property
    def pending(self) -> int:
        return self.enqueued - self.dequeued - self.dropped


class FlowQueue:
    """
    Thread-safe queue for completed flow records.

    Parameters
    ----------
    maxsize : int
        Maximum number of flows held in memory. When full, new flows are
        dropped and counted in stats.dropped. Default 1000.
    """

    def __init__(self, maxsize: int = 1000):
        self._q     = queue.Queue(maxsize=maxsize)
        self.stats  = QueueStats()

    # ── Producer side (Layer 1) ───────────────────────────────────────────────

    def put_flow(self, flow: dict) -> bool:
        """
        Enqueue a completed flow.

        Returns True on success, False if the queue is full (flow dropped).
        Non-blocking — Layer 1's sniffer thread must never stall here.
        """
        try:
            self._q.put_nowait(flow)
            self.stats.enqueued += 1
            return True
        except queue.Full:
            self.stats.dropped += 1
            return False

    # ── Consumer side (Layer 2) ───────────────────────────────────────────────

    def get_flow(self, timeout: float = 1.0) -> dict | None:
        """
        Dequeue the next completed flow.

        Returns None if no flow arrives within `timeout` seconds.
        """
        try:
            flow = self._q.get(timeout=timeout)
            self.stats.dequeued += 1
            return flow
        except queue.Empty:
            return None

    def get_all_available(self) -> list[dict]:
        """Drain every flow currently in the queue without blocking."""
        flows = []
        while True:
            flow = self.get_flow(timeout=0.0)
            if flow is None:
                break
            flows.append(flow)
        return flows

    # ── Shared ────────────────────────────────────────────────────────────────

    @property
    def size(self) -> int:
        return self._q.qsize()

    def __repr__(self) -> str:
        s = self.stats
        return (
            f"FlowQueue(pending={s.pending}, "
            f"enqueued={s.enqueued}, "
            f"dropped={s.dropped})"
        )
