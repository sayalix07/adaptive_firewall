# layer1/flow.py
# ─────────────────────────────────────────────────────────────────────────────
# Flow Aggregator
#
# A "flow" is the collection of all packets that share the same 5-tuple:
#   (src_ip, dst_ip, src_port, dst_port, protocol)
#
# Individual packets arrive too fast and too granular for ML models to use
# directly. The aggregator batches them into flows and computes statistics
# (packet count, total bytes, duration, etc.) that become ML features in
# Layer 2.
#
# Timeout behaviour:
#   A flow is "completed" and emitted once it hasn't received a new packet
#   for `timeout_seconds`. This is checked lazily on every new packet arrival
#   to avoid needing a separate timer thread.
# ─────────────────────────────────────────────────────────────────────────────

from collections import defaultdict
from datetime import datetime, timezone


class FlowAggregator:
    """
    Groups raw packet records into completed network flows.

    Parameters
    ----------
    timeout_seconds : int
        How long (in wall-clock seconds) a flow can be idle before it is
        finalised and emitted. Default is 10 s.
    """

    def __init__(self, timeout_seconds: int = 10):
        self.timeout    = timeout_seconds
        self._flows     = defaultdict(list)     # flow_key → [packet_record, ...]
        self._last_seen = {}                    # flow_key → datetime of last packet

    # ── Public API ────────────────────────────────────────────────────────────

    def add_packet(self, record: dict) -> dict | None:
        """
        Add a parsed packet record to its flow.

        Returns a completed flow dict if any flow (not necessarily this
        packet's flow) has timed out; otherwise returns None.
        """
        key = self._flow_key(record)
        now = datetime.now(timezone.utc)

        self._flows[key].append(record)
        self._last_seen[key] = now

        # Lazy timeout sweep — check all flows on every packet
        return self._sweep_timed_out(now)

    def flush_all(self) -> list[dict]:
        """
        Force-finalise every open flow. Call this on shutdown so no
        partial flows are lost.
        """
        completed = []
        for key in list(self._flows.keys()):
            completed.append(self._finalise(key))
        return completed

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _flow_key(record: dict) -> tuple:
        """
        Build a bidirectional 5-tuple key.
        Sorting src/dst ensures A→B and B→A map to the same flow.
        """
        ip_pair   = tuple(sorted([record["src_ip"],  record["dst_ip"]]))
        port_pair = tuple(sorted([record["src_port"] or 0,
                                  record["dst_port"] or 0]))
        return (*ip_pair, *port_pair, record["protocol"])

    def _sweep_timed_out(self, now: datetime) -> dict | None:
        """Return the first timed-out flow found, or None."""
        for key, last in list(self._last_seen.items()):
            elapsed = (now - last).total_seconds()
            if elapsed >= self.timeout:
                return self._finalise(key)
        return None

    def _finalise(self, key: tuple) -> dict:
        """Compute aggregate statistics and remove the flow from state."""
        packets = self._flows.pop(key, [])
        self._last_seen.pop(key, None)

        if not packets:
            return {}

        sizes    = [p["length"]    for p in packets]
        flags    = [p["tcp_flags"] for p in packets if p["tcp_flags"]]
        t_start  = datetime.fromisoformat(packets[0]["timestamp"])
        t_end    = datetime.fromisoformat(packets[-1]["timestamp"])
        duration = max((t_end - t_start).total_seconds(), 0.001)  # avoid /0

        ip_a, ip_b, port_a, port_b, proto = key

        return {
            # Identity
            "src_ip":           packets[0]["src_ip"],
            "dst_ip":           packets[0]["dst_ip"],
            "src_port":         packets[0]["src_port"],
            "dst_port":         packets[0]["dst_port"],
            "protocol":         proto,
            # Volume
            "packet_count":     len(packets),
            "total_bytes":      sum(sizes),
            "avg_pkt_size":     round(sum(sizes) / len(sizes), 2),
            "min_pkt_size":     min(sizes),
            "max_pkt_size":     max(sizes),
            # Time
            "duration_sec":     round(duration, 4),
            "pkts_per_sec":     round(len(packets) / duration, 2),
            "bytes_per_sec":    round(sum(sizes)   / duration, 2),
            # TCP flags (empty list for UDP/ICMP)
            "unique_flags":     list(set(flags)),
            "flag_count":       len(flags),
            # Timestamps
            "start_time":       packets[0]["timestamp"],
            "end_time":         packets[-1]["timestamp"],
        }
