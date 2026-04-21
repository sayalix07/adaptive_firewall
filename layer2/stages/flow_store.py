"""
stages/flow_store.py — Stage ③: Flow / Session Aggregation
============================================================
Groups individual packets into flows using a 5-tuple key:
  (src_ip, dst_ip, src_port, dst_port, protocol)

A flow is "completed" and released downstream when:
  - Its idle time exceeds `timeout_sec`   (most flows)
  - flush_all() is called                 (shutdown)

The store is an in-memory dict — suitable for single-process
deployments. For multi-process scale-out, swap the dict for
a Redis hash (same interface).
"""

import hashlib
import time
from collections import defaultdict
from typing import Dict, List, Any

from utils.logger import get_logger

log = get_logger("layer2.flow_store")


class FlowRecord:
    """Accumulates per-packet stats for one flow."""

    __slots__ = (
        "flow_id", "flow_key",
        "start_ts", "last_ts",
        "pkt_count", "byte_count",
        "src_bytes", "dst_bytes",
        "failed_count",
        "pkt_timestamps",
        "proto_num", "proto_name",
        "src_ip", "dst_ip", "src_port", "dst_port",
        "flags_seen",
    )

    def __init__(self, flow_key: tuple, first_pkt: Dict[str, Any]):
        self.flow_key   = flow_key
        self.flow_id    = _make_flow_id(flow_key)
        self.start_ts   = first_pkt["timestamp"]
        self.last_ts    = first_pkt["timestamp"]
        self.pkt_count  = 0
        self.byte_count = 0
        self.src_bytes  = 0
        self.dst_bytes  = 0
        self.failed_count = 0
        self.pkt_timestamps = []
        self.proto_num  = first_pkt["protocol_num"]
        self.proto_name = first_pkt["protocol_name"]
        self.src_ip     = first_pkt["src_ip"]
        self.dst_ip     = first_pkt["dst_ip"]
        self.src_port   = first_pkt["src_port"]
        self.dst_port   = first_pkt["dst_port"]
        self.flags_seen = set()

    def update(self, pkt: Dict[str, Any]):
        self.pkt_count  += 1
        size = pkt["pkt_size"]
        self.byte_count += size
        self.last_ts     = pkt["timestamp"]
        self.pkt_timestamps.append(pkt["timestamp"])

        # Directional byte split (src→dst vs dst→src)
        if pkt["src_ip"] == self.src_ip:
            self.src_bytes += size
        else:
            self.dst_bytes += size

        # Track RST / SYN-only as "failed attempt" signal
        flags = pkt["flags_raw"]
        RST = 0x04
        SYN = 0x02
        ACK = 0x10
        if flags & RST:
            self.failed_count += 1
        elif (flags & SYN) and not (flags & ACK):
            self.failed_count += 1   # unanswered SYN

        self.flags_seen.add(flags)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id":      self.flow_id,
            "src_ip":       self.src_ip,
            "dst_ip":       self.dst_ip,
            "src_port":     self.src_port,
            "dst_port":     self.dst_port,
            "protocol_num": self.proto_num,
            "protocol_name":self.proto_name,
            "start_ts":     self.start_ts,
            "last_ts":      self.last_ts,
            "pkt_count":    self.pkt_count,
            "byte_count":   self.byte_count,
            "src_bytes":    self.src_bytes,
            "dst_bytes":    self.dst_bytes,
            "failed_count": self.failed_count,
            "pkt_timestamps": list(self.pkt_timestamps[-200:]),  # cap memory
            "flags_union":  _union_flags(self.flags_seen),
        }


class FlowStore:
    """
    In-memory 5-tuple flow store.
    Returns a list of completed flow dicts each time a packet is ingested.
    """

    def __init__(self, timeout_sec: float = 60.0):
        self.timeout_sec = timeout_sec
        self._flows: Dict[tuple, FlowRecord] = {}
        self._last_eviction = time.time()
        self._eviction_interval = 10.0   # run eviction every 10 s

    def ingest(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not features:
            return []

        key = features["flow_key"]
        now = features["timestamp"]

        if key not in self._flows:
            self._flows[key] = FlowRecord(key, features)

        self._flows[key].update(features)

        # Periodic eviction of timed-out flows
        completed = []
        if now - self._last_eviction >= self._eviction_interval:
            completed = self._evict(now)
            self._last_eviction = now

        return completed

    def flush_all(self) -> List[Dict[str, Any]]:
        """Force-close every open flow (call at shutdown)."""
        completed = [r.to_dict() for r in self._flows.values()]
        self._flows.clear()
        log.info(f"Flushed {len(completed)} open flows")
        return completed

    def _evict(self, now: float) -> List[Dict[str, Any]]:
        expired_keys = [
            k for k, r in self._flows.items()
            if (now - r.last_ts) >= self.timeout_sec
        ]
        completed = [self._flows.pop(k).to_dict() for k in expired_keys]
        if completed:
            log.debug(f"Evicted {len(completed)} timed-out flows")
        return completed


# ------------------------------------------------------------------
def _make_flow_id(flow_key: tuple) -> str:
    raw = "|".join(str(x) for x in flow_key)
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _union_flags(flags_seen: set) -> int:
    result = 0
    for f in flags_seen:
        result |= f
    return result
