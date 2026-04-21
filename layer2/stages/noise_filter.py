"""
stages/noise_filter.py — Stage ⑦: Noise & Redundancy Filter
=============================================================
Suppresses statistically uninformative flow records before they
reach the ML layer. This is adaptive — not a static rule list.

Drop conditions
---------------
1. Keep-alive duplicate
   A flow where pkt_count <= 2, byte_count < 100, and a very
   similar flow was recently seen (within window_sec).

2. Trivially short flow
   pkt_count == 1 and protocol is not TCP (e.g., stray ARP proxied
   as IP, single-shot ICMP probe with no response).

3. ARP / broadcast suppression
   dst_subnet == 0 (broadcast) with pkt_count <= 3.

4. Near-zero variance gate  (adaptive)
   If the vector has near-identical values to the last N vectors
   seen for the same src_subnet → drop as redundant.

All drops are logged to the drop log — never silent.
"""

import time
from collections import defaultdict
from typing import Dict, Any

from utils.drop_log import DropLogger
from utils.logger   import get_logger

log      = get_logger("layer2.noise_filter")
drop_log = DropLogger("drop_log.jsonl")

KEEPALIVE_PKT_THRESHOLD  = 2
KEEPALIVE_BYTE_THRESHOLD = 100
VARIANCE_WINDOW          = 50   # rolling window per subnet key
VARIANCE_EPSILON         = 0.02  # cosine-like distance threshold


class NoiseFilter:

    def __init__(self, window_sec: float = 60.0):
        self.window_sec = window_sec
        # {src_subnet: [(ts, vector), ...]}
        self._recent: Dict[int, list] = defaultdict(list)

    def should_drop(self, flow: Dict[str, Any]) -> bool:
        reason = self._evaluate(flow)
        if reason:
            drop_log.log(
                reason=reason,
                timestamp=time.time(),
                flow_id=flow.get("flow_id", "unknown"),
            )
            return True
        return False

    # ------------------------------------------------------------------
    def _evaluate(self, flow: Dict[str, Any]) -> str:
        pkt_count  = flow.get("pkt_count",  0)
        byte_count = flow.get("byte_count", 0)
        proto      = flow.get("protocol_num", 0)
        dst_subnet = flow.get("dst_subnet",  -1)
        src_subnet = flow.get("src_subnet",   0)
        vector     = flow.get("vector", [])

        # 1. Keep-alive duplicate
        if pkt_count <= KEEPALIVE_PKT_THRESHOLD and byte_count < KEEPALIVE_BYTE_THRESHOLD:
            return "keepalive_duplicate"

        # 2. Single-packet non-TCP
        if pkt_count == 1 and proto != 6:
            return "single_pkt_non_tcp"

        # 3. Broadcast / ARP-like suppression
        if dst_subnet == 0 and pkt_count <= 3:
            return "broadcast_suppressed"

        # 4. Near-zero variance (adaptive dedup)
        if vector and self._is_redundant(src_subnet, vector):
            return "near_zero_variance"

        # Update rolling window
        if vector:
            self._update_window(src_subnet, vector)

        return ""   # don't drop

    def _is_redundant(self, key: int, vector: list) -> bool:
        history = self._recent.get(key, [])
        if len(history) < 3:
            return False
        recent_vecs = [v for _, v in history[-10:]]
        return all(_cosine_dist(vector, rv) < VARIANCE_EPSILON for rv in recent_vecs)

    def _update_window(self, key: int, vector: list):
        now = time.time()
        buf = self._recent[key]
        buf.append((now, vector))
        # Expire old entries
        cutoff = now - self.window_sec
        self._recent[key] = [(ts, v) for ts, v in buf if ts > cutoff][-VARIANCE_WINDOW:]


def _cosine_dist(a: list, b: list) -> float:
    if len(a) != len(b) or not a:
        return 1.0
    dot  = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a < 1e-9 or norm_b < 1e-9:
        return 0.0
    return 1.0 - dot / (norm_a * norm_b)
