"""
stages/emitter.py — Stage ⑧: Structured Output Formatter
==========================================================
Assembles the final JSON record that is forwarded to Layer 3
(the ML detection model).

Output schema
-------------
{
  "flow_id":      str   — 16-char hex flow identifier
  "window_start": float — flow start Unix timestamp
  "window_end":   float — flow end   Unix timestamp
  "meta": {
      "pkt_count":     int
      "byte_count":    int
      "protocol":      str   — e.g. "TCP"
      "flags_summary": str   — e.g. "SYN|ACK"
  },
  "features": {          — named float values for human readability
      "src_subnet":  float,
      ...
  },
  "vector": [float, ...]  — fixed-length float32 list for model input
}

Layer 3 should consume ONLY `vector` for inference.
`features` and `meta` are for logging, debugging, and explainability.

NO security judgement is made here — this module is output-only.
"""

from typing import Dict, Any, List
from utils.logger import get_logger

log = get_logger("layer2.emitter")

FEATURE_ORDER: List[str] = [
    "src_subnet", "dst_subnet",
    "src_port_norm", "dst_port_norm",
    "protocol_enc",
    "pkt_size_norm",
    "ttl_norm",
    "flags_syn", "flags_ack", "flags_fin", "flags_rst", "flags_psh", "flags_urg",
    "pkt_rate_norm",
    "byte_ratio",
    "conn_duration_norm",
    "failed_ratio",
    "iat_mean_norm",
    "iat_std_norm",
]

FLAG_NAMES = {
    "flags_syn": "SYN",
    "flags_ack": "ACK",
    "flags_fin": "FIN",
    "flags_rst": "RST",
    "flags_psh": "PSH",
    "flags_urg": "URG",
}


class Emitter:

    def emit(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        vector = [round(float(flow.get(f, 0.0)), 6) for f in FEATURE_ORDER]

        features = {f: vector[i] for i, f in enumerate(FEATURE_ORDER)}

        flags_set = [name for key, name in FLAG_NAMES.items() if flow.get(key, 0)]
        flags_summary = "|".join(flags_set) if flags_set else "NONE"

        record = {
            "flow_id":      flow.get("flow_id", "unknown"),
            "window_start": round(float(flow.get("start_ts", 0)), 3),
            "window_end":   round(float(flow.get("last_ts",  0)), 3),
            "meta": {
                "pkt_count":     flow.get("pkt_count", 0),
                "byte_count":    flow.get("byte_count", 0),
                "protocol":      flow.get("protocol_name", "UNKNOWN"),
                "flags_summary": flags_summary,
            },
            "features":     features,
            "vector":       vector,
        }

        log.debug(f"Emitted flow {record['flow_id']} | {record['meta']['protocol']} | {record['meta']['pkt_count']} pkts")
        return record
