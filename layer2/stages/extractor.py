"""
stages/extractor.py — Stage ②: Raw Feature Extraction
=======================================================
Takes the raw field dict from the validator and produces a
clean, typed feature dict ready for flow aggregation.

No ML transformations here — just safe parsing and typing.
Payload bytes are intentionally NOT stored.
"""

from typing import Dict, Any
from utils.logger import get_logger

log = get_logger("layer2.extractor")

# Protocol number → name mapping (RFC 790)
PROTO_MAP = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    132: "SCTP",
}


class FeatureExtractor:
    """
    Converts a raw field dict into a normalized feature dict.
    All values are primitive Python types (int, float, str).
    """

    def extract(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not raw:
            return {}

        proto_num  = raw.get("protocol", 0)
        proto_name = PROTO_MAP.get(proto_num, f"OTHER_{proto_num}")

        features = {
            # Identity
            "timestamp":   float(raw.get("timestamp", 0.0)),
            "src_ip":      raw.get("src_ip",   "0.0.0.0"),
            "dst_ip":      raw.get("dst_ip",   "0.0.0.0"),
            "src_port":    int(raw.get("src_port",  0)),
            "dst_port":    int(raw.get("dst_port",  0)),
            # Network
            "protocol_num":  proto_num,
            "protocol_name": proto_name,
            "pkt_size":      int(raw.get("pkt_size", 0)),
            "ttl":           int(raw.get("ttl", 0)),
            # TCP flags as raw int (decoded in encoder stage)
            "flags_raw":     int(raw.get("flags", 0)),
            # 5-tuple flow key (used by FlowStore)
            "flow_key": (
                raw.get("src_ip"),
                raw.get("dst_ip"),
                raw.get("src_port"),
                raw.get("dst_port"),
                proto_num,
            ),
        }
        return features
