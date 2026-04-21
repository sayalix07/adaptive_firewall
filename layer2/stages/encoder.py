"""
stages/encoder.py — Stage ⑤: Categorical Encoding
====================================================
Converts non-numeric fields to numbers that an ML model can consume.

Encoding scheme
---------------
protocol_enc      int  — well-known protocol integer (TCP=6, UDP=17, …)
                         unknown protocols map to 255
flags_syn         int  — 1 if SYN bit set, else 0
flags_ack         int  — 1 if ACK bit set, else 0
flags_fin         int  — 1 if FIN bit set, else 0
flags_rst         int  — 1 if RST bit set, else 0
flags_psh         int  — 1 if PSH bit set, else 0
flags_urg         int  — 1 if URG bit set, else 0
src_subnet        int  — /24 octet of src_ip (last-octet stripped)
dst_subnet        int  — /24 octet of dst_ip
src_port_norm     float— src_port / 65535  → [0..1]
dst_port_norm     float— dst_port / 65535  → [0..1]

Raw IP strings and port integers are NOT forwarded to avoid raw-IP
leakage into the model (which could cause spurious correlations).
"""

from typing import Dict, Any
from utils.logger import get_logger

log = get_logger("layer2.encoder")

# TCP flag bitmask positions (RFC 793)
FLAG_URG = 0x20
FLAG_ACK = 0x10
FLAG_PSH = 0x08
FLAG_RST = 0x04
FLAG_SYN = 0x02
FLAG_FIN = 0x01

KNOWN_PROTOCOLS = {1, 6, 17, 47, 50, 51, 58, 132}


class CategoricalEncoder:

    def encode(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        result = {k: v for k, v in flow.items()
                  if k not in ("src_ip", "dst_ip", "src_port", "dst_port",
                                "protocol_name", "flow_key", "pkt_timestamps")}

        # Protocol
        proto = flow.get("protocol_num", 0)
        result["protocol_enc"] = proto if proto in KNOWN_PROTOCOLS else 255

        # TCP flags (union of all flags seen in the flow)
        flags = flow.get("flags_union", 0)
        result["flags_syn"] = int(bool(flags & FLAG_SYN))
        result["flags_ack"] = int(bool(flags & FLAG_ACK))
        result["flags_fin"] = int(bool(flags & FLAG_FIN))
        result["flags_rst"] = int(bool(flags & FLAG_RST))
        result["flags_psh"] = int(bool(flags & FLAG_PSH))
        result["flags_urg"] = int(bool(flags & FLAG_URG))

        # IP → /24 subnet integer
        result["src_subnet"] = _ip_to_subnet_int(flow.get("src_ip", "0.0.0.0"))
        result["dst_subnet"] = _ip_to_subnet_int(flow.get("dst_ip", "0.0.0.0"))

        # Port normalisation
        result["src_port_norm"] = round(flow.get("src_port", 0) / 65535, 5)
        result["dst_port_norm"] = round(flow.get("dst_port", 0) / 65535, 5)

        return result


def _ip_to_subnet_int(ip: str) -> int:
    """Return the first octet of an IPv4 address as a class-A subnet proxy."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            # Use first two octets as a /16 integer proxy
            return int(parts[0]) * 256 + int(parts[1])
    except Exception:
        pass
    return 0
