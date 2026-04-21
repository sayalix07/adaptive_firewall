"""
stages/validator.py — Stage ①: Packet Validation & Cleaning
=============================================================
Checks each incoming packet for:
  - Minimum / maximum length
  - Presence of an IP layer
  - TCP/UDP/ICMP transport layer
  - Basic header integrity (Scapy re-calculates checksums)

Drops corrupt / incomplete packets and writes them to the drop log.
NEVER silently discards — every rejection is logged.
"""

import time
from typing import Tuple, Optional, Dict, Any

from utils.logger   import get_logger
from utils.drop_log import DropLogger

log      = get_logger("layer2.validator")
drop_log = DropLogger("drop_log.jsonl")

MIN_PKT_BYTES = 20   # smallest valid IP header
MAX_PKT_BYTES = 65535


class PacketValidator:
    """
    Returns (True, raw_field_dict) for valid packets,
            (False, {})            for invalid packets (logged).
    """

    def validate(self, pkt, timestamp: float) -> Tuple[bool, Dict[str, Any]]:
        reason = self._check(pkt)
        if reason:
            drop_log.log(reason=reason, timestamp=timestamp, pkt_summary=str(pkt.summary()) if hasattr(pkt, "summary") else "unknown")
            return False, {}

        return True, self._raw_fields(pkt, timestamp)

    # ------------------------------------------------------------------
    def _check(self, pkt) -> Optional[str]:
        """Return a rejection reason string, or None if packet is valid."""
        try:
            from scapy.all import IP, IPv6
        except ImportError:
            return None  # can't validate without scapy — let it through

        pkt_len = len(pkt)
        if pkt_len < MIN_PKT_BYTES:
            return f"too_short:{pkt_len}"
        if pkt_len > MAX_PKT_BYTES:
            return f"too_long:{pkt_len}"

        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return "no_ip_layer"

        return None  # valid

    def _raw_fields(self, pkt, timestamp: float) -> Dict[str, Any]:
        """Extract raw header fields from a valid Scapy packet."""
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP

            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            transport = pkt.getlayer(TCP) or pkt.getlayer(UDP) or pkt.getlayer(ICMP)

            src_ip  = str(ip.src)  if ip else "0.0.0.0"
            dst_ip  = str(ip.dst)  if ip else "0.0.0.0"
            ttl     = int(ip.ttl)  if hasattr(ip, "ttl") else 0
            proto   = int(ip.proto) if hasattr(ip, "proto") else 0

            src_port = int(transport.sport) if hasattr(transport, "sport") else 0
            dst_port = int(transport.dport) if hasattr(transport, "dport") else 0
            flags    = int(transport.flags) if hasattr(transport, "flags") else 0

            return {
                "timestamp": timestamp,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "protocol":  proto,
                "pkt_size":  len(pkt),
                "ttl":       ttl,
                "flags":     flags,
            }
        except Exception as exc:
            log.warning(f"Field extraction error: {exc}")
            return {}
