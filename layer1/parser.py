# layer1/parser.py
# ─────────────────────────────────────────────────────────────────────────────
# Packet Parser
# Receives a raw Scapy packet and returns a structured dict of fields.
# Returns None for non-IP packets (ARP, LLDP, etc.) which we skip.
# ─────────────────────────────────────────────────────────────────────────────

from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP, UDP, ICMP


def parse_packet(pkt) -> dict | None:
    """
    Extract structured fields from a raw Scapy packet.

    Returns
    -------
    dict  — parsed packet record with IP/transport layer fields
    None  — if the packet has no IP layer (skip silently)
    """
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip":    ip.src,
        "dst_ip":    ip.dst,
        "protocol":  _protocol_name(ip.proto),
        "length":    len(pkt),          # total packet size in bytes
        "ttl":       ip.ttl,
        "src_port":  None,
        "dst_port":  None,
        "tcp_flags": None,
    }

    # ── TCP ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record["src_port"]  = tcp.sport
        record["dst_port"]  = tcp.dport
        record["tcp_flags"] = str(tcp.flags)   # e.g. "S", "SA", "FA", "R"
        record["protocol"]  = "TCP"

    # ── UDP ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record["src_port"] = udp.sport
        record["dst_port"] = udp.dport
        record["protocol"] = "UDP"

    # ── ICMP ─────────────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"

    return record


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

def _protocol_name(proto_num: int) -> str:
    return _PROTO_MAP.get(proto_num, f"PROTO_{proto_num}")
