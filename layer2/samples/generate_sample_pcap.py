"""
samples/generate_sample_pcap.py
================================
Generates a synthetic sample.pcap with mixed traffic for testing Layer 2
without needing a live network interface.

Run:
    python samples/generate_sample_pcap.py
    # produces samples/sample.pcap
"""

import os
import random
import time

def main():
    try:
        from scapy.all import (
            Ether, IP, TCP, UDP, ICMP, Raw,
            wrpcap, RandShort, RandIP,
        )
    except ImportError:
        print("scapy not installed — run: pip install scapy")
        return

    os.makedirs("samples", exist_ok=True)
    packets = []
    base_ts = time.time() - 120

    # --- Normal HTTP flows ---
    for i in range(30):
        src = f"192.168.1.{random.randint(2, 50)}"
        dst = "93.184.216.34"   # example.com
        sport = random.randint(40000, 60000)
        ts = base_ts + i * 0.4

        # SYN
        pkt = Ether() / IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=80, flags="S")
        pkt.time = ts
        packets.append(pkt)

        # SYN-ACK
        pkt2 = Ether() / IP(src=dst, dst=src, ttl=56) / TCP(sport=80, dport=sport, flags="SA")
        pkt2.time = ts + 0.01
        packets.append(pkt2)

        # ACK + data
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt3 = Ether() / IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=80, flags="PA") / Raw(payload)
        pkt3.time = ts + 0.02
        packets.append(pkt3)

    # --- UDP DNS queries ---
    for i in range(20):
        src = f"10.0.0.{random.randint(2, 30)}"
        pkt = Ether() / IP(src=src, dst="8.8.8.8", ttl=64) / UDP(sport=random.randint(1024, 65535), dport=53) / Raw(b"\x00" * 28)
        pkt.time = base_ts + i * 1.2
        packets.append(pkt)

    # --- ICMP pings ---
    for i in range(10):
        src = f"172.16.0.{random.randint(1,20)}"
        pkt = Ether() / IP(src=src, dst="192.168.1.1", ttl=128) / ICMP()
        pkt.time = base_ts + i * 3.0
        packets.append(pkt)

    # --- Simulated SYN scan (many RST responses) ---
    attacker = "203.0.113.99"
    for port in range(22, 42):
        pkt = Ether() / IP(src=attacker, dst="192.168.1.10", ttl=45) / TCP(sport=54321, dport=port, flags="S")
        pkt.time = base_ts + 50 + port * 0.05
        packets.append(pkt)

        rst = Ether() / IP(src="192.168.1.10", dst=attacker, ttl=64) / TCP(sport=port, dport=54321, flags="R")
        rst.time = base_ts + 50 + port * 0.05 + 0.005
        packets.append(rst)

    wrpcap("samples/sample.pcap", packets)
    print(f"Written {len(packets)} packets → samples/sample.pcap")


if __name__ == "__main__":
    main()
