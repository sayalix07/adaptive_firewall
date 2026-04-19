#!/usr/bin/env python3
# main.py
# ─────────────────────────────────────────────────────────────────────────────
# ML-Powered Adaptive Firewall — Phase 1 Entry Point
#
# Runs Layer 1 (packet capture) and prints completed flow records to the
# terminal. This is the test harness for Phase 1; later phases will import
# PacketCaptureEngine and FlowQueue directly instead of using main.py.
#
# Usage
# ─────
#   sudo python main.py                    # auto-detect interface
#   sudo python main.py --iface eth0       # specify interface
#   sudo python main.py --iface eth0 --duration 60 --timeout 5
#
# Requires root / Administrator for raw socket access.
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import json
import signal
import sys
import time

from colorama import Fore, Style, init

from layer1.capture       import PacketCaptureEngine
from layer1.queue_manager import FlowQueue

init(autoreset=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Adaptive Firewall — Phase 1: Live packet capture",
    )
    p.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface to sniff on (default: auto-detect)",
    )
    p.add_argument(
        "--duration", "-d",
        type=int,
        default=60,
        help="Capture duration in seconds (default: 60, 0 = run until Ctrl+C)",
    )
    p.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Flow idle timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--filter", "-f",
        default=None,
        dest="bpf",
        help="BPF filter string e.g. 'tcp port 80' (default: capture all)",
    )
    p.add_argument(
        "--queue-size",
        type=int,
        default=1000,
        help="Max flows buffered in memory (default: 1000)",
    )
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Print raw JSON only — no colour headers (for piping to files)",
    )
    return p.parse_args()


# ── Interface detection ───────────────────────────────────────────────────────

def detect_interface() -> str:
    """
    Return the first non-loopback active interface Scapy can see.
    Falls back to 'eth0' if detection fails.
    """
    try:
        from scapy.arch import get_if_list
        candidates = [i for i in get_if_list() if i != "lo"]
        if candidates:
            return candidates[0]
    except Exception:
        pass
    return "eth0"


# ── Pretty printer ────────────────────────────────────────────────────────────

PROTO_COLOUR = {
    "TCP":  Fore.CYAN,
    "UDP":  Fore.YELLOW,
    "ICMP": Fore.MAGENTA,
}

def print_flow(flow: dict, json_only: bool = False):
    if json_only:
        print(json.dumps(flow))
        return

    proto  = flow.get("protocol", "?")
    colour = PROTO_COLOUR.get(proto, Fore.WHITE)

    header = (
        f"{colour}[FLOW]{Style.RESET_ALL} "
        f"{Fore.GREEN}{flow.get('src_ip','?')}:{flow.get('src_port','?')}{Style.RESET_ALL}"
        f"  →  "
        f"{Fore.RED}{flow.get('dst_ip','?')}:{flow.get('dst_port','?')}{Style.RESET_ALL}"
        f"  {colour}{proto}{Style.RESET_ALL}"
        f"  pkts={flow.get('packet_count','?')}"
        f"  bytes={flow.get('total_bytes','?')}"
        f"  dur={flow.get('duration_sec','?')}s"
        f"  pps={flow.get('pkts_per_sec','?')}"
    )
    if flow.get("unique_flags"):
        header += f"  flags={flow['unique_flags']}"

    print(header)


def print_queue_stats(flow_queue: FlowQueue, engine: PacketCaptureEngine):
    s  = engine.stats
    qs = flow_queue.stats
    print(
        f"\n{Fore.WHITE}── Stats ──────────────────────────────────────{Style.RESET_ALL}\n"
        f"  Packets seen:    {s.packets_seen}\n"
        f"  Packets parsed:  {s.packets_parsed}\n"
        f"  Flows emitted:   {s.flows_emitted}\n"
        f"  Parse errors:    {s.parse_errors}\n"
        f"  Queue dropped:   {qs.dropped}\n"
        f"  Active flows:    {engine._aggregator.active_flow_count}\n"
        f"{Fore.WHITE}───────────────────────────────────────────────{Style.RESET_ALL}"
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    args      = parse_args()
    iface     = args.iface or detect_interface()
    run_until = time.time() + args.duration if args.duration > 0 else None

    print(
        f"\n{Fore.CYAN}━━━ Adaptive Firewall — Phase 1: Packet Capture ━━━{Style.RESET_ALL}\n"
        f"  Interface : {iface}\n"
        f"  Duration  : {'until Ctrl+C' if run_until is None else f'{args.duration}s'}\n"
        f"  Timeout   : {args.timeout}s per flow\n"
        f"  BPF filter: {args.bpf or 'none (capture all)'}\n"
    )

    flow_queue = FlowQueue(maxsize=args.queue_size)
    engine     = PacketCaptureEngine(
        interface=iface,
        flow_queue=flow_queue,
        flow_timeout=args.timeout,
        bpf_filter=args.bpf,
    )

    # Graceful Ctrl+C
    def _handle_sigint(sig, frame):
        print(f"\n{Fore.YELLOW}[Main] Interrupt received — shutting down…{Style.RESET_ALL}")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _handle_sigint)

    engine.start()
    print(f"{Fore.GREEN}[Main] Capture running. Waiting for flows…{Style.RESET_ALL}\n")

    flow_count = 0
    try:
        while True:
            # Check duration limit
            if run_until and time.time() >= run_until:
                print(f"\n{Fore.YELLOW}[Main] Duration reached.{Style.RESET_ALL}")
                break

            flow = flow_queue.get_flow(timeout=1.0)
            if flow:
                flow_count += 1
                print_flow(flow, json_only=args.json_only)

    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        print_queue_stats(flow_queue, engine)
        print(f"\n{Fore.CYAN}[Main] Total flows printed: {flow_count}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
