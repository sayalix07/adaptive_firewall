# layer1/capture.py
# ─────────────────────────────────────────────────────────────────────────────
# Packet Capture Engine
#
# Runs a Scapy sniffer in a background daemon thread.
# Every raw packet goes through the parser, then the flow aggregator.
# Completed flows are pushed to the FlowQueue for Layer 2 to consume.
#
# Threading model
# ───────────────
#   Main thread   →  start() / stop()
#   Sniffer thread →  _run()  (daemon — dies automatically if main exits)
#
# The sniffer thread never blocks the main thread. The stop_filter lambda
# lets Scapy's internal loop check the _stop_event on every packet so we
# can exit cleanly without killing the process.
# ─────────────────────────────────────────────────────────────────────────────

import threading
from dataclasses import dataclass, field

from scapy.all import sniff

from .parser        import parse_packet
from .flow          import FlowAggregator
from .queue_manager import FlowQueue


@dataclass
class CaptureStats:
    packets_seen:   int = 0
    packets_parsed: int = 0
    flows_emitted:  int = 0
    parse_errors:   int = 0


class PacketCaptureEngine:
    """
    Full Layer 1 engine: sniff → parse → aggregate → queue.

    Parameters
    ----------
    interface    : str        Network interface to sniff on (e.g. "eth0")
    flow_queue   : FlowQueue  Output queue shared with Layer 2
    flow_timeout : int        Seconds of idle time before a flow is finalised
    bpf_filter   : str | None Optional BPF filter string (e.g. "tcp port 80")
    """

    def __init__(
        self,
        interface:    str,
        flow_queue:   FlowQueue,
        flow_timeout: int = 10,
        bpf_filter:   str | None = None,
    ):
        self.interface    = interface
        self.flow_queue   = flow_queue
        self.bpf_filter   = bpf_filter
        self.stats        = CaptureStats()

        self._aggregator  = FlowAggregator(timeout_seconds=flow_timeout)
        self._stop_event  = threading.Event()
        self._thread      = threading.Thread(
            target=self._run,
            name="layer1-sniffer",
            daemon=True,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Start the background sniffer thread."""
        print(f"[Layer1] Capture starting on '{self.interface}'"
              + (f"  filter='{self.bpf_filter}'" if self.bpf_filter else ""))
        self._thread.start()

    def stop(self):
        """
        Signal the sniffer to stop, flush all open flows, and wait for the
        thread to exit.
        """
        print("[Layer1] Stopping capture…")
        self._stop_event.set()

        # Flush every still-open flow so nothing is lost on shutdown
        for flow in self._aggregator.flush_all():
            if flow:
                self._emit(flow)

        self._thread.join(timeout=8)
        print(f"[Layer1] Stopped.  {self._stats_summary()}")

    @property
    def is_running(self) -> bool:
        return self._thread.is_alive()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self):
        """Entry point for the sniffer thread."""
        sniff(
            iface=self.interface,
            filter=self.bpf_filter or "",
            prn=self._on_packet,
            store=False,                                    # never buffer in RAM
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _on_packet(self, pkt):
        """Callback invoked by Scapy for every captured packet."""
        self.stats.packets_seen += 1

        try:
            record = parse_packet(pkt)
        except Exception:
            self.stats.parse_errors += 1
            return

        if record is None:
            return                      # non-IP packet — skip

        self.stats.packets_parsed += 1

        completed_flow = self._aggregator.add_packet(record)
        if completed_flow:
            self._emit(completed_flow)

    def _emit(self, flow: dict):
        """Push a completed flow to the output queue."""
        enqueued = self.flow_queue.put_flow(flow)
        if enqueued:
            self.stats.flows_emitted += 1

    def _stats_summary(self) -> str:
        s = self.stats
        return (
            f"packets_seen={s.packets_seen}  "
            f"parsed={s.packets_parsed}  "
            f"flows_emitted={s.flows_emitted}  "
            f"errors={s.parse_errors}"
        )
