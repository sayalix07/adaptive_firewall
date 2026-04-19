# Adaptive Firewall — Phase 1: Packet Capture Engine

## Project structure

```
adaptive_firewall/
├── layer1/
│   ├── __init__.py        # Package exports
│   ├── capture.py         # Sniffer thread (ties everything together)
│   ├── parser.py          # Raw packet → structured dict
│   ├── flow.py            # Packet dicts → completed flow records
│   └── queue_manager.py   # Thread-safe queue between L1 and L2
├── main.py                # Entry point / test harness
├── requirements.txt
└── README.md
```

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Find your network interface

```bash
# Linux / Mac
ip a
ifconfig

# Windows
ipconfig
```

Common values: `eth0`, `wlan0`, `en0`, `ens33`

---

## Running

> Raw packet capture always requires root (Linux/Mac) or Administrator (Windows).

### Quick start — auto-detect interface, run for 60 seconds

```bash
sudo python main.py
```

### Specify interface

```bash
sudo python main.py --iface eth0
```

### Full options

```bash
sudo python main.py \
  --iface eth0 \       # network interface
  --duration 120 \     # seconds to run (0 = until Ctrl+C)
  --timeout 10 \       # flow idle timeout in seconds
  --filter "tcp" \     # optional BPF filter
  --queue-size 2000    # max flows buffered in memory
```

### Run until Ctrl+C

```bash
sudo python main.py --duration 0
```

### Capture only TCP traffic to port 80

```bash
sudo python main.py --iface eth0 --filter "tcp port 80"
```

### Pipe raw JSON to a file

```bash
sudo python main.py --json-only > flows.json
```

---

## Sample output

```
━━━ Adaptive Firewall — Phase 1: Packet Capture ━━━
  Interface : eth0
  Duration  : 60s
  Timeout   : 10s per flow
  BPF filter: none (capture all)

[Layer1] Capture starting on 'eth0'
[Main] Capture running. Waiting for flows…

[FLOW] 192.168.1.5:52341  →  142.250.77.46:443   TCP  pkts=14  bytes=9820  dur=3.42s  pps=4.09  flags=['S', 'SA', 'A', 'FA']
[FLOW] 192.168.1.5:52342  →  8.8.8.8:53          UDP  pkts=2   bytes=168   dur=0.012s pps=166.7
[FLOW] 192.168.1.5:52343  →  104.21.3.55:443     TCP  pkts=31  bytes=44200 dur=8.11s  pps=3.82  flags=['S', 'SA', 'A']

── Stats ──────────────────────────────────────
  Packets seen:    847
  Packets parsed:  831
  Flows emitted:   3
  Parse errors:    0
  Queue dropped:   0
  Active flows:    12
───────────────────────────────────────────────
```

---

## What each flow record contains

| Field | Description |
|---|---|
| `src_ip` / `dst_ip` | Source and destination IP addresses |
| `src_port` / `dst_port` | Ports (null for ICMP) |
| `protocol` | TCP / UDP / ICMP |
| `packet_count` | Number of packets in the flow |
| `total_bytes` | Total bytes transferred |
| `avg_pkt_size` | Mean packet size in bytes |
| `min_pkt_size` / `max_pkt_size` | Size range |
| `duration_sec` | Flow lifetime in seconds |
| `pkts_per_sec` | Packet rate |
| `bytes_per_sec` | Throughput |
| `unique_flags` | Set of TCP flag strings seen (e.g. `["S","SA","FA"]`) |
| `start_time` / `end_time` | ISO timestamps |

These fields are the raw input to **Phase 2 (Feature Engineering)**.

---

## Next phase

Phase 2 will consume flows from the queue and compute ML-ready features:
- SYN/ACK ratio (detects SYN floods)
- Port diversity score (detects port scans)
- Payload entropy (detects encrypted C2 traffic)
- Bytes-per-packet variance
