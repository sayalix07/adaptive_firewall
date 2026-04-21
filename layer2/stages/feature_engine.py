"""
stages/feature_engine.py — Stage ④: Derived Feature Computation
=================================================================
Computes higher-order, per-flow features from aggregated flow data.

Features computed
-----------------
pkt_rate          packets / second
byte_rate         bytes / second
byte_ratio        src_bytes / (src_bytes + dst_bytes)  [0..1]
conn_duration_s   last_ts - start_ts
failed_ratio      failed_count / pkt_count
iat_mean_s        mean inter-arrival time in seconds
iat_std_s         std  inter-arrival time in seconds

All features are carefully guarded for divide-by-zero.
No ML transforms are applied here (that is Stage ⑥).
"""

import statistics
from typing import Dict, Any

from utils.logger import get_logger

log = get_logger("layer2.feature_engine")


class FeatureEngine:

    def compute(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(flow)  # start with a copy

        pkt_count  = max(flow.get("pkt_count",  1), 1)
        byte_count = max(flow.get("byte_count", 0), 0)
        src_bytes  = flow.get("src_bytes", 0)
        dst_bytes  = flow.get("dst_bytes", 0)
        start_ts   = flow.get("start_ts",  0.0)
        last_ts    = flow.get("last_ts",   0.0)
        failed     = flow.get("failed_count", 0)

        duration = max(last_ts - start_ts, 1e-6)

        result["pkt_rate"]       = round(pkt_count  / duration, 4)
        result["byte_rate"]      = round(byte_count / duration, 4)
        result["conn_duration_s"]= round(duration, 4)

        total_dir = src_bytes + dst_bytes
        result["byte_ratio"] = round(src_bytes / total_dir, 4) if total_dir > 0 else 0.5

        result["failed_ratio"] = round(failed / pkt_count, 4)

        timestamps = flow.get("pkt_timestamps", [])
        if len(timestamps) >= 2:
            iats = [
                round(timestamps[i+1] - timestamps[i], 6)
                for i in range(len(timestamps) - 1)
                if timestamps[i+1] > timestamps[i]
            ]
            if iats:
                result["iat_mean_s"] = round(statistics.mean(iats), 6)
                result["iat_std_s"]  = round(statistics.pstdev(iats), 6) if len(iats) > 1 else 0.0
            else:
                result["iat_mean_s"] = 0.0
                result["iat_std_s"]  = 0.0
        else:
            result["iat_mean_s"] = 0.0
            result["iat_std_s"]  = 0.0

        return result
