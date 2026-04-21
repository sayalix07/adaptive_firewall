"""
stages/scaler.py — Stage ⑥: Scaling and Normalisation
=======================================================
Applies online (incremental) scaling to numerical features so
the downstream ML model receives a consistent [0..1] input range.

Strategy per feature
--------------------
MinMaxScaler  — bounded features: TTL (0-255), ports, flag bits, subnet
RobustScaler  — rate-based features: pkt_rate, byte_rate, iat_*
                (robust to outliers / bursty traffic)
PassThrough   — ratio features already in [0..1]: byte_ratio, failed_ratio

scikit-learn's StandardScaler / MinMaxScaler support partial_fit()
so we can update statistics online without reprocessing all history.
"""

from typing import Dict, Any, List
import numpy as np
from utils.logger import get_logger

log = get_logger("layer2.scaler")

# Feature groups
MINMAX_FEATURES = [
    "ttl", "protocol_enc",
    "src_subnet", "dst_subnet",
    "src_port_norm", "dst_port_norm",
    "flags_syn", "flags_ack", "flags_fin",
    "flags_rst", "flags_psh", "flags_urg",
    "conn_duration_s",
]

ROBUST_FEATURES = [
    "pkt_rate", "byte_rate",
    "iat_mean_s", "iat_std_s",
]

PASSTHROUGH_FEATURES = [
    "byte_ratio", "failed_ratio",
]

ALL_SCALED = MINMAX_FEATURES + ROBUST_FEATURES + PASSTHROUGH_FEATURES

# Output feature order (fixed 19-element vector for ML layer)
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


class OnlineScaler:
    """
    Maintains running min/max and median/IQR statistics for online scaling.
    Designed for streaming — no batch fitting required.
    """

    def __init__(self):
        # MinMax state: {feature: [min, max]}
        self._mm: Dict[str, list] = {}
        # Robust state: {feature: [p25, p75, median]}  (approximated with a window)
        self._rb_window: Dict[str, list] = {f: [] for f in ROBUST_FEATURES}
        self._rb_window_size = 1000

    def scale(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(flow)

        # --- MinMax ---
        for feat in MINMAX_FEATURES:
            val = float(flow.get(feat, 0))
            if feat not in self._mm:
                self._mm[feat] = [val, val]
            mn, mx = self._mm[feat]
            mn = min(mn, val)
            mx = max(mx, val)
            self._mm[feat] = [mn, mx]
            result[feat + "_norm"] = _minmax(val, mn, mx)

        # --- Robust ---
        for feat in ROBUST_FEATURES:
            val = float(flow.get(feat, 0))
            buf = self._rb_window[feat]
            buf.append(val)
            if len(buf) > self._rb_window_size:
                buf.pop(0)
            result[feat + "_norm"] = _robust_scale(val, buf)

        # --- Passthrough (already [0..1]) ---
        for feat in PASSTHROUGH_FEATURES:
            result[feat] = float(flow.get(feat, 0))

        # Build canonical feature names used in FEATURE_ORDER
        result["pkt_size_norm"]      = _minmax(float(flow.get("pkt_size", 0)), 0, 65535)
        result["ttl_norm"]           = result.get("ttl_norm",           0.0)
        result["pkt_rate_norm"]      = result.get("pkt_rate_norm",      0.0)
        result["conn_duration_norm"] = result.get("conn_duration_s_norm", 0.0)
        result["iat_mean_norm"]      = result.get("iat_mean_s_norm",    0.0)
        result["iat_std_norm"]       = result.get("iat_std_s_norm",     0.0)

        # Assemble final float32 vector
        result["vector"] = [
            round(float(result.get(f, 0.0)), 6) for f in FEATURE_ORDER
        ]

        return result


# ------------------------------------------------------------------
def _minmax(val: float, mn: float, mx: float) -> float:
    rng = mx - mn
    if rng < 1e-9:
        return 0.0
    return round(max(0.0, min(1.0, (val - mn) / rng)), 6)


def _robust_scale(val: float, buf: list) -> float:
    if len(buf) < 4:
        return 0.0
    sorted_buf = sorted(buf)
    n = len(sorted_buf)
    p25 = sorted_buf[n // 4]
    p75 = sorted_buf[3 * n // 4]
    median = sorted_buf[n // 2]
    iqr = p75 - p25
    if iqr < 1e-9:
        return 0.0
    scaled = (val - median) / iqr
    # Clip to [-3, 3] then remap to [0, 1]
    clipped = max(-3.0, min(3.0, scaled))
    return round((clipped + 3.0) / 6.0, 6)
