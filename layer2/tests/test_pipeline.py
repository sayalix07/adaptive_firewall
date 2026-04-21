"""
tests/test_pipeline.py
=======================
Unit tests for all Layer 2 stages.
Run with:
    pytest tests/test_pipeline.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import time


# ──────────────────────────────────────────────
# Stage ②: FeatureExtractor
# ──────────────────────────────────────────────
def test_extractor_basic():
    from stages.extractor import FeatureExtractor
    raw = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
        "src_port": 54321, "dst_port": 53,
        "protocol": 17, "pkt_size": 80, "ttl": 64, "flags": 0,
    }
    fe = FeatureExtractor()
    feat = fe.extract(raw)
    assert feat["protocol_name"] == "UDP"
    assert feat["src_port"] == 54321
    assert feat["flow_key"] == ("192.168.1.10", "8.8.8.8", 54321, 53, 17)


def test_extractor_unknown_protocol():
    from stages.extractor import FeatureExtractor
    raw = {
        "timestamp": 1.0, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
        "src_port": 0, "dst_port": 0, "protocol": 99,
        "pkt_size": 40, "ttl": 128, "flags": 0,
    }
    feat = FeatureExtractor().extract(raw)
    assert feat["protocol_name"] == "OTHER_99"


# ──────────────────────────────────────────────
# Stage ③: FlowStore
# ──────────────────────────────────────────────
def test_flow_store_aggregates():
    from stages.flow_store import FlowStore
    store = FlowStore(timeout_sec=5.0)
    pkt = {
        "flow_key": ("1.1.1.1", "2.2.2.2", 1234, 80, 6),
        "timestamp": 0.0, "pkt_size": 100,
        "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
        "protocol_num": 6, "protocol_name": "TCP", "flags_raw": 2,
        "src_port": 1234, "dst_port": 80,
    }
    for i in range(5):
        pkt2 = dict(pkt, timestamp=float(i), pkt_size=100)
        store.ingest(pkt2)
    flows = store.flush_all()
    assert len(flows) == 1
    assert flows[0]["pkt_count"] == 5
    assert flows[0]["byte_count"] == 500


def test_flow_store_multiple_keys():
    from stages.flow_store import FlowStore
    store = FlowStore(timeout_sec=5.0)
    for i in range(3):
        store.ingest({
            "flow_key": (f"10.0.0.{i}", "2.2.2.2", i*100, 80, 6),
            "timestamp": 0.0, "pkt_size": 50,
            "src_ip": f"10.0.0.{i}", "dst_ip": "2.2.2.2",
            "protocol_num": 6, "protocol_name": "TCP", "flags_raw": 2,
            "src_port": i*100, "dst_port": 80,
        })
    flows = store.flush_all()
    assert len(flows) == 3


# ──────────────────────────────────────────────
# Stage ④: FeatureEngine
# ──────────────────────────────────────────────
def test_feature_engine_derived():
    from stages.feature_engine import FeatureEngine
    flow = {
        "flow_id": "abc", "pkt_count": 10, "byte_count": 1000,
        "src_bytes": 800, "dst_bytes": 200,
        "start_ts": 0.0, "last_ts": 5.0,
        "failed_count": 2,
        "pkt_timestamps": [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0],
    }
    fe = FeatureEngine()
    result = fe.compute(flow)
    assert result["pkt_rate"] == pytest.approx(2.0, rel=0.01)
    assert result["byte_ratio"] == pytest.approx(0.8, rel=0.01)
    assert result["failed_ratio"] == pytest.approx(0.2, rel=0.01)
    assert result["conn_duration_s"] == pytest.approx(5.0, rel=0.01)
    assert "iat_mean_s" in result
    assert "iat_std_s" in result


# ──────────────────────────────────────────────
# Stage ⑤: CategoricalEncoder
# ──────────────────────────────────────────────
def test_encoder_flags():
    from stages.encoder import CategoricalEncoder
    enc = CategoricalEncoder()
    flow = {
        "protocol_num": 6, "protocol_name": "TCP",
        "flags_union": 0x02 | 0x10,  # SYN + ACK
        "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
        "src_port": 54321, "dst_port": 443,
    }
    result = enc.encode(flow)
    assert result["flags_syn"] == 1
    assert result["flags_ack"] == 1
    assert result["flags_fin"] == 0
    assert result["flags_rst"] == 0
    assert result["protocol_enc"] == 6


def test_encoder_unknown_protocol():
    from stages.encoder import CategoricalEncoder
    flow = {
        "protocol_num": 200, "protocol_name": "UNKNOWN",
        "flags_union": 0, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
        "src_port": 0, "dst_port": 0,
    }
    result = CategoricalEncoder().encode(flow)
    assert result["protocol_enc"] == 255


# ──────────────────────────────────────────────
# Stage ⑥: OnlineScaler
# ──────────────────────────────────────────────
def test_scaler_output_range():
    from stages.scaler import OnlineScaler, FEATURE_ORDER
    scaler = OnlineScaler()
    flow = {
        "ttl": 64, "protocol_enc": 6, "src_subnet": 192, "dst_subnet": 10,
        "src_port_norm": 0.83, "dst_port_norm": 0.006,
        "flags_syn": 1, "flags_ack": 0, "flags_fin": 0,
        "flags_rst": 0, "flags_psh": 0, "flags_urg": 0,
        "conn_duration_s": 2.5,
        "pkt_rate": 4.0, "byte_rate": 400.0,
        "iat_mean_s": 0.25, "iat_std_s": 0.1,
        "byte_ratio": 0.75, "failed_ratio": 0.1,
        "pkt_size": 512,
    }
    # Warm up scaler with multiple samples
    for i in range(10):
        varied = dict(flow, pkt_rate=float(i+1), byte_rate=float(i*100))
        result = scaler.scale(varied)

    assert "vector" in result
    assert len(result["vector"]) == len(FEATURE_ORDER)
    for v in result["vector"]:
        assert isinstance(v, float), f"Expected float, got {type(v)}"


# ──────────────────────────────────────────────
# Stage ⑦: NoiseFilter
# ──────────────────────────────────────────────
def test_noise_filter_keepalive():
    from stages.noise_filter import NoiseFilter
    nf = NoiseFilter()
    flow = {"pkt_count": 1, "byte_count": 40, "protocol_num": 6,
            "dst_subnet": 1, "src_subnet": 10, "vector": [0.1]*19,
            "flow_id": "test1"}
    assert nf.should_drop(flow) is True   # single pkt TCP keepalive


def test_noise_filter_normal_flow():
    from stages.noise_filter import NoiseFilter
    nf = NoiseFilter()
    flow = {"pkt_count": 20, "byte_count": 2000, "protocol_num": 6,
            "dst_subnet": 10, "src_subnet": 192, "vector": [0.5]*19,
            "flow_id": "test2"}
    assert nf.should_drop(flow) is False


# ──────────────────────────────────────────────
# Stage ⑧: Emitter
# ──────────────────────────────────────────────
def test_emitter_output_schema():
    from stages.emitter import Emitter, FEATURE_ORDER
    emitter = Emitter()
    flow = {
        "flow_id": "deadbeef1234", "start_ts": 1000.0, "last_ts": 1060.0,
        "pkt_count": 50, "byte_count": 5000,
        "protocol_name": "TCP", "flags_union": 0x12,
        "flags_syn": 1, "flags_ack": 1, "flags_fin": 0,
        "flags_rst": 0, "flags_psh": 0, "flags_urg": 0,
        **{f: 0.5 for f in FEATURE_ORDER},
    }
    record = emitter.emit(flow)
    assert "flow_id"      in record
    assert "vector"       in record
    assert "features"     in record
    assert "meta"         in record
    assert len(record["vector"]) == len(FEATURE_ORDER)
    assert record["meta"]["protocol"] == "TCP"


# ──────────────────────────────────────────────
# Full pipeline smoke test (no scapy required)
# ──────────────────────────────────────────────
def test_pipeline_flush():
    """Integration smoke test: push raw field dicts through the pipeline."""
    from pipeline import PreprocessingPipeline

    pipeline = PreprocessingPipeline(flow_timeout_sec=1.0)

    # Simulate 10 packets for one flow via internal path
    from stages.extractor import FeatureExtractor
    fe = FeatureExtractor()

    raw_base = {
        "timestamp": 0.0, "src_ip": "192.168.1.5", "dst_ip": "93.184.216.34",
        "src_port": 55000, "dst_port": 443, "protocol": 6,
        "pkt_size": 200, "ttl": 64, "flags": 0x02,
    }
    for i in range(10):
        raw = dict(raw_base, timestamp=float(i) * 0.2)
        features = fe.extract(raw)
        pipeline.flow_store.ingest(features)

    records = pipeline.flush()
    assert len(records) == 1
    rec = records[0]
    assert rec["meta"]["pkt_count"] == 10
    assert len(rec["vector"]) == 19
