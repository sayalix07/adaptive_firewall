"""
ML Firewall — Layer 2: Preprocessing & Feature Engineering
===========================================================
Entry point. Reads raw packets from Layer 1 (Kafka or a PCAP file),
runs the full preprocessing pipeline, and emits structured feature
vectors to stdout / an output Kafka topic.

Usage:
    # From PCAP file (no Kafka needed):
    python main.py --mode pcap --file samples/sample.pcap

    # From Kafka (Layer 1 → Layer 2 live):
    python main.py --mode kafka \
        --broker localhost:9092 \
        --in-topic  layer1_raw_packets \
        --out-topic layer2_feature_vectors
"""

import argparse
import json
import sys
import time

from pipeline import PreprocessingPipeline
from utils.logger import get_logger

log = get_logger("layer2.main")


def run_pcap(args):
    """Process a PCAP file — no Kafka dependency needed."""
    try:
        from scapy.all import rdpcap
    except ImportError:
        log.error("scapy not installed — run: pip install scapy")
        sys.exit(1)

    pipeline = PreprocessingPipeline()
    packets = rdpcap(args.file)
    log.info(f"Loaded {len(packets)} packets from {args.file}")

    emitted = 0
    for pkt in packets:
        records = pipeline.process_packet(pkt, timestamp=time.time())
        for record in records:
            print(json.dumps(record))
            emitted += 1

    # Flush remaining open flows
    for record in pipeline.flush():
        print(json.dumps(record))
        emitted += 1

    log.info(f"Emitted {emitted} feature vectors")


def run_kafka(args):
    """Consume raw packets from Layer 1 Kafka topic, emit to output topic."""
    try:
        from confluent_kafka import Consumer, Producer, KafkaException
    except ImportError:
        log.error("confluent-kafka not installed — run: pip install confluent-kafka")
        sys.exit(1)

    consumer = Consumer({
        "bootstrap.servers": args.broker,
        "group.id": "layer2-preprocessing",
        "auto.offset.reset": "latest",
    })
    producer = Producer({"bootstrap.servers": args.broker})
    consumer.subscribe([args.in_topic])

    pipeline = PreprocessingPipeline()
    log.info(f"Consuming from {args.in_topic} → emitting to {args.out_topic}")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                raise KafkaException(msg.error())

            raw = msg.value()
            records = pipeline.process_raw_bytes(raw, timestamp=time.time())
            for record in records:
                producer.produce(
                    args.out_topic,
                    key=record["flow_id"].encode(),
                    value=json.dumps(record).encode(),
                )
            producer.poll(0)
    except KeyboardInterrupt:
        log.info("Shutting down — flushing open flows")
        for record in pipeline.flush():
            producer.produce(
                args.out_topic,
                key=record["flow_id"].encode(),
                value=json.dumps(record).encode(),
            )
        producer.flush()
        consumer.close()


def main():
    parser = argparse.ArgumentParser(description="ML Firewall Layer 2")
    parser.add_argument("--mode", choices=["pcap", "kafka"], default="pcap")
    parser.add_argument("--file", default="samples/sample.pcap",
                        help="PCAP file path (pcap mode)")
    parser.add_argument("--broker", default="localhost:9092")
    parser.add_argument("--in-topic",  default="layer1_raw_packets")
    parser.add_argument("--out-topic", default="layer2_feature_vectors")
    args = parser.parse_args()

    if args.mode == "pcap":
        run_pcap(args)
    else:
        run_kafka(args)


if __name__ == "__main__":
    main()
