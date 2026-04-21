"""utils/drop_log.py — append-only JSONL drop log."""
import json
import os
import threading
import time


class DropLogger:
    """Thread-safe append-only JSONL file for dropped packets/flows."""

    def __init__(self, path: str = "drop_log.jsonl"):
        self._path = path
        self._lock = threading.Lock()

    def log(self, reason: str, timestamp: float = None, **kwargs):
        entry = {
            "ts":     round(timestamp or time.time(), 3),
            "reason": reason,
            **kwargs,
        }
        with self._lock:
            with open(self._path, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
