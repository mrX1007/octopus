#!/usr/bin/env python3

import time
import threading
from typing import Dict, Optional
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class MetricEntry:
    """A single metric data point."""
    name: str
    metric_type: str     # "counter", "gauge", "timer"
    value: float = 0.0
    count: int = 0       # for timers: number of observations
    total: float = 0.0   # for timers: total accumulated time
    min_val: float = float('inf')
    max_val: float = 0.0
    last_updated: float = field(default_factory=time.time)


class Metrics:
    """
    Thread-safe in-process metrics collector.

    Metric types:
      - counter: monotonically increasing integer
      - gauge: point-in-time value
      - timer: measures duration with min/max/avg stats
    """

    def __init__(self):
        self._metrics: Dict[str, MetricEntry] = {}
        self._lock = threading.Lock()
        self._start_time = time.time()

    def counter(self, name: str, value: int = 1):
        """Increment a counter by value."""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = MetricEntry(name=name, metric_type="counter")
            entry = self._metrics[name]
            entry.value += value
            entry.last_updated = time.time()

    def gauge(self, name: str, value: float):
        """Set a gauge to an absolute value."""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = MetricEntry(name=name, metric_type="gauge")
            entry = self._metrics[name]
            entry.value = value
            entry.last_updated = time.time()

    @contextmanager
    def timer(self, name: str):
        """
        Context manager to measure duration.

        Usage:
            with metrics.timer("scan.nmap"):
                run_nmap()
        """
        start = time.time()
        try:
            yield
        finally:
            elapsed = time.time() - start
            with self._lock:
                if name not in self._metrics:
                    self._metrics[name] = MetricEntry(
                        name=name, metric_type="timer")
                entry = self._metrics[name]
                entry.count += 1
                entry.total += elapsed
                entry.value = elapsed  # last observed value
                entry.min_val = min(entry.min_val, elapsed)
                entry.max_val = max(entry.max_val, elapsed)
                entry.last_updated = time.time()

    def record_timer(self, name: str, duration: float):
        """Record a timer value directly (without context manager)."""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = MetricEntry(
                    name=name, metric_type="timer")
            entry = self._metrics[name]
            entry.count += 1
            entry.total += duration
            entry.value = duration
            entry.min_val = min(entry.min_val, duration)
            entry.max_val = max(entry.max_val, duration)
            entry.last_updated = time.time()

    def get(self, name: str) -> Optional[float]:
        """Get current value of a metric."""
        with self._lock:
            entry = self._metrics.get(name)
            return entry.value if entry else None

    def report(self) -> dict:
        """Generate a full metrics report."""
        with self._lock:
            uptime = time.time() - self._start_time
            report = {
                "uptime_seconds": round(uptime, 1),
                "counters": {},
                "gauges": {},
                "timers": {},
            }

            for name, entry in sorted(self._metrics.items()):
                if entry.metric_type == "counter":
                    report["counters"][name] = int(entry.value)

                elif entry.metric_type == "gauge":
                    report["gauges"][name] = round(entry.value, 3)

                elif entry.metric_type == "timer":
                    avg = entry.total / entry.count if entry.count > 0 else 0
                    report["timers"][name] = {
                        "count": entry.count,
                        "total": round(entry.total, 3),
                        "avg": round(avg, 3),
                        "min": round(entry.min_val, 3) if entry.min_val != float('inf') else 0,
                        "max": round(entry.max_val, 3),
                    }

            return report

    def reset(self):
        """Reset all metrics."""
        with self._lock:
            self._metrics.clear()
            self._start_time = time.time()


# Global singleton
_global_metrics: Optional[Metrics] = None


def get_metrics() -> Metrics:
    """Get or create the global metrics instance."""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = Metrics()
    return _global_metrics
