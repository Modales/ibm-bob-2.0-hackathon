"""
observability_exporter.py — Prometheus / OpenTelemetry Metrics
==============================================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

Enterprise observability for the modernization pipeline. Exposes three custom
metrics plus a ``/metrics`` endpoint in Prometheus text exposition format —
scrapeable by any standard Prometheus/Grafana stack.

Metrics
-------
* ``modernizer_vulnerabilities_patched_total`` (Counter)   — patches that
  passed consensus + AST gate + sandbox, labeled by severity.
* ``modernizer_agent_debate_duration_seconds`` (Histogram) — wall time of the
  multi-agent consensus stage, labeled by verdict.
* ``modernizer_code_test_pass_rate`` (Gauge)               — rolling pass rate
  (0..1) of sandbox-tested refactors over the most recent runs.

Design notes
------------
* ``prometheus_client`` is used when installed. When it is not (offline CI,
  minimal demo boxes), the module falls back to a small in-process registry
  implementing the same interface — metrics still accumulate and ``/metrics``
  still renders valid exposition text. Nothing ever crashes because of a
  missing metrics library.
* Recording is fire-and-forget from the pipeline's perspective:
  ``record_pipeline_run`` never raises.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("orchestrator.observability_exporter")

# ---------------------------------------------------------------------------
# Backend: prometheus_client when available, else an in-process fallback
# ---------------------------------------------------------------------------

try:  # pragma: no cover - environment dependent
    from prometheus_client import Counter, Gauge, Histogram, generate_latest

    _PROM_AVAILABLE = True
except Exception as exc:
    logger.warning("prometheus_client unavailable (%s); using in-process fallback registry.", exc)
    _PROM_AVAILABLE = False


#: Rolling window for the pass-rate gauge.
PASS_RATE_WINDOW: int = int(os.getenv("PASS_RATE_WINDOW", "50"))


class _FallbackRegistry:
    """
    Minimal Prometheus-compatible store: counters, histograms (count+sum),
    and a gauge, rendered as valid exposition text. Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._histograms: Dict[str, Dict[str, float]] = {}
        self._gauge: float = 0.0

    # -- record -------------------------------------------------------------
    def inc_counter(self, name: str, labels: Dict[str, str], amount: float = 1.0) -> None:
        key = name + "|" + self._label_key(labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + amount

    def observe_histogram(self, name: str, labels: Dict[str, str], value: float) -> None:
        key = name + "|" + self._label_key(labels)
        with self._lock:
            bucket = self._histograms.setdefault(key, {"count": 0.0, "sum": 0.0})
            bucket["count"] += 1
            bucket["sum"] += value

    def set_gauge(self, value: float) -> None:
        with self._lock:
            self._gauge = value

    # -- render ---------------------------------------------------------------
    @staticmethod
    def _label_key(labels: Dict[str, str]) -> str:
        return "|".join(f"{k}={v}" for k, v in sorted(labels.items()))

    @staticmethod
    def _label_str(labels_part: str) -> str:
        if not labels_part:
            return ""
        pairs = ",".join(f'{k}="{v}"' for k, v in (p.split("=", 1) for p in labels_part.split("|")))
        return "{" + pairs + "}"

    def render(self) -> bytes:
        lines: List[str] = []
        with self._lock:
            for key, value in sorted(self._counters.items()):
                name, _, labels = key.partition("|")
                lines.append(f"{name}{self._label_str(labels)} {value}")
            for key, bucket in sorted(self._histograms.items()):
                name, _, labels = key.partition("|")
                label_str = self._label_str(labels)
                lines.append(f"{name}_count{label_str} {bucket['count']}")
                lines.append(f"{name}_sum{label_str} {bucket['sum']}")
            lines.append(f"modernizer_code_test_pass_rate {self._gauge}")
        return ("\n".join(lines) + "\n").encode()


# ---------------------------------------------------------------------------
# Metric handles (created once at import)
# ---------------------------------------------------------------------------

_FALLBACK = _FallbackRegistry()

if _PROM_AVAILABLE:
    VULNERABILITIES_PATCHED = Counter(  # type: ignore[assignment]
        "modernizer_vulnerabilities_patched_total",
        "Vulnerabilities patched end-to-end (consensus + AST gate + sandbox pass).",
        ["severity"],
    )
    AGENT_DEBATE_DURATION = Histogram(  # type: ignore[assignment]
        "modernizer_agent_debate_duration_seconds",
        "Duration of the multi-agent consensus debate stage.",
        ["verdict"],
    )
    CODE_TEST_PASS_RATE = Gauge(  # type: ignore[assignment]
        "modernizer_code_test_pass_rate",
        "Rolling sandbox pass rate of refactors (0..1).",
    )

#: Rolling window of recent sandbox outcomes (True/False) for the gauge.
_recent_outcomes: Deque[bool] = deque(maxlen=PASS_RATE_WINDOW)


# ---------------------------------------------------------------------------
# Recording API — called by the pipeline after each run
# ---------------------------------------------------------------------------

def record_vulnerability_patched(severity: str) -> None:
    """Increment the patched-vulnerabilities counter for one severity band."""
    severity = severity.lower()
    try:
        if _PROM_AVAILABLE:
            VULNERABILITIES_PATCHED.labels(severity=severity).inc()
        else:
            _FALLBACK.inc_counter("modernizer_vulnerabilities_patched_total", {"severity": severity})
    except Exception as exc:  # metrics must never break the pipeline
        logger.warning("metric record failed (patched counter): %s", exc)


def record_debate_duration(seconds: float, approved: bool) -> None:
    """Observe one consensus-debate duration, labeled by verdict."""
    verdict = "approved" if approved else "rejected"
    try:
        if _PROM_AVAILABLE:
            AGENT_DEBATE_DURATION.labels(verdict=verdict).observe(max(0.0, seconds))
        else:
            _FALLBACK.observe_histogram("modernizer_agent_debate_duration_seconds", {"verdict": verdict}, seconds)
    except Exception as exc:
        logger.warning("metric record failed (debate histogram): %s", exc)


def record_sandbox_outcome(passed: bool) -> None:
    """Add one sandbox outcome and refresh the rolling pass-rate gauge."""
    try:
        _recent_outcomes.append(bool(passed))
        rate = sum(_recent_outcomes) / len(_recent_outcomes)
        if _PROM_AVAILABLE:
            CODE_TEST_PASS_RATE.set(rate)
        else:
            _FALLBACK.set_gauge(rate)
    except Exception as exc:
        logger.warning("metric record failed (pass-rate gauge): %s", exc)


def record_pipeline_run(
    refactors: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    debate_durations: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    One-call integration point: given a finished pipeline run, update all
    three metrics. Never raises.
    """
    for i, refactor in enumerate(refactors):
        vuln = vulnerabilities[i] if i < len(vulnerabilities) else {}
        severity = str(vuln.get("severity", "medium"))
        if refactor.get("status") == "success":
            record_vulnerability_patched(severity)
            record_sandbox_outcome(True)
        elif refactor.get("status") in {"failed", "rejected_ast_gate", "rejected_consensus"}:
            record_sandbox_outcome(False)

    for d in debate_durations or []:
        record_debate_duration(float(d.get("seconds", 0.0)), bool(d.get("approved", False)))


def render_metrics() -> bytes:
    """Render the current metric set in Prometheus text exposition format."""
    if _PROM_AVAILABLE:
        return generate_latest()
    return _FALLBACK.render()


# ---------------------------------------------------------------------------
# Self-test: `python observability_exporter.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    record_pipeline_run(
        refactors=[{"status": "success"}, {"status": "rejected_consensus"}],
        vulnerabilities=[{"severity": "critical"}, {"severity": "high"}],
        debate_durations=[{"seconds": 1.24, "approved": True}, {"seconds": 0.87, "approved": False}],
    )
    print(f"backend: {'prometheus_client' if _PROM_AVAILABLE else 'fallback'}")
    print(render_metrics().decode())
