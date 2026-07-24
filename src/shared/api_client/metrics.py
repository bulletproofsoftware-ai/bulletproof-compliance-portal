"""Prometheus instrumentation for the compliance API client."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


def build_metrics(registry: CollectorRegistry | None = None) -> dict[str, object]:
    """Return a dict of metrics. A separate registry can be supplied for tests
    so that repeated import doesn't double-register."""
    reg = registry  # None => default registry
    metrics: dict[str, object] = {}

    metrics["request_duration"] = Histogram(
        "compliance_api_request_duration_seconds",
        "Compliance API request duration",
        labelnames=("endpoint", "method"),
        registry=reg,
    )
    metrics["request_total"] = Counter(
        "compliance_api_request_total",
        "Compliance API request count by status",
        labelnames=("endpoint", "method", "status"),
        registry=reg,
    )
    metrics["circuit_breaker_state"] = Gauge(
        "compliance_api_circuit_breaker_state",
        "0=closed, 1=half_open, 2=open",
        registry=reg,
    )
    return metrics


__all__ = ["build_metrics"]
