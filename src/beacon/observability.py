"""Metrics and tracing in one place: Prometheus counters and OpenTelemetry spans.

Metrics are exposed at ``/metrics`` by the API and worker; spans are exported
over OTLP when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set and are no-ops otherwise.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

from prometheus_client import Counter, Histogram

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

logger = logging.getLogger(__name__)
F = TypeVar("F", bound="Callable[..., Any]")

_events = Counter("beacon_events_total", "Night Shift counters", ["service", "name"])
_values = Histogram(
    "beacon_values",
    "Night Shift measured values (seconds, milliseconds, attempts)",
    ["service", "name", "unit"],
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1000, 3000, 10000, 30000),
)
_service: ContextVar[str] = ContextVar("beacon_service", default="")
_tracer: Any = None


def _get_tracer() -> Any:
    global _tracer  # noqa: PLW0603
    if _tracer is None:
        _tracer = False
        if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            try:
                from opentelemetry import trace
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
                from opentelemetry.sdk.resources import Resource
                from opentelemetry.sdk.trace import TracerProvider
                from opentelemetry.sdk.trace.export import BatchSpanProcessor

                provider = TracerProvider(
                    resource=Resource.create(
                        {"service.name": os.environ.get("OTEL_SERVICE_NAME", "beacon")}
                    )
                )
                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
                trace.set_tracer_provider(provider)
                _tracer = trace.get_tracer("beacon")
            except Exception:  # telemetry must never break the request
                logger.exception("OpenTelemetry setup failed; tracing disabled")
    return _tracer


def reset() -> None:
    global _tracer  # noqa: PLW0603
    _tracer = None


@contextmanager
def metrics_scope(**dimensions: str) -> Iterator[None]:
    """Label the metrics recorded inside with the service name."""
    token = _service.set(str(dimensions.get("service") or "beacon"))
    try:
        yield
    finally:
        _service.reset(token)


def metric(name: str, value: float, *, unit: str = "Count") -> None:
    service = _service.get()
    if not service:
        return
    try:
        if unit == "Count":
            _events.labels(service, name).inc(float(value))
        else:
            _values.labels(service, name, unit).observe(float(value))
    except Exception:
        logger.exception("metric %s failed", name)


def metadata(key: str, value: str) -> None:
    """Kept for call-site compatibility: the value goes to the structured log."""
    if value:
        logger.debug("meta %s=%s", key, value)


def span(name: str) -> Callable[[F], F]:
    """OpenTelemetry span around a function; transparent when tracing is off."""

    def decorate(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = _get_tracer()
            if not tracer:
                return fn(*args, **kwargs)
            with tracer.start_as_current_span(name):
                return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate
