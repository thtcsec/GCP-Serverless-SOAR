"""
GCP SOAR — Cloud Monitoring Metrics & Cloud Trace Instrumentation
Custom metrics emission and distributed tracing for SOAR observability.
"""

import time
from datetime import datetime, timezone
from typing import Optional

from ..core.config import config
from ..core.logger import logger


def emit_metric(
    metric_type: str,
    value: float = 1.0,
    labels: Optional[dict] = None,
) -> None:
    """Write a custom monitoring metric to Cloud Monitoring."""
    try:
        from google.cloud import monitoring_v3  # type: ignore[attr-defined]
        from google.api import metric_pb2
        from google.protobuf import timestamp_pb2  # type: ignore[import-untyped]
        from ..clients.gcp import get_monitoring_client

        client = get_monitoring_client()
        project_name = f"projects/{config.project_id}"

        series = monitoring_v3.TimeSeries()
        series.metric.type = f"custom.googleapis.com/soar/{metric_type}"
        series.resource.type = "global"
        series.resource.labels["project_id"] = config.project_id

        if labels:
            for k, v in labels.items():
                series.metric.labels[k] = v

        now = datetime.now(timezone.utc)
        seconds = int(now.timestamp())
        nanos = int((now.timestamp() - seconds) * 1e9)

        point = monitoring_v3.Point()
        point.value.double_value = value
        point.interval.end_time.seconds = seconds
        point.interval.end_time.nanos = nanos
        series.points = [point]

        client.create_time_series(
            request={"name": project_name, "time_series": [series]}
        )
    except Exception as e:
        logger.warning(f"Failed to emit metric {metric_type}: {e}")


def get_tracer(name: str = "gcp-soar"):
    """Return an OpenTelemetry tracer configured with Cloud Trace exporter."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from ..clients.gcp import get_trace_exporter

        provider = trace.get_tracer_provider()
        if not isinstance(provider, TracerProvider):
            exporter = get_trace_exporter()
            provider = TracerProvider()
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)

        return trace.get_tracer(name)
    except Exception as e:
        logger.warning(f"Failed to initialise Cloud Trace: {e}")
        from opentelemetry import trace
        return trace.get_tracer(name)


class PlaybookTimer:
    """Context manager to measure and emit playbook execution duration."""

    def __init__(self, playbook_name: str):
        self.playbook_name = playbook_name
        self._start: float = 0

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.monotonic() - self._start) * 1000
        labels = {"playbook": self.playbook_name}
        emit_metric("playbook_duration_ms", duration_ms, labels)
        if exc_type is None:
            emit_metric("playbook_success", 1.0, labels)
        else:
            emit_metric("playbook_failure", 1.0, labels)
        return False
