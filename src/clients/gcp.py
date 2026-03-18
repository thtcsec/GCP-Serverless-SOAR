"""
GCP SOAR Client Facade
Centralised, lazily-initialised Google Cloud client management.
"""

from functools import lru_cache

from google.cloud import compute_v1
from google.cloud import logging as cloud_logging
from google.cloud import storage as storage  # type: ignore[attr-defined]


@lru_cache(maxsize=1)
def get_instances_client() -> compute_v1.InstancesClient:
    return compute_v1.InstancesClient()


@lru_cache(maxsize=1)
def get_disks_client() -> compute_v1.DisksClient:
    return compute_v1.DisksClient()


@lru_cache(maxsize=1)
def get_snapshots_client() -> compute_v1.SnapshotsClient:
    return compute_v1.SnapshotsClient()


@lru_cache(maxsize=1)
def get_firewalls_client() -> compute_v1.FirewallsClient:
    return compute_v1.FirewallsClient()


@lru_cache(maxsize=1)
def get_storage_client() -> storage.Client:
    return storage.Client()


@lru_cache(maxsize=1)
def get_logging_client() -> cloud_logging.Client:
    return cloud_logging.Client()


def get_iam_client():
    """Return the IAM Admin client (imported lazily to avoid hard failures)."""
    from google.cloud import iam_admin_v1

    return iam_admin_v1.IAMClient()


def get_publisher():
    """Return a Pub/Sub publisher client."""
    from google.cloud import pubsub_v1

    return pubsub_v1.PublisherClient()


def get_resource_manager_client():
    """Return the Resource Manager v3 projects client."""
    from google.cloud import resourcemanager_v3

    return resourcemanager_v3.ProjectsClient()


def get_monitoring_client():
    """Return the Cloud Monitoring MetricServiceClient."""
    from google.cloud import monitoring_v3

    return monitoring_v3.MetricServiceClient()


def get_trace_exporter():
    """Return the Cloud Trace exporter for OpenTelemetry."""
    from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter

    return CloudTraceSpanExporter()
