"""Tests for GKE Pod Eviction playbook (GCP)."""

from unittest.mock import MagicMock, patch


def make_gke_audit_event(method_name="io.k8s.core.v1.pods.exec", cluster="my-cluster", pod="bad-pod"):
    resource = (
        f"//container.googleapis.com/projects/my-project/locations/us-central1"
        f"/clusters/{cluster}/namespaces/default/pods/{pod}"
    )
    return {
        "protoPayload": {
            "methodName": method_name,
            "resourceName": resource,
            "serviceName": "container.googleapis.com",
            "authenticationInfo": {"principalEmail": "attacker@example.com"},
            "request": {},
            "status": {},
        },
        "timestamp": "2026-03-01T00:00:00Z",
        "severity": "HIGH",
        "resource": {},
    }


def make_scc_container_threat_event(severity="HIGH"):
    return {
        "name": "organizations/123/sources/456/findings/789",
        "category": "CONTAINER_THREAT",
        "severity": severity,
        "resourceName": ("//container.googleapis.com/projects/my-project/locations/us-central1/clusters/my-cluster"),
        "state": "ACTIVE",
        "resource": {
            "name": "my-cluster",
            "projectDisplayName": "my-project",
            "type": "container.googleapis.com/Cluster",
        },
    }


class TestGKEPodEvictionCanHandle:
    def test_handles_pod_exec(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        assert pb.can_handle(make_gke_audit_event("io.k8s.core.v1.pods.exec")) is True

    def test_handles_pod_create(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        assert pb.can_handle(make_gke_audit_event("io.k8s.core.v1.pods.create")) is True

    def test_handles_scc_container_threat_high(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        assert pb.can_handle(make_scc_container_threat_event("HIGH")) is True

    def test_rejects_scc_container_threat_low(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        assert pb.can_handle(make_scc_container_threat_event("LOW")) is False

    def test_rejects_non_k8s_service(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        event = make_gke_audit_event()
        event["protoPayload"]["serviceName"] = "iam.googleapis.com"
        assert pb.can_handle(event) is False

    def test_rejects_malformed_event(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        assert pb.can_handle({"bad": "data"}) is False


class TestGKEPodEvictionParseResource:
    def test_parse_full_resource(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        resource = (
            "//container.googleapis.com/projects/proj/locations/us-central1"
            "/clusters/my-cluster/namespaces/default/pods/bad-pod"
        )
        cluster, ns, pod = GKEPodEvictionPlaybook._parse_k8s_resource(resource)
        assert cluster == "my-cluster"
        assert ns == "default"
        assert pod == "bad-pod"

    def test_parse_partial_resource(self):
        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        cluster, ns, pod = GKEPodEvictionPlaybook._parse_k8s_resource("some/clusters/mycluster")
        assert cluster == "mycluster"
        assert pod == ""


class TestGKEPodEvictionExecute:
    @patch("src.playbooks.gke_pod_eviction.PlaybookTimer")
    @patch("src.playbooks.gke_pod_eviction.emit_metric")
    @patch("src.playbooks.gke_pod_eviction.get_tracer")
    def test_execute_high_severity_auto_isolate(self, mock_tracer, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.return_value.start_as_current_span.return_value = mock_span

        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        pb.audit = MagicMock()

        with (
            patch.object(pb, "_apply_quarantine_label") as mock_label,
            patch.object(pb, "_collect_pod_logs_to_gcs") as mock_logs,
        ):
            event = make_gke_audit_event(method_name="io.k8s.core.v1.pods.exec")
            result = pb.execute(event)

            assert result is True
            mock_label.assert_called_once()
            mock_logs.assert_called_once()

    @patch("src.playbooks.gke_pod_eviction.PlaybookTimer")
    @patch("src.playbooks.gke_pod_eviction.emit_metric")
    @patch("src.playbooks.gke_pod_eviction.get_tracer")
    def test_execute_no_cluster_returns_false(self, mock_tracer, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.return_value.start_as_current_span.return_value = mock_span

        from src.playbooks.gke_pod_eviction import GKEPodEvictionPlaybook

        pb = GKEPodEvictionPlaybook.__new__(GKEPodEvictionPlaybook)
        pb.audit = MagicMock()

        # Empty resource_name, no cluster extractable
        event = make_gke_audit_event()
        event["protoPayload"]["resourceName"] = ""
        result = pb.execute(event)
        assert result is False

    def test_gke_audit_event_model_is_risky(self):
        from src.models.events import GKEAuditEvent

        event = make_gke_audit_event("io.k8s.core.v1.pods.exec")
        ev = GKEAuditEvent.model_validate(event)
        assert ev.is_risky is True

    def test_gke_audit_event_model_non_risky(self):
        from src.models.events import GKEAuditEvent

        event = make_gke_audit_event("io.k8s.core.v1.pods.get")
        ev = GKEAuditEvent.model_validate(event)
        assert ev.is_risky is False

    def test_audit_actions_exist(self):
        from src.core.audit_logger import AuditAction

        assert AuditAction.EVICT_POD == "EVICT_POD"
        assert AuditAction.APPLY_NETWORK_POLICY == "APPLY_NETWORK_POLICY"
        assert AuditAction.COLLECT_POD_LOGS == "COLLECT_POD_LOGS"
