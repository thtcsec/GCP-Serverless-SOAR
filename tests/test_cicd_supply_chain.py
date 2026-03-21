"""Tests for CI/CD Supply Chain playbook (GCP)."""

from unittest.mock import MagicMock, patch


def make_cloudbuild_event(method_name="google.devtools.cloudbuild.v1.CloudBuild.CreateBuild", trigger_id="trigger-123"):
    return {
        "protoPayload": {
            "methodName": method_name,
            "resourceName": "projects/my-project/builds/build-abc",
            "serviceName": "cloudbuild.googleapis.com",
            "authenticationInfo": {"principalEmail": "attacker@company.com"},
            "request": {
                "id": "build-abc",
                "triggerId": trigger_id,
                "build": {
                    "substitutions": {"_SECRET_TOKEN": "something-sensitive"},
                },
            },
            "status": {},
        },
        "timestamp": "2026-03-01T00:00:00Z",
        "resource": {},
    }


class TestCICDSupplyChainGCPCanHandle:
    def test_handles_create_build(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        method = "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"
        assert pb.can_handle(make_cloudbuild_event(method)) is True

    def test_handles_update_build_trigger(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        method = "google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger"
        assert pb.can_handle(make_cloudbuild_event(method)) is True

    def test_rejects_non_risky_method(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        method = "google.devtools.cloudbuild.v1.CloudBuild.GetBuild"
        assert pb.can_handle(make_cloudbuild_event(method)) is False

    def test_rejects_wrong_service(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        event = make_cloudbuild_event()
        event["protoPayload"]["serviceName"] = "iam.googleapis.com"
        assert pb.can_handle(event) is False

    def test_rejects_malformed_event(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        assert pb.can_handle({"bad": "data"}) is False


class TestCICDSupplyChainGCPBehaviorScore:
    def test_suspicious_substitutions_high_score(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        request = {"build": {"substitutions": {"_SECRET_TOKEN": "abc"}}}
        score = CICDSupplyChainPlaybook._behavior_score(
            "service@project.iam.gserviceaccount.com",
            "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild",
            request,
        )
        assert score >= 40.0

    def test_update_trigger_high_score(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score = CICDSupplyChainPlaybook._behavior_score(
            "svc@proj.iam.gserviceaccount.com",
            "google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger",
            {},
        )
        assert score >= 35.0

    def test_external_actor_boosts_score(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score_external = CICDSupplyChainPlaybook._behavior_score(
            "attacker@gmail.com",
            "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild",
            {},
        )
        score_internal = CICDSupplyChainPlaybook._behavior_score(
            "svc@proj.iam.gserviceaccount.com",
            "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild",
            {},
        )
        assert score_external > score_internal

    def test_max_score_capped(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score = CICDSupplyChainPlaybook._behavior_score(
            "attacker@gmail.com",
            "google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger",
            {"build": {"substitutions": {"_KEY": "val"}}},
        )
        assert score <= 100.0


class TestCICDSupplyChainGCPExecute:
    @patch("src.playbooks.cicd_supply_chain.PlaybookTimer")
    @patch("src.playbooks.cicd_supply_chain.emit_metric")
    @patch("src.playbooks.cicd_supply_chain.get_tracer")
    def test_execute_returns_true(self, mock_tracer, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.return_value.start_as_current_span.return_value = mock_span

        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        pb.audit = MagicMock()

        with (
            patch.object(pb, "_cancel_build"),
            patch.object(pb, "_disable_trigger"),
            patch.object(pb, "_notify_slack"),
            patch.object(pb, "_publish_alert"),
        ):
            event = make_cloudbuild_event()
            result = pb.execute(event)
            assert result is True

    @patch("src.playbooks.cicd_supply_chain.PlaybookTimer")
    @patch("src.playbooks.cicd_supply_chain.emit_metric")
    @patch("src.playbooks.cicd_supply_chain.get_tracer")
    def test_execute_returns_false_on_exception(self, mock_tracer, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.return_value.start_as_current_span.return_value = mock_span

        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        pb.audit = MagicMock()

        # Completely broken event that cannot be parsed
        result = pb.execute({"totally": "broken"})
        assert result is False

    def test_cloud_build_model(self):
        from src.models.events import CloudBuildAuditEvent

        event = make_cloudbuild_event("google.devtools.cloudbuild.v1.CloudBuild.CreateBuild")
        ev = CloudBuildAuditEvent.model_validate(event)
        assert ev.is_risky is True

    def test_cloud_build_model_non_risky(self):
        from src.models.events import CloudBuildAuditEvent

        event = make_cloudbuild_event("google.devtools.cloudbuild.v1.CloudBuild.GetBuild")
        ev = CloudBuildAuditEvent.model_validate(event)
        assert ev.is_risky is False

    def test_audit_actions_exist(self):
        from src.core.audit_logger import AuditAction

        assert AuditAction.CANCEL_BUILD == "CANCEL_BUILD"
        assert AuditAction.DISABLE_BUILD_TRIGGER == "DISABLE_BUILD_TRIGGER"
        assert AuditAction.QUARANTINE_ARTIFACT == "QUARANTINE_ARTIFACT"
