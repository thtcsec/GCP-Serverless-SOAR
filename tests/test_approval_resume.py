"""Human approval persist + resume path (GCP)."""

from __future__ import annotations

from unittest.mock import patch

from src.core.approval_store import MemoryApprovalStore, build_pending_record
from src.core.event_normalizer import UnifiedIncident
from src.core.pipeline import IncidentPipeline
from src.playbooks.registry import PlaybookRegistry


def _incident() -> UnifiedIncident:
    return UnifiedIncident(
        incident_id="inc-gcp-1",
        platform="gcp",
        severity="MEDIUM",
        action="CreateServiceAccountKey",
        resource="projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com",
        resource_type="service_account",
        raw_event_type="IAMAuditEvent",
        decision="REQUIRE_APPROVAL",
        risk_score=55.0,
        raw_event={"protoPayload": {"methodName": "CreateServiceAccountKey"}},
        trace_id="trace-test",
    )


@patch("src.core.pipeline.SlackNotifier")
def test_request_approval_persists_and_notifies(mock_slack_cls):
    store = MemoryApprovalStore()
    pipe = IncidentPipeline(registry=PlaybookRegistry(), approval_store=store)
    mock_slack_cls.return_value.send_interactive_approval.return_value = {"notification_sent": True}

    pipe._request_approval(_incident(), {"summary": "needs review"})
    pending = store.get("inc-gcp-1")
    assert pending is not None
    assert pending["status"] == "pending"
    mock_slack_cls.return_value.send_interactive_approval.assert_called_once()


def test_resume_reject_and_approve():
    store = MemoryApprovalStore()
    inc = _incident()
    store.put(
        build_pending_record(
            incident_id=inc.incident_id,
            raw_event=inc.raw_event,
            incident_snapshot=inc.model_dump(exclude={"raw_event"}),
            score_result={},
        )
    )
    pipe = IncidentPipeline(registry=PlaybookRegistry(), approval_store=store)
    rejected = pipe.resume_approval(incident_id=inc.incident_id, action="reject", actor="analyst")
    assert rejected["body"]["status"] == "rejected"

    store.put(
        build_pending_record(
            incident_id=inc.incident_id,
            raw_event=inc.raw_event,
            incident_snapshot=inc.model_dump(exclude={"raw_event"}),
            score_result={},
        )
    )
    with patch.object(pipe._registry, "dispatch", return_value={"status": "executed"}) as mock_dispatch:
        approved = pipe.resume_approval(incident_id=inc.incident_id, action="approve", actor="slack:bob")
        assert approved["statusCode"] == 200
        assert mock_dispatch.call_args[0][0].decision == "AUTO_ISOLATE"


def test_unified_incident_has_trace_id():
    inc = UnifiedIncident()
    assert inc.trace_id
