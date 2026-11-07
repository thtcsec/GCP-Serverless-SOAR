"""Human approval persist + resume path (GCP)."""

from __future__ import annotations

from unittest.mock import patch

from src.core.approval_store import MemoryApprovalStore, build_pending_record
from src.core.event_normalizer import UnifiedIncident
from src.core.pipeline import IncidentPipeline
from src.playbooks.registry import PlaybookRegistry


def _pending_pipeline():
    store = MemoryApprovalStore()
    incident = _incident()
    store.put(
        build_pending_record(
            incident_id=incident.incident_id,
            raw_event=incident.raw_event,
            incident_snapshot=incident.model_dump(exclude={"raw_event"}),
            score_result={},
        )
    )
    return IncidentPipeline(registry=PlaybookRegistry(), approval_store=store), store, incident.incident_id


def test_concurrent_approvals_only_dispatch_once():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    pipe, store, incident_id = _pending_pipeline()
    started, release = Event(), Event()

    def execute(_):
        started.set()
        assert release.wait(5)
        return {"statusCode": 200, "body": {"status": "executed"}}

    with patch.object(pipe, "_execute_playbook", side_effect=execute) as dispatch:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(pipe.resume_approval, incident_id=incident_id, action="approve")
            try:
                assert started.wait(5)
                second = pipe.resume_approval(incident_id=incident_id, action="approve")
                assert second["statusCode"] == 409
            finally:
                release.set()
            assert first.result()["statusCode"] == 200
        dispatch.assert_called_once()
    assert store.get(incident_id)["status"] == "executed"


def test_failed_playbook_is_not_marked_executed():
    pipe, store, incident_id = _pending_pipeline()
    with patch.object(pipe._registry, "dispatch", return_value={"status": "failed"}):
        result = pipe.resume_approval(incident_id=incident_id, action="approve")
    assert result["statusCode"] == 500
    assert store.get(incident_id)["status"] == "failed"


def test_playbook_exception_records_failed_state():
    import pytest

    pipe, store, incident_id = _pending_pipeline()
    with (
        patch.object(pipe._registry, "dispatch", side_effect=RuntimeError("provider unavailable")),
        pytest.raises(RuntimeError, match="provider unavailable"),
    ):
        pipe.resume_approval(incident_id=incident_id, action="approve")
    assert store.get(incident_id)["status"] == "failed"


def test_approve_reject_race_uses_atomic_transition():
    pipe, store, incident_id = _pending_pipeline()
    with patch.object(store, "transition", return_value=False), patch.object(pipe._registry, "dispatch") as dispatch:
        assert pipe.resume_approval(incident_id=incident_id, action="approve")["statusCode"] == 409
        assert pipe.resume_approval(incident_id=incident_id, action="reject")["statusCode"] == 409
        dispatch.assert_not_called()


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

    inc = _incident()
    inc.anomaly_score = -0.8
    inc.threat_classification = {"mitre_ttps": ["T1078"]}
    pipe._request_approval(inc, {"summary": "needs review"})
    pending = store.get("inc-gcp-1")
    assert pending is not None
    assert pending["status"] == "pending"
    payload = mock_slack_cls.return_value.send_interactive_approval.call_args[0][0]
    assert payload["anomaly_score"] == -0.8
    assert payload["mitre_ttps"] == ["T1078"]


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
