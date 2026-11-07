"""Transport failures must reach the trigger's retry mechanism."""

from unittest.mock import patch

import pytest

from src import entrypoint


@pytest.mark.parametrize(
    "adapter",
    [
        "soar_responder",
        "sa_compromise_responder",
        "storage_exfil_responder",
        "queue_processor",
    ],
)
@pytest.mark.parametrize("failure", ["response", "exception"])
def test_adapter_propagates_pipeline_failures(adapter, failure):
    with (
        patch.object(entrypoint, "_decode_pubsub_cloud_event", return_value={}),
        patch.object(entrypoint, "_decode_audit_cloud_event", return_value={}),
        patch.object(entrypoint, "handle_event") as handle,
    ):
        if failure == "response":
            handle.return_value = {"statusCode": 500}
        else:
            handle.side_effect = RuntimeError("provider unavailable")
        with pytest.raises(RuntimeError):
            getattr(entrypoint, adapter)(object())


def test_successful_dispatch_is_not_retried():
    with patch.object(entrypoint, "handle_event", return_value={"statusCode": 200}):
        assert entrypoint._dispatch_event({}) == {"statusCode": 200}
