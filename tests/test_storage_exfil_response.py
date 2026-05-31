from unittest.mock import MagicMock, patch

import src.storage_exfil_response as resp


def make_cloud_event(
    method_name="storage.objects.get",
    bucket_name="test-bucket",
    object_name="test-obj",
    principal="attacker@example.com",
    caller_ip="1.2.3.4",
):
    return MagicMock(
        id="event-123",
        data={
            "protoPayload": {
                "methodName": method_name,
                "serviceName": "storage.googleapis.com",
                "resourceName": f"projects/_/buckets/{bucket_name}/objects/{object_name}" if bucket_name else "",
                "authenticationInfo": {"principalEmail": principal},
                "request": {"callerIp": caller_ip},
                "status": {},
            },
            "timestamp": "2026-03-10T00:00:00Z",
        },
    )


class TestStorageExfilResponse:
    @patch("src.entrypoint.handle_event")
    def test_storage_exfil_responder_delegates_to_pipeline(self, mock_handle):
        mock_handle.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        resp.storage_exfil_responder(make_cloud_event())

        mock_handle.assert_called_once()
        event_data = mock_handle.call_args[0][0]
        assert event_data["protoPayload"]["serviceName"] == "storage.googleapis.com"
