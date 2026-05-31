from unittest.mock import MagicMock, patch

import src.sa_compromise_response as resp


def make_cloud_event(
    method_name="iam.serviceAccounts.createKey",
    sa_email="test@project.iam.gserviceaccount.com",
    caller_ip="1.2.3.4",
):
    return MagicMock(
        data={
            "protoPayload": {
                "methodName": method_name,
                "resourceName": f"projects/test-project/serviceAccounts/{sa_email}" if sa_email else "",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "attacker@example.com"},
                "request": {"callerIp": caller_ip},
                "status": {},
            },
            "timestamp": "2026-03-10T00:00:00Z",
        }
    )


class TestSACompromiseResponse:
    @patch("src.entrypoint.handle_event")
    def test_sa_compromise_responder_delegates_to_pipeline(self, mock_handle):
        mock_handle.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        resp.sa_compromise_responder(make_cloud_event())

        mock_handle.assert_called_once()
        event_data = mock_handle.call_args[0][0]
        assert event_data["protoPayload"]["serviceName"] == "iam.googleapis.com"
