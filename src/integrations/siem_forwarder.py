"""
GCP SOAR — SIEM Forwarder
Forwards incident data to external SIEM platforms.
Supports: Google Chronicle (UDM), Splunk (HEC), Elastic (ECS).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("gcp-soar.integrations.siem")


class SIEMForwarder:
    """Forward security events to one or more SIEM backends."""

    def __init__(self) -> None:
        self.siem_type = os.environ.get("SIEM_TYPE", "chronicle")
        self.endpoint = os.environ.get("SIEM_ENDPOINT", "")
        self.api_key = os.environ.get("SIEM_API_KEY", "")

        if not self.endpoint:
            self._load_from_secrets()

    def _load_from_secrets(self) -> None:
        try:
            from google.cloud import secretmanager  # type: ignore[attr-defined]

            client = secretmanager.SecretManagerServiceClient()
            project_id = os.environ.get("PROJECT_ID", "")

            def _secret(name: str) -> str:
                resp = client.access_secret_version(
                    name=f"projects/{project_id}/secrets/{name}/versions/latest"
                )
                return resp.payload.data.decode("utf-8")

            self.endpoint = _secret("siem-endpoint")
            self.api_key = _secret("siem-api-key")
        except Exception as exc:
            logger.error(f"Cannot load SIEM secrets: {exc}")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def forward_incident_data(self, incident: Dict[str, Any]) -> bool:
        """Transform and send a single incident to the configured SIEM."""
        if not self.endpoint:
            logger.warning("SIEM endpoint not configured")
            return False

        transformed = self._transform(incident)
        return self._send(transformed)

    def forward_batch_events(self, events: list[Dict[str, Any]]) -> int:
        """Send a batch of events. Returns count of successfully forwarded events."""
        sent = 0
        for event in events:
            if self.forward_incident_data(event):
                sent += 1
        return sent

    def test_connection(self) -> bool:
        """Verify connectivity to the SIEM endpoint."""
        try:
            req = urllib.request.Request(self.endpoint, method="HEAD")
            req.add_header("Authorization", f"Bearer {self.api_key}")
            urllib.request.urlopen(req, timeout=10)  # nosec B310
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Format transformers
    # ------------------------------------------------------------------ #

    def _transform(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        if self.siem_type == "splunk":
            return self._to_splunk_hec(incident)
        if self.siem_type == "elastic":
            return self._to_elastic_ecs(incident)
        return self._to_chronicle_udm(incident)

    @staticmethod
    def _to_chronicle_udm(incident: Dict) -> Dict:
        return {
            "events": [
                {
                    "metadata": {
                        "event_timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "GENERIC_EVENT",
                        "product_name": "GCP-SOAR",
                    },
                    "principal": {
                        "hostname": incident.get("instance_name", ""),
                        "ip": incident.get("caller_ip", ""),
                    },
                    "target": {
                        "resource": {
                            "name": incident.get("resource_name", ""),
                            "resource_type": incident.get("resource_type", "COMPUTE"),
                        }
                    },
                    "security_result": [
                        {
                            "severity": incident.get("severity", "HIGH"),
                            "category_details": [incident.get("category", "")],
                            "action": ["BLOCK"],
                            "description": incident.get("description", ""),
                        }
                    ],
                    "additional": {
                        "fields": {k: {"string_value": str(v)} for k, v in incident.items()},
                    },
                }
            ]
        }

    @staticmethod
    def _to_splunk_hec(incident: Dict) -> Dict:
        return {
            "event": incident,
            "sourcetype": "gcp:soar:incident",
            "source": "gcp-soar",
            "time": datetime.now(timezone.utc).timestamp(),
        }

    @staticmethod
    def _to_elastic_ecs(incident: Dict) -> Dict:
        return {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "action": incident.get("actions_taken", []),
                "severity": incident.get("risk_score", 0),
            },
            "cloud": {
                "provider": "gcp",
                "project": {"id": incident.get("project_id", "")},
                "region": incident.get("zone", ""),
            },
            "threat": {
                "indicator": {"type": incident.get("category", "")},
            },
            "source": {"ip": incident.get("caller_ip", "")},
            "message": json.dumps(incident),
        }

    # ------------------------------------------------------------------ #

    def _send(self, payload: Dict) -> bool:
        headers = {"Content-Type": "application/json"}
        if self.siem_type == "splunk":
            headers["Authorization"] = f"Splunk {self.api_key}"
        else:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )
        try:
            urllib.request.urlopen(req)  # nosec B310
            logger.info(f"Forwarded event to {self.siem_type}")
            return True
        except Exception as exc:
            logger.error(f"SIEM forward failed: {exc}")
            return False
