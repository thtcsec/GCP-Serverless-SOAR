"""
GCP SOAR — API Gateway Abuse Playbook
Handles DDoS or application layer abuse detected by Cloud Armor or API Gateway.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from google.cloud import compute_v1
from google.cloud import logging as gcp_logging

from src.clients import gcp
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.config import config
from src.core.event_normalizer import UnifiedIncident
from src.core.logger import logger
from src.models.events import APIGatewayAuditEvent
from src.playbooks._helpers import coerce_incident, is_dry_run
from src.playbooks.base import Playbook


class APIGatewayAbusePlaybook(Playbook):
    """Playbook to block malicious IPs abusing API Gateway via Cloud Armor."""

    def __init__(self) -> None:
        self.audit = AuditLogger()
        self.project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self.policy_name = os.environ.get("CLOUD_ARMOR_POLICY_NAME", "")
        self.priority = int(os.environ.get("CLOUD_ARMOR_BLOCK_PRIORITY", "1000"))

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            event_data = incident.raw_event
            proto_payload = event_data.get("protoPayload", {})
            if not proto_payload:
                return False

            service_name = proto_payload.get("serviceName", "")
            if "apigateway.googleapis.com" not in service_name and "compute.googleapis.com" not in service_name:
                return False

            event = APIGatewayAuditEvent.model_validate(event_data)
            return event.is_ddos_abuse
        except Exception:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        try:
            event_data = incident.raw_event
            event = APIGatewayAuditEvent.model_validate(event_data)
            client_ip = event.client_ip

            if not client_ip:
                logger.error("No client IP found in APIGateway finding")
                return False

            if is_dry_run(incident):
                return self._build_preview(client_ip)

            logger.info(f"Executing API Gateway Abuse Playbook for IP={client_ip}")
            self.audit.log(
                AuditAction.PLAYBOOK_STARTED,
                client_ip,
                actor="GCP_SOAR",
                details={"source": "api_gateway"},
            )

            if not self.policy_name or not self.project_id:
                logger.warning("Cloud Armor Policy configuration missing in env vars")
                return False

            self._collect_evidence(client_ip, event_data)

            target_ip = f"{client_ip}/32" if ":" not in client_ip else f"{client_ip}/128"
            self._block_ip(target_ip)

            self.audit.log(AuditAction.PLAYBOOK_COMPLETED, client_ip, actor="GCP_SOAR")
            return True

        except Exception as e:
            logger.error(f"API Gateway Abuse playbook failed: {e}", exc_info=True)
            with contextlib.suppress(Exception):
                self.audit.log(AuditAction.PLAYBOOK_FAILED, "cloud_armor", actor="GCP_SOAR", success=False)
            return False

    def _build_preview(self, client_ip: str) -> dict[str, Any]:
        target_ip = f"{client_ip}/32" if ":" not in client_ip else f"{client_ip}/128"
        return {
            "mode": "dry_run",
            "playbook": "APIGatewayAbuse",
            "target_resource": client_ip,
            "summary": "Preview only. No Cloud Armor deny rules were added.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "collect_evidence",
                    "target": config.forensic_bucket or "UNCONFIGURED",
                    "details": "Store Cloud Logging evidence to GCS if FORENSIC_BUCKET is configured.",
                },
                {
                    "step": 2,
                    "action": "get_security_policy",
                    "target": self.policy_name or "UNCONFIGURED",
                    "details": f"Fetch Cloud Armor policy in project {self.project_id or 'UNCONFIGURED'}.",
                },
                {
                    "step": 3,
                    "action": "add_rule",
                    "target": target_ip,
                    "details": f"Add deny(403) rule for {target_ip} at priority {self.priority}.",
                },
            ],
        }

    @staticmethod
    def _safe_key_component(value: str) -> str:
        return value.replace(":", "_").replace("/", "_")

    @staticmethod
    def _top_counts(values: list[str], limit: int) -> list[dict[str, Any]]:
        counter = Counter(v for v in values if v)
        return [{"value": value, "count": count} for value, count in counter.most_common(limit)]

    def _summarize_logs(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        top_n = int(os.environ.get("API_EVIDENCE_TOP_N", "5"))
        services = [str(entry.get("service", "")) for entry in logs]
        methods = [str(entry.get("method", "")) for entry in logs]
        status_codes = [str(entry.get("statusCode", "")) for entry in logs]
        user_agents = [str(entry.get("userAgent", "")) for entry in logs]

        return {
            "entries": len(logs),
            "top_services": self._top_counts(services, top_n),
            "top_methods": self._top_counts(methods, top_n),
            "top_status_codes": self._top_counts(status_codes, top_n),
            "top_user_agents": self._top_counts(user_agents, top_n),
        }

    def _collect_evidence(self, client_ip: str, event_data: dict[str, Any]) -> None:
        if not config.forensic_bucket:
            return

        try:
            lookback_minutes = int(os.environ.get("API_EVIDENCE_LOOKBACK_MINUTES", "15"))
            max_entries = int(os.environ.get("API_EVIDENCE_MAX_ENTRIES", "200"))
            services_raw = os.environ.get(
                "API_EVIDENCE_SERVICES",
                "apigateway.googleapis.com,run.googleapis.com,cloudfunctions.googleapis.com,compute.googleapis.com",
            )
            services = [s.strip() for s in services_raw.split(",") if s.strip()]

            start_time = datetime.now(UTC) - timedelta(minutes=lookback_minutes)
            service_filter = " OR ".join([f'protoPayload.serviceName="{s}"' for s in services])
            filter_parts = [
                f'timestamp>="{start_time.isoformat()}"',
                f'protoPayload.requestMetadata.callerIp="{client_ip}"',
            ]
            if service_filter:
                filter_parts.append(f"({service_filter})")

            filter_str = " AND ".join(filter_parts)
            logging_client = gcp.get_logging_client()

            logs: list[dict[str, Any]] = []
            for entry in logging_client.list_entries(
                filter_=filter_str,
                order_by=gcp_logging.DESCENDING,
                max_results=max_entries,
            ):
                api_repr = entry.to_api_repr()
                payload = api_repr.get("protoPayload", {}) or {}
                request_meta = payload.get("requestMetadata", {}) or {}
                status = payload.get("status", {}) or {}
                logs.append(
                    {
                        "timestamp": api_repr.get("timestamp", ""),
                        "service": payload.get("serviceName", ""),
                        "method": payload.get("methodName", ""),
                        "resource": payload.get("resourceName", ""),
                        "callerIp": request_meta.get("callerIp", ""),
                        "userAgent": request_meta.get("callerSuppliedUserAgent", ""),
                        "statusCode": status.get("code", 0),
                    }
                )

            safe_ip = self._safe_key_component(client_ip) or "unknown"
            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            key = f"evidence/api_gateway/{safe_ip}/{ts}.json"
            payload = {
                "client_ip": client_ip,
                "collected_at": datetime.now(UTC).isoformat(),
                "event": event_data,
                "logs": logs,
                "summary": self._summarize_logs(logs),
            }

            bucket = gcp.get_storage_client().bucket(config.forensic_bucket)
            bucket.blob(key).upload_from_string(json.dumps(payload, default=str), content_type="application/json")

            self.audit.log(
                AuditAction.COLLECT_EVIDENCE,
                client_ip,
                actor="GCP_SOAR",
                details={"gcs_key": key},
            )
        except Exception as exc:
            logger.warning(f"Failed to collect API abuse evidence for {client_ip}: {exc}")

    def _block_ip(self, target_ip: str) -> None:
        """Add a deny rule to Cloud Armor Security Policy."""
        try:
            security_policies = gcp.get_security_policies_client()
            policy = security_policies.get(project=self.project_id, security_policy=self.policy_name)

            # Check if IP already blocked
            for rule in policy.rules:
                if rule.match.versioned_expr == "SRC_IPS_V1" and target_ip in rule.match.config.src_ip_ranges:
                    logger.info(f"IP {target_ip} is already blocked.")
                    return

            # Append the new IP to a rule or create a new rule (Simplified: create new rule with specific priority)
            # Find an available priority near self.priority
            used_priorities = {r.priority for r in policy.rules}
            current_priority = self.priority
            while current_priority in used_priorities and current_priority < 2147483646:
                current_priority += 1

            new_rule = compute_v1.SecurityPolicyRule(
                priority=current_priority,
                match=compute_v1.SecurityPolicyRuleMatcher(
                    versioned_expr="SRC_IPS_V1",
                    config=compute_v1.SecurityPolicyRuleMatcherConfig(src_ip_ranges=[target_ip]),
                ),
                action="deny(403)",
                description="Auto-blocked by SOAR APIGatewayAbuse playbook",
            )

            security_policies.add_rule(
                project=self.project_id, security_policy=self.policy_name, security_policy_rule_resource=new_rule
            )
            logger.info(f"Added Cloud Armor deny rule for {target_ip} at priority {current_priority}")

        except Exception as e:
            logger.warning(f"Failed to block IP {target_ip} in Cloud Armor: {e}")
            raise
