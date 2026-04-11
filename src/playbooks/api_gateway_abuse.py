"""
GCP SOAR — API Gateway Abuse Playbook
Handles DDoS or application layer abuse detected by Cloud Armor or API Gateway.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from google.cloud import compute_v1

from src.clients import gcp
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.logger import logger
from src.models.events import APIGatewayAuditEvent
from src.playbooks.base import Playbook


class APIGatewayAbusePlaybook(Playbook):
    """Playbook to block malicious IPs abusing API Gateway via Cloud Armor."""

    def __init__(self) -> None:
        self.security_policies = gcp.get_security_policies_client()
        self.audit = AuditLogger()
        self.project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self.policy_name = os.environ.get("CLOUD_ARMOR_POLICY_NAME", "")
        self.priority = int(os.environ.get("CLOUD_ARMOR_BLOCK_PRIORITY", "1000"))

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            # For GCP Audit Logs
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

    def execute(self, event_data: dict[str, Any]) -> bool:
        try:
            event = APIGatewayAuditEvent.model_validate(event_data)
            client_ip = event.client_ip

            if not client_ip:
                logger.error("No client IP found in APIGateway finding")
                return False

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

            target_ip = f"{client_ip}/32" if ":" not in client_ip else f"{client_ip}/128"
            self._block_ip(target_ip)

            self.audit.log(AuditAction.PLAYBOOK_COMPLETED, client_ip, actor="GCP_SOAR")
            return True

        except Exception as e:
            logger.error(f"API Gateway Abuse playbook failed: {e}", exc_info=True)
            with contextlib.suppress(Exception):
                self.audit.log(AuditAction.PLAYBOOK_FAILED, "cloud_armor", actor="GCP_SOAR", success=False)
            return False

    def _block_ip(self, target_ip: str) -> None:
        """Add a deny rule to Cloud Armor Security Policy."""
        try:
            policy = self.security_policies.get(project=self.project_id, security_policy=self.policy_name)

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

            self.security_policies.add_rule(
                project=self.project_id, security_policy=self.policy_name, security_policy_rule_resource=new_rule
            )
            logger.info(f"Added Cloud Armor deny rule for {target_ip} at priority {current_priority}")

        except Exception as e:
            logger.warning(f"Failed to block IP {target_ip} in Cloud Armor: {e}")
            raise
