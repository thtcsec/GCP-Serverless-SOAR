"""
GCP SOAR — Policy Engine
Central scoring and decision gate for the incident pipeline.
All risk scoring happens here — playbooks must not re-score independently.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from ..integrations.anomaly_detector import AnomalyDetector
from ..integrations.intel import ThreatIntelService
from ..integrations.scoring import ScoringEngine
from .event_normalizer import UnifiedIncident

logger = logging.getLogger("gcp-soar.policy")

HIGH_RISK_IAM_METHODS = [
    "CreateServiceAccountKey",
    "SetIamPolicy",
    "UndeleteServiceAccountKey",
    "CreateServiceAccount",
    "UploadServiceAccountKey",
]

# Playbooks that perform domain-specific analysis before acting.
_EVALUATE_TYPES = {"StorageAuditEvent"}


class PolicyEngine:
    """Score incidents and produce a policy decision before playbook execution."""

    def __init__(
        self,
        intel_service: ThreatIntelService | None = None,
        scoring_engine: ScoringEngine | None = None,
        anomaly_detector: AnomalyDetector | None = None,
    ) -> None:
        self._intel = intel_service or ThreatIntelService()
        self._scoring = scoring_engine or ScoringEngine()
        self._anomaly = anomaly_detector or AnomalyDetector()

    def evaluate(self, incident: UnifiedIncident) -> dict[str, Any]:
        """
        Enrich and score an incident. Updates *incident* in place and returns
        the scoring payload consumed by the pipeline and audit trail.
        """
        if incident.raw_event_type in _EVALUATE_TYPES:
            return self._evaluate_storage(incident)

        if incident.raw_event_type == "IAMAuditEvent":
            return self._evaluate_iam(incident)

        if incident.raw_event_type == "SCCFinding":
            return self._evaluate_scc(incident)

        return self._evaluate_default(incident)

    def _evaluate_scc(self, incident: UnifiedIncident) -> dict[str, Any]:
        severity = incident.severity.upper()
        # Align ordinal mapping with AWS GuardDuty bands: CRITICAL/HIGH/MEDIUM/LOW
        if severity == "CRITICAL":
            base_severity = 10.0
        elif severity == "HIGH":
            base_severity = 8.0
        elif severity in ("MEDIUM", "MODERATE"):
            base_severity = 5.0
        elif severity == "LOW":
            base_severity = 2.0
        else:
            base_severity = 5.0

        intel_report: dict[str, Any] = {}
        source_ip = incident.source_ip

        if not source_ip:
            source_ip = self._extract_scc_ip(incident.raw_event)
            incident.source_ip = source_ip or incident.source_ip

        if source_ip:
            intel_report = self._intel.get_ip_report(source_ip)
            incident.intel_summary = intel_report

        return self._score_with_anomaly(incident, intel_report, base_severity)

    def _evaluate_iam(self, incident: UnifiedIncident) -> dict[str, Any]:
        caller_ip = incident.source_ip
        action = incident.action
        intel_report: dict[str, Any] = {}

        # Parity with AWS IAM bands: risky action → 6 else 4, +2 external, +2 off-hours
        base_risk = 6.0 if any(m in action for m in HIGH_RISK_IAM_METHODS) else 4.0
        if caller_ip and not caller_ip.startswith(("compute.google", "container.google")):
            base_risk += 2.0
        hour = datetime.now(UTC).hour
        if hour >= 23 or hour <= 5:
            base_risk += 2.0
        base_risk = min(base_risk, 10.0)

        if caller_ip and not caller_ip.startswith(("compute.google", "container.google")):
            intel_report = self._intel.get_ip_report(caller_ip)
            incident.intel_summary = intel_report

        return self._score_with_anomaly(incident, intel_report, base_risk)

    def _evaluate_storage(self, incident: UnifiedIncident) -> dict[str, Any]:
        """Storage exfiltration requires playbook-side pattern analysis."""
        result = {
            "risk_score": 0.0,
            "decision": "EVALUATE",
            "decision_rationale": ("Storage read delegated to StorageExfiltration playbook for pattern analysis."),
            "recommended_action": "evaluate_exfiltration_patterns",
            "summary": "Pipeline delegated evaluation to storage playbook.",
            "breakdown": {},
            "anomaly_score": 0.0,
        }
        self._apply_result(incident, result)
        return result

    def _evaluate_default(self, incident: UnifiedIncident) -> dict[str, Any]:
        severity_map = {"LOW": 2.0, "MEDIUM": 5.0, "HIGH": 8.0, "CRITICAL": 10.0}
        base = severity_map.get(incident.severity.upper(), 5.0)
        intel_report: dict[str, Any] = {}

        if incident.source_ip:
            intel_report = self._intel.get_ip_report(incident.source_ip)
            incident.intel_summary = intel_report

        return self._score_with_anomaly(incident, intel_report, base)

    def _score_with_anomaly(
        self,
        incident: UnifiedIncident,
        intel_report: dict[str, Any],
        base_severity: float,
    ) -> dict[str, Any]:
        features = self._build_anomaly_features(incident, intel_report, base_severity)
        anomaly_score = self._anomaly.predict(features)
        if anomaly_score == 0.0 and len(self._anomaly._history) < 2:
            anomaly_score = self._heuristic_anomaly(features)
        self._observe_anomaly(features)

        result = self._scoring.calculate_risk_score(
            intel_report,
            base_severity,
            anomaly_score=anomaly_score,
        )
        result["anomaly_score"] = anomaly_score
        breakdown = dict(result.get("breakdown") or {})
        breakdown["anomaly_score"] = anomaly_score
        result["breakdown"] = breakdown
        self._apply_result(incident, result)
        return result

    def _observe_anomaly(self, features: dict[str, float]) -> None:
        try:
            self._anomaly._history.append(self._anomaly._extract_features(features))
            if len(self._anomaly._history) > 500:
                self._anomaly._history = self._anomaly._history[-500:]
        except Exception as exc:
            logger.debug("anomaly observe skipped: %s", exc)

    @staticmethod
    def _build_anomaly_features(
        incident: UnifiedIncident,
        intel_report: dict[str, Any],
        base_severity: float,
    ) -> dict[str, float]:
        now = datetime.now(UTC)
        abuse = float(intel_report.get("abuseipdb", {}).get("abuseConfidenceScore", 0) or 0)
        vt = float(intel_report.get("virustotal", {}).get("malicious", 0) or 0)
        return {
            "hour_of_day": float(now.hour),
            "day_of_week": float(now.weekday()),
            "ip_reputation_score": max(abuse, vt * 10.0),
            "action_risk_level": float(base_severity),
            "request_frequency": float(len(incident.related_incidents) + 1),
        }

    @staticmethod
    def _heuristic_anomaly(features: dict[str, float]) -> float:
        hour = features.get("hour_of_day", 12.0)
        risk = features.get("action_risk_level", 0.0)
        ip_rep = features.get("ip_reputation_score", 0.0)
        if ip_rep >= 80:
            return -0.8
        if (hour >= 23 or hour <= 5) and risk >= 7:
            return -0.7
        if risk >= 9:
            return -0.55
        return 0.0

    @staticmethod
    def _apply_result(incident: UnifiedIncident, result: dict[str, Any]) -> None:
        incident.risk_score = float(result.get("risk_score", 0.0))
        incident.decision = str(result.get("decision", "IGNORE"))
        incident.anomaly_score = float(result.get("anomaly_score", 0.0))

    @staticmethod
    def _extract_scc_ip(raw_event: dict[str, Any]) -> str:
        indicator = raw_event.get("indicator", {})
        ip_addresses = indicator.get("ipAddresses", [])
        if ip_addresses:
            return ip_addresses[0]

        for conn in raw_event.get("connections", []):
            remote_ip = conn.get("destinationIp") or conn.get("sourceIp")
            if remote_ip:
                return remote_ip
        return ""

    @staticmethod
    def should_execute_playbook(decision: str) -> bool:
        return decision in {"AUTO_ISOLATE", "EVALUATE"}
