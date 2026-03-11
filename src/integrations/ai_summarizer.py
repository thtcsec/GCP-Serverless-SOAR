"""
GCP SOAR — AI Incident Summarizer (Google Vertex AI)
Uses Gemini foundation models to generate human-readable incident summaries
from raw UnifiedIncident data, enriching Slack alerts with actionable context.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-3-flash-preview"
DEFAULT_LOCATION = os.environ.get("VERTEX_LOCATION", "us-central1")

SYSTEM_PROMPT = (
    "You are a senior Security Operations Center (SOC) analyst. "
    "Given the structured JSON of a security incident, produce a concise, "
    "actionable summary in 3-5 sentences suitable for a Slack alert. "
    "Include: what happened, which resource is affected, severity assessment, "
    "and your recommended immediate next step. "
    "Do NOT use markdown formatting. Keep it plain text."
)


class AISummarizer:
    """Generate human-readable incident summaries via Google Vertex AI."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        location: str = DEFAULT_LOCATION,
        project_id: Optional[str] = None,
        client: Optional[Any] = None,
    ):
        self.model_name = model_name
        self.location = location
        self.project_id = project_id or os.environ.get(
            "GCP_PROJECT_ID", ""
        )
        self._client = client

    def _get_client(self) -> Any:
        """Lazy-init the Vertex AI GenerativeModel."""
        if self._client is None:
            from google.cloud import aiplatform  # type: ignore
            aiplatform.init(
                project=self.project_id,
                location=self.location,
            )
            from vertexai.generative_models import GenerativeModel  # type: ignore
            self._client = GenerativeModel(
                self.model_name,
                system_instruction=SYSTEM_PROMPT,
            )
        return self._client

    def summarize_incident(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Summarize an incident using Vertex AI Gemini.

        Args:
            incident_data: UnifiedIncident dict or raw finding data.

        Returns:
            Dict with 'summary' (str) and 'model_name' (str).
            On failure returns 'summary' with a fallback message.
        """
        try:
            user_message = (
                "Summarize the following security incident:\n\n"
                + json.dumps(incident_data, indent=2, default=str)
            )

            model = self._get_client()
            response = model.generate_content(user_message)

            summary_text = response.text

            logger.info("AI summary generated successfully.")
            return {
                "summary": summary_text,
                "model_name": self.model_name,
            }

        except Exception as exc:  # noqa: BLE001
            logger.error("AI summarizer error: %s", exc)
            return self._fallback_summary(incident_data)

    # ------------------------------------------------------------------
    # Fallback: deterministic template when AI is unavailable
    # ------------------------------------------------------------------
    @staticmethod
    def _fallback_summary(
        incident_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return a rule-based summary when Vertex AI is unreachable."""
        severity = incident_data.get("severity", "UNKNOWN")
        resource = incident_data.get("resource", "N/A")
        action = incident_data.get("action", "N/A")
        source_ip = incident_data.get("source_ip", "N/A")
        risk_score = incident_data.get("risk_score", 0)
        decision = incident_data.get("decision", "N/A")

        summary = (
            f"[AUTO] {severity} severity incident detected on resource "
            f"'{resource}'. Action: {action}. Source IP: {source_ip}. "
            f"Risk score: {risk_score}/100 → Decision: {decision}. "
            f"AI summary unavailable — review raw finding for details."
        )
        return {"summary": summary, "model_name": "fallback"}
