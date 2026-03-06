"""
GCP SOAR Workflow — Detect Severity
Classifies the severity of an SCC finding and enriches the event
with priority and threat-context metadata.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

import functions_framework

logger = logging.getLogger("gcp-soar.workflow.severity")

SEVERITY_THRESHOLDS = {
    "CRITICAL": 8.0,
    "HIGH": 6.0,
    "MEDIUM": 4.0,
}

PRIORITY_MAP = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
}

THREAT_KEYWORDS = {
    "malware": ["Malware", "Trojan", "Backdoor", "Ransomware"],
    "exfiltration": ["Exfiltration", "Data Loss", "Unauthorized Copy"],
    "lateral_movement": ["Lateral Movement", "Port Scan", "Reconnaissance"],
    "persistence": ["Persistence", "Cryptocurrency mining", "Crypto", "ServiceAccountKey"],
}


def classify_severity(score: float) -> str:
    for level, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return level
    return "LOW"


def detect_threat_context(category: str) -> list[str]:
    contexts = []
    for ctx, keywords in THREAT_KEYWORDS.items():
        if any(kw.lower() in category.lower() for kw in keywords):
            contexts.append(ctx)
    return contexts or ["unknown"]


@functions_framework.http
def detect_severity(request):
    """HTTP Cloud Function invoked by Cloud Workflows."""
    body = request.get_json(silent=True) or {}

    severity_str = body.get("severity", "MEDIUM")
    category = body.get("category", "")

    # SCC severity is a string; normalise to a numeric score for threshold logic
    score_map = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.0}
    score = score_map.get(severity_str, 5.0)

    classification = classify_severity(score)
    threat_contexts = detect_threat_context(category)

    result = {
        **body,
        "severity_classification": classification,
        "severity_score": score,
        "priority": PRIORITY_MAP.get(classification, "P4"),
        "threat_contexts": threat_contexts,
    }

    logger.info(f"Severity classified: {classification} / {PRIORITY_MAP.get(classification)}")
    return json.dumps(result), 200, {"Content-Type": "application/json"}
