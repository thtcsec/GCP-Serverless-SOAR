"""DEPRECATED — delegates to unified pipeline via workflow.__init__."""

from .__init__ import detect_severity


def classify_severity(payload: dict | float | int) -> str:
    """Deprecated helper retained for legacy tests — use PolicyEngine instead."""
    if isinstance(payload, int | float):
        if payload >= 8:
            return "CRITICAL"
        if payload >= 5:
            return "HIGH"
        return "LOW"

    severity = str(payload.get("severity", "LOW")).upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "AUTO_ISOLATE"
    if severity == "MEDIUM":
        return "REQUIRE_APPROVAL"
    return "IGNORE"


__all__ = ["detect_severity", "classify_severity"]

