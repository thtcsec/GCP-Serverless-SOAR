# Re-export integration classes for backwards compatibility and test patching.
from .ai_summarizer import AISummarizer
from .anomaly_detector import AnomalyDetector
from .intel import ThreatIntelService
from .jira import create_jira_issue
from .jira_manager import JiraManager
from .scoring import ScoringEngine
from .siem_forwarder import SIEMForwarder
from .slack_notifier import SlackNotifier

__all__ = [
    "AISummarizer",
    "AnomalyDetector",
    "ThreatIntelService",
    "create_jira_issue",
    "JiraManager",
    "ScoringEngine",
    "SIEMForwarder",
    "SlackNotifier",
]
