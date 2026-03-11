# 🧠 Internal Architecture: GCP Serverless SOAR

An advanced **Security Orchestration** framework with multi-source intelligence, AI/ML anomaly detection, and granular containment strategy.

## 1. Core Components

*   **Detection Layer (SCC, Cloud Audit Logs, Event Threat Detection, VPC Flow Logs):** Real-time monitoring of Service Account misuse, Storage bucket exfiltration, and network anomalies.
*   **Intelligence & Scoring Layer:**
    *   **VirusTotal:** Cross-references source IPs against global threat databases (~70 engines).
    *   **AbuseIPDB:** Filters out scanners and known brute-force bots based on community-sourced reputation.
    *   **ML Anomaly Detection (Isolation Forest):** Behavioral analysis using feature vectors (`hour_of_day`, `day_of_week`, `ip_reputation_score`, `action_risk_level`, `request_frequency`) with Z-Score fallback.
    *   **Scoring Engine (0-100):** Dynamically calculates `risk_score` combining threat intel confidence, finding severity, and anomaly boost (+15). Outputs: `IGNORE (<40)`, `REQUIRE_APPROVAL (40-70)`, `AUTO_ISOLATE (>70)`.
*   **Workflow Orchestration:**
    *   **Event Routing:** Eventarc → Pub/Sub Topic for event-driven delivery.
    *   **Workflow Engine:** Cloud Workflows → Cloud Functions (Remediation Worker) + Cloud Run (Forensic Analyst).
    *   **Human Approval:** Slack/Jira integration for human-in-the-loop decisions.
    *   **Event Normalization:** Converts native events into `UnifiedIncident` schema for cross-cloud compatibility.
    *   **Incident Correlator:** Groups related alerts by shared IOCs (IP, actor, ±5 min window) to detect multi-stage campaigns.
*   **Containment Hierarchy (Function > Process > Permissions > Network):**
    *   **Process-Level:** Kill malicious processes and quarantine files via Compute Engine metadata scripts.
    *   **Permissions-Level:** Revoke SA keys, disable Service Account, remove IAM bindings.
    *   **Network-Level:** Block egress traffic via Firewall rules or network tags (last resort).

## 2. Response Flow

1.  **Enrichment:** On receiving a finding, the system queries multiple Threat Intel sources and runs ML anomaly detection.
2.  **Scoring:** The Scoring Engine evaluates all signals and calculates the risk score with anomaly boost.
    *   Low risk → **Logged & Ignored**.
    *   Medium risk → **Alert Sent (Awaiting Human Approval)**.
    *   High risk → **Automated Containment** (process kill → credential revocation → network isolation).
3.  **Remediation:**
    *   **Process Containment:** Kill suspicious processes (xmrig, cryptominer) via metadata script.
    *   **Identity Lockdown:** SA keys disabled, IAM roles stripped.
    *   **Network Isolation:** Firewall rules applied.
    *   **Evidence Collection:** Persistent disk snapshots captured for IR teams.
4.  **Audit & Compliance:** All actions logged to immutable audit trail (Cloud Logging → GCS archival). Full context published to Jira for governance.

## 3. Observability & Security Hardening

*   **Cloud Monitoring Dashboard (Terraform):** Function execution volume, error rate, MTTR, Pub/Sub depth, Cloud Workflows status, Cloud Run metrics.
*   **Alerting Policies:** Auto-alert on Cloud Function errors and Pub/Sub backlogs.
*   **Secret Rotation:** 90-day rotation policy for all API keys via Secret Manager.
*   **Audit Logger:** Structured audit trail for every SOAR action with Cloud Logging + GCS archival.

## 4. Why Serverless?
*   **Cost:** You don't pay for idle. The platform only costs ~$5-15/month for low/moderate traffic.
*   **Speed:** It reacts in milliseconds, far faster than any human operator.
*   **Scale:** Whether 1 or 1,000 incidents, GCP auto-scales Cloud Functions and Cloud Run to handle them all simultaneously.

---
**Bottom Line:** A "Self-Healing" security perimeter with multi-layer intelligence, ML anomaly detection, and granular containment — from killing a single process to full network lockdown. 🛡️
