# 🧠 Internal Architecture: GCP Serverless SOAR

An advanced **Security Orchestration** framework using multi-source signal enrichment for automated incident response.

## 1. Core Pillars

*   **Ingestion (SCC & Cloud Audit Logs):** Real-time monitoring of Service Account (SA) misuse and Storage bucket exfiltration patterns.
*   **Enrichment Engine:**
    *   **VirusTotal Integration:** Cross-references source IPs against global threat databases (~70 engines).
    *   **AbuseIPDB Integration:** Filters out scanners and known brute-force bots based on community-sourced reputation scores.
*   **Orchestration (Scoring Engine):**
    *   Translates raw signals into actionable **Risk Scores**.
    *   Automated decision logic: `AUTO_ISOLATE` for critical threats, `REQUIRE_APPROVAL` for suspicious telemetry.
*   **Execution (Cloud Functions):** Event-triggered responders that execute surgical remediation playbooks.

## 2. Automated Remediation Flow

1.  **Signal:** SCC detects a suspicious Service Account key creation or high-volume data download from Cloud Storage.
2.  **Analysis:** The system enriches the finding with external Threat Intel. If the IP has a high **Abuse Confidence Score**, it triggers isolation.
3.  **Action (Surgical Response):**
    *   **Identity Lockdown:** Disables SA keys and removes critical IAM roles (Project Editor/Owner).
    *   **Network Isolation:** Blocks egress traffic via Cloud Armor or dynamic Firewall tags.
    *   **Bucket Protection:** Enables S3/Storage Versioning and Object Lock to prevent data tampering.
    *   **Evidence:** Captures persistent disk snapshots for IR teams.
4.  **Governance:** Publishes full incident context to Pub/Sub and creates a **Jira** forensic record.

## 3. Why This Is Powerful
*   **Total Automation:** If a hack happens at 3:00 AM, the system locks the hacker out while you sleep.
*   **Scaling:** Whether 1 or 1,000 servers are attacked, GCP spawns 1,000 "Robots" to handle them all simultaneously.

---
**Bottom Line:** You have built a "Self-Healing" security perimeter. In the world of Cloud Computing, this is the gold standard of defense! 🛡️
