# 🧠 How it Works: GCP Serverless SOAR (Simplified)

Think of this system as an **Automatic Quarantine Chamber** for your Google Cloud servers.

## 1. Key Roles (The Cast)

*   **Security Command Center - SCC (The Watchtower):** This is Google's built-in security center. It scans your projects for vulnerabilities or suspicious behavior (e.g., Cryptocurrency mining).
*   **Pub/Sub (The Courier):** When SCC detects a thief, it writes an alarm letter and drops it into the Pub/Sub mailbox.
*   **Cloud Functions (The Responder):** As soon as a letter arrives in the mailbox, this "Robot" (your Python code) awakens to handle the scene.
*   **Cloud Armor / Firewall (The Barrier):** The keys used to lock the thief inside.

## 2. The Automated "Remediation" Flow

1.  **Alarm:** SCC detects malware on a Virtual Machine (GCE) and sends a signal.
2.  **Trigger:** The Cloud Function receives the signal and starts its "Playbook."
3.  **Action:** The "Robot" performs these steps in a flash:
    *   **Isolation:** Applies the `isolated-vm` Network Tag. Instantly, all Firewall rules kick in to block all traffic. The hacker loses connection.
    *   **SSH Block:** Disables project-wide SSH keys for that machine, preventing any "backdoor" access.
    *   **SA Detach:** Removes the Service Account (permissions) from the machine so the hacker can't reach your databases or file buckets.
    *   **Snapshot:** Creates a backup "image" of the drive so you can investigate the "crime scene" later.
4.  **Notify:** Opens a **Jira Incident Ticket** to keep a record for the security team.

## 3. Why This Is Powerful
*   **Total Automation:** If a hack happens at 3:00 AM, the system locks the hacker out while you sleep.
*   **Scaling:** Whether 1 or 1,000 servers are attacked, GCP spawns 1,000 "Robots" to handle them all simultaneously.

---
**Bottom Line:** You have built a "Self-Healing" security perimeter. In the world of Cloud Computing, this is the gold standard of defense! 🛡️
