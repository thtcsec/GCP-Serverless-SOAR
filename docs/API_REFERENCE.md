# GCP Serverless SOAR — API & Event Reference

## Table of Contents

- [Overview](#overview)
- [Event Sources & Triggers](#event-sources--triggers)
- [Cloud Function Event Schemas](#cloud-function-event-schemas)
- [Playbook Reference](#playbook-reference)
- [Configuration Reference](#configuration-reference)
- [Custom Metrics Reference](#custom-metrics-reference)
- [Integration Endpoints](#integration-endpoints)
- [Error Handling](#error-handling)

---

## Overview

The GCP Serverless SOAR Engine is an event-driven remediation platform triggered by GCP security services. It receives events via **Eventarc → Pub/Sub → Cloud Functions** and dispatches them to the appropriate playbook for automated incident response.

**Architecture Flow:**
```
SCC/ETD/Audit Logs → Eventarc → Pub/Sub → Cloud Function (SOAR Engine) → Playbook Execution
                                    ↓
                                  DLQ (failed events)
```

---

## Event Sources & Triggers

| Source Service | Event Category | Finding Type | Target Playbook |
|---|---|---|---|
| Security Command Center | Compute findings | `MALWARE`, `CRYPTOMINING`, `SUSPICIOUS_NETWORK` | GCEContainmentPlaybook |
| Cloud Audit Logs (IAM) | IAM events | `SetIamPolicy`, `CreateServiceAccountKey`, `CreateServiceAccount`, `InsertProjectOwner`, `SetProjectIamAdmin` | SACompromisePlaybook |
| Cloud Audit Logs (Storage) | Storage events | `storage.objects.get`, `storage.objects.list`, `storage.buckets.get` | StorageExfiltrationPlaybook |

---

## Cloud Function Event Schemas

### SCC Finding (Pub/Sub Message)

```json
{
  "message": {
    "data": "<base64-encoded-json>",
    "attributes": {
      "source": "scc"
    }
  }
}
```

**Decoded `data` payload:**
```json
{
  "finding": {
    "name": "organizations/123/sources/456/findings/789",
    "category": "MALWARE",
    "severity": "CRITICAL",
    "resourceName": "//compute.googleapis.com/projects/myproject/zones/us-central1-a/instances/instance-1",
    "state": "ACTIVE",
    "sourceProperties": {},
    "eventTime": "2026-03-01T00:00:00Z",
    "createTime": "2026-03-01T00:00:00Z"
  },
  "resource": {
    "name": "//compute.googleapis.com/projects/myproject/zones/us-central1-a/instances/instance-1",
    "projectDisplayName": "My Project",
    "type": "google.compute.Instance"
  }
}
```

### IAM Audit Log Event

```json
{
  "protoPayload": {
    "methodName": "SetIamPolicy",
    "authenticationInfo": {
      "principalEmail": "attacker@project.iam.gserviceaccount.com"
    },
    "serviceName": "iam.googleapis.com",
    "request": {},
    "response": {}
  },
  "resource": {
    "type": "service_account",
    "labels": {
      "email_id": "target-sa@project.iam.gserviceaccount.com",
      "project_id": "my-project"
    }
  },
  "severity": "NOTICE",
  "timestamp": "2026-03-01T00:00:00Z"
}
```

### Storage Audit Log Event

```json
{
  "protoPayload": {
    "methodName": "storage.objects.get",
    "authenticationInfo": {
      "principalEmail": "user@example.com"
    },
    "serviceName": "storage.googleapis.com",
    "resourceName": "projects/_/buckets/sensitive-bucket/objects/secret.txt"
  },
  "resource": {
    "type": "gcs_bucket",
    "labels": {
      "bucket_name": "sensitive-bucket",
      "project_id": "my-project"
    }
  },
  "severity": "INFO",
  "timestamp": "2026-03-01T00:00:00Z"
}
```

---

## Playbook Reference

### GCEContainmentPlaybook

**Trigger:** SCC finding with `category` in `[MALWARE, CRYPTOMINING, SUSPICIOUS_NETWORK]`

**Actions Performed:**
1. **Network Isolation** — Removes all network tags and applies isolation firewall rules
2. **Forensic Snapshot** — Creates a disk snapshot of all attached disks with forensic labels
3. **Instance Stop** — Stops the compromised GCE instance
4. **Metadata Lock** — Removes SSH keys from instance metadata

**Required Configuration:**
| Variable | Description |
|---|---|
| `GCP_PROJECT` | GCP project ID |

---

### SACompromisePlaybook

**Trigger:** IAM audit event with `methodName` in `[SetIamPolicy, CreateServiceAccountKey, CreateServiceAccount, InsertProjectOwner, SetProjectIamAdmin]`

**Actions Performed:**
1. **Disable Service Account Keys** — Lists and disables all keys for the compromised service account
2. **Disable Service Account** — Disables the service account itself to prevent further API calls

---

### StorageExfiltrationPlaybook

**Trigger:** Storage audit event with `methodName` in `[storage.objects.get, storage.objects.list, storage.buckets.get]`

**Actions Performed:**
1. **Lock Bucket** — Applies Uniform Bucket-Level Access to prevent direct ACL manipulation
2. **Remove Offending IAM** — Revokes the offending principal's access to the bucket
3. **Enable Versioning** — Ensures object versioning is enabled to preserve evidence

---

## Configuration Reference

Configuration is managed via the `SOARConfig` dataclass, reading from environment variables.

| Variable | Type | Default | Description |
|---|---|---|---|
| `GCP_PROJECT` | `str` | `""` | GCP project ID for API calls |
| `LOG_LEVEL` | `str` | `"INFO"` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `REGION` | `str` | `"us-central1"` | Default GCP region |
| `SLACK_WEBHOOK_URL` | `str` | `""` | Slack webhook for incident notifications |

---

## Custom Metrics Reference

All metrics are emitted to **Cloud Monitoring** under the namespace `custom.googleapis.com/soar/`.

| Metric Name | Unit | Labels | Description |
|---|---|---|---|
| `FindingsProcessed` | Count | `playbook` | Number of findings processed per playbook |
| `PlaybookSuccess` | Count | `playbook` | Successful playbook executions |
| `PlaybookFailure` | Count | `playbook` | Failed playbook executions |
| `PlaybookDuration` | Milliseconds | `playbook` | Execution time of each playbook run |

### Tracing

- **Provider:** OpenTelemetry SDK → Cloud Trace exporter
- **Tracer Name:** `soar-engine`
- **Span Convention:** One span per playbook execution, with attributes for finding ID and severity

---

## Integration Endpoints

### Slack Notifier
- **Purpose:** Sends incident alerts to a Slack channel via webhook
- **Configuration:** `SLACK_WEBHOOK_URL` stored in Secret Manager
- **Payload:** JSON with incident details, severity, and remediation status

### Jira Manager
- **Purpose:** Creates Jira tickets for security incidents
- **Configuration:** `JIRA_URL`, `JIRA_PROJECT_KEY`, `JIRA_API_TOKEN` in Secret Manager
- **Ticket Fields:** Summary, description, priority (mapped from severity), labels

### SIEM Forwarder
- **Purpose:** Forwards enriched events to external SIEM (Splunk, ELK, Chronicle)
- **Configuration:** `SIEM_ENDPOINT`, `SIEM_API_KEY` in Secret Manager
- **Format:** JSON with original event + remediation actions + timestamps

---

## Error Handling

### Cloud Function Error Strategy

| Scenario | Behavior |
|---|---|
| Valid event, playbook succeeds | Returns `200 OK`, metrics emitted |
| Valid event, no matching playbook | Returns `200 OK`, event logged and ignored |
| Valid event, playbook fails | Returns `200 OK`, error logged, `PlaybookFailure` metric emitted |
| Invalid event data | Returns `200 OK`, logged as warning |
| Unhandled exception | Returns `500`, message retried via Pub/Sub (then DLQ after max retries) |

### Dead Letter Queue

Failed messages are routed to a Pub/Sub DLQ subscription after the configured retry limit. The DLQ is monitored via a Cloud Monitoring alert policy.
