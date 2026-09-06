# Migration guide — v1 → v2 (GCP Serverless SOAR)

## Breaking changes

| Area | v1 | v2 |
|------|----|----|
| Orchestration spine | Cloud Workflows / multi-path often implied | `entrypoint` → `handle_event()` → `IncidentPipeline` only |
| Mid-risk incidents | notify only | persist pending + Slack buttons / API resume |
| Scoring thresholds (lab drift) | some lab trees used 10/25 | canonical **40 / 70** (parity with AWS) |
| Schema | no `trace_id` | `UnifiedIncident.trace_id` required for full dump/resume |

## Upgrade steps

1. Pull tag `v2.0.0` (or download release function zip).
2. Redeploy Cloud Function Gen2 with entry `soar_responder` (and optional `slack_interactions` HTTP).
3. Set env:
   - `SLACK_WEBHOOK_URL`
   - (prod) `SLACK_SIGNING_SECRET`, `APPROVAL_STORE=firestore`, `APPROVAL_FIRESTORE_COLLECTION=...`
   - (lab) `LAB_MOCK_INTEL=true`
4. Confirm scoring: mid-band events stay `REQUIRE_APPROVAL` until approve/reject.
5. Resume test:
   ```json
   {"approval_action":"approve","incident_id":"<id>"}
   ```

## Compatibility

- Playbooks (GCE / SA / Storage / GKE / Cloud SQL / …) still register through `handlers.py`.
- `workflow/_legacy.py` remains for old Terraform entry points only — do not put new logic there.
