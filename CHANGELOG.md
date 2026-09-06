# Changelog

All notable changes to **GCP Serverless SOAR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-09-06

### Added
- Unified `IncidentPipeline` spine shared with AWS contract
- Slack **interactive approval** with pending store (`memory` / `firestore`)
- Resume API envelope: `{"approval_action":"approve|reject","incident_id":"..."}`
- HTTP `slack_interactions` Cloud Function entry for Slack Interactivity
- Optional HTTP `health` probe in `entrypoint.py`
- `trace_id` on `UnifiedIncident` (parity with AWS)
- Master multi-cloud architecture diagram (`images/master_architecture.png`)
- `LAB_MOCK_INTEL` support for deterministic lab scoring

### Changed
- Scoring bands restored to canonical parity with AWS: IGNORE &lt;40, REQUIRE_APPROVAL 40–69, AUTO_ISOLATE ≥70
- IAM base-risk bands aligned with AWS (risky → 6 else 4, +2 external, +2 off-hours)
- SCC severity ordinals include LOW/MEDIUM mapping
- Optional audit-log responders via `enable_audit_log_responders` (off by default)
- Architecture docs: Cloud Workflows marked legacy delegate only

### Removed / Deprecated
- Workflow YAML / `_legacy.py` as business spine (stubs remain for compatibility)
- Unused deprecated diagram variants purged

### Migration
See [MIGRATION_v2.md](./MIGRATION_v2.md).

## [1.0.0] — 2026-03-11

### Added
- Initial public release: SCC/audit responders, Terraform lab, playbooks
