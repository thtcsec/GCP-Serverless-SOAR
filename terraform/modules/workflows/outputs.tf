output "incident_response_workflow_id" {
  description = "ID of the incident response workflow"
  value       = google_workflows_workflow.incident_response.id
}

output "detect_severity_workflow_id" {
  description = "ID of the severity detection workflow"
  value       = google_workflows_workflow.detect_severity.id
}

output "isolate_instance_workflow_id" {
  description = "ID of the instance isolation workflow"
  value       = google_workflows_workflow.isolate_instance.id
}

output "create_snapshot_workflow_id" {
  description = "ID of the snapshot creation workflow"
  value       = google_workflows_workflow.create_snapshot.id
}

output "workflow_service_account_email" {
  description = "Email of the workflow service account"
  value       = google_service_account.workflow_sa.email
}
