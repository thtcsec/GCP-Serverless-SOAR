output "soar_central_sa_email" {
  description = "Email of the central SOAR service account"
  value       = google_service_account.soar_central_sa.email
}

output "soar_cross_project_sa_email" {
  description = "Email of the cross-project responder service account"
  value       = var.enable_cross_project_access ? google_service_account.soar_cross_project_sa[0].email : null
}

output "central_logs_bucket_name" {
  description = "Name of the centralized logging bucket"
  value       = google_storage_bucket.central_logs.name
}

output "central_logs_bucket_url" {
  description = "URL of the centralized logging bucket"
  value       = google_storage_bucket.central_logs.url
}

output "audit_log_sink_name" {
  description = "Name of the audit log sink"
  value       = google_logging_project_sink.soar_audit_sink.name
}
