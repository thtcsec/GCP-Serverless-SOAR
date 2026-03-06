output "integration_events_topic" {
  description = "Name of the integration events Pub/Sub topic"
  value       = google_pubsub_topic.integration_events.name
}

output "integration_sa_email" {
  description = "Email of the integrations service account"
  value       = google_service_account.integration_sa.email
}

output "slack_notifier_url" {
  description = "URL of the Slack notifier Cloud Function"
  value       = var.enable_slack_integration ? google_cloudfunctions2_function.slack_notifier[0].service_config[0].uri : null
}

output "jira_manager_url" {
  description = "URL of the Jira manager Cloud Function"
  value       = var.enable_jira_integration ? google_cloudfunctions2_function.jira_manager[0].service_config[0].uri : null
}

output "siem_forwarder_url" {
  description = "URL of the SIEM forwarder Cloud Function"
  value       = var.enable_siem_integration ? google_cloudfunctions2_function.siem_forwarder[0].service_config[0].uri : null
}
