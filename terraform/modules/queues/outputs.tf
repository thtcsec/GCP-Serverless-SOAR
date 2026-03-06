output "security_events_topic" {
  description = "Name of the security events Pub/Sub topic"
  value       = google_pubsub_topic.security_events.name
}

output "security_events_dlq_topic" {
  description = "Name of the security events dead letter topic"
  value       = google_pubsub_topic.security_events_dlq.name
}

output "security_events_subscription" {
  description = "Name of the security events subscription"
  value       = google_pubsub_subscription.security_events_subscription.name
}

output "message_processor_url" {
  description = "URL of the message processor Cloud Run service"
  value       = google_cloud_run_service.message_processor.status[0].url
}

output "message_processor_service_account" {
  description = "Email of the message processor service account"
  value       = google_service_account.message_processor_sa.email
}
