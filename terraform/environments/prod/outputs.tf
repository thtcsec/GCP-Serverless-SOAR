# Network
output "network_self_link" {
  description = "Self link of the VPC network"
  value       = module.infra.network_self_link
}

# Security
output "isolation_firewall_name" {
  description = "Name of the isolation firewall rule"
  value       = module.infra.isolation_firewall_name
}

output "soar_central_sa_email" {
  description = "Email of the central SOAR service account"
  value       = module.security_enterprise.soar_central_sa_email
}

# Workflows
output "incident_response_workflow_id" {
  description = "ID of the incident response workflow"
  value       = module.workflows.incident_response_workflow_id
}

# Queues
output "security_events_topic" {
  description = "Name of the security events Pub/Sub topic"
  value       = module.queues.security_events_topic
}

# Containers
output "isolation_worker_url" {
  description = "URL of the isolation worker Cloud Run service"
  value       = module.containers.isolation_worker_url
}

output "forensics_worker_url" {
  description = "URL of the forensics worker Cloud Run service"
  value       = module.containers.forensics_worker_url
}

output "forensics_bucket_name" {
  description = "Name of the forensics storage bucket"
  value       = module.containers.forensics_bucket_name
}
