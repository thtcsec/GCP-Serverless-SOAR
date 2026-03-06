# Existing Infrastructure Outputs
output "network_self_link" {
  description = "Self link of the VPC network"
  value       = module.network.network_self_link
}

output "subnet_self_link" {
  description = "Self link of the subnet"
  value       = module.network.subnet_self_link
}

output "isolation_firewall_name" {
  description = "Name of the isolation firewall rule"
  value       = module.security.isolation_firewall_name
}

# Enterprise Module Outputs
output "incident_response_workflow_id" {
  description = "ID of the incident response workflow"
  value       = module.workflows.incident_response_workflow_id
}

output "security_events_topic" {
  description = "Name of the security events Pub/Sub topic"
  value       = module.queues.security_events_topic
}

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
