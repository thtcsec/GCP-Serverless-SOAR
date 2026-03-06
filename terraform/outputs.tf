output "target_vm_public_ip" {
  description = "Public IP of the target Vulnerable VM for SSH and simulated attacks"
  value       = google_compute_instance.target_vm.network_interface.0.access_config.0.nat_ip
}

output "target_vm_name" {
  description = "Name of the target VM"
  value       = google_compute_instance.target_vm.name
}

output "pubsub_topic" {
  description = "Pub/Sub Topic to route SCC Alerts to"
  value       = google_pubsub_topic.scc_findings_topic.id
}

output "cloud_function_url" {
  description = "URL of the SOAR Cloud Function deployed"
  value       = google_cloudfunctions2_function.soar_responder_function.service_config[0].uri
}
