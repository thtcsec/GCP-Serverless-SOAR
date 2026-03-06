variable "project_id" {
  description = "The GCP Project ID where resources will be deployed"
  type        = string
}

variable "region" {
  description = "The GCP region to deploy resources in"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone for the Compute Engine instance"
  type        = string
  default     = "us-central1-a"
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for the Cloud Function to send incident resolution alerts to the SOC team."
  type        = string
  default     = "" # Provide value in terraform.tfvars or CLI during apply
}

variable "forensic_jump_host_ip" {
  description = "The IP address (CIDR) of the SOC team's jump shell. Used to SSH into isolated VMs."
  type        = string
  default     = "0.0.0.0/0" # Change to actual corporate VPN / Jumpbox IP in real deployment
}
