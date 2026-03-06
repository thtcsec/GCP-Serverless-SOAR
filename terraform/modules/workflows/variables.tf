variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "approval_wait_time" {
  description = "Wait time for human approval in seconds"
  type        = number
  default     = 3600 # 1 hour
}

variable "isolation_firewall_name" {
  description = "Name of the isolation firewall rule"
  type        = string
  default     = "soar-isolation-firewall"
}

variable "labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default = {
    project     = "soar"
    managed-by  = "terraform"
    environment = "production"
  }
}
