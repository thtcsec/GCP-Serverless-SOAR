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

variable "enable_slack_integration" {
  description = "Whether to enable Slack integration"
  type        = bool
  default     = true
}

variable "enable_jira_integration" {
  description = "Whether to enable Jira integration"
  type        = bool
  default     = true
}

variable "enable_siem_integration" {
  description = "Whether to enable SIEM integration"
  type        = bool
  default     = true
}

variable "labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default = {
    project    = "soar"
    managed-by = "terraform"
  }
}
