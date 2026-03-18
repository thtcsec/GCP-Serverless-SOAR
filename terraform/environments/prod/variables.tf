variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
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

variable "zone" {
  description = "GCP zone for Compute Engine instance"
  type        = string
  default     = "us-central1-a"
}

variable "org_id" {
  description = "GCP Organization ID for org-level policies"
  type        = string
  default     = ""
}

variable "approval_wait_time" {
  description = "Wait time for human approval in seconds"
  type        = number
  default     = 3600 # 1 hour for prod — requires proper review
}

variable "enable_cross_project_access" {
  description = "Whether to enable cross-project SOAR access"
  type        = bool
  default     = true
}

variable "target_project_ids" {
  description = "List of target GCP project IDs for cross-project response"
  type        = list(string)
  default     = []
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
    project     = "soar"
    managed-by  = "terraform"
    environment = "production"
  }
}
