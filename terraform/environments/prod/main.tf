# Production Environment Configuration
terraform {
  required_version = ">= 1.0"

  backend "gcs" {
    bucket = "soar-tf-state-prod"
    prefix = "terraform/state"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ==========================================
# Root infra (network, security, compute, function - single module)
# ==========================================
module "infra" {
  source = "../../"

  project_id = var.project_id
  region     = var.region
  zone       = var.zone
}

# ==========================================
# Security Enterprise (from modules/)
# ==========================================
module "security_enterprise" {
  source = "../../modules/security"

  environment = var.environment
  project_id  = var.project_id
  region      = var.region

  enable_cross_project_access = var.enable_cross_project_access
  target_project_ids          = var.target_project_ids
  org_id                      = var.org_id

  labels = var.labels
}

# ==========================================
# Enterprise Modules
# ==========================================
module "workflows" {
  source = "../../modules/workflows"

  environment              = var.environment
  project_id               = var.project_id
  region                   = var.region
  approval_wait_time        = var.approval_wait_time
  isolation_firewall_name  = module.infra.isolation_firewall_name
  labels                   = var.labels
}

module "queues" {
  source = "../../modules/queues"

  environment             = var.environment
  project_id              = var.project_id
  region                  = var.region
  message_processor_image = "${var.region}-docker.pkg.dev/${var.project_id}/soar-containers/message-processor:latest"
  labels                  = var.labels
}

module "containers" {
  source = "../../modules/containers"

  environment             = var.environment
  project_id              = var.project_id
  region                  = var.region
  isolation_worker_image   = "${var.region}-docker.pkg.dev/${var.project_id}/soar-containers/isolation-worker:latest"
  forensics_worker_image   = "${var.region}-docker.pkg.dev/${var.project_id}/soar-containers/forensics-worker:latest"
  isolation_firewall_name = module.infra.isolation_firewall_name
  labels                  = var.labels
}

module "integrations" {
  source = "../../modules/integrations"

  environment              = var.environment
  project_id               = var.project_id
  region                   = var.region
  enable_slack_integration  = var.enable_slack_integration
  enable_jira_integration  = var.enable_jira_integration
  enable_siem_integration   = var.enable_siem_integration
  labels                   = var.labels
}
