# Pub/Sub Topic to receive Security Command Center findings
resource "google_pubsub_topic" "scc_findings_topic" {
  name = "scc-high-severity-findings"
}

# Note: Security Command Center requires Organization-level access to configure Continuous Exports via Terraform
# For this lab, we assume the user has configured SCC to export to this topic manually or via org-level TF.
# We will create the topic here for the function to listen to.

# Service Account for the SOAR Cloud Function
resource "google_service_account" "soar_function_sa" {
  account_id   = "soar-responder-sa"
  display_name = "SOAR Responder Service Account"
}

# Grant the SOAR function permissions to execute its playbook
# 1. Compute Admin (to stop instances, change tags, detach SAs, take snapshots)
resource "google_project_iam_member" "soar_compute_admin" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${google_service_account.soar_function_sa.email}"
}

resource "google_project_iam_member" "soar_disk_admin" {
  project = var.project_id
  role    = "roles/compute.storageAdmin"
  member  = "serviceAccount:${google_service_account.soar_function_sa.email}"
}

resource "google_project_iam_member" "soar_iam_admin" {
  project = var.project_id
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:${google_service_account.soar_function_sa.email}"
}

resource "google_project_iam_member" "soar_project_iam_admin" {
  project = var.project_id
  role    = "roles/resourcemanager.projectIamAdmin"
  member  = "serviceAccount:${google_service_account.soar_function_sa.email}"
}

# 2. Allow event routing from PubSub (Cloud function invoker) is handled automatically 
# by Cloud Functions gen2 with Eventarc when we create the binding in function.tf.
