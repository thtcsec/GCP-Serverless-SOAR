# 🚀 Deployment Guide: GCP Serverless SOAR

This guide walks you through deploying the complete Serverless SOAR platform onto your Google Cloud project using the provided automated script.

## 📋 Prerequisites

Before you begin, ensure you have the following installed and configured on your local machine:

1.  **Google Cloud SDK (`gcloud`):** Installed and configured with a project that has billing enabled.
    ```bash
    gcloud auth login
    gcloud config set project YOUR_PROJECT_ID
    ```
2.  **Terraform:** Version 1.5.0 or newer.
3.  **Docker:** Required for building and pushing the Cloud Run Forensics Worker container to Artifact Registry.
4.  **Bash:** (Windows users can use Git Bash or WSL).

## 🛠️ Automated Deployment

We provide an all-in-one deployment script at `scripts/deploy.sh`. This script will:
1. Enable necessary GCP APIs (Compute, Functions, Workflows, Secret Manager, etc.).
2. Initialize Terraform and create a GCS bucket for remote state.
3. Build the Docker image for the Cloud Run Forensic Worker and push it to Artifact Registry.
4. Deploy all GCP infrastructure using Terraform.
5. Help you configure basic integrations via Secret Manager.

### Step-by-Step

1. **Clone the project:**
   ```bash
   git clone https://github.com/thtcsec/GCP-Serverless-SOAR.git
   cd GCP-Serverless-SOAR
   ```

2. **Run the deployment script:**
   ```bash
   # Make the script executable
   chmod +x ./scripts/deploy.sh
   
   # Deploy the 'prod' environment
   ./scripts/deploy.sh prod deploy
   ```

3. **Provide API Keys (Interactive):**
   During deployment, the script will prompt you for your `VirusTotal` and `AbuseIPDB` API keys so it can configure Threat Intelligence enrichment. You can skip this and configure them later.

---

## 🔗 Configuring Integrations

After deployment, you need to provide the secrets for your integrations securely via Google Secret Manager.

### 1. Slack (Real-time Alerts)
Create an incoming webhook in your Slack workspace and save it:
```bash
gcloud secrets create slack-webhook-url --replication-policy automatic
echo "YOUR_WEBHOOK_URL" | gcloud secrets versions add slack-webhook-url --data-file=-
```

### 2. Jira (Forensic Tracking)
```bash
gcloud secrets create jira-url --replication-policy automatic
echo "https://your-domain.atlassian.net" | gcloud secrets versions add jira-url --data-file=-

gcloud secrets create jira-username --replication-policy automatic
echo "email@example.com" | gcloud secrets versions add jira-username --data-file=-

gcloud secrets create jira-api-token --replication-policy automatic
echo "YOUR_JIRA_TOKEN" | gcloud secrets versions add jira-api-token --data-file=-

gcloud secrets create jira-project-key --replication-policy automatic
echo "SEC" | gcloud secrets versions add jira-project-key --data-file=-
```

### 3. Threat Intelligence
If you skipped the prompt during deployment:
```bash
gcloud secrets create virustotal-api-key --replication-policy automatic
echo "YOUR_VT_KEY" | gcloud secrets versions add virustotal-api-key --data-file=-

gcloud secrets create abuseipdb-api-key --replication-policy automatic
echo "YOUR_ABUSEIPDB_KEY" | gcloud secrets versions add abuseipdb-api-key --data-file=-
```

---

## 🧪 Testing the Deployment

We provide a built-in Attack Simulator to instantly test if the SOAR platform works.

```bash
# Run the Red Team simulator container
docker compose run --rm attacker
```
From the interactive menu, select `1` to trigger the GCE Crypto Miner attack. Within ~15-30 seconds, you should receive a Slack alert, and the targeted Compute Engine VM will be isolated.

## 🧹 Cleanup / Teardown

To destroy all deployed resources and stop incurring costs:
```bash
./scripts/deploy.sh prod cleanup
```
