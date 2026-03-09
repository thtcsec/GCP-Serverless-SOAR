#!/bin/bash
# Simulation script to trigger Service Account compromise detection
# This script simulates suspicious service account activities to test the SOAR playbook

PROJECT_ID=$1
SA_NAME=${2:-"test-sa-compromise"}

if [ -z "$PROJECT_ID" ]; then
    echo "Usage: ./gcp_sa_compromise_simulation.sh <project-id> [service-account-name]"
    echo "Example: ./gcp_sa_compromise_simulation.sh my-gcp-project test-sa-compromise"
    exit 1
fi

SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

echo "[*] Starting Service Account compromise simulation..."
echo "[*] Project ID: $PROJECT_ID"
echo "[*] Service Account: $SA_EMAIL"

# Create test service account
echo "[*] Creating test service account..."
gcloud iam service-accounts create $SA_NAME \
    --description="Test service account for compromise simulation" \
    --display-name="Test SA Compromise" \
    --project=$PROJECT_ID 2>/dev/null || echo "Service account already exists"

# Create service account key (suspicious activity)
echo "[*] Creating service account key (suspicious activity)..."
gcloud iam service-accounts keys create ~/sa-key.json \
    --iam-account=$SA_EMAIL \
    --project=$PROJECT_ID

# Grant excessive permissions
echo "[*] Granting excessive permissions (suspicious activity)..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/editor"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/storage.admin"

# Simulate key creation from multiple sources (compromise pattern)
echo "[*] Simulating multiple key creations..."
for i in {1..3}; do
    gcloud iam service-accounts keys create ~/sa-key-${i}.json \
        --iam-account=$SA_EMAIL \
        --project=$PROJECT_ID &
done

wait

# Enable additional sensitive APIs
echo "[*] Enabling sensitive APIs..."
gcloud services enable compute.googleapis.com --project=$PROJECT_ID
gcloud services enable iam.googleapis.com --project=$PROJECT_ID
gcloud services enable cloudresourcemanager.googleapis.com --project=$PROJECT_ID

# Grant compute admin role
echo "[*] Granting compute admin role..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/compute.admin"

# Create additional service accounts (privilege escalation pattern)
echo "[*] Creating additional service accounts (privilege escalation)..."
for i in {1..2}; do
    gcloud iam service-accounts create "${SA_NAME}-escalated-${i}" \
        --description="Escalated service account ${i}" \
        --display-name="Escalated SA ${i}" \
        --project=$PROJECT_ID &
done

wait

# Clean up key files (but keep the first one for testing)
echo "[*] Cleaning up key files..."
rm -f ~/sa-key-1.json ~/sa-key-2.json ~/sa-key-3.json

echo "[+] Service Account compromise simulation complete!"
echo "[*] Check your Cloud Audit Logs for:"
echo "    - Service account creation events"
echo "    - Service account key creation"
echo "    - IAM policy binding changes"
echo "    - Role assignments"
echo "    - API enablement events"
echo "[*] The SOAR playbook should detect these suspicious activities"
echo "[*] Test key file location: ~/sa-key.json"
