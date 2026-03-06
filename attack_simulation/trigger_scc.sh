#!/bin/bash
# Script to directly trigger the Cloud Function by publishing to Pub/Sub
# Use this to test the Playbook WITHOUT waiting for actual SCC detection.

PROJECT_ID=$1
ZONE=$2
INSTANCE_NAME=$3

if [ -z "$PROJECT_ID" ] || [ -z "$ZONE" ] || [ -z "$INSTANCE_NAME" ]; then
  echo "Usage: ./trigger_scc.sh <PROJECT_ID> <VM_ZONE> <VM_NAME>"
  echo "Example: ./trigger_scc.sh my-gcp-project us-central1-a gce-target-01"
  exit 1
fi

echo "[*] Constructing fake SCC High Severity Finding..."

# Create the fake payload mimicking SCC output
PAYLOAD=$(cat <<EOF
{
  "finding": {
    "name": "projects/${PROJECT_ID}/sources/12345/findings/abcdef",
    "parent": "projects/${PROJECT_ID}/sources/12345",
    "resourceName": "//compute.googleapis.com/projects/${PROJECT_ID}/zones/${ZONE}/instances/${INSTANCE_NAME}",
    "state": "ACTIVE",
    "category": "Cryptocurrency mining",
    "severity": "HIGH",
    "eventTime": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  }
}
EOF
)

# SCC natively sends just the finding object inside the PubSum message
echo "[*] Publishing to Pub/Sub topic: scc-high-severity-findings..."
gcloud pubsub topics publish scc-high-severity-findings --message="$PAYLOAD"

echo "[+] Message published! Check your Cloud Function logs."
