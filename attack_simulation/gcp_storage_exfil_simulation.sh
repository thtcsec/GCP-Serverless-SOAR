#!/bin/bash
# Simulation script to trigger Cloud Storage data exfiltration detection
# This script simulates large volume Cloud Storage downloads to test the SOAR playbook

BUCKET_NAME=$1
PROJECT_ID=$2

if [ -z "$BUCKET_NAME" ] || [ -z "$PROJECT_ID" ]; then
    echo "Usage: ./gcp_storage_exfil_simulation.sh <bucket-name> <project-id>"
    echo "Example: ./gcp_storage_exfil_simulation.sh my-test-bucket my-gcp-project"
    exit 1
fi

echo "[*] Starting Cloud Storage data exfiltration simulation..."
echo "[*] Target bucket: $BUCKET_NAME"
echo "[*] Project ID: $PROJECT_ID"

# Create some test files to upload
echo "[*] Creating test files..."
dd if=/dev/zero of=test_file_1MB.bin bs=1M count=1 2>/dev/null
dd if=/dev/zero of=test_file_10MB.bin bs=1M count=10 2>/dev/null
dd if=/dev/zero of=test_file_100MB.bin bs=1M count=100 2>/dev/null

# Upload files to bucket
echo "[*] Uploading test files to bucket..."
gsutil cp test_file_1MB.bin gs://$BUCKET_NAME/
gsutil cp test_file_10MB.bin gs://$BUCKET_NAME/
gsutil cp test_file_100MB.bin gs://$BUCKET_NAME/

# Simulate high-frequency downloads
echo "[*] Simulating high-frequency downloads..."
for i in {1..50}; do
    gsutil cp gs://$BUCKET_NAME/test_file_1MB.bin ./downloaded_${i}.bin &
    if [ $((i % 10)) -eq 0 ]; then
        wait
        echo "[*] Completed batch $((i/10)) of downloads"
    fi
done

wait

# Simulate large volume download
echo "[*] Simulating large volume download..."
for i in {1..10}; do
    gsutil cp gs://$BUCKET_NAME/test_file_100MB.bin ./large_download_${i}.bin &
done

wait

# Simulate downloads from different "users" (different service accounts)
echo "[*] Simulating downloads from multiple sources..."
for i in {1..3}; do
    gcloud auth activate-service-account --key-file=/dev/null 2>/dev/null || true
    gsutil cp gs://$BUCKET_NAME/test_file_10MB.bin ./multi_source_${i}.bin &
done

wait

# Clean up local files
echo "[*] Cleaning up local files..."
rm -f test_file_*.bin downloaded_*.bin large_download_*.bin multi_source_*.bin

echo "[+] Cloud Storage exfiltration simulation complete!"
echo "[*] Check your Cloud Audit Logs for:"
echo "    - High-frequency storage.objects.get operations"
echo "    - Large volume downloads"
echo "    - Multiple source IP addresses"
echo "[*] The SOAR playbook should trigger if thresholds are exceeded"
