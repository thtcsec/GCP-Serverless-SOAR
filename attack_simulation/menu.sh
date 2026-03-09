#!/bin/bash

# Ensure clear screen for the menu
clear

echo "=================================================="
echo "      GCP Serverless SOAR - Attack Simulator      "
echo "=================================================="
echo -e "\nPlease ensure that you have mounted your ~/.config/gcloud."
echo -e "Or pass the GOOGLE_APPLICATION_CREDENTIALS into this container.\n"

# Verify GCP Authentication check
echo "Checking GCP Identity..."
if gcloud auth list --filter=status:ACTIVE --format="value(account)" > /dev/null 2>&1; then
    echo "✅ Authentication successful."
else
    echo "⚠️  WARNING: Could not connect to GCP. Check your credentials."
fi

echo "--------------------------------------------------"
echo "1. Simulate GCE Crypto Miner (Port Scan / DNS)"
echo "2. Simulate Cloud Storage Data Exfiltration"
echo "3. Simulate Service Account Compromise (SCC Trigger)"
echo "4. Run All GCP Simulations"
echo "0. Exit"
echo "--------------------------------------------------"

read -p "Select an option [0-4]: " opt

case $opt in
    1)
        echo -e "\n[*] Running GCE Crypto Miner Simulation..."
        /attacks/scripts/gcp_miner.sh
        ;;
    2)
        echo -e "\n[*] Running Cloud Storage Exfiltration Simulation..."
        /attacks/scripts/gcp_storage_exfil_simulation.sh
        ;;
    3)
        echo -e "\n[*] Running Service Account Compromise Simulation..."
        /attacks/scripts/gcp_sa_compromise_simulation.sh
        /attacks/scripts/trigger_scc.sh
        ;;
    4)
        echo -e "\n[*] Running ALL GCP Simulations sequentially..."
        /attacks/scripts/gcp_miner.sh
        /attacks/scripts/gcp_storage_exfil_simulation.sh
        /attacks/scripts/gcp_sa_compromise_simulation.sh
        /attacks/scripts/trigger_scc.sh
        ;;
    0)
        echo "Exiting Attack Simulator."
        exit 0
        ;;
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac

echo -e "\n[*] Simulation completed."
