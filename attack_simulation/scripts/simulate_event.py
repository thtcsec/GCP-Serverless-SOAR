import json
import argparse
from datetime import UTC, datetime

from src.handlers import handle_event

def simulate_event(scenario: str):
    print(f"Simulating GCP event for scenario: {scenario}")
    
    if scenario in ("ransomware", "gke_pod_isolation"):
        mock_event = {
            "name": f"organizations/123/sources/456/findings/{scenario}",
            "severity": "HIGH",
            "category": "Execution: Malicious binary" if scenario == "gke_pod_isolation" else "Malware",
            "resourceName": "//compute.googleapis.com/projects/mock-project/zones/us-central1-a/instances/mock-instance" if scenario == "ransomware" else "//container.googleapis.com/projects/mock-project/locations/us-central1/clusters/mock-cluster",
            "resource": {
                "type": "google.compute.Instance" if scenario == "ransomware" else "k8s.io/Node"
            },
            "sourceProperties": {}
        }
        if scenario == "gke_pod_isolation":
            mock_event["sourceProperties"] = {
                "cluster_name": "mock-cluster",
                "namespace": "default",
                "pod": "compromised-pod-123"
            }
            
    elif scenario == "iam_compromise":
        mock_event = {
            "protoPayload": {
                "methodName": "SetIamPolicy",
                "resourceName": "projects/mock-project/serviceAccounts/mock-sa@mock.iam.gserviceaccount.com",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "attacker@evil.com"},
                "status": {},
                "request": {}
            }
        }
    
    elif scenario == "cloudsql_compromise":
        mock_event = {
            "protoPayload": {
                "methodName": "cloudsql.instances.update",
                "resourceName": "projects/mock-project/instances/mock-db",
                "serviceName": "cloudsql.googleapis.com",
                "authenticationInfo": {"principalEmail": "attacker@evil.com"},
                "status": {},
                "request": {}
            }
        }
    else:
        print("Unknown scenario")
        return

    print("Simulating event submission to GCP Handler...")
    response = handle_event(mock_event)
    print(f"Function Response: {json.dumps(response, indent=2)}")

    # Write mock audit to local file for dashboard
    log_file = "audit.log"
    with open(log_file, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now(UTC).isoformat(),
            "action": f"PLAYBOOK_TRIGGERED: {scenario}",
            "resource_id": mock_event.get("resourceName", "N/A"),
            "actor": "GCP_SIMULATOR",
            "success": response.get("statusCode") == 200,
            "details": response
        }) + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=str, default="ransomware", help="Scenario to simulate")
    args = parser.parse_args()
    simulate_event(args.scenario)
