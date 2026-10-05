import os
import time
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_ecdat_zip():
    zip_path = r"c:\Users\user\Downloads\ecdat-test-project (2).zip"
    if not os.path.exists(zip_path):
        print("Zip path not found:", zip_path)
        return

    print("Uploading ecdat-test-project (2).zip ...")
    with open(zip_path, "rb") as f:
        files = {"file": ("ecdat-test-project.zip", f, "application/zip")}
        r = requests.post(f"{BASE_URL}/scans/upload?project_name=ECDAT%20Test%20Project", files=files)
    
    assert r.status_code == 202
    scan_id = r.json()["scan_id"]
    print("Scan ID:", scan_id)

    for _ in range(30):
        r = requests.get(f"{BASE_URL}/scans/{scan_id}/status")
        status_data = r.json()
        print(f"Status: {status_data['status']} | Stage: {status_data['stage']} | Progress: {status_data['progress_percentage']}%")
        if status_data["status"] in ("completed", "failed"):
            break
        time.sleep(1)

    r_scans = requests.get(f"{BASE_URL}/scans")
    print("\n--- Scans List ---")
    print(r_scans.json())

    r_findings = requests.get(f"{BASE_URL}/scans/{scan_id}/findings")
    findings = r_findings.json()
    print(f"\n--- Findings Count: {len(findings)} ---")
    for f in findings:
        print("Finding:", {
            "id": f.get("id"),
            "artifact_type": f.get("artifact_type"),
            "algorithm": f.get("algorithm"),
            "risk_score": f.get("risk_score"),
            "risk_band": f.get("risk_band"),
            "confidence": f.get("confidence"),
            "sensitivity": f.get("sensitivity"),
            "quantum_class": f.get("quantum_class"),
            "shor_vulnerable": f.get("shor_vulnerable"),
        })

    r_risk = requests.get(f"{BASE_URL}/scans/{scan_id}/risk")
    print("\n--- Risk API ---")
    print(r_risk.json())

if __name__ == "__main__":
    test_ecdat_zip()
