import time
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"

def run_live_test():
    print("[1] Testing /health ...")
    r = requests.get(f"{BASE_URL}/health")
    assert r.status_code == 200
    print("Health response:", r.json())

    print("\n[2] Testing /system/info ...")
    r = requests.get(f"{BASE_URL}/system/info")
    assert r.status_code == 200
    print("System info:", r.json())

    print("\n[3] Triggering upload scan with sample certificate file ...")
    cert_file_path = "ECDAT-main/samples/certificates/rsa2048_cert.pem"
    with open(cert_file_path, "rb") as f:
        files = {"file": ("rsa2048_cert.pem", f, "application/x-pem-file")}
        r = requests.post(f"{BASE_URL}/scans/upload", files=files)
    
    assert r.status_code == 202
    scan_meta = r.json()
    scan_id = scan_meta["scan_id"]
    print(f"Scan created! scan_id: {scan_id}")

    print("\n[4] Polling scan status ...")
    for _ in range(20):
        r = requests.get(f"{BASE_URL}/scans/{scan_id}/status")
        status_data = r.json()
        print(f"Status: {status_data['status']} | Stage: {status_data['stage']} | Progress: {status_data['progress_percentage']}%")
        if status_data["status"] in ("completed", "failed"):
            break
        time.sleep(1)

    assert status_data["status"] == "completed"

    print("\n[5] Fetching scan findings ...")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    print(f"Found {len(findings)} findings.")
    for f in findings:
        print(f" - Finding ID: {f['id']} | Artifact: {f['artifact_type']} | Algorithm: {f['algorithm']} | Band: {f['risk_band']} | Shor: {f['shor_vulnerable']} | Mosca X/Y/Z: {f['mosca_x']}/{f['mosca_y']}/{f['mosca_z']}")

    print("\n[6] Fetching CBOM JSON ...")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}/cbom")
    assert r.status_code == 200
    cbom = r.json()
    print("CBOM components count:", len(cbom.get("components", [])))

    print("\n[7] Fetching CycloneDX 1.6 export ...")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}/cyclonedx")
    assert r.status_code == 200
    cdx = r.json()
    print("CycloneDX specVersion:", cdx.get("specVersion"))

    print("\n[8] Testing remediation status update ...")
    if findings:
        fid = findings[0]["id"]
        r = requests.post(f"{BASE_URL}/scans/{scan_id}/remediation/{fid}/status", json={"status": "merged", "choice": "bridge"})
        assert r.status_code == 200
        print("Remediation update response:", r.json())

    print("\nSUCCESS: All Live Integration Tests Passed!")

if __name__ == "__main__":
    run_live_test()
