import time
import zipfile
import os
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"

def create_sample_zip(zip_path="sample_project.zip"):
    samples_dir = "ECDAT-main/samples"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(samples_dir):
            for file in files:
                abs_file = os.path.join(root, file)
                rel_file = os.path.relpath(abs_file, samples_dir)
                zipf.write(abs_file, rel_file)
    return zip_path

def test_full_project_zip_scan():
    zip_path = create_sample_zip()
    print(f"\n[Zip Test] Uploading full sample project ZIP ({zip_path}) ...")
    with open(zip_path, "rb") as f:
        files = {"file": ("sample_project.zip", f, "application/zip")}
        r = requests.post(f"{BASE_URL}/scans/upload?project_name=Full%20Sample%20Project", files=files)
    
    assert r.status_code == 202
    scan_meta = r.json()
    scan_id = scan_meta["scan_id"]
    print(f"Zip scan created! scan_id: {scan_id}")

    for _ in range(30):
        r = requests.get(f"{BASE_URL}/scans/{scan_id}/status")
        status_data = r.json()
        print(f"Status: {status_data['status']} | Stage: {status_data['stage']} | Progress: {status_data['progress_percentage']}%")
        if status_data["status"] in ("completed", "failed"):
            break
        time.sleep(1)

    assert status_data["status"] == "completed"

    r = requests.get(f"{BASE_URL}/scans/{scan_id}/findings")
    if r.status_code != 200:
        print("Findings error response code:", r.status_code)
        print("Findings response text:", r.text[:1000])
        return

    findings = r.json()
    print(f"\n[Zip Test Results] Discovered {len(findings)} findings across uploaded project archive!")
    
    shor_count = sum(1 for f in findings if f.get("shor_vulnerable"))
    grover_count = sum(1 for f in findings if f.get("quantum_class") == "grover")
    cw_count = sum(1 for f in findings if f.get("classically_weak"))
    print(f" - Shor Vulnerable (Quantum Broken): {shor_count}")
    print(f" - Grover Affected (Symmetric): {grover_count}")
    print(f" - Classically Weak (MD5/SHA1/DES): {cw_count}")

    r = requests.get(f"{BASE_URL}/scans/{scan_id}/cbom")
    cbom = r.json()
    print(" - CBOM Components:", len(cbom.get("components", [])))

    r = requests.get(f"{BASE_URL}/scans/{scan_id}/mosca")
    mosca = r.json()
    print(" - Mosca Portfolio Status:", mosca.get("mosca_status"))

    print("\nSUCCESS: ZIP Project Scan Test Passed!")

if __name__ == "__main__":
    test_full_project_zip_scan()
