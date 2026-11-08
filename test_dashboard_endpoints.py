import os
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def get_client_or_url():
    """Returns either a URL handler or a Flask test client if server is not running."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    is_live = (sock.connect_ex(('127.0.0.1', 5000)) == 0)
    sock.close()
    if is_live:
        import urllib.request
        import urllib.error
        return "LIVE", urllib.request, urllib.error
    else:
        from dashboard.app import app
        return "TEST_CLIENT", app.test_client(), None

def test_dashboard_endpoints():
    print("=" * 60)
    print(" TESTING DASHBOARD API & DOWNLOAD FUNCTIONALITY")
    print("=" * 60)

    mode, client, err_mod = get_client_or_url()
    print(f"[*] Test mode: {mode}")

    def do_get(path):
        if mode == "LIVE":
            req = client.urlopen(f"{BASE_URL}{path}")
            return req.status if hasattr(req, "status") else 200, req.read()
        else:
            resp = client.get(path)
            return resp.status_code, resp.data

    def do_post_json(path, data_dict):
        if mode == "LIVE":
            data = json.dumps(data_dict).encode("utf-8")
            req = client.Request(f"{BASE_URL}{path}", data=data, method="POST", headers={"Content-Type": "application/json"})
            try:
                resp = client.urlopen(req)
                return resp.status if hasattr(resp, "status") else 200, resp.read()
            except err_mod.HTTPError as he:
                return he.code, he.read()
        else:
            resp = client.post(path, json=data_dict)
            return resp.status_code, resp.data

    # 1. Test /api/dashboard
    status, body = do_get("/api/dashboard")
    dash = json.loads(body.decode("utf-8"))
    print("\n[TEST 1] /api/dashboard:")
    print(f"  Selected Image : {dash.get('selected_image')}")
    print(f"  Execution Time : {dash.get('execution_time')}")
    print(f"  Overall Risk   : {dash.get('overview', {}).get('overall_risk')}")
    print(f"  Total Vulns    : {dash.get('overview', {}).get('vulnerabilities')}")
    print(f"  M1 Status      : {dash.get('modules', {}).get('M1', {}).get('status')}")
    print(f"  M2 Status      : {dash.get('modules', {}).get('M2', {}).get('status')}")
    print(f"  M11 Report URL : {dash.get('current_report', {}).get('report_download_url')}")
    assert dash.get("modules"), "Expected modules dict in dashboard"

    # 2. Test /api/runs
    status, body = do_get("/api/runs")
    runs = json.loads(body.decode("utf-8"))
    print(f"\n[TEST 2] /api/runs (Found {len(runs)} historical runs):")
    for r in runs[:5]:
        print(f"  Run ID: {r.get('run_id')} | Image: {r.get('image')} | Started: {r.get('start_time')} | Status: {r.get('status')}")
    assert len(runs) > 0, "Expected at least 1 recorded run"

    latest_run_id = runs[0].get("run_id")
    print(f"\n[TEST 3] /api/run/{latest_run_id}:")
    status, body = do_get(f"/api/run/{latest_run_id}")
    run_detail = json.loads(body.decode("utf-8"))
    assert run_detail.get("run_id") == latest_run_id
    img_name = run_detail.get("selected_image") or run_detail.get("image")
    print(f"  Verified run details for: {img_name}")
    assert img_name, "Expected valid image name in run details"

    # 4. Test /api/report/download
    print(f"\n[TEST 4] /api/report/download:")
    try:
        status, content = do_get("/api/report/download")
        if status == 200:
            print(f"  Downloaded PDF report: size={len(content)} bytes, header={content[:4]}")
            assert content.startswith(b"%PDF"), f"Expected %PDF header, got {content[:10]}"
            print("  [OK] Successfully downloaded forensic PDF report via /api/report/download")
        else:
            print(f"  Report download returned status {status} (No report generated yet)")
    except Exception as e:
        print(f"  [FAIL] Failed to download report: {e}")
        raise

    # 5. Test /download/evidence/<folder>
    print(f"\n[TEST 5] Evidence zip download:")
    if os.path.exists("evidence"):
        ev_folders = [f for f in os.listdir("evidence") if os.path.isdir(os.path.join("evidence", f))]
        if ev_folders:
            sample_folder = ev_folders[0]
            status, content = do_get(f"/download/evidence/{sample_folder}")
            print(f"  Downloaded evidence zip for '{sample_folder}': status={status}, size={len(content)} bytes, header={content[:4]}")
            assert content.startswith(b"PK"), f"Expected zip header PK, got {content[:4]}"
            print(f"  [OK] Successfully verified evidence ZIP bundle download for {sample_folder}")

    # 6. Test image validation on /api/pipeline/run
    print(f"\n[TEST 6] /api/pipeline/run validation error handling:")
    status, body = do_post_json("/api/pipeline/run", {"image": "invalid/image:::syntax@@@"})
    res = json.loads(body.decode("utf-8"))
    print(f"  Expected HTTP 400: got {status}: {res.get('error')}")
    assert status == 400, f"Expected 400 Bad Request, got {status}"
    print("  [OK] Successfully rejected invalid image input with descriptive error")

    # 7. Test empty image validation
    status, body = do_post_json("/api/pipeline/run", {"image": "   "})
    res = json.loads(body.decode("utf-8"))
    print(f"  Expected HTTP 400: got {status}: {res.get('error')}")
    assert status == 400, f"Expected 400 Bad Request, got {status}"
    print("  [OK] Successfully rejected empty image input")

    # 8. Test /api/workload/available
    print(f"\n[TEST 8] /api/workload/available:")
    status, body = do_get("/api/workload/available")
    assert status == 200, f"Expected 200 OK, got {status}"
    avail = json.loads(body.decode("utf-8"))
    print(f"  Available workloads: {len(avail.get('available_workloads', []))}")
    print(f"  Active target: {avail.get('active_workload')}")
    assert "available_workloads" in avail, "Expected 'available_workloads' list in response"

    # 9. Test /api/workload/select
    print(f"\n[TEST 9] /api/workload/select:")
    status, body = do_post_json("/api/workload/select", {"workload_name": "python-app"})
    assert status == 200, f"Expected 200 OK, got {status}"
    sel_res = json.loads(body.decode("utf-8"))
    assert sel_res.get("success") is True, "Expected success: true"
    assert sel_res.get("workload", {}).get("workload_name") == "python-app"
    print(f"  [OK] Successfully persisted target selection: {sel_res.get('workload', {}).get('workload_name')}")

    # 10. Test /api/m4/data real telemetry
    print(f"\n[TEST 10] /api/m4/data real-time telemetry:")
    status, body = do_get("/api/m4/data?workload_name=python-app")
    assert status == 200, f"Expected 200 OK, got {status}"
    m4_res = json.loads(body.decode("utf-8"))
    assert m4_res.get("success") is True, "Expected success: true"
    m4_data = m4_res.get("m4", {})
    print(f"  Pod: {m4_data.get('pod')} | CPU: {m4_data.get('cpu')} | Mem: {m4_data.get('memory')} | Status: {m4_data.get('status')}")
    assert m4_data.get("pod"), "Expected pod name in M4 telemetry"
    assert m4_data.get("status") in ["NORMAL", "THREAT DETECTED", "UNAVAILABLE", "FAILED"]
    print("  [OK] Successfully verified real-time M4 telemetry endpoint")

    # 11. Test /api/m5/data real security inspection
    print(f"\n[TEST 11] /api/m5/data real-time security inspection:")
    status, body = do_get("/api/m5/data?workload_name=python-app")
    assert status == 200, f"Expected 200 OK, got {status}"
    m5_res = json.loads(body.decode("utf-8"))
    assert m5_res.get("success") is True, "Expected success: true"
    m5_data = m5_res.get("m5", {})
    print(f"  Pod: {m5_data.get('pod')} | Status: {m5_data.get('status')} | Sev: {m5_data.get('severity')} | Privileged: {m5_data.get('privileged')}")
    assert m5_data.get("pod"), "Expected pod name in M5 telemetry"
    assert m5_data.get("status") in ["NORMAL", "SUSPICIOUS ACTIVITY DETECTED", "UNAVAILABLE", "FAILED"]
    assert "raw_output" in m5_data, "Expected raw_output in M5 telemetry"
    print("  [OK] Successfully verified real-time M5 inspection endpoint")

    # 12. Test /api/module/refresh
    print(f"\n[TEST 12] /api/module/refresh:")
    status, body = do_post_json("/api/module/refresh", {"module": "all", "workload_name": "python-app"})
    assert status == 200, f"Expected 200 OK, got {status}"
    ref_res = json.loads(body.decode("utf-8"))
    assert ref_res.get("success") is True, "Expected success: true"
    assert ref_res.get("telemetry", {}).get("workload_name") == "python-app"
    print(f"  [OK] Successfully executed live module refresh: {ref_res.get('message')}")

    print("\n" + "=" * 60)
    print(" ALL DASHBOARD API & DOWNLOAD TESTS PASSED!")
    print("=" * 60)

if __name__ == "__main__":
    test_dashboard_endpoints()
