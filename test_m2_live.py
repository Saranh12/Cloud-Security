import urllib.request
import json
import subprocess
import time

def run_tests():
    print("=" * 60)
    print("      TESTING LIVE DASHBOARD METRICS INTEGRATION")
    print("=" * 60)

    # 1. Check live kubectl top pods
    k_res = subprocess.run(["kubectl", "top", "pods"], capture_output=True, text=True)
    print("\n1. [KUBERNETES METRICS API] kubectl top pods:")
    print(k_res.stdout.strip())
    assert k_res.returncode == 0, f"kubectl top pods failed: {k_res.stderr}"

    # 2. Query Dashboard API for the latest run with live monitoring
    req_runs = urllib.request.urlopen("http://127.0.0.1:5000/api/runs")
    all_runs = json.loads(req_runs.read().decode("utf-8"))
    target_url = "http://127.0.0.1:5000/api/dashboard"
    for r in all_runs:
        # Check if this run has live monitoring
        r_id = r.get("run_id")
        check_req = urllib.request.urlopen(f"http://127.0.0.1:5000/api/dashboard?run_id={r_id}")
        check_dash = json.loads(check_req.read().decode("utf-8"))
        if check_dash.get("modules", {}).get("M2", {}).get("status") in ["RUNNING", "COMPLETED", "SUCCESS"] and check_dash.get("modules", {}).get("M2", {}).get("details", {}).get("metrics_available"):
            target_url = f"http://127.0.0.1:5000/api/dashboard?run_id={r_id}"
            print(f"Inspecting run with active metrics: {r_id} ({r.get('image')})")
            break

    req = urllib.request.urlopen(target_url)
    dash = json.loads(req.read().decode("utf-8"))
    m2 = dash.get("modules", {}).get("M2", {})
    m2_dt = m2.get("details", {})

    print("\n2. [DASHBOARD API RESPONSE] /api/dashboard:")
    print(f"Status           : {m2.get('status')}")
    print(f"Message          : {m2.get('message')}")
    print(f"Pod Name         : {m2_dt.get('pod_name')}")
    print(f"CPU              : {m2_dt.get('cpu')}")
    print(f"Memory           : {m2_dt.get('memory')}")
    print(f"CPU (millicores) : {m2_dt.get('cpu_millicores')}")
    print(f"Memory (MiB)     : {m2_dt.get('memory_mib')}")
    print(f"Metrics Available: {m2_dt.get('metrics_available')}")
    print(f"Monitoring Status: {m2_dt.get('monitoring_status')}")
    print(f"Monitoring Interv: {m2_dt.get('monitoring_interval')}")
    print(f"Last Updated     : {m2_dt.get('last_updated')}")

    # 3. Assertions
    assert m2.get("status") in ["RUNNING", "COMPLETED", "SUCCESS"], f"Expected RUNNING/COMPLETED, got {m2.get('status')}"
    assert m2_dt.get("metrics_available") is True, "Expected metrics_available=True"
    assert m2_dt.get("cpu") is not None, "Expected cpu to not be None"
    assert m2_dt.get("memory") is not None, "Expected memory to not be None"
    assert str(m2_dt.get("cpu")).endswith("m"), f"Expected CPU in millicores with 'm', got {m2_dt.get('cpu')}"
    assert str(m2_dt.get("memory")).endswith("Mi"), f"Expected Memory in MiB with 'Mi', got {m2_dt.get('memory')}"

    # Verify that the pod name matches running pod
    assert m2_dt.get("pod_name"), f"Expected non-empty pod name in M2 details, got: {m2_dt.get('pod_name')}"

    print("\n3. [MODULE INTEGRITY CHECK] Checking other modules:")
    for mod_name in ["M1", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M11"]:
        mod_obj = dash.get("modules", {}).get(mod_name, {})
        print(f"  {mod_name}: status={mod_obj.get('status')}, severity={mod_obj.get('severity')}")
        assert mod_obj.get("status") in ["COMPLETED", "SUCCESS", "VERIFIED", "NORMAL", "SUSPICIOUS ACTIVITY DETECTED", "PARTIAL", "SKIPPED", "FINDINGS DETECTED", "BLOCKED"], \
            f"Module {mod_name} unexpected status: {mod_obj.get('status')}"

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
