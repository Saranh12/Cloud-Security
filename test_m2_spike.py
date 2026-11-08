import urllib.request
import json
import subprocess
import time

def test_spike():
    print("=" * 60)
    print("      TESTING LIVE CPU LOAD PROPAGATION TO DASHBOARD")
    print("=" * 60)

    # 1. Get current pod name
    req = urllib.request.urlopen("http://127.0.0.1:5000/api/dashboard")
    dash = json.loads(req.read().decode("utf-8"))
    pod_name = dash["modules"]["M2"]["details"]["pod_name"]
    print(f"Target Pod: {pod_name}")

    # 2. Trigger CPU load inside the pod
    print("\nTriggering CPU workload inside the pod...")
    subprocess.run([
        "kubectl", "exec", pod_name, "--", "sh", "-c",
        "(head -c 100000000 /dev/urandom | sha256sum) & (head -c 100000000 /dev/urandom | sha256sum) &"
    ], capture_output=True, text=True)

    # 3. Wait for metrics-server to sample (about 8-12 seconds)
    print("Waiting 10 seconds for metrics-server telemetry sample...")
    time.sleep(10)

    # 4. Check kubectl top pods
    k_res = subprocess.run(["kubectl", "top", "pods"], capture_output=True, text=True)
    print("\nKubernetes 'kubectl top pods' output:")
    print(k_res.stdout.strip())

    # 5. Check dashboard API
    req = urllib.request.urlopen("http://127.0.0.1:5000/api/dashboard")
    dash = json.loads(req.read().decode("utf-8"))
    m2_dt = dash["modules"]["M2"]["details"]

    print("\nDashboard API /api/dashboard M2 readings:")
    print(f"Pod      : {m2_dt.get('pod_name')}")
    print(f"CPU      : {m2_dt.get('cpu')}")
    print(f"Memory   : {m2_dt.get('memory')}")
    print(f"Updated  : {m2_dt.get('last_updated')}")

    # Verify that dashboard received the genuine metrics
    for line in k_res.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[0] == pod_name:
            expected_cpu = parts[1]
            print(f"\nVerification: kubectl reports {expected_cpu}, dashboard reports {m2_dt.get('cpu')}")
            assert m2_dt.get("cpu") == expected_cpu, f"Mismatch: expected {expected_cpu}, got {m2_dt.get('cpu')}"
            print("VERIFICATION SUCCESSFUL: Dashboard reflects exact live cluster metrics!")
            break

if __name__ == "__main__":
    test_spike()
