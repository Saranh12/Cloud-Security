import urllib.request
import json
import subprocess
import time

def test_interval():
    print("=" * 65)
    print("     TESTING CONTINUOUS 5-SECOND METRIC INTERVALS")
    print("=" * 65)

    req = urllib.request.urlopen("http://127.0.0.1:5000/api/dashboard")
    dash = json.loads(req.read().decode("utf-8"))
    pod_name = dash["modules"]["M2"]["details"]["pod_name"]

    # Start CPU intensive task in pod
    subprocess.run([
        "kubectl", "exec", pod_name, "--", "sh", "-c",
        "for i in $(seq 1 15); do (head -c 20000000 /dev/urandom | sha256sum > /dev/null &); sleep 1; done &"
    ], capture_output=True, text=True)

    print(f"Monitoring pod {pod_name} every 5 seconds for 4 consecutive intervals:\n")
    readings = []
    for step in range(1, 5):
        time.sleep(5)
        # Fetch directly from kubectl
        k_res = subprocess.run(["kubectl", "top", "pods"], capture_output=True, text=True)
        k_line = [l for l in k_res.stdout.strip().split("\n") if l.startswith(pod_name)]
        k_cpu = k_line[0].split()[1] if k_line else "N/A"
        k_mem = k_line[0].split()[2] if k_line else "N/A"

        # Fetch from dashboard API
        req = urllib.request.urlopen("http://127.0.0.1:5000/api/dashboard")
        dash = json.loads(req.read().decode("utf-8"))
        m2_dt = dash["modules"]["M2"]["details"]
        dash_cpu = m2_dt.get("cpu")
        dash_mem = m2_dt.get("memory")
        updated = m2_dt.get("last_updated")

        print(f"Interval #{step}:")
        print(f"  kubectl      -> CPU: {k_cpu:<6} | Memory: {k_mem}")
        print(f"  Dashboard API-> CPU: {dash_cpu:<6} | Memory: {dash_mem} | Time: {updated}")
        readings.append((k_cpu, dash_cpu))

    print("\nSummary of readings (kubectl vs Dashboard API):")
    for idx, (k, d) in enumerate(readings, 1):
        print(f"  Sample {idx}: kubectl={k} == dashboard={d} -> {k == d}")
        assert k == d, f"Discrepancy at sample {idx}: {k} != {d}"

    print("\nSUCCESS: All intervals match Kubernetes Metrics API readings perfectly!")

if __name__ == "__main__":
    test_interval()
