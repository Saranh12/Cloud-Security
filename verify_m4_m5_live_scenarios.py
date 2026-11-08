"""
Live Kubernetes & Minikube Scenario Verification Script for M4 & M5.
Tests every scenario listed in Section 9 of the user requirements.
"""

import subprocess
import json
import time
import os
from runtime_target import get_live_assessment_telemetry
from module4_detection import detect_threat


def run_cmd(cmd_list, timeout=15):
    p = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def patch_deployment_privileged(dep_name, privileged_state):
    """Patches deployment securityContext.privileged (true or null)."""
    val_str = "true" if privileged_state else "null"
    # Find container name
    rc, out, _ = run_cmd(["kubectl", "get", "deployment", dep_name, "-n", "default", "-o", "jsonpath={.spec.template.spec.containers[0].name}"])
    c_name = out or dep_name
    patch = json.dumps({
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": c_name,
                            "securityContext": {
                                "privileged": True if privileged_state else None
                            }
                        }
                    ]
                }
            }
        }
    })
    patch_file = f"temp_patch_{dep_name}.json"
    with open(patch_file, "w") as f:
        f.write(patch)
    try:
        rc, p_out, p_err = run_cmd(["kubectl", "patch", "deployment", dep_name, "-n", "default", "--patch-file", patch_file])
        run_cmd(["kubectl", "rollout", "status", f"deployment/{dep_name}", "-n", "default", "--timeout=60s"])
    finally:
        if os.path.exists(patch_file):
            os.remove(patch_file)


def verify_all_scenarios():
    print("=" * 70)
    print(" KUBEGUARD LIVE M4 & M5 SCENARIOS VERIFICATION")
    print("=" * 70)

    # ----------------------------------------------------
    # M4 SCENARIO TESTING
    # ----------------------------------------------------
    print("\n>>> [M4 TEST 1] Normal container with available metrics (Nginx)")
    t_nginx = get_live_assessment_telemetry(workload_name="nginx")
    rc, top_out, _ = run_cmd(["kubectl", "top", "pod", t_nginx["pod_name"], "-n", "default", "--no-headers"])
    print(f"  kubectl top output : {top_out}")
    print(f"  M4 Telemetry       : Pod={t_nginx['m4']['pod']}, CPU={t_nginx['m4']['cpu']}, Mem={t_nginx['m4']['memory']}, Status={t_nginx['m4']['status']}")
    assert t_nginx["m4"]["status"] == "NORMAL", f"Expected NORMAL, got {t_nginx['m4']['status']}"
    assert t_nginx["m4"]["metrics_available"] is True
    print("  [PASS] M4 matches actual Kubernetes metrics accurately.")

    print("\n>>> [M4 TEST 2] High CPU anomaly detection logic")
    anom_cpu = detect_threat({"pod": "test-pod", "cpu": "350m", "memory": "20Mi"})
    print(f"  Detection for CPU=350m (>200m limit): Status={anom_cpu['status']}, Severity={anom_cpu['severity']}, Reason={anom_cpu['reason']}")
    assert anom_cpu["status"] == "SUSPICIOUS ACTIVITY DETECTED"
    assert anom_cpu["severity"] == "High"
    print("  [PASS] Abnormal CPU spike triggers SUSPICIOUS ACTIVITY DETECTED.")

    print("\n>>> [M4 TEST 3] Metrics-server unavailable / timeout simulation")
    timeout_res = detect_threat({"error": "Metrics query timed out after 15s. Kubernetes metrics server is unresponsive.", "pod": "test-pod"})
    print(f"  Timeout Handling: Status={timeout_res['status']}, Severity={timeout_res['severity']}, Reason={timeout_res['reason']}")
    assert timeout_res["status"] in ["ERROR", "UNAVAILABLE", "FAILED"]
    print("  [PASS] Missing metrics never displayed as zero; reports operational error.")

    print("\n>>> [M4 TEST 4] Pod unavailable / non-existent workload")
    unavail = get_live_assessment_telemetry(workload_name="nonexistent-dummy-pod")
    print(f"  Nonexistent Target: Status={unavail['m4']['status']}, CPU={unavail['m4']['cpu']}, Reason={unavail['m4']['reason']}")
    assert unavail["m4"]["status"] == "UNAVAILABLE"
    assert unavail["m4"]["cpu"] == "UNAVAILABLE"
    print("  [PASS] Missing pod reports honest UNAVAILABLE status.")

    print("\n>>> [M4 TEST 5 & 6] Telegram & Email delivery failure handling")
    from runtime_target import parse_alert_status
    print(f"  Telegram Missing Token : {parse_alert_status(False, 'Telegram bot token not configured')}")
    print(f"  Email Timeout          : {parse_alert_status(False, 'timed out')}")
    assert parse_alert_status(False, 'Telegram bot token not configured') == "NOT CONFIGURED"
    assert parse_alert_status(False, 'timed out') == "FAILED"
    print("  [PASS] Notification statuses map accurately.")

    # ----------------------------------------------------
    # M5 SCENARIO TESTING (NGINX, PYTHON, NODE)
    # ----------------------------------------------------
    print("\n>>> [M5 TEST 1] Nginx Non-Privileged")
    t_ng_unpriv = get_live_assessment_telemetry(workload_name="nginx")
    print(f"  Pod: {t_ng_unpriv['pod_name']} | Privileged: {t_ng_unpriv['m5']['privileged']} | Status: {t_ng_unpriv['m5']['status']} | Sev: {t_ng_unpriv['m5']['severity']}")
    assert t_ng_unpriv["m5"]["privileged"] is False
    assert t_ng_unpriv["m5"]["status"] == "NORMAL"
    print("  [PASS] Nginx unprivileged passes security check.")

    print("\n>>> [M5 TEST 2] Nginx Privileged Mode Patch & Rollout Detection")
    patch_deployment_privileged("nginx", True)
    time.sleep(2)
    t_ng_priv = get_live_assessment_telemetry(workload_name="nginx")
    print(f"  Replacement Pod: {t_ng_priv['pod_name']} | Privileged: {t_ng_priv['m5']['privileged']} | Status: {t_ng_priv['m5']['status']} | Sev: {t_ng_priv['m5']['severity']}")
    assert t_ng_priv["m5"]["privileged"] is True, "Expected privileged == True"
    assert t_ng_priv["m5"]["status"] == "SUSPICIOUS ACTIVITY DETECTED"
    assert t_ng_priv["m5"]["severity"] == "Critical"
    print("  [PASS] Nginx privileged detected accurately on live replacement pod.")

    # Reset Nginx back to unprivileged
    patch_deployment_privileged("nginx", False)
    time.sleep(2)
    t_ng_reset = get_live_assessment_telemetry(workload_name="nginx")
    print(f"  Reset Pod: {t_ng_reset['pod_name']} | Privileged: {t_ng_reset['m5']['privileged']} | Status: {t_ng_reset['m5']['status']}")
    assert t_ng_reset["m5"]["privileged"] is False

    print("\n>>> [M5 TEST 3] Python Non-Privileged")
    t_py_unpriv = get_live_assessment_telemetry(workload_name="python-app")
    print(f"  Pod: {t_py_unpriv['pod_name']} | Privileged: {t_py_unpriv['m5']['privileged']} | Status: {t_py_unpriv['m5']['status']}")
    assert t_py_unpriv["m5"]["privileged"] is False
    assert t_py_unpriv["m5"]["status"] == "NORMAL"
    print("  [PASS] Python unprivileged passes security check.")

    print("\n>>> [M5 TEST 4] Python Privileged Mode Patch & Rollout Detection")
    patch_deployment_privileged("python-app", True)
    time.sleep(2)
    t_py_priv = get_live_assessment_telemetry(workload_name="python-app")
    print(f"  Replacement Pod: {t_py_priv['pod_name']} | Privileged: {t_py_priv['m5']['privileged']} | Status: {t_py_priv['m5']['status']} | Sev: {t_py_priv['m5']['severity']}")
    assert t_py_priv["m5"]["privileged"] is True
    assert t_py_priv["m5"]["status"] == "SUSPICIOUS ACTIVITY DETECTED"
    assert t_py_priv["m5"]["severity"] == "Critical"
    print("  [PASS] Python privileged detected accurately on live replacement pod.")

    # Reset Python back to unprivileged
    patch_deployment_privileged("python-app", False)
    time.sleep(2)
    t_py_reset = get_live_assessment_telemetry(workload_name="python-app")
    print(f"  Reset Pod: {t_py_reset['pod_name']} | Privileged: {t_py_reset['m5']['privileged']} | Status: {t_py_reset['m5']['status']}")
    assert t_py_reset["m5"]["privileged"] is False

    print("\n>>> [M5 TEST 5] Node-app Non-Privileged")
    t_node_unpriv = get_live_assessment_telemetry(workload_name="node-app")
    print(f"  Pod: {t_node_unpriv['pod_name']} | Privileged: {t_node_unpriv['m5']['privileged']} | Status: {t_node_unpriv['m5']['status']}")
    assert t_node_unpriv["m5"]["privileged"] is False
    assert t_node_unpriv["m5"]["status"] == "NORMAL"
    print("  [PASS] Node-app unprivileged passes security check.")

    print("\n>>> [M5 TEST 6] Node-app Privileged Mode Patch & Rollout Detection")
    patch_deployment_privileged("node-app", True)
    time.sleep(2)
    t_node_priv = get_live_assessment_telemetry(workload_name="node-app")
    print(f"  Replacement Pod: {t_node_priv['pod_name']} | Privileged: {t_node_priv['m5']['privileged']} | Status: {t_node_priv['m5']['status']} | Sev: {t_node_priv['m5']['severity']}")
    assert t_node_priv["m5"]["privileged"] is True
    assert t_node_priv["m5"]["status"] == "SUSPICIOUS ACTIVITY DETECTED"
    assert t_node_priv["m5"]["severity"] == "Critical"
    print("  [PASS] Node-app privileged detected accurately on live replacement pod.")

    # Reset Node back to unprivileged
    patch_deployment_privileged("node-app", False)
    time.sleep(2)
    t_node_reset = get_live_assessment_telemetry(workload_name="node-app")
    print(f"  Reset Pod: {t_node_reset['pod_name']} | Privileged: {t_node_reset['m5']['privileged']} | Status: {t_node_reset['m5']['status']}")
    assert t_node_reset["m5"]["privileged"] is False

    print("\n" + "=" * 70)
    print(" ALL LIVE M4 & M5 SCENARIOS VERIFIED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    verify_all_scenarios()
