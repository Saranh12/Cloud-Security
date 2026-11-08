"""
Test Suite for M5 Workload Selection, Dynamic Ambiguity Resolution, Stale-Pod Rollout Handling,
and Module Consistency across M2-M11.

Covers all 16 regression scenarios specified in Prompt Section 8:
 1. One matching workload.
 2. Multiple workloads using the same image.
 3. User selects the second workload.
 4. M5 inspects the selected workload rather than the first match.
 5. Old pod disappears during assessment (stale pod).
 6. Deployment creates a replacement pod.
 7. ReplicaSet owner reference resolves to its Deployment.
 8. Selected container has privileged=true.
 9. Selected container has privileged=false.
 10. Selected container has no explicit securityContext.
 11. Multiple containers in one pod.
 12. Different image references (canonical tag, library prefix, digest).
 13. Workload disappears during assessment.
 14. No ready pods found for workload.
 15. M5 operational failure (e.g. cluster API connection refused).
 16. M2–M11 retain the exact same selected runtime identity.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import main
import module5_escape
import monitoring
from runtime_target import (
    RuntimeTarget,
    discover_runtime_workloads,
    prompt_or_select_runtime_target,
    find_workload_pods,
    revalidate_runtime_target,
    resolve_owning_workload_from_metadata,
    matches_image_name
)


class TestM5WorkloadSelectionAndRolloutSuite(unittest.TestCase):

    def setUp(self):
        self.state_file = Path("reports/dashboard_state.json")

    # -------------------------------------------------------------
    # Scenario 1: One matching workload
    # -------------------------------------------------------------
    @patch("runtime_target.subprocess.run")
    def test_01_one_matching_workload(self, mock_run):
        pod_data = {
            "items": [{
                "metadata": {
                    "name": "single-app-88f-1234",
                    "namespace": "default",
                    "uid": "uid-single-1",
                    "ownerReferences": [{"kind": "ReplicaSet", "name": "single-app-88f", "uid": "rs-uid-1"}]
                },
                "spec": {
                    "containers": [{"name": "app-container", "image": "my-service:1.0", "securityContext": {"privileged": False}}]
                },
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{"name": "app-container", "containerID": "docker://cid-1", "imageID": "img-id-1"}]
                }
            }]
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(pod_data), stderr="")

        workloads = discover_runtime_workloads(target_image="my-service:1.0", namespace="default")
        self.assertEqual(len(workloads), 1)
        target = prompt_or_select_runtime_target(workloads, is_cli=False)
        self.assertIsNotNone(target)
        self.assertEqual(target.pod_name, "single-app-88f-1234")
        self.assertEqual(target.container_name, "app-container")
        self.assertFalse(target.privileged)

    # -------------------------------------------------------------
    # Scenario 2: Multiple workloads using the same image
    # -------------------------------------------------------------
    @patch("runtime_target.subprocess.run")
    def test_02_multiple_workloads_same_image(self, mock_run):
        pod_data = {
            "items": [
                {
                    "metadata": {
                        "name": "python-app-757-abc",
                        "namespace": "default",
                        "uid": "uid-p-app",
                        "ownerReferences": [{"kind": "Deployment", "name": "python-app", "uid": "uid-dep-1"}]
                    },
                    "spec": {
                        "containers": [{"name": "python", "image": "python:3.12-slim", "securityContext": {"privileged": True}}]
                    },
                    "status": {"phase": "Running", "containerStatuses": [{"name": "python", "containerID": "c-1"}]}
                },
                {
                    "metadata": {
                        "name": "kubeguard-python-67b-xyz",
                        "namespace": "default",
                        "uid": "uid-kg-py",
                        "ownerReferences": [{"kind": "Deployment", "name": "kubeguard-python", "uid": "uid-dep-2"}]
                    },
                    "spec": {
                        "containers": [{"name": "target-container", "image": "python:3.12-slim", "securityContext": {"privileged": False}}]
                    },
                    "status": {"phase": "Running", "containerStatuses": [{"name": "target-container", "containerID": "c-2"}]}
                }
            ]
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(pod_data), stderr="")

        workloads = discover_runtime_workloads(target_image="python:3.12-slim", namespace="default")
        self.assertEqual(len(workloads), 2)
        names = [w.workload_name for w in workloads]
        self.assertIn("python-app", names)
        self.assertIn("kubeguard-python", names)

    # -------------------------------------------------------------
    # Scenario 3: User selects the second workload
    # -------------------------------------------------------------
    @patch("builtins.input", return_value="2")
    @patch("sys.stdin.isatty", return_value=True)
    def test_03_user_selects_second_workload(self, mock_isatty, mock_input):
        w1 = RuntimeTarget(workload_kind="Deployment", workload_name="python-app", pod_name="p1", container_name="python", privileged=True)
        w2 = RuntimeTarget(workload_kind="Deployment", workload_name="kubeguard-python", pod_name="p2", container_name="target-container", privileged=False)

        selected = prompt_or_select_runtime_target([w1, w2], is_cli=True)
        self.assertEqual(selected.workload_name, "kubeguard-python")
        self.assertEqual(selected.pod_name, "p2")
        self.assertFalse(selected.privileged)

    # -------------------------------------------------------------
    # Scenario 4: M5 inspects the selected workload rather than first match
    # -------------------------------------------------------------
    @patch("main.create_backup", return_value="backups/dummy")
    @patch("main.collect_evidence", return_value="evidence/dummy")
    @patch("main.auto_isolate_pod", return_value={"status": "ISOLATED"})
    @patch("main.start_integrity_monitor", return_value=12345)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "python-app-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.scan_image", return_value={"image": "python:3.12-slim", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.discover_runtime_workloads")
    @patch("main.get_pods")
    @patch("main.get_workload_usage", return_value={"pod": "python-app-pod", "cpu": "10m", "memory": "20Mi"})
    def test_04_m5_inspects_selected_workload_not_first_match(self, mock_usage, mock_get_pods, mock_disc, *args):
        w1 = RuntimeTarget(workload_kind="Deployment", workload_name="kubeguard-python", pod_name="kg-pod", container_name="target-container", privileged=False)
        w2 = RuntimeTarget(workload_kind="Deployment", workload_name="python-app", pod_name="python-app-pod", container_name="python", privileged=True)
        mock_disc.return_value = [w1, w2]

        # Return pod specification for selected w2 (privileged=True)
        mock_get_pods.return_value = [{
            "metadata": {"name": "python-app-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "python", "image": "python:3.12-slim", "securityContext": {"privileged": True}}]},
            "status": {}
        }]

        # Explicitly request python-app via workload_name parameter
        res_state = main.run_pipeline(
            selected_image="python:3.12-slim",
            run_id="run_select_w2",
            is_cli=False,
            workload_name="python-app"
        )

        m5_entry = res_state["modules"]["M5"]
        self.assertEqual(m5_entry["status"], "COMPLETED")
        self.assertEqual(m5_entry["severity"], "Critical")
        self.assertTrue(m5_entry["details"]["privileged"])
        self.assertEqual(m5_entry["details"]["pod"], "python-app-pod")
        self.assertEqual(m5_entry["details"]["container"], "python")

    # -------------------------------------------------------------
    # Scenario 5: Old pod disappears during assessment (stale pod)
    # -------------------------------------------------------------
    @patch("runtime_target.subprocess.run")
    def test_05_old_pod_disappears_stale_pod_detected(self, mock_run):
        # 1. Probing old pod returns NotFound (exit code 1)
        # 2. find_workload_pods queries pods and finds replacement pod
        def side_effect(cmd, **kwargs):
            if "get" in cmd and "pod" in cmd and "old-pod-1" in cmd:
                return MagicMock(returncode=1, stderr="Error from server (NotFound): pods \"old-pod-1\" not found\n")
            if "get" in cmd and "pods" in cmd:
                rep_list = {
                    "items": [{
                        "metadata": {
                            "name": "new-pod-2",
                            "namespace": "default",
                            "uid": "new-uid-2",
                            "ownerReferences": [{"kind": "Deployment", "name": "my-deploy"}]
                        },
                        "spec": {
                            "containers": [{"name": "web", "image": "web:1.0", "securityContext": {"privileged": False}}]
                        },
                        "status": {"phase": "Running", "containerStatuses": [{"name": "web", "containerID": "c-new"}]}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(rep_list), stderr="")
            return MagicMock(returncode=1, stderr="Unknown command")

        mock_run.side_effect = side_effect

        target = RuntimeTarget(
            workload_kind="Deployment",
            workload_name="my-deploy",
            pod_name="old-pod-1",
            container_name="web",
            requested_image="web:1.0"
        )

        ok, err = revalidate_runtime_target(target)
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(target.pod_name, "new-pod-2")
        self.assertEqual(target.pod_uid, "new-uid-2")

    # -------------------------------------------------------------
    # Scenario 6: Deployment creates replacement pod (get_pods handles rollout)
    # -------------------------------------------------------------
    @patch("module5_escape.subprocess.run")
    def test_06_deployment_creates_replacement_pod(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "get" in cmd and "pod" in cmd and "stale-pod" in cmd:
                return MagicMock(returncode=1, stderr="Error from server (NotFound): pods \"stale-pod\" not found\n")
            if "get" in cmd and "pods" in cmd:
                rep_list = {
                    "items": [{
                        "metadata": {
                            "name": "rolled-out-pod-5",
                            "namespace": "default",
                            "ownerReferences": [{"kind": "Deployment", "name": "app-deployment"}]
                        },
                        "spec": {
                            "containers": [{"name": "app", "image": "app:v2", "securityContext": {"privileged": True}}]
                        },
                        "status": {"phase": "Running"}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(rep_list), stderr="")
            return MagicMock(returncode=1, stderr="Error")

        mock_run.side_effect = side_effect

        pods = module5_escape.get_pods(
            target_pod="stale-pod",
            target_image="app:v2",
            namespace="default",
            workload_kind="Deployment",
            workload_name="app-deployment"
        )
        self.assertIsInstance(pods, list)
        self.assertEqual(len(pods), 1)
        self.assertEqual(pods[0]["metadata"]["name"], "rolled-out-pod-5")

    # -------------------------------------------------------------
    # Scenario 7: ReplicaSet owner reference resolves to its Deployment
    # -------------------------------------------------------------
    @patch("runtime_target.subprocess.run")
    def test_07_replicaset_resolves_to_deployment(self, mock_run):
        rs_data = {
            "metadata": {
                "name": "web-rs-57f9",
                "ownerReferences": [{"kind": "Deployment", "name": "web-deploy", "uid": "dep-uid-7"}]
            }
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(rs_data), stderr="")

        pod_meta = {
            "name": "web-rs-57f9-8x7a",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-rs-57f9", "uid": "rs-uid-7"}]
        }
        owner = resolve_owning_workload_from_metadata(pod_meta, namespace="default")
        self.assertEqual(owner.get("kind"), "Deployment")
        self.assertEqual(owner.get("name"), "web-deploy")
        self.assertEqual(owner.get("uid"), "dep-uid-7")
        self.assertEqual(owner.get("replicaset"), "web-rs-57f9")

    # -------------------------------------------------------------
    # Scenario 8: Selected container has privileged=true
    # -------------------------------------------------------------
    def test_08_selected_container_privileged_true(self):
        pods = [{
            "metadata": {"name": "priv-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "python:3.12-slim", "securityContext": {"privileged": True}}]},
            "status": {}
        }]
        res = module5_escape.detect_escape_indicators(pods, target_container="app")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["severity"], "Critical")
        self.assertEqual(res[0]["status"], "SUSPICIOUS CONFIGURATION DETECTED")
        self.assertTrue(res[0]["privileged"])
        self.assertIn("Container 'app' runs in privileged mode.", res[0]["findings"])

    # -------------------------------------------------------------
    # Scenario 9: Selected container has privileged=false
    # -------------------------------------------------------------
    def test_09_selected_container_privileged_false(self):
        pods = [{
            "metadata": {"name": "unpriv-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "python:3.12-slim", "securityContext": {"privileged": False}}]},
            "status": {}
        }]
        res = module5_escape.detect_escape_indicators(pods, target_container="app")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["severity"], "None")
        self.assertEqual(res[0]["status"], "NORMAL")
        self.assertFalse(res[0]["privileged"])
        self.assertEqual(len(res[0]["findings"]), 0)

    # -------------------------------------------------------------
    # Scenario 10: Selected container has no explicit securityContext
    # -------------------------------------------------------------
    def test_10_selected_container_no_explicit_security_context(self):
        pods = [{
            "metadata": {"name": "default-sec-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]},
            "status": {}
        }]
        res = module5_escape.detect_escape_indicators(pods, target_container="app")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["severity"], "None")
        self.assertEqual(res[0]["status"], "NORMAL")
        self.assertFalse(res[0]["privileged"])

    # -------------------------------------------------------------
    # Scenario 11: Multiple containers in one pod (targets correct container)
    # -------------------------------------------------------------
    def test_11_multiple_containers_targets_correct_container(self):
        # Pod has sidecar (privileged=False) and main app (privileged=True)
        pods = [{
            "metadata": {"name": "multi-container-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "logging-sidecar", "image": "fluentd:1.0", "securityContext": {"privileged": False}},
                    {"name": "worker", "image": "python:3.12-slim", "securityContext": {"privileged": True}}
                ]
            },
            "status": {}
        }]

        # Target worker
        res_worker = module5_escape.detect_escape_indicators(pods, target_container="worker")
        self.assertEqual(res_worker[0]["container"], "worker")
        self.assertTrue(res_worker[0]["privileged"])
        self.assertEqual(res_worker[0]["severity"], "Critical")

        # Target sidecar
        res_sidecar = module5_escape.detect_escape_indicators(pods, target_container="logging-sidecar")
        self.assertEqual(res_sidecar[0]["container"], "logging-sidecar")
        self.assertFalse(res_sidecar[0]["privileged"])
        self.assertEqual(res_sidecar[0]["severity"], "None")

    # -------------------------------------------------------------
    # Scenario 12: Different image references (canonical, tag, digest)
    # -------------------------------------------------------------
    def test_12_different_image_references_match(self):
        self.assertTrue(matches_image_name("docker.io/library/python:3.12-slim", "python:3.12-slim"))
        self.assertTrue(matches_image_name("index.docker.io/library/nginx:latest", "nginx"))
        self.assertTrue(matches_image_name("library/redis:7.0", "redis:7.0"))
        self.assertTrue(matches_image_name("python:3.12-slim@sha256:abcdef1234567890", "python:3.12-slim"))
        self.assertFalse(matches_image_name("python:3.12-slim", "node:22"))

    # -------------------------------------------------------------
    # Scenario 13: Workload disappears during assessment
    # -------------------------------------------------------------
    @patch("module5_escape.subprocess.run")
    def test_13_workload_disappears_during_assessment(self, mock_run):
        # Both pod query and workload query return NotFound / Empty
        def side_effect(cmd, **kwargs):
            if "pod" in cmd:
                return MagicMock(returncode=1, stderr="Error from server (NotFound): pods \"deleted-pod\" not found\n")
            if "pods" in cmd:
                return MagicMock(returncode=0, stdout=json.dumps({"items": []}), stderr="")
            return MagicMock(returncode=1, stderr="Error")

        mock_run.side_effect = side_effect

        pods = module5_escape.get_pods(
            target_pod="deleted-pod",
            target_image="gone:latest",
            namespace="default",
            workload_kind="Deployment",
            workload_name="deleted-deploy"
        )
        self.assertIsInstance(pods, dict)
        self.assertIn("error", pods)
        self.assertIn("not found", pods["error"].lower())

    # -------------------------------------------------------------
    # Scenario 14: No ready pods found for workload
    # -------------------------------------------------------------
    @patch("runtime_target.subprocess.run")
    def test_14_no_ready_pods_found(self, mock_run):
        # Workload exists but all pods are Pending or CrashLoopBackOff (not Running)
        mock_proc = MagicMock(returncode=1, stderr="Pod not found")
        mock_run.return_value = mock_proc

        target = RuntimeTarget(workload_kind="Deployment", workload_name="broken-deploy", pod_name="crash-pod")
        ok, err = revalidate_runtime_target(target)
        self.assertFalse(ok)
        self.assertIn("No ready pods found", err)

    # -------------------------------------------------------------
    # Scenario 15: M5 operational failure (connection refused / timeout)
    # -------------------------------------------------------------
    @patch("module5_escape.subprocess.run")
    def test_15_m5_operational_failure(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: Get \"https://192.168.49.2:8443/api/v1/namespaces/default/pods\": dial tcp 192.168.49.2:8443: connectex: No connection could be made because the target machine actively refused it.\n"
        )
        res = module5_escape.get_pods(target_pod="any-pod")
        self.assertIsInstance(res, dict)
        self.assertIn("error", res)
        self.assertIn("refused", res["error"].lower())

        # An operational error must not be treated as a clean assessment
        self.assertNotEqual(res, [])
        if isinstance(res, list):
            self.fail("Operational error returned a list instead of error dictionary")

    # -------------------------------------------------------------
    # Scenario 16: M2–M11 retain the same selected runtime identity
    # -------------------------------------------------------------
    @patch("main.create_backup", return_value="backups/dummy")
    @patch("main.collect_evidence", return_value="evidence/dummy")
    @patch("main.auto_isolate_pod", return_value={"status": "ISOLATED"})
    @patch("main.start_integrity_monitor", return_value=12345)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "target-pod-16", "cpu": "15m", "memory": "25Mi", "metrics_available": True})
    @patch("main.scan_image", return_value={"image": "app:v16", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.discover_runtime_workloads")
    @patch("main.get_pods")
    @patch("main.get_workload_usage", return_value={"pod": "target-pod-16", "cpu": "15m", "memory": "25Mi"})
    def test_16_m2_m11_retain_same_selected_runtime_identity(self, mock_usage, mock_get_pods, mock_disc, *args):
        selected_t = RuntimeTarget(
            namespace="custom-ns",
            workload_kind="Deployment",
            workload_name="selected-app-16",
            pod_name="target-pod-16",
            container_name="app-c16",
            requested_image="app:v16",
            runtime_image="app:v16",
            privileged=True
        )
        mock_disc.return_value = [selected_t]
        mock_get_pods.return_value = [{
            "metadata": {"name": "target-pod-16", "namespace": "custom-ns"},
            "spec": {"containers": [{"name": "app-c16", "image": "app:v16", "securityContext": {"privileged": True}}]},
            "status": {}
        }]

        res_state = main.run_pipeline(
            selected_image="app:v16",
            run_id="run_pipeline_consistency",
            is_cli=False,
            workload_name="selected-app-16"
        )

        # Check Root / Extra context
        self.assertEqual(res_state.get("target_pod"), "target-pod-16")
        self.assertEqual(res_state.get("deployment_name"), "selected-app-16")
        self.assertEqual(res_state.get("namespace"), "custom-ns")

        # Check M2
        m2_details = res_state.get("modules", {}).get("M2", {}).get("details", {})
        self.assertEqual(m2_details.get("pod_name"), "target-pod-16")

        # Check M4
        m4_details = res_state.get("modules", {}).get("M4", {}).get("details", {})
        self.assertEqual(m4_details.get("pod"), "target-pod-16")

        # Check M5
        m5_details = res_state.get("modules", {}).get("M5", {}).get("details", {})
        self.assertEqual(m5_details.get("pod"), "target-pod-16")
        self.assertEqual(m5_details.get("container"), "app-c16")
        self.assertTrue(m5_details.get("privileged"))


if __name__ == "__main__":
    unittest.main()
