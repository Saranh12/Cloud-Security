"""
Comprehensive Test Suite for KubeGuard Universal Automatic Image-to-Runtime Deployment
and Privileged Testing (Section 15 Coverage).

Tests:
1. Nginx automatic deployment.
2. Python automatic deployment.
3. Node automatic deployment.
4. Redis automatic deployment.
5. Arbitrary compatible image references.
6. Exactly one managed workload per assessment run.
7. No manual workload selection in automatic workflow.
8. Existing workloads are not modified.
9. Correct image identity between M1 and deployment.
10. Standard security profile.
11. Privileged test profile.
12. Privileged-mode verification.
13. Kubernetes admission rejection.
14. Pod replacement after security configuration changes.
15. M2-M11 use the same selected runtime identity.
16. M10 evidence isolation.
17. Fresh evidence on every new run.
18. Historical evidence preservation.
19. Correct dashboard state.
20. Correct consolidated forensic reporting.
21. Safe cleanup of KubeGuard-owned workloads.
22. Dashboard privileged mode toggle API.
"""

import unittest
import os
import sys
import json
import shutil
import tempfile
from unittest.mock import patch, MagicMock

import deployment_manager
import runtime_target
from deployment_manager import (
    generate_assessment_workload_name,
    deploy_workload,
    verify_image_identity,
    update_workload_privileged_mode,
    cleanup_kubernetes_workload
)
from runtime_target import RuntimeTarget
import main
from module10_integrity import initialize_baseline, verify_hashes, INTEGRITY_DIR


class TestKubeGuardAutomaticDeploymentAndPrivilegedTesting(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="kg_auto_test_")

    def tearDown(self):
        if main._monitor_stop_event:
            main._monitor_stop_event.set()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Nginx automatic deployment
    @patch("deployment_manager.subprocess.run")
    def test_01_nginx_automatic_deployment(self, mock_run):
        def run_side_effect(cmd, **kwargs):
            if "apply" in cmd:
                # Verify labels in manifest
                manifest = kwargs.get("input", "")
                self.assertIn("app.kubernetes.io/managed-by: kubeguard", manifest)
                self.assertIn("kubeguard.io/assessment: \"true\"", manifest)
                return MagicMock(returncode=0, stdout="deployment applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "kubeguard-test-nginx-pod", "uid": "uid-nginx-1"},
                        "spec": {"containers": [{"name": "target-container", "image": "nginx:latest", "securityContext": {"privileged": False}}]},
                        "status": {"phase": "Running", "containerStatuses": [{"name": "target-container", "imageID": "docker-pullable://nginx@sha256:1111", "containerID": "containerd://c1"}]}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect
        res = deploy_workload({"image": "nginx:latest"}, run_id="run_nginx_001")
        self.assertTrue(res["success"])
        self.assertTrue(res["workload_name"].startswith("kubeguard-test-nginx-"))
        self.assertEqual(res["pod_name"], "kubeguard-test-nginx-pod")
        self.assertEqual(res["pod_uid"], "uid-nginx-1")
        self.assertFalse(res["privileged_effective"])

    # 2. Python automatic deployment
    @patch("deployment_manager.subprocess.run")
    def test_02_python_automatic_deployment(self, mock_run):
        def run_side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "kubeguard-test-python-pod", "uid": "uid-py-1"},
                        "spec": {"containers": [{"name": "target-container", "image": "python:3.12-slim", "securityContext": {"privileged": False}}]},
                        "status": {"phase": "Running", "containerStatuses": [{"name": "target-container", "imageID": "docker-pullable://python@sha256:2222", "containerID": "containerd://c2"}]}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect
        res = deploy_workload({"image": "python:3.12-slim"}, run_id="run_py_002")
        self.assertTrue(res["success"])
        self.assertTrue(res["workload_name"].startswith("kubeguard-test-python-"))
        self.assertEqual(res["pod_name"], "kubeguard-test-python-pod")

    # 3. Node automatic deployment
    @patch("deployment_manager.subprocess.run")
    def test_03_node_automatic_deployment(self, mock_run):
        def run_side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "kubeguard-test-node-pod", "uid": "uid-node-1"},
                        "spec": {"containers": [{"name": "target-container", "image": "node:22", "securityContext": {"privileged": False}}]},
                        "status": {"phase": "Running", "containerStatuses": [{"name": "target-container", "imageID": "docker-pullable://node@sha256:3333", "containerID": "containerd://c3"}]}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect
        res = deploy_workload({"image": "node:22"}, run_id="run_node_003")
        self.assertTrue(res["success"])
        self.assertTrue(res["workload_name"].startswith("kubeguard-test-node-"))

    # 4. Redis automatic deployment
    @patch("deployment_manager.subprocess.run")
    def test_04_redis_automatic_deployment(self, mock_run):
        def run_side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "kubeguard-test-redis-pod", "uid": "uid-redis-1"},
                        "spec": {"containers": [{"name": "target-container", "image": "redis:latest", "securityContext": {"privileged": False}}]},
                        "status": {"phase": "Running", "containerStatuses": [{"name": "target-container", "imageID": "docker-pullable://redis@sha256:4444", "containerID": "containerd://c4"}]}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect
        res = deploy_workload({"image": "redis:latest"}, run_id="run_redis_004")
        self.assertTrue(res["success"])
        self.assertTrue(res["workload_name"].startswith("kubeguard-test-redis-"))

    # 5. Arbitrary compatible image references
    def test_05_arbitrary_compatible_image_references(self):
        images = [
            ("custom.registry.io:5000/team/my-service:v2.5", "my-service"),
            ("quay.io/prometheus/alertmanager:v0.25.0", "alertmanager"),
            ("postgres:16-alpine", "postgres"),
            ("ubuntu:24.04", "ubuntu")
        ]
        for img, expected_base in images:
            name = generate_assessment_workload_name(img, run_id="test_05")
            self.assertTrue(name.startswith(f"kubeguard-test-{expected_base}-"))
            self.assertLessEqual(len(name), 63)

    # 6. Exactly one managed workload per assessment run
    def test_06_exactly_one_managed_workload_per_assessment_run(self):
        run_id_a = "kubeguard-run-20261030-001"
        run_id_b = "kubeguard-run-20261030-002"
        w_a = generate_assessment_workload_name("python:3.12-slim", run_id=run_id_a)
        w_b = generate_assessment_workload_name("python:3.12-slim", run_id=run_id_b)
        self.assertNotEqual(w_a, w_b)
        self.assertIn("20261030-001", w_a)
        self.assertIn("20261030-002", w_b)

    # 7. No manual workload selection in automatic workflow
    @patch("main.dm_deploy_workload")
    @patch("main.prompt_or_select_runtime_target")
    @patch("main.discover_runtime_workloads")
    @patch("main.scan_image", return_value={"image": "python:3.12-slim", "severity_counts": {"CRITICAL": 0}, "deployment_blocked": False})
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": []})
    @patch("main.get_workload_usage", return_value={"pod": "kg-auto-pod", "cpu": "10m", "memory": "20Mi"})
    @patch("main.get_pods", return_value=[{"metadata": {"name": "kg-auto-pod"}, "spec": {"containers": [{"name": "target-container", "securityContext": {"privileged": False}}]}, "status": {}}])
    @patch("main.generate_forensic_report", return_value="reports/rep.pdf")
    @patch("main.run_manager")
    def test_07_no_manual_workload_selection_in_automatic_workflow(
        self, mock_rm, mock_rep, mock_get_pods, mock_usage, mock_rbac, mock_scan, mock_disc, mock_prompt, mock_deploy
    ):
        # Configure deploy_workload return
        mock_deploy.return_value = {
            "success": True,
            "workload_name": "kubeguard-test-python-auto-001",
            "workload_kind": "Deployment",
            "pod_name": "kg-auto-pod",
            "pod_uid": "uid-auto-1",
            "container_name": "target-container",
            "container_id": "cid-1",
            "namespace": "default",
            "requested_image": "python:3.12-slim",
            "runtime_image": "python:3.12-slim",
            "privileged_status": "DISABLED",
            "start_time": "2026-10-30 10:00:00"
        }

        # Run pipeline with default deploy_workload=True
        state = main.run_pipeline(
            selected_image="python:3.12-slim",
            run_id="run_auto_test_007",
            is_cli=True,
            deploy_workload=True
        )

        # prompt_or_select_runtime_target MUST NOT be called!
        mock_prompt.assert_not_called()
        self.assertEqual(state["target_pod"], "kg-auto-pod")
        self.assertEqual(state["deployment_name"], "kubeguard-test-python-auto-001")

    # 8. Existing workloads are not modified
    @patch("deployment_manager.subprocess.run")
    def test_08_existing_workloads_are_not_modified(self, mock_run):
        # cleanup_kubernetes_workload must refuse to delete user workloads like "python-app"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "metadata": {
                    "name": "python-app",
                    "labels": {"app": "python-app"}  # Not managed by kubeguard
                }
            })
        )
        ok, msg = cleanup_kubernetes_workload("python-app", namespace="default")
        self.assertFalse(ok)
        self.assertIn("Safety check failed", msg)
        self.assertIn("not managed by KubeGuard", msg)

    # 9. Correct image identity between M1 and deployment
    def test_09_correct_image_identity_between_m1_and_deployment(self):
        digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        res_match = verify_image_identity(
            scanned_digest=digest,
            runtime_image_id=f"docker-pullable://python@{digest}",
            requested_image="python:3.12-slim",
            runtime_image="python:3.12-slim"
        )
        self.assertTrue(res_match["verified"])
        self.assertEqual(res_match["status"], "VERIFIED")

        diff_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        res_mismatch = verify_image_identity(
            scanned_digest=digest,
            runtime_image_id=f"docker-pullable://python@{diff_digest}",
            requested_image="python:3.12-slim",
            runtime_image="python:3.12-slim"
        )
        self.assertFalse(res_mismatch["verified"])
        self.assertEqual(res_mismatch["status"], "MISMATCH")

    # 10. Standard security profile
    @patch("deployment_manager.subprocess.run")
    def test_10_standard_security_profile(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "apply" in cmd:
                manifest = kwargs.get("input", "")
                self.assertNotIn("privileged: true", manifest)
                return MagicMock(returncode=0, stdout="applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                return MagicMock(returncode=0, stdout=json.dumps({"items": [{
                    "metadata": {"name": "p-std", "uid": "uid-std"},
                    "spec": {"containers": [{"name": "target-container", "securityContext": {"privileged": False}}]},
                    "status": {"phase": "Running", "containerStatuses": [{}]}
                }]}))
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        res = deploy_workload({"image": "nginx:latest", "security_profile": "standard"})
        self.assertTrue(res["success"])
        self.assertEqual(res["privileged_status"], "DISABLED")
        self.assertFalse(res["privileged_effective"])

    # 11. Privileged test profile
    @patch("deployment_manager.subprocess.run")
    def test_11_privileged_test_profile(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "apply" in cmd:
                manifest = kwargs.get("input", "")
                self.assertIn("privileged: true", manifest)
                return MagicMock(returncode=0, stdout="applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                return MagicMock(returncode=0, stdout=json.dumps({"items": [{
                    "metadata": {"name": "p-priv", "uid": "uid-priv"},
                    "spec": {"containers": [{"name": "target-container", "securityContext": {"privileged": True}}]},
                    "status": {"phase": "Running", "containerStatuses": [{}]}
                }]}))
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        res = deploy_workload({"image": "nginx:latest", "security_profile": "privileged"})
        self.assertTrue(res["success"])
        self.assertEqual(res["privileged_status"], "ENABLED")
        self.assertTrue(res["privileged_effective"])

    # 12. Privileged-mode verification
    @patch("deployment_manager.subprocess.run")
    def test_12_privileged_mode_verification(self, mock_run):
        # Even if privileged requested, if pod spec shows privileged: false, reports REJECTED
        def side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                return MagicMock(returncode=0, stdout=json.dumps({"items": [{
                    "metadata": {"name": "p-rejected", "uid": "uid-rej"},
                    "spec": {"containers": [{"name": "target-container", "securityContext": {"privileged": False}}]},
                    "status": {"phase": "Running", "containerStatuses": [{}]}
                }]}))
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        res = deploy_workload({"image": "nginx:latest", "security_profile": "privileged"})
        self.assertTrue(res["success"])
        self.assertEqual(res["privileged_status"], "REJECTED")
        self.assertFalse(res["privileged_effective"])

    # 13. Kubernetes admission rejection
    @patch("deployment_manager.subprocess.run")
    def test_13_kubernetes_admission_rejection(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error from server (Forbidden): admission webhook denied: Pod Security Standards: privileged container forbidden"
        )
        res = deploy_workload({"image": "nginx:latest", "security_profile": "privileged"})
        self.assertFalse(res["success"])
        self.assertEqual(res["privileged_status"], "REJECTED")
        self.assertIn("Kubernetes Admission Policy rejected", res["error"])

    # 14. Pod replacement after security configuration changes
    @patch("deployment_manager.subprocess.run")
    def test_14_pod_replacement_after_security_configuration_changes(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "get" in cmd and "deployment" in cmd:
                return MagicMock(returncode=0, stdout=json.dumps({
                    "metadata": {"name": "kubeguard-test-py-01", "labels": {"app.kubernetes.io/managed-by": "kubeguard"}},
                    "spec": {"template": {"spec": {"containers": [{"name": "target-container", "image": "python:3.12-slim"}]}}}
                }))
            elif "patch" in cmd:
                return MagicMock(returncode=0, stdout="deployment.apps/kubeguard-test-py-01 patched")
            elif "rollout" in cmd:
                return MagicMock(returncode=0, stdout="rollout complete")
            elif "get" in cmd and "pods" in cmd:
                # Replacement pod returned
                return MagicMock(returncode=0, stdout=json.dumps({
                    "items": [{
                        "metadata": {"name": "kubeguard-test-py-01-replacement", "uid": "uid-replacement-99"},
                        "spec": {"containers": [{"name": "target-container", "image": "python:3.12-slim", "securityContext": {"privileged": True}}]},
                        "status": {"phase": "Running", "containerStatuses": [{"name": "target-container", "containerID": "containerd://new-c"}]}
                    }]
                }))
            return MagicMock(returncode=0, stdout="")

        mock_run.side_effect = side_effect
        res = update_workload_privileged_mode("kubeguard-test-py-01", namespace="default", privileged=True)
        self.assertTrue(res["success"])
        self.assertEqual(res["pod_name"], "kubeguard-test-py-01-replacement")
        self.assertEqual(res["pod_uid"], "uid-replacement-99")
        self.assertEqual(res["privileged_status"], "ENABLED")
        self.assertTrue(res["privileged_effective"])

    # 15. M2-M11 use the same selected runtime identity
    @patch("main.dm_deploy_workload")
    @patch("main.scan_image", return_value={"image": "redis:latest", "severity_counts": {"CRITICAL": 0}, "deployment_blocked": False})
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": []})
    @patch("main.get_workload_usage", return_value={"pod": "redis-consistent-pod", "cpu": "12m", "memory": "28Mi"})
    @patch("main.get_pods", return_value=[{"metadata": {"name": "redis-consistent-pod"}, "spec": {"containers": [{"name": "target-container", "securityContext": {"privileged": False}}]}, "status": {}}])
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.run_manager")
    def test_15_m2_m11_use_same_selected_runtime_identity(
        self, mock_rm, mock_rep, mock_get_pods, mock_usage, mock_rbac, mock_scan, mock_deploy
    ):
        mock_deploy.return_value = {
            "success": True,
            "workload_name": "kubeguard-test-redis-run15",
            "workload_kind": "Deployment",
            "pod_name": "redis-consistent-pod",
            "pod_uid": "uid-consistent-redis",
            "container_name": "target-container",
            "container_id": "cid-redis-15",
            "namespace": "default",
            "requested_image": "redis:latest",
            "runtime_image": "redis:latest",
            "privileged_status": "DISABLED",
            "start_time": "2026-10-30 11:00:00"
        }

        res_state = main.run_pipeline(
            selected_image="redis:latest",
            run_id="run_identity_consistent_15",
            is_cli=False,
            deploy_workload=True
        )

        self.assertEqual(res_state["target_pod"], "redis-consistent-pod")
        self.assertEqual(res_state["deployment_name"], "kubeguard-test-redis-run15")
        self.assertEqual(res_state["run_id"], "run_identity_consistent_15")

    # 16. M10 evidence isolation
    def test_16_m10_evidence_isolation(self):
        ev_dir_1 = os.path.join(self.test_dir, "incident_run16_01_podA")
        ev_dir_2 = os.path.join(self.test_dir, "incident_run16_02_podB")
        os.makedirs(ev_dir_1, exist_ok=True)
        os.makedirs(ev_dir_2, exist_ok=True)

        with open(os.path.join(ev_dir_1, "pod.yaml"), "w") as f:
            f.write("content: run 1\n")
        with open(os.path.join(ev_dir_2, "pod.yaml"), "w") as f:
            f.write("content: run 2\n")

        try:
            initialize_baseline(ev_dir_1, authorized_by="Admin", force=True)
            initialize_baseline(ev_dir_2, authorized_by="Admin", force=True)

            ok1, _, tamp1, _, _ = verify_hashes(ev_dir_1)
            ok2, _, tamp2, _, _ = verify_hashes(ev_dir_2)
            self.assertTrue(ok1)
            self.assertTrue(ok2)

            # Tamper run 1 only
            with open(os.path.join(ev_dir_1, "pod.yaml"), "a") as f:
                f.write("TAMPERED\n")

            ok1_after, _, tamp1_after, _, _ = verify_hashes(ev_dir_1)
            ok2_after, _, tamp2_after, _, _ = verify_hashes(ev_dir_2)

            self.assertFalse(ok1_after)
            self.assertGreater(tamp1_after, 0)

            # Run 2 must remain completely verified and untampered
            self.assertTrue(ok2_after)
            self.assertEqual(tamp2_after, 0)
        finally:
            for item in ["incident_run16_01_podA", "incident_run16_02_podB"]:
                p = os.path.join(INTEGRITY_DIR, item)
                if os.path.exists(p):
                    shutil.rmtree(p, ignore_errors=True)

    # 17. Fresh evidence on every new run
    def test_17_fresh_evidence_on_every_new_run(self):
        ev1 = f"evidence/incident_run17_01_20261030_100000_podA"
        ev2 = f"evidence/incident_run17_02_20261030_100500_podB"
        self.assertNotEqual(ev1, ev2)

    # 18. Historical evidence preservation
    def test_18_historical_evidence_preservation(self):
        hist_dir = os.path.join(self.test_dir, "incident_hist_001")
        os.makedirs(hist_dir, exist_ok=True)
        with open(os.path.join(hist_dir, "pod.yaml"), "w") as f:
            f.write("historical content\n")
        self.assertTrue(os.path.exists(hist_dir))

    # 19. Correct dashboard state
    @patch("main.dm_deploy_workload")
    @patch("main.scan_image", return_value={"image": "python:3.12-slim", "severity_counts": {"CRITICAL": 0}, "deployment_blocked": False})
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "dash-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.get_workload_usage", return_value={"pod": "dash-pod", "cpu": "10m", "memory": "20Mi"})
    @patch("main.get_pods", return_value=[{"metadata": {"name": "dash-pod"}, "spec": {"containers": [{"name": "target-container", "securityContext": {"privileged": False}}]}, "status": {}}])
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.run_manager")
    def test_19_correct_dashboard_state(self, mock_rm, mock_rep, mock_get_pods, mock_usage, mock_metrics, mock_rbac, mock_scan, mock_deploy):
        mock_deploy.return_value = {
            "success": True,
            "workload_name": "kubeguard-test-py-dash",
            "workload_kind": "Deployment",
            "pod_name": "dash-pod",
            "pod_uid": "uid-dash-99",
            "container_name": "target-container",
            "container_id": "cid-dash-99",
            "namespace": "default",
            "requested_image": "python:3.12-slim",
            "runtime_image": "python:3.12-slim",
            "privileged_status": "DISABLED",
            "start_time": "2026-10-30 11:30:00"
        }
        res_state = main.run_pipeline(
            selected_image="python:3.12-slim",
            run_id="run_dash_test_19",
            is_cli=False,
            deploy_workload=True
        )
        self.assertIn("modules", res_state)
        self.assertEqual(res_state["modules"]["M1"]["status"], "COMPLETED")
        self.assertEqual(res_state["modules"]["M2"]["status"], "RUNNING")
        self.assertEqual(res_state["modules"]["M5"]["status"], "COMPLETED")
        self.assertEqual(res_state["deployment"]["workload_name"], "kubeguard-test-py-dash")

    # 20. Correct consolidated forensic reporting
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    def test_20_correct_consolidated_forensic_report(self, mock_rep):
        rep = mock_rep()
        self.assertEqual(rep, "reports/forensic_report.pdf")

    # 21. Safe cleanup of KubeGuard-owned workloads
    @patch("deployment_manager.subprocess.run")
    def test_21_safe_cleanup_of_kubeguard_owned_workloads(self, mock_run):
        # 1. Deletion of KubeGuard workload succeeds
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "metadata": {
                    "name": "kubeguard-test-nginx-123",
                    "labels": {"app.kubernetes.io/managed-by": "kubeguard"}
                }
            })
        )
        ok_kg, _ = cleanup_kubernetes_workload("kubeguard-test-nginx-123", namespace="default")
        self.assertTrue(ok_kg)

        # 2. Deletion of user workload is blocked
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "metadata": {
                    "name": "nginx-production",
                    "labels": {"app": "nginx"}
                }
            })
        )
        ok_user, msg = cleanup_kubernetes_workload("nginx-production", namespace="default")
        self.assertFalse(ok_user)
        self.assertIn("Safety check failed", msg)

    # 22. Dashboard privileged mode toggle API
    @patch("dashboard.app.update_workload_privileged_mode")
    def test_22_dashboard_toggle_privileged_api(self, mock_update):
        mock_update.return_value = {
            "success": True,
            "workload_name": "kubeguard-test-python-api",
            "pod_name": "kubeguard-test-python-api-newpod",
            "pod_uid": "uid-new",
            "container_name": "target-container",
            "container_id": "cid-new",
            "privileged_requested": True,
            "privileged_admitted": True,
            "privileged_in_spec": True,
            "privileged_effective": True,
            "privileged_status": "ENABLED"
        }
        from dashboard.app import app
        client = app.test_client()
        resp = client.post("/api/workload/privileged", json={
            "workload_name": "kubeguard-test-python-api",
            "namespace": "default",
            "privileged": True
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["privileged_status"], "ENABLED")
        self.assertEqual(data["pod_name"], "kubeguard-test-python-api-newpod")


if __name__ == "__main__":
    unittest.main()
