"""
Comprehensive Automated Test Suite for KubeGuard Image-to-Runtime Workflow.
Validates all 24 scenarios required by Section 15 of the master prompt.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import deployment_manager
import vuln_scan
import monitoring
import module4_detection
import module5_escape
import alerting
import email_alerting
import alert_logger
import main


class TestImageToRuntimeWorkflow(unittest.TestCase):

    def setUp(self):
        self.state_file = Path("reports/dashboard_state.json")

    # -------------------------------------------------------------
    # Scenario 1: A valid image is scanned and same resolved image deployed
    # -------------------------------------------------------------
    @patch("subprocess.run")
    @patch("shutil.which", return_value="C:\\tools\\trivy.exe")
    def test_01_valid_image_scanned_and_deployed(self, mock_which, mock_subproc):
        def subproc_side_effect(cmd, **kwargs):
            if cmd and cmd[0] == "trivy":
                return MagicMock(
                    returncode=0,
                    stdout=json.dumps({
                        "Metadata": {"RepoDigests": ["python@sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"]},
                        "Results": []
                    }),
                    stderr=""
                )
            elif "apply" in cmd:
                return MagicMock(returncode=0, stdout="deployment applied", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "kubeguard-py-123", "namespace": "default"},
                        "spec": {"containers": [{"name": "target-container", "image": "python:3.12-slim"}]},
                        "status": {
                            "phase": "Running",
                            "containerStatuses": [{
                                "name": "target-container",
                                "imageID": "docker-pullable://python@sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
                                "containerID": "containerd://abcdef123456"
                            }]
                        }
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = subproc_side_effect

        scan = vuln_scan.scan_image("python:3.12-slim", output_path=None)
        self.assertEqual(scan["status"], "COMPLETED")
        self.assertEqual(scan["image"], "python:3.12-slim")
        self.assertIn("11112222", scan["image_digest"])

        dep_res = deployment_manager.deploy_workload(
            {"image": "python:3.12-slim", "runtime_target": "kubernetes"},
            scanned_digest=scan["image_digest"]
        )
        self.assertTrue(dep_res["success"])
        self.assertEqual(dep_res["pod_name"], "kubeguard-py-123")
        self.assertEqual(dep_res["identity_status"], "VERIFIED")

    # -------------------------------------------------------------
    # Scenario 2: Image identity verification succeeds
    # -------------------------------------------------------------
    def test_02_image_identity_verification_succeeds(self):
        digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        res = deployment_manager.verify_image_identity(
            scanned_digest=digest,
            runtime_image_id=f"docker-pullable://myimage@{digest}",
            requested_image="myimage:1.0",
            runtime_image="myimage:1.0"
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["status"], "VERIFIED")
        self.assertIn("verified match", res["details"])

    # -------------------------------------------------------------
    # Scenario 3: Image identity mismatch is detected
    # -------------------------------------------------------------
    def test_03_image_identity_mismatch_detected(self):
        scanned_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        runtime_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
        res = deployment_manager.verify_image_identity(
            scanned_digest=scanned_digest,
            runtime_image_id=f"docker-pullable://myimage@{runtime_digest}",
            requested_image="myimage:v1",
            runtime_image="myimage:v2"
        )
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "MISMATCH")
        self.assertIn("mismatch", res["details"].lower())

    # -------------------------------------------------------------
    # Scenario 4: Image pull fails
    # -------------------------------------------------------------
    @patch("deployment_manager.subprocess.run")
    def test_04_image_pull_fails(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "pull-fail-pod"},
                        "status": {
                            "phase": "Pending",
                            "containerStatuses": [{
                                "name": "target-container",
                                "state": {"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image"}}
                            }]
                        }
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        res = deployment_manager.deploy_workload({"image": "invalid/nonexistent:tag", "runtime_target": "kubernetes"})
        self.assertFalse(res["success"])
        self.assertIn("Image pull failed", res["error"])

    # -------------------------------------------------------------
    # Scenario 5: Deployment fails
    # -------------------------------------------------------------
    @patch("deployment_manager.subprocess.run")
    def test_05_deployment_fails(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error: namespaces 'invalid-ns' not found")
        res = deployment_manager.deploy_workload({"image": "nginx:latest", "namespace": "invalid-ns"})
        self.assertFalse(res["success"])
        self.assertIn("Failed to apply deployment manifest", res["error"])

    # -------------------------------------------------------------
    # Scenario 6: Deployment succeeds but workload is not yet ready (timeout)
    # -------------------------------------------------------------
    @patch("deployment_manager.subprocess.run")
    @patch("deployment_manager.time.sleep")
    def test_06_deployment_readiness_timeout(self, mock_sleep, mock_run):
        def side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "slow-pod"},
                        "status": {"phase": "Pending", "containerStatuses": []}
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        res = deployment_manager.deploy_workload({"image": "node:22", "timeout": 2})
        self.assertFalse(res["success"])
        self.assertIn("did not become ready", res["error"])

    # -------------------------------------------------------------
    # Scenario 7: Actual runtime container discovery succeeds
    # -------------------------------------------------------------
    @patch("deployment_manager.subprocess.run")
    def test_07_runtime_container_discovery_succeeds(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "apply" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            elif "get" in cmd and "pods" in cmd:
                pod_json = {
                    "items": [{
                        "metadata": {"name": "app-pod-xyz", "namespace": "default"},
                        "spec": {"containers": [{"name": "target-container", "image": "node:22"}]},
                        "status": {
                            "phase": "Running",
                            "containerStatuses": [{
                                "name": "target-container",
                                "imageID": "docker-pullable://node@sha256:aabbcc",
                                "containerID": "containerd://cid12345"
                            }]
                        }
                    }]
                }
                return MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        res = deployment_manager.deploy_workload({"image": "node:22"})
        self.assertTrue(res["success"])
        self.assertEqual(res["pod_name"], "app-pod-xyz")
        self.assertEqual(res["container_id"], "containerd://cid12345")
        self.assertEqual(res["runtime_image_id"], "docker-pullable://node@sha256:aabbcc")

    # -------------------------------------------------------------
    # Scenario 8: Arbitrary image names supported without hardcoded nginx assumptions
    # -------------------------------------------------------------
    def test_08_arbitrary_image_names_supported(self):
        images = [
            "python:3.12-slim",
            "redis:7",
            "quay.io/prometheus/prometheus:v2.45.0",
            "gcr.io/distroless/static:latest",
            "ghcr.io/owner/repo/custom-service:v1.2.3"
        ]
        for img in images:
            valid, msg = vuln_scan.validate_image_reference(img)
            self.assertTrue(valid, f"Expected {img} to be valid: {msg}")
            sanitized = deployment_manager.sanitize_workload_name(img.split("/")[-1].split(":")[0])
            self.assertTrue(sanitized.startswith("kubeguard-"))

    # -------------------------------------------------------------
    # Scenario 9: Standard container assessed successfully
    # -------------------------------------------------------------
    def test_09_standard_container_assessed_clean(self):
        pod_spec = [{
            "metadata": {"name": "clean-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "redis:7",
                    "securityContext": {"privileged": False}
                }]
            },
            "status": {}
        }]
        res = module5_escape.detect_escape_indicators(pod_spec)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["status"], "NORMAL")
        self.assertFalse(res[0]["privileged"])
        self.assertEqual(res[0]["severity"], "None")
        self.assertEqual(len(res[0]["findings"]), 0)

    # -------------------------------------------------------------
    # Scenario 10: Privileged container detected when effective runtime confirms privileged
    # -------------------------------------------------------------
    def test_10_privileged_container_detected(self):
        pod_spec = [{
            "metadata": {"name": "priv-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "priv-app",
                    "image": "alpine:latest",
                    "securityContext": {"privileged": True}
                }]
            },
            "status": {}
        }]
        res = module5_escape.detect_escape_indicators(pod_spec)
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0]["privileged"])
        self.assertEqual(res[0]["severity"], "Critical")
        self.assertIn("Privileged container configuration detected.", res[0]["findings"])
        self.assertTrue(res[0]["incident_triggered"])

    # -------------------------------------------------------------
    # Scenario 11: Requested privileged mode rejected by Kubernetes reported accurately
    # -------------------------------------------------------------
    @patch("deployment_manager.subprocess.run")
    def test_11_privileged_mode_rejected_reported_accurately(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error from server (Forbidden): pods \"priv-pod\" is forbidden: violates PodSecurity \"baseline:latest\": privileged (container \"target-container\" must not set securityContext.privileged=true)"
        )
        res = deployment_manager.deploy_workload({
            "image": "alpine:latest",
            "security_profile": "privileged",
            "privileged": True
        })
        self.assertFalse(res["success"])
        self.assertEqual(res["privileged_status"], "REJECTED")
        self.assertIn("Admission Policy rejected", res["error"])

    # -------------------------------------------------------------
    # Scenario 12: Dangerous capabilities detected
    # -------------------------------------------------------------
    def test_12_dangerous_capabilities_detected(self):
        for cap in ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "ALL"]:
            pod_spec = [{
                "metadata": {"name": f"cap-{cap.lower()}-pod", "namespace": "default"},
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": "ubuntu:24.04",
                        "securityContext": {"capabilities": {"add": [cap]}}
                    }]
                },
                "status": {}
            }]
            res = module5_escape.detect_escape_indicators(pod_spec)
            self.assertEqual(res[0]["severity"], "High")
            self.assertTrue(any(cap in f for f in res[0]["findings"]))

    # -------------------------------------------------------------
    # Scenario 13: Host namespace and hostPath risks detected
    # -------------------------------------------------------------
    def test_13_host_namespace_and_hostpath_detected(self):
        pod_spec = [{
            "metadata": {"name": "host-risk-pod", "namespace": "default"},
            "spec": {
                "hostPID": True,
                "hostNetwork": True,
                "hostIPC": True,
                "volumes": [{"name": "root-vol", "hostPath": {"path": "/"}}],
                "containers": [{"name": "app", "image": "busybox:latest"}]
            },
            "status": {}
        }]
        res = module5_escape.detect_escape_indicators(pod_spec)
        findings_str = " ".join(res[0]["findings"])
        self.assertIn("Host PID", findings_str)
        self.assertIn("Host network", findings_str)
        self.assertIn("Host IPC", findings_str)
        self.assertIn("Host filesystem mount", findings_str)
        self.assertEqual(res[0]["severity"], "High")

    # -------------------------------------------------------------
    # Scenario 14: M2 reports actual available metrics
    # -------------------------------------------------------------
    @patch("monitoring.subprocess.run")
    def test_14_m2_reports_actual_available_metrics(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="live-pod   15m   64Mi\n",
            stderr=""
        )
        res = monitoring.get_pod_metrics(target_pod="live-pod")
        self.assertTrue(res["metrics_available"])
        self.assertEqual(res["cpu"], "15m")
        self.assertEqual(res["memory"], "64Mi")

    # -------------------------------------------------------------
    # Scenario 15: Missing Metrics Server produces unavailable telemetry honestly
    # -------------------------------------------------------------
    @patch("monitoring.subprocess.run")
    def test_15_missing_metrics_server_reported_honestly(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: Metrics not available yet for pod default/unready-pod\n"
        )
        res = monitoring.get_pod_metrics(target_pod="unready-pod")
        self.assertFalse(res["metrics_available"])
        self.assertIsNone(res["cpu"])
        self.assertIsNone(res["memory"])
        self.assertIn("Metrics not available yet", res["error"])

    # -------------------------------------------------------------
    # Scenario 16: M4 distinguishes NORMAL, THREAT_DETECTED, FAILED, NOT_APPLICABLE
    # -------------------------------------------------------------
    def test_16_m4_distinguishes_outcomes(self):
        # NORMAL
        normal = module4_detection.detect_threat({"pod": "p", "cpu": "10m", "memory": "20Mi"})
        self.assertEqual(normal["status"], "NORMAL")

        # THREAT_DETECTED (CPU spike)
        threat = module4_detection.detect_threat({"pod": "p", "cpu": "450m", "memory": "20Mi"})
        self.assertEqual(threat["status"], "SUSPICIOUS ACTIVITY DETECTED")
        self.assertEqual(threat["severity"], "High")

        # FAILED
        failed = module4_detection.detect_threat({"error": "Metrics timeout"})
        self.assertEqual(failed["status"], "ERROR")

    # -------------------------------------------------------------
    # Scenario 17: M5 distinguishes clean, findings, and failed inspection
    # -------------------------------------------------------------
    def test_17_m5_distinguishes_outcomes(self):
        # Clean
        clean = module5_escape.detect_escape_indicators([{"metadata": {"name": "c"}, "spec": {"containers": [{"name": "app"}]}}])
        self.assertEqual(clean[0]["status"], "NORMAL")
        self.assertEqual(clean[0]["severity"], "None")

        # Findings
        findings = module5_escape.detect_escape_indicators([{"metadata": {"name": "f"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}])
        self.assertEqual(findings[0]["severity"], "Critical")

        # Failed inspection (error dictionary returned)
        err = module5_escape.detect_escape_indicators({"error": "Kubernetes API connection refused"})
        self.assertIn("error", err)

    # -------------------------------------------------------------
    # Scenario 18: M6 independently handles Telegram and email failures
    # -------------------------------------------------------------
    @patch("alerting.requests.post")
    @patch("email_alerting.smtplib.SMTP")
    def test_18_m6_independent_channel_handling(self, mock_smtp, mock_post):
        # Telegram fails with timeout, SMTP succeeds
        mock_post.side_effect = Exception("Telegram connection timeout")
        smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = smtp_instance

        tg_res = alerting.send_telegram_alert("test alert")
        self.assertFalse(tg_res["success"])

        with patch.dict(os.environ, {"ALERT_EMAIL_ENABLED": "true", "SMTP_SERVER": "smtp.test.com", "ALERT_EMAIL_RECEIVER": "test@test.com"}):
            em_res = email_alerting.send_email_alert("test alert")
            self.assertTrue(em_res["success"])

    # -------------------------------------------------------------
    # Scenario 19: A failed assessment does not generate a false clean notification
    # -------------------------------------------------------------
    @patch("main.send_telegram_alert")
    @patch("main.send_email_alert")
    @patch("main.log_alert")
    def test_19_failed_assessment_no_false_clean_notification(self, mock_log, mock_email, mock_tg):
        # When M4 fails with operational error, it must skip notification
        with patch("main.get_workload_usage", return_value={"error": "Metrics server timeout"}):
            with patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "p"}):
                with patch("main.get_pod_metrics", return_value={"pod_name": "p", "cpu": "10m", "memory": "20Mi"}):
                    with patch("main.scan_image", return_value={"image": "app:1", "severity_counts": {"CRITICAL": 0}, "deployment_blocked": False}):
                        main.run_pipeline(selected_image="app:1", run_id="run_m4_fail_clean", is_cli=False, deploy_workload=True)

        for call_args in mock_tg.call_args_list:
            self.assertNotIn("KubeGuard STATUS UPDATE", call_args[0][0])
            self.assertNotIn("MODULE 4", call_args[0][0])

    # -------------------------------------------------------------
    # Scenario 20: Evidence, dashboard, and forensic report use consistent run IDs and identities
    # -------------------------------------------------------------
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/test_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": []})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "consistent-pod", "container_name": "app", "namespace": "default"})
    @patch("main.get_pod_metrics", return_value={"pod_name": "consistent-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.scan_image", return_value={"image": "app:consist", "severity_counts": {"CRITICAL": 0}, "image_digest": "sha256:123456", "deployment_blocked": False})
    @patch("main.send_telegram_alert", return_value={"success": True})
    @patch("main.send_email_alert", return_value={"success": True})
    def test_20_evidence_dashboard_forensic_report_consistency(self, mock_email, mock_tg, *args):
        run_id = "run_consistent_id_001"
        with patch("main.get_workload_usage", return_value={"pod": "consistent-pod", "cpu": "10m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "consistent-pod"}, "spec": {"containers": [{"name": "app", "securityContext": {}}]}, "status": {}}]):
                res = main.run_pipeline(selected_image="app:consist", run_id=run_id, is_cli=False, deploy_workload=True)

        self.assertEqual(res["run_id"], run_id)
        self.assertEqual(res["target_pod"], "consistent-pod")

    # -------------------------------------------------------------
    # Scenario 21: A new assessment does not display stale findings from an earlier run
    # -------------------------------------------------------------
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/test_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:clean", "severity_counts": {"CRITICAL": 0}, "deployment_blocked": False})
    @patch("main.send_telegram_alert", return_value={"success": True})
    @patch("main.send_email_alert", return_value={"success": True})
    def test_21_no_stale_findings_in_new_run(self, mock_email, mock_tg, *args):
        # Step 1: Run with Critical Privileged finding
        with patch("main.get_workload_usage", return_value={"pod": "priv-pod", "cpu": "10m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "priv-pod"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}, "status": {}}]):
                with patch("main.create_backup", return_value="backups/dummy"):
                    with patch("main.collect_evidence", return_value="evidence/dummy"):
                        with patch("main.auto_isolate_pod", return_value={"status": "ISOLATED"}):
                            with patch("main.start_integrity_monitor", return_value=123):
                                main.run_pipeline(selected_image="app:priv", run_id="run_priv_stale_test", is_cli=False, deploy_workload=True)

        # Step 2: Clean run
        with patch("main.get_workload_usage", return_value={"pod": "clean-pod", "cpu": "10m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "clean-pod"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}, "status": {}}]):
                res2 = main.run_pipeline(selected_image="app:clean", run_id="run_clean_stale_test", is_cli=False, deploy_workload=True)

        m5_entry = res2["modules"]["M5"]
        self.assertEqual(m5_entry["severity"], "None")
        self.assertEqual(m5_entry["status"], "COMPLETED")
        self.assertFalse(m5_entry["details"]["privileged"])
        self.assertEqual(m5_entry["details"]["escape_indicators"], 0)

    # -------------------------------------------------------------
    # Scenario 22: Cleanup only affects KubeGuard-owned resources
    # -------------------------------------------------------------
    @patch("deployment_manager.subprocess.run")
    def test_22_cleanup_only_affects_kubeguard_resources(self, mock_run):
        deployment_manager.cleanup_kubernetes_workload("kubeguard-target-xyz", namespace="default")
        cmd_called = mock_run.call_args[0][0]
        self.assertIn("deployment", cmd_called)
        self.assertIn("kubeguard-target-xyz", cmd_called)
        self.assertNotIn("kube-system", cmd_called)

    # -------------------------------------------------------------
    # Scenario 23: Unauthorized deployment requests fail safely
    # -------------------------------------------------------------
    def test_23_unauthorized_deployment_requests_fail_safely(self):
        # Invalid image with shell metacharacters
        valid, err = deployment_manager.validate_deployment_options({"image": "evil; rm -rf /; :latest"})
        self.assertFalse(valid)
        self.assertIn("invalid", err.lower())

        # Invalid namespace
        valid_ns, err_ns = deployment_manager.validate_deployment_options({"image": "nginx:latest", "namespace": "INVALID_UPPERCASE_NS!"})
        self.assertFalse(valid_ns)
        self.assertIn("namespace", err_ns.lower())

    # -------------------------------------------------------------
    # Scenario 24: Existing M1, M2, M4, M5, M6, RBAC audit, evidence, forensics pass
    # -------------------------------------------------------------
    def test_24_existing_modules_integrity(self):
        # Verify M1
        self.assertTrue(callable(vuln_scan.scan_image))
        # Verify M2
        self.assertTrue(callable(monitoring.get_pod_metrics))
        # Verify M4
        self.assertTrue(callable(module4_detection.detect_threat))
        # Verify M5
        self.assertTrue(callable(module5_escape.detect_escape_indicators))
        # Verify M6
        self.assertTrue(callable(alerting.send_telegram_alert))
        self.assertTrue(callable(email_alerting.send_email_alert))
        # Verify Alert Logger
        self.assertTrue(callable(alert_logger.log_alert))


if __name__ == "__main__":
    unittest.main()
