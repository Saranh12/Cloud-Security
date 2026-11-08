"""
Test Suite for Module 4 (M4) kubectl Timeout Handling, Threat Detection, and Dashboard Synchronization.
Covers all 14 required verification scenarios specified in the master prompt.
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

import module4_detection
import main


class TestM4KubectlTimeoutAndSynchronization(unittest.TestCase):
    """
    Comprehensive tests for M4 timeout handling, metric parsing, threat evaluation,
    dashboard synchronization, and non-blocking M5/M6 behavior.
    """

    def setUp(self):
        self.state_file = Path("reports/dashboard_state.json")
        self.alert_log_file = Path("logs/alerts.log")

    # -------------------------------------------------------------
    # Scenario 1: kubectl top pod succeeds and returns metrics
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_01_kubectl_top_succeeds_and_returns_metrics(self, mock_run):
        mock_proc = MagicMock(
            returncode=0,
            stdout="my-pod-xyz   15m   42Mi\n",
            stderr=""
        )
        mock_run.return_value = mock_proc

        result = module4_detection.get_workload_usage(target_pod="my-pod-xyz", namespace="default")
        self.assertNotIn("error", result)
        self.assertEqual(result.get("pod"), "my-pod-xyz")
        self.assertEqual(result.get("cpu"), "15m")
        self.assertEqual(result.get("memory"), "42Mi")

    # -------------------------------------------------------------
    # Scenario 2: Metrics indicate threat (cpu > 200 or memory > 100)
    # -------------------------------------------------------------
    def test_02_metrics_indicate_threat(self):
        # CPU spike > 200m
        cpu_threat_data = {"pod": "worker-pod", "cpu": "250m", "memory": "50Mi"}
        cpu_res = module4_detection.detect_threat(cpu_threat_data)
        self.assertEqual(cpu_res.get("status"), "SUSPICIOUS ACTIVITY DETECTED")
        self.assertEqual(cpu_res.get("severity"), "High")
        self.assertIn("CPU usage detected", cpu_res.get("reason"))

        # Memory spike > 100Mi
        mem_threat_data = {"pod": "worker-pod", "cpu": "50m", "memory": "150Mi"}
        mem_res = module4_detection.detect_threat(mem_threat_data)
        self.assertEqual(mem_res.get("status"), "SUSPICIOUS ACTIVITY DETECTED")
        self.assertEqual(mem_res.get("severity"), "High")
        self.assertIn("memory usage detected", mem_res.get("reason"))

    # -------------------------------------------------------------
    # Scenario 3: Metrics indicate no threat (NORMAL)
    # -------------------------------------------------------------
    def test_03_metrics_indicate_no_threat_normal(self):
        clean_data = {"pod": "safe-pod", "cpu": "10m", "memory": "35Mi"}
        clean_res = module4_detection.detect_threat(clean_data)
        self.assertEqual(clean_res.get("status"), "NORMAL")
        self.assertEqual(clean_res.get("severity"), "None")
        self.assertEqual(clean_res.get("reason"), "No suspicious activity detected.")

    # -------------------------------------------------------------
    # Scenario 4: Command exceeds configured timeout (subprocess.TimeoutExpired)
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_04_command_exceeds_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["kubectl", "top", "pod", "nginx-pod"],
            timeout=15,
            output="",
            stderr=""
        )

        result = module4_detection.get_workload_usage(target_pod="nginx-pod", timeout=15)
        self.assertIn("error", result)
        self.assertTrue(result.get("timeout"))
        self.assertEqual(result.get("pod"), "nginx-pod")
        self.assertIn("timed out after 15s", result["error"])
        self.assertIn("Kubernetes metrics server is unresponsive or overloaded", result["error"])

    # -------------------------------------------------------------
    # Scenario 5: Target pod does not exist ("not found")
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_05_target_pod_not_found(self, mock_run):
        mock_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error from server (NotFound): pods \"missing-pod\" not found\n"
        )
        mock_run.return_value = mock_proc

        result = module4_detection.get_workload_usage(target_pod="missing-pod", namespace="default")
        self.assertIn("error", result)
        self.assertEqual(result.get("pod"), "missing-pod")
        self.assertIn("not found in namespace 'default'", result["error"])

    # -------------------------------------------------------------
    # Scenario 6: Metrics Server is unavailable ("metrics not available")
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_06_metrics_server_unavailable(self, mock_run):
        mock_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: Metrics not available yet for pod default/test-pod\n"
        )
        mock_run.return_value = mock_proc

        result = module4_detection.get_workload_usage(target_pod="test-pod", namespace="default")
        self.assertIn("error", result)
        self.assertEqual(result.get("pod"), "test-pod")
        self.assertIn("Metrics not available yet for pod 'test-pod'", result["error"])

    # -------------------------------------------------------------
    # Scenario 7: Kubernetes returns general error (returncode != 0)
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_07_kubernetes_general_error(self, mock_run):
        mock_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: the server is currently unable to handle the request (get pods.metrics.k8s.io)\n"
        )
        mock_run.return_value = mock_proc

        result = module4_detection.get_workload_usage(target_pod="any-pod", namespace="default")
        self.assertIn("error", result)
        self.assertIn("unable to handle the request", result["error"])

    # -------------------------------------------------------------
    # Scenario 8: Metrics output is malformed or empty
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_08_metrics_output_malformed_or_empty(self, mock_run):
        # Empty stdout
        mock_run.return_value = MagicMock(returncode=0, stdout="   \n  \n", stderr="")
        res_empty = module4_detection.get_workload_usage(target_pod="bad-pod")
        self.assertIn("error", res_empty)
        self.assertIn("empty output", res_empty["error"].lower())

        # Malformed stdout (< 3 columns)
        mock_run.return_value = MagicMock(returncode=0, stdout="bad-pod  25m\n", stderr="")
        res_malformed = module4_detection.get_workload_usage(target_pod="bad-pod")
        self.assertIn("error", res_malformed)
        self.assertIn("Malformed metrics output", res_malformed["error"])

    # -------------------------------------------------------------
    # Scenario 9: M4 fails while M5 produces valid result
    # -------------------------------------------------------------
    @patch("main.create_backup", return_value="backups/dummy_backup")
    @patch("main.collect_evidence", return_value="evidence/dummy_evidence")
    @patch("main.auto_isolate_pod", return_value={"status": "ISOLATED"})
    @patch("main.start_integrity_monitor", return_value=12345)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "survivor-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "survivor-pod", "container_name": "survivor-app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "survivor:1.0", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_09_m4_fails_while_m5_produces_valid_result(self, mock_email, mock_tg, *args):
        # M4 times out, M5 detects escape risk (privileged=True)
        m4_err = {
            "error": "Metrics query timed out after 15s for 'survivor-pod'. Kubernetes metrics server is unresponsive or overloaded.",
            "timeout": True,
            "pod": "survivor-pod"
        }
        with patch("main.get_workload_usage", return_value=m4_err):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "survivor-pod"}, "spec": {"containers": [{"name": "survivor-app", "image": "survivor:1.0", "securityContext": {"privileged": True}}]}, "status": {}}]):
                res_state = main.run_pipeline(selected_image="survivor:1.0", run_id="run_m4_fail_m5_success", is_cli=False, deploy_workload=True)

        m4_entry = res_state.get("modules", {}).get("M4", {})
        m5_entry = res_state.get("modules", {}).get("M5", {})

        # M4 is FAILED with timeout error
        self.assertEqual(m4_entry.get("status"), "FAILED")
        self.assertEqual(m4_entry.get("severity"), "None")
        self.assertIn("timed out", m4_entry.get("message"))
        self.assertEqual(m4_entry.get("details", {}).get("status"), "FAILED")

        # M5 was NOT blocked and successfully evaluated privileged container
        self.assertEqual(m5_entry.get("status"), "COMPLETED")
        self.assertEqual(m5_entry.get("severity"), "Critical")
        self.assertTrue(m5_entry.get("details", {}).get("privileged"))
        self.assertTrue(m5_entry.get("details", {}).get("escape_detected"))

    # -------------------------------------------------------------
    # Scenario 10: Dashboard state reflects timeout correctly
    # -------------------------------------------------------------
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "timed-out-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "timed-out-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:timeout", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_10_dashboard_state_reflects_timeout_correctly(self, mock_email, mock_tg, *args):
        m4_timeout = {
            "error": "Metrics query timed out after 15s for 'timed-out-pod'. Kubernetes metrics server is unresponsive or overloaded.",
            "timeout": True,
            "pod": "timed-out-pod"
        }
        with patch("main.get_workload_usage", return_value=m4_timeout):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "timed-out-pod"}, "spec": {"containers": [{"name": "app", "image": "app:timeout", "securityContext": {}}]}, "status": {}}]):
                res_state = main.run_pipeline(selected_image="app:timeout", run_id="run_state_check", is_cli=False, deploy_workload=True)

        m4_state = res_state["modules"]["M4"]
        self.assertEqual(m4_state["status"], "FAILED")
        self.assertEqual(m4_state["severity"], "None")
        self.assertIn("timed out after 15s", m4_state["message"])
        self.assertEqual(m4_state["details"]["pod"], "timed-out-pod")
        self.assertEqual(m4_state["details"]["cpu"], "N/A")
        self.assertEqual(m4_state["details"]["memory"], "N/A")
        self.assertEqual(m4_state["details"]["status"], "FAILED")
        self.assertEqual(m4_state["details"]["severity"], "None")

    # -------------------------------------------------------------
    # Scenario 11: Later successful assessment cleanly replaces previous error
    # -------------------------------------------------------------
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "retry-pod", "cpu": "20m", "memory": "40Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "retry-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:retry", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_11_later_successful_assessment_cleanly_replaces_previous_error(self, mock_email, mock_tg, *args):
        # Run 1: Timeout error
        m4_timeout = {
            "error": "Metrics query timed out after 15s for 'retry-pod'.",
            "timeout": True,
            "pod": "retry-pod"
        }
        with patch("main.get_workload_usage", return_value=m4_timeout):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "retry-pod"}, "spec": {"containers": [{"name": "app", "image": "app:retry", "securityContext": {}}]}, "status": {}}]):
                main.run_pipeline(selected_image="app:retry", run_id="run_step_error", is_cli=False, deploy_workload=True)

        # Run 2: Normal recovery
        m4_success = {"pod": "retry-pod", "cpu": "20m", "memory": "40Mi"}
        with patch("main.get_workload_usage", return_value=m4_success):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "retry-pod"}, "spec": {"containers": [{"name": "app", "image": "app:retry", "securityContext": {}}]}, "status": {}}]):
                res_state2 = main.run_pipeline(selected_image="app:retry", run_id="run_step_recovery", is_cli=False, deploy_workload=True)

        m4_now = res_state2["modules"]["M4"]
        self.assertEqual(m4_now["status"], "COMPLETED")
        self.assertEqual(m4_now["severity"], "None")
        self.assertEqual(m4_now["details"]["cpu"], "20m")
        self.assertEqual(m4_now["details"]["memory"], "40Mi")
        self.assertEqual(m4_now["details"]["status"], "NORMAL")
        self.assertNotIn("error", m4_now["details"])

    # -------------------------------------------------------------
    # Scenario 12: No stale threat or metric information displayed after a new run
    # -------------------------------------------------------------
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod-12", "cpu": "12m", "memory": "30Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod-12", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:clean-12", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_12_no_stale_threat_or_metric_after_new_run(self, mock_email, mock_tg, *args):
        # Step 1: High severity threat run
        spike_data = {"pod": "spike-pod", "cpu": "500m", "memory": "200Mi"}
        with patch("main.get_workload_usage", return_value=spike_data):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "spike-pod"}, "spec": {"containers": [{"name": "app", "image": "app:spike", "securityContext": {}}]}, "status": {}}]):
                main.run_pipeline(selected_image="app:spike", run_id="run_threat_spike", is_cli=False, deploy_workload=True)

        # Step 2: Clean run
        clean_data = {"pod": "clean-pod-12", "cpu": "12m", "memory": "30Mi"}
        with patch("main.get_workload_usage", return_value=clean_data):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "clean-pod-12"}, "spec": {"containers": [{"name": "app", "image": "app:clean-12", "securityContext": {}}]}, "status": {}}]):
                res_state = main.run_pipeline(selected_image="app:clean-12", run_id="run_clean_12", is_cli=False, deploy_workload=True)

        m4_final = res_state["modules"]["M4"]
        self.assertEqual(m4_final["severity"], "None")
        self.assertEqual(m4_final["status"], "COMPLETED")
        self.assertEqual(m4_final["details"]["cpu"], "12m")
        self.assertEqual(m4_final["details"]["memory"], "30Mi")
        self.assertEqual(m4_final["details"]["status"], "NORMAL")
        self.assertNotIn("500m", m4_final["details"]["cpu"])
        self.assertNotIn("200Mi", m4_final["details"]["memory"])

    # -------------------------------------------------------------
    # Scenario 13: M6 does not generate a false security notification on M4 failure
    # -------------------------------------------------------------
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "err-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "err-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:err", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_13_m6_does_not_generate_false_security_alert_on_m4_failure(self, mock_email, mock_tg, *args):
        m4_timeout = {
            "error": "Metrics query timed out after 15s for 'err-pod'. Kubernetes metrics server is unresponsive or overloaded.",
            "timeout": True,
            "pod": "err-pod"
        }
        with patch("main.get_workload_usage", return_value=m4_timeout):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "err-pod"}, "spec": {"containers": [{"name": "app", "image": "app:err", "securityContext": {}}]}, "status": {}}]):
                main.run_pipeline(selected_image="app:err", run_id="run_alert_check", is_cli=False, deploy_workload=True)

        # M6 must NOT have sent an M4 alert (neither Telegram nor Email)
        for call_args in mock_tg.call_args_list:
            msg = call_args[0][0]
            self.assertNotIn("MODULE 4 - THREAT DETECTION", msg)

        for call_args in mock_email.call_args_list:
            msg = call_args[0][0]
            self.assertNotIn("MODULE 4 - THREAT DETECTION", msg)

        # Alert logger must have recorded the failure as an operational error with SEVERITY=None and STATUS=FAILED
        from alert_logger import get_alert_log
        logs = get_alert_log()
        m4_fail_logs = [l for l in logs if "MODULE=M4" in l and "STATUS=FAILED" in l and "Operational error" in l]
        self.assertTrue(len(m4_fail_logs) > 0, "Expected M4 operational error to be recorded in alert log")

    # -------------------------------------------------------------
    # Scenario 14: Telemetry reuse avoids duplicate kubectl top calls
    # -------------------------------------------------------------
    @patch("module4_detection.subprocess.run")
    def test_14_cached_telemetry_reuses_m2_metrics_without_subprocess(self, mock_run):
        cached = {
            "pod": "live-app-pod",
            "cpu": "18m",
            "memory": "55Mi"
        }
        result = module4_detection.get_workload_usage(
            target_pod="live-app-pod",
            cached_metrics=cached
        )
        # subprocess.run must not have been called because cached metrics were fresh and valid
        mock_run.assert_not_called()
        self.assertEqual(result.get("pod"), "live-app-pod")
        self.assertEqual(result.get("cpu"), "18m")
        self.assertEqual(result.get("memory"), "55Mi")
        self.assertEqual(result.get("source"), "cached_telemetry")


if __name__ == "__main__":
    unittest.main()
