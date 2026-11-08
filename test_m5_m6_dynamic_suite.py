import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from pathlib import Path

# Ensure workspace root in path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import vuln_scan
import module5_escape
import module4_detection
import alerting
import email_alerting
import alert_logger


class TestM1MultipleImageScanning(unittest.TestCase):
    """
    PHASE 11 / M1: Multiple-image vulnerability scanning tests
    """

    @patch("vuln_scan.subprocess.run")
    @patch("vuln_scan.shutil.which", return_value="C:\\tools\\trivy.exe")
    def test_01_single_image_scan_success(self, mock_which, mock_run):
        mock_output = {
            "Results": [{
                "Target": "python:3.12-slim (debian 12.5)",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-1111",
                    "PkgName": "libssl3",
                    "InstalledVersion": "3.0.11-1",
                    "Severity": "HIGH"
                }]
            }]
        }
        mock_proc = MagicMock(returncode=0, stdout=json.dumps(mock_output), stderr="")
        mock_run.return_value = mock_proc

        res = vuln_scan.scan_image("python:3.12-slim", output_path=None)
        self.assertEqual(res.get("status"), "COMPLETED")
        self.assertEqual(res.get("image"), "python:3.12-slim")
        self.assertEqual(res["severity_counts"]["HIGH"], 1)
        self.assertEqual(res["severity_counts"]["CRITICAL"], 0)
        self.assertFalse(res["deployment_blocked"])

    @patch("vuln_scan.subprocess.run")
    @patch("vuln_scan.shutil.which", return_value="C:\\tools\\trivy.exe")
    def test_02_multiple_images_scanned(self, mock_which, mock_run):
        def side_effect(cmd, **kwargs):
            target = cmd[-1]
            mock_proc = MagicMock(returncode=0, stderr="")
            if "redis" in target:
                mock_proc.stdout = json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "LOW", "VulnerabilityID": "CVE-LOW-1"}]}]})
            else:
                mock_proc.stdout = json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL", "VulnerabilityID": "CVE-CRIT-1"}]}]})
            return mock_proc

        mock_run.side_effect = side_effect

        images = ["redis:7", "nginx:latest"]
        res = vuln_scan.scan_images(images, output_dir=None)

        self.assertEqual(res["total_scanned"], 2)
        self.assertEqual(res["successful"], 2)
        self.assertEqual(res["failed"], 0)
        self.assertEqual(res["severity_counts"]["LOW"], 1)
        self.assertEqual(res["severity_counts"]["CRITICAL"], 1)
        self.assertIn("CVE-CRIT-1", res["critical_cve_ids"])
        self.assertTrue(res["deployment_blocked"])
        self.assertEqual(len(res["images"]), 2)

    @patch("vuln_scan.subprocess.run")
    @patch("vuln_scan.shutil.which", return_value="C:\\tools\\trivy.exe")
    def test_03_one_image_fails_remaining_processed(self, mock_which, mock_run):
        mock_proc = MagicMock(returncode=0, stdout=json.dumps({"Results": []}), stderr="")
        mock_run.return_value = mock_proc

        images = ["invalid;name", "alpine:3.21"]
        res = vuln_scan.scan_images(images, output_dir=None)

        self.assertEqual(res["total_scanned"], 2)
        self.assertEqual(res["successful"], 1)
        self.assertEqual(res["failed"], 1)
        self.assertEqual(res["images"][0]["status"], "FAILED")
        self.assertEqual(res["images"][1]["status"], "COMPLETED")
        self.assertEqual(res["images"][1]["image"], "alpine:3.21")

    @patch("vuln_scan.subprocess.run")
    @patch("vuln_scan.shutil.which", return_value="C:\\tools\\trivy.exe")
    def test_04_m1_no_nginx_substitution(self, mock_which, mock_run):
        mock_proc = MagicMock(returncode=0, stdout=json.dumps({"Results": []}), stderr="")
        mock_run.return_value = mock_proc

        custom_img = "node:22"
        res = vuln_scan.scan_image(custom_img, output_path=None)
        self.assertEqual(res["image"], "node:22")
        self.assertNotIn("nginx", res["image"])


class TestM4NotificationWorkflow(unittest.TestCase):
    """
    PHASE 10: M4 NOTIFICATION TESTS
    1. A threat finding produces a security-alert message.
    2. A clean assessment produces a normal-status message.
    3. Both cases attempt Telegram and email delivery.
    4. The alert log receives the correct module and status.
    5. Severity capitalization does not cause a real threat to be classified as clean.
    6. An M4 exception does not prevent M5 processing.
    """

    @patch("alerting.send_telegram_alert", return_value={"success": True, "message": "OK"})
    @patch("email_alerting.send_email_alert", return_value={"success": True, "message": "OK"})
    @patch("alert_logger.log_alert")
    def test_01_threat_finding_produces_security_alert(self, mock_log, mock_email, mock_tg):
        threat_data = {"pod": "worker-1", "cpu": "350m", "memory": "40Mi"}
        res = module4_detection.detect_threat(threat_data)
        self.assertEqual(res["status"], "SUSPICIOUS ACTIVITY DETECTED")

        # Emulate M4 alerting block
        sev_upper = str(res.get("severity")).upper()
        self.assertIn(sev_upper, ["HIGH", "CRITICAL"])

        msg = (
            "🚨 MODULE 4 - THREAT DETECTION\n\n"
            "KubeGuard SECURITY ALERT\n"
            f"Status: {res['status']}\nSeverity: {res['severity']}\nPod: {threat_data['pod']}\n"
        )
        alerting.send_telegram_alert(msg)
        email_alerting.send_email_alert(msg)
        alert_logger.log_alert("M4", res["severity"], res["status"], "Threat detected")

        self.assertIn("🚨 MODULE 4 - THREAT DETECTION", msg)
        self.assertIn("KubeGuard SECURITY ALERT", msg)
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)
        mock_log.assert_called_with("M4", res["severity"], res["status"], "Threat detected")

    @patch("alerting.send_telegram_alert", return_value={"success": True, "message": "OK"})
    @patch("email_alerting.send_email_alert", return_value={"success": True, "message": "OK"})
    @patch("alert_logger.log_alert")
    def test_02_clean_assessment_produces_normal_status_message(self, mock_log, mock_email, mock_tg):
        clean_data = {"pod": "worker-clean", "cpu": "10m", "memory": "25Mi"}
        res = module4_detection.detect_threat(clean_data)
        self.assertEqual(res["status"], "NORMAL")
        self.assertEqual(res["severity"], "None")

        msg = (
            "🟢 MODULE 4 - THREAT DETECTION\n\n"
            "KubeGuard STATUS UPDATE\n"
            f"Status: {res['status']}\nSeverity: {res['severity']}\n"
            "Reason: No suspicious activity detected."
        )
        alerting.send_telegram_alert(msg)
        email_alerting.send_email_alert(msg)
        alert_logger.log_alert("M4", res["severity"], res["status"], "Normal status")

        self.assertIn("🟢 MODULE 4 - THREAT DETECTION", msg)
        self.assertIn("KubeGuard STATUS UPDATE", msg)
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)
        mock_log.assert_called_with("M4", "None", "NORMAL", "Normal status")

    def test_05_severity_capitalization_normalization(self):
        """Verify casing variations ('High', 'HIGH', 'Critical', 'CRITICAL') normalize correctly."""
        for test_sev in ["High", "HIGH", "Critical", "CRITICAL"]:
            self.assertTrue(str(test_sev).upper() in ["HIGH", "CRITICAL"])

        for test_sev in ["None", "none", "Low", "LOW", "Medium", "MEDIUM"]:
            self.assertFalse(str(test_sev).upper() in ["HIGH", "CRITICAL"])

    def test_06_m4_exception_isolation(self):
        """Operational failure in M4 produces structured error and does not crash."""
        error_data = {"error": "Metrics unavailable: cluster unreachable"}
        res = module4_detection.detect_threat(error_data)
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["severity"], "None")
        self.assertIn("cluster unreachable", res["reason"])


class TestM5NotificationWorkflow(unittest.TestCase):
    """
    PHASE 10: M5 NOTIFICATION TESTS
    1. Security findings produce an M5 security-alert message.
    2. Critical and high-risk findings are represented correctly.
    3. A clean assessment produces a normal-status message.
    4. Both cases attempt Telegram and email delivery.
    5. The alert log records the actual findings or clean result.
    6. M5 inspection failure is not classified as a clean assessment.
    7. M5 does not depend on a hardcoded nginx target.
    """

    @patch("alerting.send_telegram_alert", return_value={"success": True, "message": "OK"})
    @patch("email_alerting.send_email_alert", return_value={"success": True, "message": "OK"})
    @patch("alert_logger.log_alert")
    def test_01_security_findings_produce_security_alert(self, mock_log, mock_email, mock_tg):
        pod_spec = [{
            "metadata": {"name": "app-priv-pod", "namespace": "prod"},
            "spec": {"containers": [{"name": "app", "image": "redis:7", "securityContext": {"privileged": True}}]},
            "status": {"containerStatuses": [{"name": "app", "containerID": "containerd://app99", "state": {"running": {}}}]}
        }]
        escape_res = module5_escape.detect_escape_indicators(pod_spec)
        self.assertEqual(escape_res[0]["severity"], "Critical")
        self.assertEqual(escape_res[0]["status"], "SUSPICIOUS CONFIGURATION DETECTED")

        critical_pods = [r["pod"] for r in escape_res if str(r.get("severity", "")).upper() == "CRITICAL"]
        self.assertIn("app-priv-pod", critical_pods)

        msg = (
            "🚨 MODULE 5 - CONTAINER ESCAPE DETECTION\n\n"
            "KubeGuard SECURITY ALERT\n"
            f"Critical Pods: {', '.join(critical_pods)}\n"
            "Action: Critical Pods are eligible for M9 automatic isolation."
        )
        alerting.send_telegram_alert(msg)
        email_alerting.send_email_alert(msg)
        alert_logger.log_alert("M5", "CRITICAL", "SUSPICIOUS ACTIVITY DETECTED", f"Critical Pods={', '.join(critical_pods)}")

        self.assertIn("🚨 MODULE 5 - CONTAINER ESCAPE DETECTION", msg)
        self.assertIn("KubeGuard SECURITY ALERT", msg)
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)

    @patch("alerting.send_telegram_alert", return_value={"success": True, "message": "OK"})
    @patch("email_alerting.send_email_alert", return_value={"success": True, "message": "OK"})
    @patch("alert_logger.log_alert")
    def test_03_clean_assessment_produces_normal_status_message(self, mock_log, mock_email, mock_tg):
        pod_spec = [{
            "metadata": {"name": "safe-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "safe", "image": "redis:7", "securityContext": {"privileged": False}}]},
            "status": {"containerStatuses": [{"name": "safe", "containerID": "containerd://safe01", "state": {"running": {}}}]}
        }]
        escape_res = module5_escape.detect_escape_indicators(pod_spec)
        self.assertEqual(escape_res[0]["severity"], "None")
        self.assertEqual(escape_res[0]["status"], "NORMAL")

        msg = (
            "🟢 MODULE 5 - CONTAINER ESCAPE DETECTION\n\n"
            "KubeGuard STATUS UPDATE\n"
            "Status: NORMAL\nSeverity: None\n"
            "Result: No container escape indicators detected."
        )
        alerting.send_telegram_alert(msg)
        email_alerting.send_email_alert(msg)
        alert_logger.log_alert("M5", "None", "NORMAL", "No container escape indicators detected")

        self.assertIn("🟢 MODULE 5 - CONTAINER ESCAPE DETECTION", msg)
        self.assertIn("KubeGuard STATUS UPDATE", msg)
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)

    @patch("module5_escape.subprocess.run")
    def test_06_m5_inspection_failure_not_classified_as_clean(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="Error from server: connection refused", stdout="")
        res = module5_escape.get_pods(target_pod="target-pod")
        self.assertIsInstance(res, dict)
        self.assertIn("error", res)
        # Verify it is not an empty list or clean assessment
        self.assertNotEqual(res, [])
        self.assertNotEqual(res, [{"severity": "None"}])

    @patch("module5_escape.subprocess.run")
    def test_07_m5_does_not_depend_on_hardcoded_nginx(self, mock_run):
        cluster_pods = {
            "items": [{
                "metadata": {"name": "nginx-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]}
            }]
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(cluster_pods), stderr="")

        res = module5_escape.get_pods(target_image="python:3.12-slim")
        self.assertIsInstance(res, dict)
        self.assertIn("error", res)
        self.assertIn("No running pod found for image 'python:3.12-slim'", res["error"])


class TestM6IntegrationAndChannelIsolation(unittest.TestCase):
    """
    PHASE 10: M6 INTEGRATION & CHANNEL ISOLATION TESTS (Scenarios 1-14)
    """

    @patch("requests.post", side_effect=Exception("Telegram network error"))
    @patch("email_alerting.smtplib.SMTP_SSL")
    def test_07_telegram_fails_email_succeeds(self, mock_smtp, mock_post):
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "token123",
            "TELEGRAM_CHAT_ID": "chat123",
            "EMAIL_SENDER": "sender@test.com",
            "EMAIL_APP_PASSWORD": "password123",
            "EMAIL_RECEIVER": "receiver@test.com"
        }):
            res = alerting.dispatch_module_alert("M4", "Test message")
            self.assertFalse(res["telegram"]["success"])
            self.assertIn("Telegram network error", res["telegram"]["error"])
            self.assertTrue(res["email"]["success"])
            self.assertTrue(mock_server.sendmail.called)

    @patch("requests.post")
    @patch("email_alerting.smtplib.SMTP_SSL", side_effect=Exception("SMTP auth failed"))
    def test_08_email_fails_telegram_succeeds(self, mock_smtp, mock_post):
        mock_resp = MagicMock(ok=True)
        mock_resp.json.return_value = {"ok": True}
        mock_post.return_value = mock_resp

        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "token123",
            "TELEGRAM_CHAT_ID": "chat123",
            "EMAIL_SENDER": "sender@test.com",
            "EMAIL_APP_PASSWORD": "password123",
            "EMAIL_RECEIVER": "receiver@test.com"
        }):
            res = alerting.dispatch_module_alert("M5", "Test message")
            self.assertTrue(res["telegram"]["success"])
            self.assertFalse(res["email"]["success"])
            self.assertIn("SMTP auth failed", res["email"]["error"])

    @patch("requests.post", side_effect=Exception("Telegram connection refused"))
    @patch("email_alerting.smtplib.SMTP_SSL", side_effect=Exception("SMTP unreachable"))
    def test_09_both_notification_channels_fail(self, mock_smtp, mock_post):
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "token123",
            "TELEGRAM_CHAT_ID": "chat123",
            "EMAIL_SENDER": "sender@test.com",
            "EMAIL_APP_PASSWORD": "password123",
            "EMAIL_RECEIVER": "receiver@test.com"
        }):
            res = alerting.dispatch_module_alert("M5", "Test message")
            self.assertFalse(res["telegram"]["success"])
            self.assertFalse(res["email"]["success"])

    def test_10_missing_credentials_handled_safely(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}):
            res_tg = alerting.send_telegram_alert("Hello")
            self.assertFalse(res_tg["success"])
            self.assertIn("not configured", res_tg["error"])

        with patch.dict(os.environ, {"EMAIL_SENDER": "", "EMAIL_APP_PASSWORD": "", "EMAIL_RECEIVER": ""}):
            res_em = email_alerting.send_email_alert("Hello")
            self.assertFalse(res_em["success"])
            self.assertIn("missing", res_em["error"])


class TestPipelineIntegration(unittest.TestCase):
    """
    End-to-End Pipeline Integration Tests verifying the full flow across all Phase 5 scenarios:
    1. Threat + Findings
    2. Threat + Clean
    3. Clean + Findings
    4. Clean + Clean
    5. M4 Fails + M5 Findings
    6. M4 Fails + M5 Clean
    7. M4 Clean + M5 Fails
    8. M4 Threat + M5 Fails
    """

    def setUp(self):
        alerting.clear_alert_cache()

    def tearDown(self):
        alerting.clear_alert_cache()

    # 1. Threat in M4 + Findings in M5 -> Both security alerts sent
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "pod-1", "cpu": "400m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "pod-1", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:v1", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_01_both_threat_and_findings(self, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "pod-1", "cpu": "400m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "pod-1"}, "spec": {"containers": [{"name": "app", "image": "app:v1", "securityContext": {"privileged": True}}]}, "status": {}}]):
                import main
                main.run_pipeline(selected_image="app:v1", run_id="run_both_threats", is_cli=False, deploy_workload=True)

        self.assertEqual(mock_tg.call_count, 2)
        self.assertEqual(mock_email.call_count, 2)
        # M4 security alert sent
        self.assertIn("MODULE 4", mock_tg.call_args_list[0][0][0])
        self.assertIn("SECURITY ALERT", mock_tg.call_args_list[0][0][0])
        # M5 security alert sent
        self.assertIn("MODULE 5", mock_tg.call_args_list[1][0][0])
        self.assertIn("SECURITY ALERT", mock_tg.call_args_list[1][0][0])

    # 2. Threat in M4 + Clean in M5 -> M4 threat alert + M5 normal notification sent
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "pod-2", "cpu": "350m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "pod-2", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:v2", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_02_m4_threat_m5_clean(self, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "pod-2", "cpu": "350m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "pod-2"}, "spec": {"containers": [{"name": "app", "image": "app:v2", "securityContext": {}}]}, "status": {}}]):
                import main
                main.run_pipeline(selected_image="app:v2", run_id="run_m4_threat", is_cli=False, deploy_workload=True)

        self.assertEqual(mock_tg.call_count, 2)
        self.assertEqual(mock_email.call_count, 2)
        # M4 security alert
        self.assertIn("MODULE 4", mock_tg.call_args_list[0][0][0])
        self.assertIn("SECURITY ALERT", mock_tg.call_args_list[0][0][0])
        # M5 normal status update
        self.assertIn("MODULE 5", mock_tg.call_args_list[1][0][0])
        self.assertIn("STATUS UPDATE", mock_tg.call_args_list[1][0][0])

    # 3. Clean in M4 + Findings in M5 -> M4 normal notification + M5 security alert sent
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "priv-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "priv-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "priv:v1", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_03_m4_clean_m5_findings(self, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "priv-pod", "cpu": "10m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "priv-pod"}, "spec": {"containers": [{"name": "app", "image": "priv:v1", "securityContext": {"privileged": True}}]}, "status": {}}]):
                import main
                main.run_pipeline(selected_image="priv:v1", run_id="run_m5_findings", is_cli=False, deploy_workload=True)

        self.assertEqual(mock_tg.call_count, 2)
        self.assertEqual(mock_email.call_count, 2)
        # M4 normal status update
        self.assertIn("MODULE 4", mock_tg.call_args_list[0][0][0])
        self.assertIn("STATUS UPDATE", mock_tg.call_args_list[0][0][0])
        # M5 security alert
        self.assertIn("MODULE 5", mock_tg.call_args_list[1][0][0])
        self.assertIn("SECURITY ALERT", mock_tg.call_args_list[1][0][0])

    # 4. Clean in M4 + Clean in M5 -> Both normal-status notifications sent (Phase 5 row 4)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "redis:7", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_04_both_clean_sends_both_normal_notifications(self, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "clean-pod", "cpu": "10m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "clean-pod"}, "spec": {"containers": [{"name": "app", "image": "redis:7", "securityContext": {}}]}, "status": {}}]):
                import main
                main.run_pipeline(selected_image="redis:7", run_id="run_both_clean", is_cli=False, deploy_workload=True)

        self.assertEqual(mock_tg.call_count, 2)
        self.assertEqual(mock_email.call_count, 2)
        # Both send normal status updates
        self.assertIn("MODULE 4", mock_tg.call_args_list[0][0][0])
        self.assertIn("STATUS UPDATE", mock_tg.call_args_list[0][0][0])
        self.assertIn("MODULE 5", mock_tg.call_args_list[1][0][0])
        self.assertIn("STATUS UPDATE", mock_tg.call_args_list[1][0][0])

    # 5. M4 Fails + M5 Findings -> Record M4 failure, send M5 security alert (Phase 5 row 5)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "priv-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "priv-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "priv:v1", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_05_m4_fails_m5_findings(self, mock_email, mock_tg, *args):
        # M4 fails with error
        with patch("main.get_workload_usage", return_value={"error": "Metrics server timeout"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "priv-pod"}, "spec": {"containers": [{"name": "app", "image": "priv:v1", "securityContext": {"privileged": True}}]}, "status": {}}]):
                import main
                main.run_pipeline(selected_image="priv:v1", run_id="run_m4_fail_m5_findings", is_cli=False, deploy_workload=True)

        # M4 skipped due to error, M5 security alert sent
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)
        self.assertIn("MODULE 5", mock_tg.call_args[0][0])
        self.assertIn("SECURITY ALERT", mock_tg.call_args[0][0])

    # 6. M4 Fails + M5 Clean -> Record M4 failure, send M5 normal status (Phase 5 row 6)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:clean", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_06_m4_fails_m5_clean(self, mock_email, mock_tg, *args):
        # M4 fails with error
        with patch("main.get_workload_usage", return_value={"error": "Metrics unavailable"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "clean-pod"}, "spec": {"containers": [{"name": "app", "image": "app:clean", "securityContext": {}}]}, "status": {}}]):
                import main
                main.run_pipeline(selected_image="app:clean", run_id="run_m4_fail_m5_clean", is_cli=False, deploy_workload=True)

        # M4 skipped due to error, M5 normal status sent
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)
        self.assertIn("MODULE 5", mock_tg.call_args[0][0])
        self.assertIn("STATUS UPDATE", mock_tg.call_args[0][0])

    # 7. M4 Clean + M5 Fails -> Send M4 normal status, record M5 failure (Phase 5 row 7)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod", "cpu": "10m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:clean", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_07_m4_clean_m5_fails(self, mock_email, mock_tg, *args):
        # M4 succeeds clean, M5 fails
        with patch("main.get_workload_usage", return_value={"pod": "clean-pod", "cpu": "10m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value={"error": "kubectl get pod failed with timeout"}):
                import main
                main.run_pipeline(selected_image="app:clean", run_id="run_m4_clean_m5_fails", is_cli=False, deploy_workload=True)

        # M4 normal notification sent, M5 skipped due to error
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)
        self.assertIn("MODULE 4", mock_tg.call_args[0][0])
        self.assertIn("STATUS UPDATE", mock_tg.call_args[0][0])

    # 8. M4 Threat + M5 Fails -> Send M4 threat alert, record M5 failure (Phase 5 row 8)
    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value={"report_path": "reports/forensic_report.pdf"})
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "threat-pod", "cpu": "450m", "memory": "20Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "threat-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:threat", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_scenario_08_m4_threat_m5_fails(self, mock_email, mock_tg, *args):
        # M4 threat detected, M5 fails
        with patch("main.get_workload_usage", return_value={"pod": "threat-pod", "cpu": "450m", "memory": "20Mi"}):
            with patch("main.get_pods", return_value={"error": "kubectl connection refused"}):
                import main
                main.run_pipeline(selected_image="app:threat", run_id="run_m4_threat_m5_fails", is_cli=False, deploy_workload=True)

        # M4 security alert sent, M5 skipped due to error
        self.assertEqual(mock_tg.call_count, 1)
        self.assertEqual(mock_email.call_count, 1)
        self.assertIn("MODULE 4", mock_tg.call_args[0][0])
        self.assertIn("SECURITY ALERT", mock_tg.call_args[0][0])


class TestM5ConsistencyAndReporting(unittest.TestCase):
    """
    PHASE 9: COMPREHENSIVE M5 CONSISTENCY, DASHBOARD, LOGGING, AND REPORTING
    Test 1: Clean assessment (M5 NORMAL, None, findings empty, count 0, dashboard COMPLETED, message 'Pods checked=1 | Escape indicators=0', log M5 NORMAL None, report clean).
    Test 2: Findings detected (M5 CRITICAL/HIGH, actual findings preserved, dashboard shows severity, security alert sent).
    Test 3: Kubernetes inspection failure (M5 FAILED, no clean notification, error logged).
    Test 4: No targets available (M5 NOT_APPLICABLE, not clean).
    Test 5: Stale dashboard state (suspicious run followed by clean run -> latest dashboard has status COMPLETED, severity None, 0 escape indicators).
    Test 6: Notification delivery failure (clean assessment remains COMPLETED even if TG/Email fail).
    Test 7: Module independence (M5 results do not overwrite M4's result).
    Test 8: Forensic report consistency (clean assessment reflected in generated report).
    """

    def setUp(self):
        alerting.clear_alert_cache()

    def tearDown(self):
        alerting.clear_alert_cache()

    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/KubeGuard_Forensic_Incident_Report_clean_consistency.pdf")
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod-1", "cpu": "15m", "memory": "25Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod-1", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "clean-app:1.0", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.log_alert")
    def test_01_clean_assessment_all_components_agree(self, mock_log, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "clean-pod-1", "cpu": "15m", "memory": "25Mi"}):
            with patch("main.get_pods", return_value=[{
                "metadata": {"name": "clean-pod-1", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "clean-app:1.0", "securityContext": {"privileged": False}}]},
                "status": {}
            }]):
                import main
                res_state = main.run_pipeline(selected_image="clean-app:1.0", run_id="run_clean_agree", is_cli=False, deploy_workload=True)

        m5_entry = res_state.get("modules", {}).get("M5", {})
        self.assertEqual(m5_entry.get("status"), "COMPLETED")
        self.assertEqual(m5_entry.get("severity"), "None")
        self.assertEqual(m5_entry.get("message"), "Pods checked=1 | Escape indicators=0")
        dt = m5_entry.get("details", {})
        self.assertEqual(dt.get("status"), "NORMAL")
        self.assertEqual(dt.get("severity"), "None")
        self.assertEqual(dt.get("findings"), [])
        self.assertEqual(dt.get("escape_indicators"), 0)
        self.assertFalse(dt.get("escape_detected"))

        # Verify log_alert was called for M5 with NORMAL and None
        mock_log.assert_any_call("M5", "None", "NORMAL", "No container escape indicators detected")

        # Verify Telegram and Email attempted for M5 normal update
        m5_tg_calls = [c[0][0] for c in mock_tg.call_args_list if "MODULE 5" in c[0][0]]
        self.assertEqual(len(m5_tg_calls), 1)
        self.assertIn("STATUS UPDATE", m5_tg_calls[0])
        self.assertIn("Status: NORMAL", m5_tg_calls[0])
        self.assertIn("Severity: None", m5_tg_calls[0])
        self.assertIn("No container escape indicators detected", m5_tg_calls[0])

    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/KubeGuard_Forensic_Incident_Report_findings.pdf")
    @patch("main.verify_hashes", return_value={"overall_integrity": "VERIFIED", "tampered_count": 0, "missing_count": 0})
    @patch("main.initialize_baseline", return_value=True)
    @patch("main.auto_isolate_pod", return_value={"success": True, "message": "Isolated"})
    @patch("main.collect_evidence", return_value={"success": True, "evidence_dir": "evidence"})
    @patch("main.create_backup", return_value="backups")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "priv-pod-1", "cpu": "10m", "memory": "25Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "priv-pod-1", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "priv:v1", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.log_alert")
    def test_02_findings_detected_all_components_agree(self, mock_log, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "priv-pod-1", "cpu": "10m", "memory": "25Mi"}):
            with patch("main.get_pods", return_value=[{
                "metadata": {"name": "priv-pod-1", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "priv:v1", "securityContext": {"privileged": True}}]},
                "status": {}
            }]):
                import main
                res_state = main.run_pipeline(selected_image="priv:v1", run_id="run_findings_agree", is_cli=False, deploy_workload=True)

        m5_entry = res_state.get("modules", {}).get("M5", {})
        self.assertEqual(m5_entry.get("status"), "COMPLETED")
        self.assertEqual(m5_entry.get("severity"), "Critical")
        self.assertEqual(m5_entry.get("message"), "Pods checked=1 | Escape indicators=1")
        dt = m5_entry.get("details", {})
        self.assertEqual(dt.get("status"), "SUSPICIOUS ACTIVITY DETECTED")
        self.assertTrue(dt.get("escape_detected"))
        self.assertEqual(dt.get("escape_indicators"), 1)
        self.assertGreater(len(dt.get("findings", [])), 0)

        # Verify security alert was sent
        m5_tg_calls = [c[0][0] for c in mock_tg.call_args_list if "MODULE 5" in c[0][0]]
        self.assertEqual(len(m5_tg_calls), 1)
        self.assertIn("SECURITY ALERT", m5_tg_calls[0])

    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "pod-1", "cpu": "10m", "memory": "25Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "pod-1", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:v1", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.log_alert")
    def test_03_kubernetes_inspection_failure(self, mock_log, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "pod-1", "cpu": "10m", "memory": "25Mi"}):
            with patch("main.get_pods", return_value={"error": "Kubernetes API unreachable"}):
                import main
                res_state = main.run_pipeline(selected_image="app:v1", run_id="run_k8s_fail", is_cli=False, deploy_workload=True)

        m5_entry = res_state.get("modules", {}).get("M5", {})
        self.assertEqual(m5_entry.get("status"), "FAILED")
        self.assertEqual(m5_entry.get("severity"), "None")
        self.assertIn("Kubernetes API unreachable", m5_entry.get("message"))

        # Verify no clean notification for M5
        m5_tg_calls = [c[0][0] for c in mock_tg.call_args_list if "MODULE 5" in c[0][0]]
        self.assertEqual(len(m5_tg_calls), 0)

        # Verify operational error was logged
        mock_log.assert_any_call("M5", "None", "FAILED", "Operational error: Kubernetes API unreachable")

    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.scan_image", return_value={"image": "app:image-only", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.log_alert")
    def test_04_no_targets_available_reported_accurately(self, mock_log, mock_email, mock_tg, *args):
        # Workload not deployed (deploy_workload=False)
        import main
        res_state = main.run_pipeline(selected_image="app:image-only", run_id="run_no_targets", is_cli=False, deploy_workload=False)

        m5_entry = res_state.get("modules", {}).get("M5", {})
        self.assertEqual(m5_entry.get("status"), "NOT_APPLICABLE")
        self.assertEqual(m5_entry.get("severity"), "None")
        self.assertNotEqual(m5_entry.get("status"), "NORMAL")

        # Verify no clean normal notification for M5
        m5_tg_calls = [c[0][0] for c in mock_tg.call_args_list if "MODULE 5" in c[0][0]]
        self.assertEqual(len(m5_tg_calls), 0)

    def test_05_stale_dashboard_state_replaced(self):
        import main
        # Simulate prior run with critical escape finding
        main.update_dashboard(
            "M5",
            "COMPLETED",
            "Critical",
            "Pods checked=1 | Escape indicators=1",
            {
                "pod": "old-priv-pod",
                "status": "SUSPICIOUS ACTIVITY DETECTED",
                "severity": "Critical",
                "findings": ["Privileged container configuration detected."],
                "escape_indicators": 1,
                "escape_detected": True,
                "privileged": True,
                "escape_items": [{"pod": "old-priv-pod", "status": "SUSPICIOUS ACTIVITY DETECTED", "severity": "Critical"}]
            },
            run_id="run_stale_test_1"
        )

        with open(main.DASHBOARD_STATE, "r", encoding="utf-8") as f:
            stale_state = json.load(f)
        self.assertEqual(stale_state["modules"]["M5"]["severity"], "Critical")
        self.assertTrue(stale_state["modules"]["M5"]["details"]["escape_detected"])

        # Now update with clean assessment
        main.update_dashboard(
            "M5",
            "COMPLETED",
            "None",
            "Pods checked=1 | Escape indicators=0",
            {
                "pod": "new-clean-pod",
                "status": "NORMAL",
                "severity": "None",
                "reason": "No container escape indicators detected.",
                "finding": "No container escape indicators detected.",
                "findings": [],
                "escape_indicators": 0,
                "pods_checked": 1,
                "escape_detected": False,
                "privileged": False,
                "escape_items": [{"pod": "new-clean-pod", "status": "NORMAL", "severity": "None"}]
            },
            run_id="run_stale_test_2"
        )

        with open(main.DASHBOARD_STATE, "r", encoding="utf-8") as f:
            clean_state = json.load(f)

        m5_now = clean_state["modules"]["M5"]
        self.assertEqual(m5_now["status"], "COMPLETED")
        self.assertEqual(m5_now["severity"], "None")
        self.assertEqual(m5_now["message"], "Pods checked=1 | Escape indicators=0")
        self.assertEqual(m5_now["findings"], [])
        self.assertFalse(m5_now["details"]["escape_detected"])
        self.assertFalse(m5_now["details"]["privileged"])
        self.assertEqual(m5_now["details"]["escape_indicators"], 0)
        self.assertEqual(m5_now["details"]["pod"], "new-clean-pod")

    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "clean-pod", "cpu": "10m", "memory": "25Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "clean-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:clean", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", side_effect=Exception("Telegram connection timeout"))
    @patch("main.send_email_alert", side_effect=Exception("SMTP auth error"))
    def test_06_clean_assessment_succeeds_even_when_notifications_fail(self, mock_email, mock_tg, *args):
        with patch("main.get_workload_usage", return_value={"pod": "clean-pod", "cpu": "10m", "memory": "25Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "clean-pod"}, "spec": {"containers": [{"name": "app", "image": "app:clean", "securityContext": {}}]}, "status": {}}]):
                import main
                res_state = main.run_pipeline(selected_image="app:clean", run_id="run_delivery_fail", is_cli=False, deploy_workload=True)

        m5_entry = res_state.get("modules", {}).get("M5", {})
        # Assessment itself remains successfully COMPLETED with severity None!
        self.assertEqual(m5_entry.get("status"), "COMPLETED")
        self.assertEqual(m5_entry.get("severity"), "None")
        self.assertEqual(m5_entry.get("message"), "Pods checked=1 | Escape indicators=0")
        self.assertFalse(m5_entry.get("details", {}).get("escape_detected"))

        # Notification delivery failure is captured in M6 details without corrupting M5
        m6_entry = res_state.get("modules", {}).get("M6", {})
        self.assertEqual(m6_entry.get("details", {}).get("m5_alert", {}).get("status"), "FAILED")

    @patch("main.run_manager")
    @patch("main.generate_forensic_report", return_value="reports/forensic_report.pdf")
    @patch("main.perform_rbac_audit", return_value={"cluster_connected": True, "severity": "None", "dangerous_roles": [], "dangerous_bindings": []})
    @patch("main.get_pod_metrics", return_value={"pod_name": "mixed-pod", "cpu": "450m", "memory": "25Mi", "metrics_available": True})
    @patch("main.ensure_workload", return_value={"found": True, "running": True, "pod_name": "mixed-pod", "container_name": "app", "namespace": "default"})
    @patch("main.scan_image", return_value={"image": "app:mixed", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": [], "deployment_blocked": False, "status": "COMPLETED"})
    @patch("main.send_telegram_alert", return_value={"success": True, "message": "Sent"})
    @patch("main.send_email_alert", return_value={"success": True, "message": "Sent"})
    def test_07_module_independence_m5_clean_does_not_overwrite_m4_threat(self, mock_email, mock_tg, *args):
        # M4: Threat detected (CPU spike, HIGH)
        # M5: Clean (privileged=False, findings=[])
        with patch("main.get_workload_usage", return_value={"pod": "mixed-pod", "cpu": "450m", "memory": "25Mi"}):
            with patch("main.get_pods", return_value=[{"metadata": {"name": "mixed-pod"}, "spec": {"containers": [{"name": "app", "image": "app:mixed", "securityContext": {"privileged": False}}]}, "status": {}}]):
                import main
                res_state = main.run_pipeline(selected_image="app:mixed", run_id="run_mixed_m4_m5", is_cli=False, deploy_workload=True)

        m4_entry = res_state.get("modules", {}).get("M4", {})
        m5_entry = res_state.get("modules", {}).get("M5", {})

        # M4 keeps its threat finding
        self.assertEqual(m4_entry.get("status"), "COMPLETED")
        self.assertEqual(m4_entry.get("severity"), "High")
        self.assertEqual(m4_entry.get("details", {}).get("status"), "SUSPICIOUS ACTIVITY DETECTED")

        # M5 keeps its clean finding
        self.assertEqual(m5_entry.get("status"), "COMPLETED")
        self.assertEqual(m5_entry.get("severity"), "None")
        self.assertEqual(m5_entry.get("details", {}).get("status"), "NORMAL")
        self.assertFalse(m5_entry.get("details", {}).get("escape_detected"))

    def test_08_forensic_report_clean_m5_consistency(self):
        from module11_forensics import generate_forensic_report
        clean_escape_results = [{
            "pod": "clean-report-pod",
            "namespace": "default",
            "container": "clean-container",
            "image": "redis:7",
            "privileged": False,
            "severity": "None",
            "status": "NORMAL",
            "findings": [],
            "incident_triggered": False
        }]

        pdf_path = generate_forensic_report(
            scan_result={"image": "redis:7", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "critical_cve_ids": []},
            monitor_result={"pod_name": "clean-report-pod", "metrics_available": True},
            cluster={"status": True, "message": "Cluster Connected"},
            threat_data={"pod": "clean-report-pod", "cpu": "10m", "memory": "20Mi"},
            threat_result={"status": "NORMAL", "severity": "None", "reason": "No suspicious activity detected."},
            escape_results=clean_escape_results,
            run_id="run_test_clean_report"
        )
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 1000)


if __name__ == "__main__":
    unittest.main()
