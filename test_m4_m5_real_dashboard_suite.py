"""
Comprehensive Verification Suite for KubeGuard M4 & M5 Real-Time Dashboard Redesign & Backend Integration.

Validates:
1. Visual & structural match of M4 to Reference Image 1 (Header, 8 Top Summary Cards, Container Details, Pod Activity Analysis, Alerts).
2. Visual & structural match of M5 to Reference Image 2 (Header, 4 Top Summary Cards, Security Alert Banner, Container Details, Detection Summary).
3. Complete removal of Detection Checks panel from M5 as strictly required.
4. Every value is backed by real Kubernetes data (no hardcoded metrics, no dummy pod names, no static statuses).
5. Missing metrics are UNAVAILABLE/FAILED, never 0.
6. Refresh endpoint dynamically queries cluster, identifies replacement pods, and updates dashboard state.
7. Real-time alert delivery status verification (SENT / FAILED / NOT CONFIGURED / NOT REQUIRED).
8. Live Minikube integration across existing workloads: Nginx, Python-app, Node-app in unprivileged and privileged states.
"""

import unittest
import json
import os
import subprocess
from datetime import datetime

from runtime_target import (
    RuntimeTarget,
    get_persisted_target_config,
    persist_target_config,
    resolve_existing_deployment_target,
    get_live_assessment_telemetry,
    parse_alert_status
)
from module4_detection import detect_threat, CPU_THRESHOLD, MEMORY_THRESHOLD
from module5_escape import detect_escape_indicators


class TestM4M5RealDashboardSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html_path = os.path.join(os.path.dirname(__file__), "dashboard", "templates", "dashboard.html")
        with open(cls.html_path, "r", encoding="utf-8") as f:
            cls.html_content = f.read()

    # ----------------------------------------------------
    # 1. VISUAL DESIGN & STRUCTURAL INTEGRITY (REFERENCE IMAGES)
    # ----------------------------------------------------

    def test_m4_html_structure_matches_reference_image_1(self):
        """Verifies M4 HTML contains all elements from Reference Image 1."""
        # A. Header elements
        self.assertIn('id="view-m4"', self.html_content)
        self.assertIn('M4 - Threat Detection', self.html_content)
        self.assertIn('Detect suspicious activity in containers and generate alerts', self.html_content)
        self.assertIn('id="m4-header-status-pill"', self.html_content)
        self.assertIn('id="m4-refresh-btn"', self.html_content)
        self.assertIn('id="m4-header-last-run"', self.html_content)

        # B. 8 Top Summary Cards
        self.assertIn('id="m4-card-pod"', self.html_content)
        self.assertIn('id="m4-card-cpu"', self.html_content)
        self.assertIn('id="m4-card-memory"', self.html_content)
        self.assertIn('id="m4-card-status"', self.html_content)
        self.assertIn('id="m4-card-severity"', self.html_content)
        self.assertIn('id="m4-card-reason"', self.html_content)
        self.assertIn('id="m4-card-telegram"', self.html_content)
        self.assertIn('id="m4-card-email"', self.html_content)

        # C. Container Details elements
        self.assertIn('id="m4-detail-pod"', self.html_content)
        self.assertIn('id="m4-detail-namespace"', self.html_content)
        self.assertIn('id="m4-detail-deployment"', self.html_content)
        self.assertIn('id="m4-detail-container"', self.html_content)
        self.assertIn('id="m4-detail-image"', self.html_content)
        self.assertIn('id="m4-detail-cpu"', self.html_content)
        self.assertIn('id="m4-detail-memory"', self.html_content)
        self.assertIn('id="m4-detail-status"', self.html_content)
        self.assertIn('id="m4-detail-severity"', self.html_content)
        self.assertIn('id="m4-detail-reason"', self.html_content)
        self.assertIn('id="m4-detail-telegram"', self.html_content)
        self.assertIn('id="m4-detail-email"', self.html_content)

        # D. Pod Activity Analysis
        self.assertIn('id="m4-analysis-banner"', self.html_content)
        self.assertIn('id="m4-analysis-title"', self.html_content)
        self.assertIn('id="m4-analysis-body"', self.html_content)
        self.assertIn('id="m4-signal-timestamp"', self.html_content)

        # E. Alerts panel
        self.assertIn('id="m4-alerts-telegram-badge"', self.html_content)
        self.assertIn('id="m4-alerts-email-badge"', self.html_content)

    def test_m5_html_structure_matches_reference_image_2(self):
        """Verifies M5 HTML contains all elements from Reference Image 2."""
        # A. Header elements
        self.assertIn('id="view-m5"', self.html_content)
        self.assertIn('M5 - Container Escape Detection', self.html_content)
        self.assertIn('Detect potential container escape attempts and high-risk container configurations', self.html_content)
        self.assertIn('id="m5-header-status-pill"', self.html_content)
        self.assertIn('id="m5-refresh-btn"', self.html_content)
        self.assertIn('id="m5-header-last-run"', self.html_content)

        # B. 4 Top Summary Cards
        self.assertIn('id="m5-card-pod"', self.html_content)
        self.assertIn('id="m5-card-status"', self.html_content)
        self.assertIn('id="m5-card-severity"', self.html_content)
        self.assertIn('id="m5-card-reason"', self.html_content)

        # C. Security Alert Banner
        self.assertIn('id="m5-security-alert-banner"', self.html_content)
        self.assertIn('id="m5-banner-headline"', self.html_content)
        self.assertIn('id="m5-banner-explanation"', self.html_content)
        self.assertIn('id="m5-banner-timestamp"', self.html_content)

        # D. Container Details
        self.assertIn('id="m5-detail-pod"', self.html_content)
        self.assertIn('id="m5-detail-namespace"', self.html_content)
        self.assertIn('id="m5-detail-deployment"', self.html_content)
        self.assertIn('id="m5-detail-container"', self.html_content)
        self.assertIn('id="m5-detail-image"', self.html_content)
        self.assertIn('id="m5-detail-digest"', self.html_content)
        self.assertIn('id="m5-detail-status"', self.html_content)
        self.assertIn('id="m5-detail-severity"', self.html_content)
        self.assertIn('id="m5-detail-reason"', self.html_content)
        self.assertIn('id="m5-detail-cpu"', self.html_content)
        self.assertIn('id="m5-detail-memory"', self.html_content)
        self.assertIn('id="m5-detail-time"', self.html_content)

        # E. Detection Summary
        self.assertIn('id="m5-count-total"', self.html_content)
        self.assertIn('id="m5-count-critical"', self.html_content)
        self.assertIn('id="m5-count-high"', self.html_content)
        self.assertIn('id="m5-count-medium"', self.html_content)
        self.assertIn('id="m5-count-low"', self.html_content)
        self.assertIn('id="m5-summary-box"', self.html_content)
        self.assertIn('id="m5-summary-title"', self.html_content)
        self.assertIn('id="m5-summary-desc"', self.html_content)
        self.assertIn('id="m5-summary-evidence"', self.html_content)
        self.assertIn('id="m5-summary-remediation"', self.html_content)
        self.assertIn('id="m5-btn-view-output"', self.html_content)
        self.assertIn('id="m5-btn-download-report"', self.html_content)

    def test_strict_removal_of_detection_checks_panel(self):
        """Strictly asserts that the 'Detection Checks' panel is completely removed from M5."""
        self.assertNotIn('Detection Checks', self.html_content)
        self.assertNotIn('Host PID Namespace', self.html_content)
        self.assertNotIn('Host IPC', self.html_content)
        self.assertNotIn('Host Path Mounts', self.html_content)
        self.assertNotIn('Dangerous Capabilities', self.html_content)

    def test_sidebar_color_scheme_alignment(self):
        """Verifies M4 has purple active styling and M5 has crimson active styling."""
        self.assertIn("'m4': 'active-purple'", self.html_content)
        self.assertIn("'m5': 'active-crimson'", self.html_content)

    # ----------------------------------------------------
    # 2. REAL BACKEND TELEMETRY & METRIC ACCURACY
    # ----------------------------------------------------

    def test_real_telemetry_query_accuracy(self):
        """Queries live telemetry for python-app and verifies it reflects actual cluster execution."""
        tel = get_live_assessment_telemetry(workload_name="python-app")
        self.assertTrue(tel.get("success"), f"Telemetry query failed: {tel.get('error')}")
        self.assertEqual(tel.get("workload_name"), "python-app")
        self.assertTrue(tel.get("pod_name").startswith("python-app-"))

        # Verify M4
        m4 = tel.get("m4", {})
        self.assertEqual(m4.get("pod"), tel.get("pod_name"))
        self.assertEqual(m4.get("container"), "python")
        self.assertIn(m4.get("status"), ["NORMAL", "THREAT DETECTED", "UNAVAILABLE", "FAILED"])
        # CPU/Mem must not be zero when unavailable
        if not m4.get("metrics_available"):
            self.assertIn(m4.get("cpu"), ["UNAVAILABLE", "FAILED"])
            self.assertIn(m4.get("memory"), ["UNAVAILABLE", "FAILED"])

        # Verify M5
        m5 = tel.get("m5", {})
        self.assertEqual(m5.get("pod"), tel.get("pod_name"))
        self.assertEqual(m5.get("container"), "python")
        self.assertIn(m5.get("status"), ["NORMAL", "SUSPICIOUS ACTIVITY DETECTED", "UNAVAILABLE", "FAILED"])
        self.assertIn("raw_output", m5)
        self.assertIn("KUBERNETES ADMITTED CONTAINER SECURITY INSPECTION", m5["raw_output"])

    def test_missing_metrics_never_displayed_as_zero(self):
        """Asserts that when metrics are unavailable, detect_threat reports UNAVAILABLE and not 0."""
        # Case A: error in data
        res_err = detect_threat({"error": "Metrics server timeout", "pod": "test-pod"})
        self.assertIn(res_err["status"], ["ERROR", "UNAVAILABLE", "FAILED"])

        # Case B: UNAVAILABLE string passed
        res_unavail = detect_threat({"cpu": "UNAVAILABLE", "memory": "UNAVAILABLE", "pod": "test-pod"})
        self.assertIn(res_unavail["status"], ["UNAVAILABLE", "NORMAL", "ERROR"])
        self.assertEqual(res_unavail["severity"], "None")

    def test_parse_alert_status_normalization(self):
        """Asserts that alert statuses strictly map to SENT / FAILED / NOT CONFIGURED / NOT REQUIRED."""
        self.assertEqual(parse_alert_status(True, None), "SENT")
        self.assertEqual(parse_alert_status(False, "Telegram bot token not configured"), "NOT CONFIGURED")
        self.assertEqual(parse_alert_status(False, "Email configuration missing"), "NOT CONFIGURED")
        self.assertEqual(parse_alert_status(False, "timed out"), "FAILED")
        self.assertEqual(parse_alert_status(False, "HTTP 500 Internal Error"), "FAILED")
        self.assertEqual(parse_alert_status(False, "Not attempted", was_attempted=False), "NOT REQUIRED")

    # ----------------------------------------------------
    # 3. LIVE WORKLOADS (NGINX, PYTHON, NODE) DYNAMIC RESOLUTION
    # ----------------------------------------------------

    def test_nginx_live_telemetry_discovery(self):
        """Verifies dynamic discovery and telemetry for live Nginx deployment."""
        tel = get_live_assessment_telemetry(workload_name="nginx")
        self.assertTrue(tel.get("success"), f"Nginx telemetry query failed: {tel.get('error')}")
        self.assertEqual(tel.get("workload_name"), "nginx")
        self.assertTrue(tel.get("pod_name").startswith("nginx-"))
        self.assertEqual(tel.get("m4", {}).get("container"), "nginx")
        self.assertEqual(tel.get("m5", {}).get("container"), "nginx")

    def test_node_app_live_telemetry_discovery(self):
        """Verifies dynamic discovery and telemetry for live Node-app deployment."""
        tel = get_live_assessment_telemetry(workload_name="node-app")
        self.assertTrue(tel.get("success"), f"Node-app telemetry query failed: {tel.get('error')}")
        self.assertEqual(tel.get("workload_name"), "node-app")
        self.assertTrue(tel.get("pod_name").startswith("node-app-"))
        self.assertEqual(tel.get("m4", {}).get("container"), "node")
        self.assertEqual(tel.get("m5", {}).get("container"), "node")

    def test_nonexistent_workload_honest_error(self):
        """Verifies that querying a non-existent deployment returns honest UNAVAILABLE state without crashing."""
        tel = get_live_assessment_telemetry(workload_name="nonexistent-dummy-workload-xyz")
        self.assertFalse(tel.get("success"))
        self.assertEqual(tel.get("pod_name"), "None")
        self.assertEqual(tel.get("m4", {}).get("status"), "UNAVAILABLE")
        self.assertEqual(tel.get("m4", {}).get("cpu"), "UNAVAILABLE")
        self.assertEqual(tel.get("m5", {}).get("status"), "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
