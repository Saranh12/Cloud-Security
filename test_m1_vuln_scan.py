import unittest
from unittest.mock import patch, MagicMock
import subprocess
import json
import os
import tempfile
import vuln_scan


class TestModule1VulnScan(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.report_path = os.path.join(self.temp_dir, "trivy_scan.json")

    def tearDown(self):
        if os.path.exists(self.report_path):
            try:
                os.remove(self.report_path)
            except Exception:
                pass
        if os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
            except Exception:
                pass

    # ==========================================================
    # SCENARIO A: VALID IMAGE REFERENCES
    # ==========================================================

    def test_validate_image_reference_valid(self):
        valid_images = [
            "nginx:latest",
            "python:3.12-slim",
            "node:22",
            "node:22-alpine",
            "ubuntu:24.04",
            "alpine:3.21",
            "redis:7",
            "postgres:17",
            "eclipse-temurin:21-jre",
            "amazoncorretto:21",
            "httpd:2.4",
            "docker.io/library/nginx:latest",
            "quay.io/coreos/etcd:v3.5.0",
            "registry.internal.corp:5000/app/service:1.2.3",
            "myimage@sha256:e0b2cb1a23e1d4ecfb9b1310ccc22d0fa9a90a3444b9d7fff1e820a40b353e08"
        ]
        for img in valid_images:
            is_valid, res = vuln_scan.validate_image_reference(img)
            self.assertTrue(is_valid, f"Expected '{img}' to be valid, got: {res}")
            self.assertEqual(res, img)

    # ==========================================================
    # SCENARIO C: INVALID IMAGE REFERENCES
    # ==========================================================

    def test_validate_image_reference_invalid(self):
        invalid_images = [
            "",
            "   ",
            None,
            12345,
            "nginx; rm -rf /",
            "nginx | cat /etc/passwd",
            "nginx`whoami`",
            "python 3.12-slim",
            ":latest",
            "@sha256:abc",
            "/nginx",
            "-nginx",
            "image$(id)",
            "image>out"
        ]
        for img in invalid_images:
            is_valid, msg = vuln_scan.validate_image_reference(img)
            self.assertFalse(is_valid, f"Expected '{img}' to be invalid")
            self.assertTrue(len(msg) > 0)

    def test_scan_image_invalid_reference(self):
        result = vuln_scan.scan_image("invalid image;name", output_path=self.report_path)
        self.assertIn("error", result)
        self.assertEqual(result.get("error_type"), "INVALID_IMAGE_REFERENCE")
        self.assertEqual(result.get("status"), "FAILED")

    # ==========================================================
    # SCENARIO F: TRIVY NOT AVAILABLE
    # ==========================================================

    @patch("shutil.which", return_value=None)
    def test_scan_image_trivy_not_found(self, mock_which):
        result = vuln_scan.scan_image("nginx:latest", output_path=self.report_path)
        self.assertIn("error", result)
        self.assertEqual(result.get("error_type"), "SCANNER_NOT_FOUND")
        self.assertEqual(result.get("status"), "FAILED")

    # ==========================================================
    # SCENARIO G: TIMEOUT HANDLING
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["trivy"], timeout=10))
    def test_scan_image_timeout(self, mock_subproc, mock_which):
        result = vuln_scan.scan_image("python:3.12-slim", timeout=10, output_path=self.report_path)
        self.assertIn("error", result)
        self.assertEqual(result.get("error_type"), "TIMEOUT")
        self.assertEqual(result.get("status"), "FAILED")

    # ==========================================================
    # SCENARIO E: REGISTRY AUTHENTICATION FAILURE
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run")
    def test_scan_image_auth_failure(self, mock_subproc, mock_which):
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "FATAL repository not found or 401 Unauthorized: authentication required"
        mock_res.stdout = ""
        mock_subproc.return_value = mock_res

        result = vuln_scan.scan_image("private-registry.com/secure:1.0", output_path=self.report_path)
        self.assertIn("error", result)
        self.assertEqual(result.get("error_type"), "AUTH_FAILED")
        self.assertEqual(result.get("status"), "FAILED")

    # ==========================================================
    # SCENARIO D: IMAGE NOT FOUND
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run")
    def test_scan_image_not_found(self, mock_subproc, mock_which):
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "FATAL image scan error: manifest unknown: manifest unknown"
        mock_res.stdout = ""
        mock_subproc.return_value = mock_res

        result = vuln_scan.scan_image("nonexistent-image-xyz:99.99", output_path=self.report_path)
        self.assertIn("error", result)
        self.assertEqual(result.get("error_type"), "IMAGE_NOT_FOUND")
        self.assertEqual(result.get("status"), "FAILED")

    # ==========================================================
    # SCENARIO H: MALFORMED JSON OUTPUT
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run")
    def test_scan_image_malformed_json(self, mock_subproc, mock_which):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "{malformed json without closing brace"
        mock_res.stderr = ""
        mock_subproc.return_value = mock_res

        result = vuln_scan.scan_image("ubuntu:24.04", output_path=self.report_path)
        self.assertIn("error", result)
        self.assertEqual(result.get("error_type"), "MALFORMED_OUTPUT")
        self.assertEqual(result.get("status"), "FAILED")

    # ==========================================================
    # SCENARIOS A, I, J: SUCCESSFUL SCAN WITH VULNERABILITIES
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run")
    def test_scan_image_with_vulnerabilities(self, mock_subproc, mock_which):
        sample_output = {
            "SchemaVersion": 2,
            "ArtifactName": "python:3.12-slim",
            "Metadata": {
                "OS": {"Family": "debian", "Name": "13.7"},
                "RepoDigests": ["python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"],
                "ImageID": "sha256:df18428df8a0f9189c84e7424d214b4c50092af1f9dca5842a00c41c39bda316"
            },
            "Results": [
                {
                    "Target": "python:3.12-slim (debian 13.7)",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "libssl3",
                            "InstalledVersion": "3.0.1",
                            "FixedVersion": "3.0.2",
                            "Severity": "CRITICAL",
                            "Title": "Remote Code Execution in OpenSSL",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-1234"
                        },
                        {
                            "VulnerabilityID": "CVE-2023-5678",
                            "PkgName": "curl",
                            "InstalledVersion": "7.88.1",
                            "FixedVersion": "7.88.2",
                            "Severity": "HIGH",
                            "Title": "Buffer overflow in curl",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-5678"
                        },
                        {
                            "VulnerabilityID": "CVE-2023-9999",
                            "PkgName": "bash",
                            "InstalledVersion": "5.2.15",
                            "FixedVersion": None,
                            "Severity": "LOW",
                            "Title": "Minor issue in bash",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-9999"
                        }
                    ]
                }
            ]
        }
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = json.dumps(sample_output)
        mock_res.stderr = ""
        mock_subproc.return_value = mock_res

        result = vuln_scan.scan_image("python:3.12-slim", output_path=self.report_path)

        self.assertNotIn("error", result)
        self.assertEqual(result["image"], "python:3.12-slim")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(result["severity_counts"]["HIGH"], 1)
        self.assertEqual(result["severity_counts"]["MEDIUM"], 0)
        self.assertEqual(result["severity_counts"]["LOW"], 1)
        self.assertEqual(result["total_vulnerabilities"], 3)
        self.assertTrue(result["deployment_blocked"])
        self.assertEqual(result["critical_cve_ids"], ["CVE-2023-1234"])
        self.assertEqual(result["os"], "debian 13.7")
        self.assertEqual(result["image_digest"], "python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1")
        self.assertEqual(len(result["vulnerabilities"]), 3)

        # Confirm report was saved to self.report_path
        self.assertTrue(os.path.exists(self.report_path))
        with open(self.report_path, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
            self.assertEqual(saved_data["ArtifactName"], "python:3.12-slim")

    # ==========================================================
    # SCENARIOS B, K: ZERO VULNERABILITIES IS A SUCCESSFUL SCAN
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run")
    def test_scan_image_zero_vulnerabilities(self, mock_subproc, mock_which):
        sample_output = {
            "SchemaVersion": 2,
            "ArtifactName": "alpine:3.21",
            "Metadata": {
                "OS": {"Family": "alpine", "Name": "3.21.0"},
                "RepoDigests": ["alpine@sha256:123456789"]
            },
            "Results": [
                {
                    "Target": "alpine:3.21 (alpine 3.21.0)",
                    "Class": "os-pkgs",
                    "Type": "alpine"
                    # No Vulnerabilities key or empty list
                }
            ]
        }
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = json.dumps(sample_output)
        mock_res.stderr = ""
        mock_subproc.return_value = mock_res

        result = vuln_scan.scan_image("alpine:3.21", output_path=self.report_path)

        self.assertNotIn("error", result)
        self.assertEqual(result["image"], "alpine:3.21")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["severity_counts"]["CRITICAL"], 0)
        self.assertEqual(result["severity_counts"]["HIGH"], 0)
        self.assertEqual(result["severity_counts"]["MEDIUM"], 0)
        self.assertEqual(result["severity_counts"]["LOW"], 0)
        self.assertEqual(result["total_vulnerabilities"], 0)
        self.assertFalse(result["deployment_blocked"])
        self.assertEqual(result["critical_cve_ids"], [])
        self.assertEqual(result["vulnerabilities"], [])

    # ==========================================================
    # SCENARIO L: PREVENT STALE REPORT FROM MASQUERADING
    # ==========================================================

    @patch("shutil.which", return_value="/usr/local/bin/trivy")
    @patch("subprocess.run")
    def test_prevents_stale_report_masquerade(self, mock_subproc, mock_which):
        # Create an existing stale report
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"stale": True, "old_image": "old:v1"}))
        self.assertTrue(os.path.exists(self.report_path))

        # Simulate a failing scan
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "FATAL image scan error: network timeout"
        mock_res.stdout = ""
        mock_subproc.return_value = mock_res

        result = vuln_scan.scan_image("new-image:latest", output_path=self.report_path)

        self.assertIn("error", result)
        self.assertEqual(result.get("status"), "FAILED")
        # Ensure stale report was purged so it cannot masquerade as result
        self.assertFalse(os.path.exists(self.report_path))

    # ==========================================================
    # SECRET REDACTION
    # ==========================================================

    def test_sanitize_error_message(self):
        secret_msg = "Failed to pull from https://admin:SuperSecretPassword123@myregistry.io/v2 with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
        sanitized = vuln_scan.sanitize_error_message(secret_msg)
        self.assertNotIn("SuperSecretPassword123", sanitized)
        self.assertIn("https://admin:***@myregistry.io/v2", sanitized)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized)


if __name__ == "__main__":
    unittest.main()
