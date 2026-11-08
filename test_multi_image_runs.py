import unittest
import json
import os
import subprocess
from pathlib import Path
from dashboard.app import app
import run_manager

class TestMultiImageWorkflow(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_01_dashboard_page_elements(self):
        """Verify dashboard HTML contains Start Security Scan button and image input."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn('id="target-image-input"', html)
        self.assertIn('Start Security Scan', html)
        self.assertIn('id="run-history-select"', html)
        self.assertIn('redis:7', html)
        self.assertIn('nginx:latest', html)
        self.assertIn('python:3.12-slim', html)
        self.assertIn('node:22', html)

    def test_02_validation_rejects_empty_image(self):
        """Verify empty or whitespace image is rejected with HTTP 400 and clear error."""
        res = self.client.post("/api/pipeline/run", json={"image": ""})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "FAILED")
        self.assertIn("cannot be empty", data["error"])

        res2 = self.client.post("/api/pipeline/run", json={"image": "   "})
        self.assertEqual(res2.status_code, 400)
        data2 = res2.get_json()
        self.assertEqual(data2["status"], "FAILED")

    def test_03_validation_rejects_malformed_image(self):
        """Verify malformed images with command injection or spaces are rejected."""
        bad_images = [
            "nginx; rm -rf /",
            "nginx`whoami`",
            "python 3.12-slim",
            ":latest",
            "-invalid"
        ]
        for bad in bad_images:
            res = self.client.post("/api/pipeline/run", json={"image": bad})
            self.assertEqual(res.status_code, 400, f"Expected 400 for '{bad}'")
            data = res.get_json()
            self.assertEqual(data["status"], "FAILED")
            self.assertTrue(len(data.get("error", "")) > 0)

    def test_04_runs_endpoint_lists_history(self):
        """Verify /api/runs returns historical runs with images and IDs."""
        res = self.client.get("/api/runs")
        self.assertEqual(res.status_code, 200)
        runs = res.get_json()
        self.assertIsInstance(runs, list)
        self.assertTrue(len(runs) >= 2)
        images = [r.get("image") for r in runs]
        self.assertIn("nginx:latest", images)
        self.assertIn("python:3.12-slim", images)

    def test_05_historical_run_isolation(self):
        """Verify querying /api/dashboard?run_id=<run_id> returns run-specific telemetry."""
        runs = self.client.get("/api/runs").get_json()
        nginx_run = next(r for r in runs if r.get("image") == "nginx:latest")
        python_run = next(r for r in runs if r.get("image") == "python:3.12-slim")

        # Query Run 1 (nginx)
        r1_res = self.client.get(f"/api/dashboard?run_id={nginx_run['run_id']}")
        self.assertEqual(r1_res.status_code, 200)
        r1_data = r1_res.get_json()
        self.assertEqual(r1_data["run_id"], nginx_run["run_id"])
        self.assertEqual(r1_data["selected_image"], "nginx:latest")
        self.assertEqual(r1_data["modules"]["M1"]["details"]["image"], "nginx:latest")
        # Nginx had 4 critical CVEs
        self.assertEqual(r1_data["modules"]["M1"]["details"]["severity_counts"]["CRITICAL"], 4)

        # Query Run 2 (python)
        r2_res = self.client.get(f"/api/dashboard?run_id={python_run['run_id']}")
        self.assertEqual(r2_res.status_code, 200)
        r2_data = r2_res.get_json()
        self.assertEqual(r2_data["run_id"], python_run["run_id"])
        self.assertEqual(r2_data["selected_image"], "python:3.12-slim")
        self.assertEqual(r2_data["modules"]["M1"]["details"]["image"], "python:3.12-slim")
        # Python had 0 critical CVEs
        self.assertEqual(r2_data["modules"]["M1"]["details"]["severity_counts"]["CRITICAL"], 0)

        # Ensure Run 1 and Run 2 did not overwrite each other's reports
        self.assertNotEqual(r1_data["run_id"], r2_data["run_id"])
        self.assertNotEqual(r1_data["selected_image"], r2_data["selected_image"])

    def test_06_reports_and_evidence_files_exist(self):
        """Verify that reports and evidence files from previous runs exist on disk."""
        runs = self.client.get("/api/runs").get_json()
        completed_runs = [r for r in runs if r.get("status") == "COMPLETED"]
        failed_runs = [r for r in runs if r.get("status") == "FAILED"]

        self.assertTrue(len(completed_runs) >= 2)
        for r in completed_runs:
            run_id = r["run_id"]
            run_dir = Path("runs") / run_id
            self.assertTrue(run_dir.exists(), f"Run directory {run_dir} should exist")
            meta_file = run_dir / "run_metadata.json"
            self.assertTrue(meta_file.exists(), f"Metadata file {meta_file} should exist")
            rep_dir = run_dir / "reports"
            self.assertTrue(rep_dir.exists(), f"Reports directory {rep_dir} should exist")
            pdf_files = list(rep_dir.glob("*.pdf"))
            self.assertTrue(len(pdf_files) > 0, f"Run {run_id} should have generated PDF report")

        for r in failed_runs:
            self.assertIsNone(r.get("report_path"), "Failed runs should not have report_path")

if __name__ == "__main__":
    unittest.main()
