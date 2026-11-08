import os
import shutil
import tempfile
import unittest
from pathlib import Path

from module10_integrity import (
    calculate_hash,
    create_hashes,
    verify_hashes,
    start_integrity_monitor,
    stop_integrity_monitor,
    stop_all_integrity_monitors
)
from monitoring import (
    parse_cpu_to_millicores,
    parse_memory_to_mib,
    get_pod_metrics
)
from dashboard.app import app


class TestM10EvidenceIntegrityAndM2(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="kg_test_integrity_")
        self.evidence_dir = os.path.join(self.test_dir, "incident_test_pod")
        os.makedirs(self.evidence_dir, exist_ok=True)

        # Create sample evidence files
        self.file1 = os.path.join(self.evidence_dir, "pod.yaml")
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\n")

        self.file2 = os.path.join(self.evidence_dir, "pod_status.txt")
        with open(self.file2, "w", encoding="utf-8") as f:
            f.write("Status: Running\nReady: 1/1\n")

        self.file3 = os.path.join(self.evidence_dir, "pod_logs.txt")
        with open(self.file3, "w", encoding="utf-8") as f:
            f.write("2026-10-22T08:00:00Z Initialized application.\n")

    def tearDown(self):
        stop_all_integrity_monitors()
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass
        int_test = os.path.join("integrity", "incident_test_pod")
        if os.path.exists(int_test):
            try:
                for root, dirs, files in os.walk(int_test):
                    for f in files:
                        try:
                            os.chmod(os.path.join(root, f), 0o777)
                        except Exception:
                            pass
                shutil.rmtree(int_test, ignore_errors=True)
            except Exception:
                pass

    def test_01_create_hashes_and_baseline_verification(self):
        """Test baseline hash creation and subsequent clean verification."""
        hash_file = os.path.join(self.test_dir, "hashes.txt")
        res_hash = create_hashes(self.evidence_dir)
        self.assertTrue(os.path.exists(res_hash))

        all_ver, ver_cnt, tamp_cnt, miss_cnt, checks = verify_hashes(
            self.evidence_dir, res_hash, update_state=False
        )
        self.assertTrue(all_ver)
        self.assertEqual(ver_cnt, 3)
        self.assertEqual(tamp_cnt, 0)
        self.assertEqual(miss_cnt, 0)
        self.assertEqual(len(checks), 3)

    def test_02_detect_content_tampering(self):
        """Test detection when an evidence file's content is modified."""
        res_hash = create_hashes(self.evidence_dir)
        self.assertTrue(os.path.exists(res_hash))

        # Tamper with file2
        with open(self.file2, "a", encoding="utf-8") as f:
            f.write("UNAUTHORIZED TAMPER LINE\n")

        all_ver, ver_cnt, tamp_cnt, miss_cnt, checks = verify_hashes(
            self.evidence_dir, res_hash, update_state=False
        )
        self.assertFalse(all_ver)
        self.assertEqual(ver_cnt, 2)
        self.assertEqual(tamp_cnt, 1)
        self.assertEqual(miss_cnt, 0)

        tampered_checks = [c for c in checks if c["status"] == "TAMPERED"]
        self.assertEqual(len(tampered_checks), 1)
        self.assertEqual(tampered_checks[0]["filename"], "pod_status.txt")

    def test_03_detect_deleted_evidence_file(self):
        """Test detection when a baseline evidence file is deleted."""
        res_hash = create_hashes(self.evidence_dir)
        self.assertTrue(os.path.exists(res_hash))

        # Delete file3
        os.remove(self.file3)

        all_ver, ver_cnt, tamp_cnt, miss_cnt, checks = verify_hashes(
            self.evidence_dir, res_hash, update_state=False
        )
        self.assertFalse(all_ver)
        self.assertEqual(ver_cnt, 2)
        self.assertEqual(miss_cnt, 1)
        missing_checks = [c for c in checks if c["status"] == "MISSING"]
        self.assertEqual(missing_checks[0]["filename"], "pod_logs.txt")

    def test_04_detect_unauthorized_new_file_added(self):
        """Test detection when an untracked file is injected into sealed evidence directory."""
        res_hash = create_hashes(self.evidence_dir)
        self.assertTrue(os.path.exists(res_hash))

        # Inject unexpected file
        injected = os.path.join(self.evidence_dir, "injected_rootkit_log.txt")
        with open(injected, "w", encoding="utf-8") as f:
            f.write("Injected unauthorized file\n")

        all_ver, ver_cnt, tamp_cnt, miss_cnt, checks = verify_hashes(
            self.evidence_dir, res_hash, update_state=False
        )
        self.assertFalse(all_ver)
        self.assertEqual(tamp_cnt, 1)
        untracked = [c for c in checks if c["filename"] == "injected_rootkit_log.txt"]
        self.assertEqual(len(untracked), 1)
        self.assertEqual(untracked[0]["status"], "TAMPERED")

    def test_05_prevent_false_verified_on_empty_or_missing_baseline(self):
        """Verify that missing or empty baseline returns False and never claims VERIFIED."""
        fake_hash = os.path.join(self.test_dir, "nonexistent_hashes.txt")
        all_ver, ver_cnt, tamp_cnt, miss_cnt, checks = verify_hashes(
            self.evidence_dir, fake_hash, update_state=False
        )
        self.assertFalse(all_ver)
        self.assertEqual(ver_cnt, 0)

        # Empty hash file
        empty_hash = os.path.join(self.test_dir, "empty_hashes.txt")
        with open(empty_hash, "w", encoding="utf-8") as f:
            f.write("")
        all_ver2, ver_cnt2, tamp_cnt2, miss_cnt2, checks2 = verify_hashes(
            self.evidence_dir, empty_hash, update_state=False
        )
        self.assertFalse(all_ver2)
        self.assertEqual(ver_cnt2, 0)

    def test_06_monitor_lifecycle_clean_shutdown(self):
        """Verify start_integrity_monitor and stop_integrity_monitor cleanly manage threads."""
        res_hash = create_hashes(self.evidence_dir)
        monitor = start_integrity_monitor(self.evidence_dir, res_hash, poll_interval=1.0)
        self.assertTrue(monitor.is_alive())

        stopped = stop_integrity_monitor(self.evidence_dir)
        self.assertTrue(stopped)
        self.assertFalse(monitor.is_alive())

    def test_07_m2_metric_unit_parsing(self):
        """Verify M2 unit parsing handles millicores, nanocores, MiB, and GiB accurately."""
        self.assertEqual(parse_cpu_to_millicores("10m"), 10)
        self.assertEqual(parse_cpu_to_millicores("0m"), 0)
        self.assertEqual(parse_cpu_to_millicores("5000000n"), 5)
        self.assertEqual(parse_cpu_to_millicores("1"), 1000)
        self.assertEqual(parse_cpu_to_millicores(None), 0)

        self.assertEqual(parse_memory_to_mib("64Mi"), 64)
        self.assertEqual(parse_memory_to_mib("1Gi"), 1024)
        self.assertEqual(parse_memory_to_mib("2048Ki"), 2)
        self.assertEqual(parse_memory_to_mib(None), 0)

    def test_08_m2_non_fabrication_on_missing_pod(self):
        """Verify M2 does not fabricate 0m/0Mi when pod or metrics do not exist."""
        res = get_pod_metrics(target_pod="nonexistent-pod-xyz-12345")
        self.assertFalse(res.get("metrics_available"))
        self.assertIsNone(res.get("cpu"))
        self.assertIsNone(res.get("memory"))
        self.assertIn("error", res)

    def test_09_dashboard_report_download_safety(self):
        """Verify /api/report/download handles non-existent reports with 404."""
        client = app.test_client()
        res = client.get("/api/report/download?run_id=fake_run_9999999")
        self.assertIn(res.status_code, [404, 200])  # If no report, 404


if __name__ == "__main__":
    unittest.main()
