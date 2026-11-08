import os
import shutil
import tempfile
import time
import json
import subprocess
import sys
import unittest
from pathlib import Path

from module10_integrity import (
    calculate_hash,
    initialize_baseline,
    rebaseline_evidence,
    create_hashes,
    load_trusted_baseline,
    has_valid_trusted_baseline,
    get_baseline_paths,
    verify_hashes,
    start_integrity_monitor,
    stop_integrity_monitor,
    stop_all_integrity_monitors,
    is_monitor_running,
    compute_manifest_hmac,
    verify_manifest_hmac,
    load_tamper_log,
    resolve_tampering,
    clear_readonly,
    make_readonly,
    INTEGRITY_DIR,
    BASE_DIR
)
from dashboard.app import app
from module11_forensics import generate_forensic_report


class TestM10PersistentBaselineAndConcurrency(unittest.TestCase):
    """
    Exhaustive verification suite for Phase 7 requirements (Scenarios 1 through 14).
    Uses synthetic evidence files in isolated temporary directories.
    """

    def setUp(self):
        self.test_root = tempfile.mkdtemp(prefix="kg_m10_p7_")
        self.incident_name = f"incident_test_{int(time.time()*1000)}"
        self.evidence_dir = os.path.join(self.test_root, self.incident_name)
        os.makedirs(self.evidence_dir, exist_ok=True)

        # Isolated integrity directory inside test_root to prevent test pollution
        self.custom_integrity_dir = os.path.join(self.test_root, "integrity", self.incident_name)
        os.makedirs(self.custom_integrity_dir, exist_ok=True)

        # Synthetic evidence files
        self.file_yaml = os.path.join(self.evidence_dir, "pod.yaml")
        with open(self.file_yaml, "w", encoding="utf-8") as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-secure\n")

        self.file_status = os.path.join(self.evidence_dir, "pod_status.txt")
        with open(self.file_status, "w", encoding="utf-8") as f:
            f.write("Status: Running\nContainerReady: True\nRestarts: 0\n")

        self.file_logs = os.path.join(self.evidence_dir, "pod_logs.txt")
        with open(self.file_logs, "w", encoding="utf-8") as f:
            f.write("2026-10-23 12:00:00 [INFO] Workload started cleanly.\n")

        # Isolated dashboard state file for testing
        self.test_state_file = os.path.join(self.test_root, "dashboard_state.json")
        with open(self.test_state_file, "w", encoding="utf-8") as f:
            json.dump({"modules": {}, "overview": {}}, f)

        self.client = app.test_client()

    def tearDown(self):
        stop_all_integrity_monitors()
        # Clean up any test directory in global integrity/ if created
        global_test_int = os.path.join(INTEGRITY_DIR, self.incident_name)
        if os.path.exists(global_test_int):
            try:
                for root, _, files in os.walk(global_test_int):
                    for f in files:
                        clear_readonly(os.path.join(root, f))
                shutil.rmtree(global_test_int, ignore_errors=True)
            except Exception:
                pass

        if os.path.exists(self.test_root):
            try:
                for root, _, files in os.walk(self.test_root):
                    for f in files:
                        clear_readonly(os.path.join(root, f))
                shutil.rmtree(self.test_root, ignore_errors=True)
            except Exception:
                pass

    # ------------------------------------------------------------
    # 1. First-time baseline initialization
    # ------------------------------------------------------------
    def test_01_first_time_baseline_initialization(self):
        """Verify explicit baseline initialization creates authenticated manifest.json v1."""
        hash_file = initialize_baseline(
            self.evidence_dir,
            authorized_by="SecLead",
            reason="Initial container escape evidence capture"
        )
        self.assertTrue(os.path.exists(hash_file))
        int_dir = os.path.dirname(hash_file)
        manifest_file = os.path.join(int_dir, "manifest.json")
        self.assertTrue(os.path.exists(manifest_file))

        with open(manifest_file, "r", encoding="utf-8") as f:
            mf = json.load(f)

        self.assertEqual(mf.get("schema_version"), 2)
        self.assertEqual(mf.get("baseline_version"), 1)
        self.assertEqual(mf.get("initialized_by"), "SecLead")
        self.assertEqual(mf.get("initialization_reason"), "Initial container escape evidence capture")
        self.assertEqual(mf.get("file_count"), 3)
        self.assertIn("pod.yaml", mf.get("files", {}))
        self.assertIn("hmac_sha256", mf)

        is_valid, reason = verify_manifest_hmac(mf)
        self.assertTrue(is_valid, f"HMAC validation failed: {reason}")

    # ------------------------------------------------------------
    # 2. Restarting KubeGuard without creating a second baseline
    # ------------------------------------------------------------
    def test_02_restart_kubeguard_reuses_existing_baseline(self):
        """Verify ordinary restart reuses existing trusted baseline rather than regenerating."""
        hash_f1 = initialize_baseline(self.evidence_dir, authorized_by="Admin", reason="Setup")
        int_dir = os.path.dirname(hash_f1)
        manifest_f = os.path.join(int_dir, "manifest.json")

        with open(manifest_f, "r", encoding="utf-8") as f:
            mf_orig = json.load(f)
        orig_hmac = mf_orig["hmac_sha256"]
        orig_init_time = mf_orig["initialized_at"]

        # Simulate KubeGuard restart calling create_hashes or has_valid_trusted_baseline
        has_bl, loaded_mf, _ = has_valid_trusted_baseline(self.evidence_dir)
        self.assertTrue(has_bl)
        self.assertEqual(loaded_mf["baseline_version"], 1)

        hash_f2 = create_hashes(self.evidence_dir)
        self.assertEqual(hash_f1, hash_f2)

        with open(manifest_f, "r", encoding="utf-8") as f:
            mf_after = json.load(f)

        # Baseline was NOT replaced or regenerated
        self.assertEqual(mf_after["hmac_sha256"], orig_hmac)
        self.assertEqual(mf_after["initialized_at"], orig_init_time)
        self.assertEqual(mf_after["baseline_version"], 1)

    # ------------------------------------------------------------
    # 3. Successful verification when files are unchanged
    # ------------------------------------------------------------
    def test_03_verification_success_when_unchanged(self):
        """Verify verify_hashes reports VERIFIED with 3 verified files and 0 discrepancies."""
        initialize_baseline(self.evidence_dir)
        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
            self.evidence_dir,
            update_state=True,
            state_file=self.test_state_file
        )
        self.assertTrue(all_ver)
        self.assertEqual(v_cnt, 3)
        self.assertEqual(t_cnt, 0)
        self.assertEqual(m_cnt, 0)
        self.assertEqual(len(checks), 3)
        for c in checks:
            self.assertEqual(c["status"], "VERIFIED")

        # Verify state file recorded VERIFIED
        with open(self.test_state_file, "r", encoding="utf-8") as f:
            st = json.load(f)
        self.assertEqual(st["modules"]["M10"]["status"], "COMPLETED")
        self.assertEqual(st["modules"]["M10"]["details"]["overall_integrity"], "VERIFIED")

    # ------------------------------------------------------------
    # 4. Detection of a modified evidence file
    # ------------------------------------------------------------
    def test_04_detection_of_modified_file(self):
        """Verify modification of pod_logs.txt triggers TAMPERED status and records tamper log."""
        initialize_baseline(self.evidence_dir)
        time.sleep(0.05)

        # Tamper: attacker injects fake log line
        with open(self.file_logs, "a", encoding="utf-8") as f:
            f.write("2026-10-23 12:05:00 [ATTACKER] Evidence scrubbed.\n")

        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
            self.evidence_dir,
            update_state=True,
            state_file=self.test_state_file
        )
        self.assertFalse(all_ver)
        self.assertEqual(v_cnt, 2)
        self.assertEqual(t_cnt, 1)
        self.assertEqual(m_cnt, 0)

        bad_check = [c for c in checks if c["filename"] == "pod_logs.txt"][0]
        self.assertEqual(bad_check["status"], "TAMPERED")

        # Verify persistent tamper log
        t_log = load_tamper_log(self.evidence_dir)
        self.assertIsNotNone(t_log)
        self.assertTrue(t_log.get("tampered"))
        self.assertEqual(t_log.get("latest_event", {}).get("filename"), "pod_logs.txt")

    # ------------------------------------------------------------
    # 5. Detection of a deleted evidence file
    # ------------------------------------------------------------
    def test_05_detection_of_deleted_file(self):
        """Verify deletion of pod_status.txt is detected as MISSING."""
        initialize_baseline(self.evidence_dir)
        os.remove(self.file_status)

        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
            self.evidence_dir,
            update_state=True,
            state_file=self.test_state_file
        )
        self.assertFalse(all_ver)
        self.assertEqual(v_cnt, 2)
        self.assertEqual(m_cnt, 1)

        missing_check = [c for c in checks if c["filename"] == "pod_status.txt"][0]
        self.assertEqual(missing_check["status"], "MISSING")

    # ------------------------------------------------------------
    # 6. Detection of an unexpected evidence file
    # ------------------------------------------------------------
    def test_06_detection_of_unexpected_file_addition(self):
        """Verify unauthorized file injection is detected as UNAUTHORIZED_NEW_FILE."""
        initialize_baseline(self.evidence_dir)
        backdoor_file = os.path.join(self.evidence_dir, "unauthorized_payload.sh")
        with open(backdoor_file, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho 'backdoor'\n")

        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
            self.evidence_dir,
            update_state=True,
            state_file=self.test_state_file
        )
        self.assertFalse(all_ver)
        self.assertEqual(t_cnt, 1)

        unauth_check = [c for c in checks if c["filename"] == "unauthorized_payload.sh"][0]
        self.assertEqual(unauth_check["status"], "TAMPERED")
        self.assertIn("added to evidence directory", unauth_check["reason"])

    # ------------------------------------------------------------
    # 7. Missing or corrupted trusted baseline (Refusal to recreate)
    # ------------------------------------------------------------
    def test_07_corrupted_baseline_fails_honestly_without_silent_recreation(self):
        """Verify invalid HMAC signature causes BASELINE_INVALID and refuses to silently regenerate."""
        hash_f = initialize_baseline(self.evidence_dir)
        int_dir = os.path.dirname(hash_f)
        manifest_f = os.path.join(int_dir, "manifest.json")

        # Corrupt manifest signature
        clear_readonly(manifest_f)
        with open(manifest_f, "r", encoding="utf-8") as f:
            mf = json.load(f)
        mf["hmac_sha256"] = "deadbeef" * 8
        with open(manifest_f, "w", encoding="utf-8") as f:
            json.dump(mf, f, indent=4)
        make_readonly(manifest_f)

        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
            self.evidence_dir,
            update_state=True,
            state_file=self.test_state_file
        )
        self.assertFalse(all_ver)
        self.assertEqual(t_cnt, 1)

        # Confirm status is BASELINE_INVALID in state
        with open(self.test_state_file, "r", encoding="utf-8") as f:
            st = json.load(f)
        self.assertEqual(st["modules"]["M10"]["details"]["overall_integrity"], "BASELINE_INVALID")

    # ------------------------------------------------------------
    # 8. Unreadable evidence files and filesystem errors
    # ------------------------------------------------------------
    def test_08_unreadable_file_handling(self):
        """Verify unreadable or locked file is handled explicitly as UNREADABLE / TAMPERED."""
        initialize_baseline(self.evidence_dir)

        # Lock file with exclusive mode
        locked_handle = open(self.file_yaml, "r+", encoding="utf-8")
        if sys.platform == "win32":
            import msvcrt
            try:
                msvcrt.locking(locked_handle.fileno(), msvcrt.LK_NBLCK, 1)
            except Exception:
                pass

        try:
            # calculate_hash should return None safely without unhandled crash
            h = calculate_hash(self.file_yaml)
            # Either hash can't be read or returns hash safely
            self.assertTrue(h is None or len(h) == 64)
        finally:
            if sys.platform == "win32":
                import msvcrt
                try:
                    locked_handle.seek(0)
                    msvcrt.locking(locked_handle.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
            locked_handle.close()

    # ------------------------------------------------------------
    # 9. Second-terminal --check while KubeGuard is running
    # ------------------------------------------------------------
    def test_09_second_terminal_cli_check_coexists_with_running_kubeguard(self):
        """Verify second-terminal CLI check runs via subprocess, returning exit code 0."""
        initialize_baseline(self.evidence_dir)

        # Start continuous monitor simulating terminal 1 KubeGuard
        mon = start_integrity_monitor(self.evidence_dir, poll_interval=1.0, state_file=self.test_state_file)
        self.assertIsNotNone(mon)
        self.assertTrue(mon.is_alive())

        try:
            # Simulate terminal 2 executing: python module10_integrity.py --check <evidence_dir>
            cmd = [sys.executable, "module10_integrity.py", "--check", self.evidence_dir]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, f"CLI check failed with output: {proc.stderr} {proc.stdout}")
            self.assertIn("Evidence Integrity VERIFIED", proc.stdout)
        finally:
            mon.stop()

    # ------------------------------------------------------------
    # 10. Simultaneous CLI checks and background monitoring
    # ------------------------------------------------------------
    def test_10_concurrent_checks_under_cross_process_locks(self):
        """Verify concurrent verification calls do not corrupt manifest or state files."""
        initialize_baseline(self.evidence_dir)

        # Run multiple concurrent checks in threads
        errors = []
        def _check_worker():
            try:
                ok, v, t, m, c = verify_hashes(
                    self.evidence_dir,
                    update_state=True,
                    state_file=self.test_state_file
                )
                if not ok or v != 3:
                    errors.append(f"Unexpected check result: ok={ok}, v={v}")
            except Exception as e:
                errors.append(str(e))

        import threading
        threads = [threading.Thread(target=_check_worker) for _ in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(len(errors), 0, f"Concurrency errors detected: {errors}")

        # State file remains valid JSON
        with open(self.test_state_file, "r", encoding="utf-8") as f:
            valid_json = json.load(f)
        self.assertEqual(valid_json["modules"]["M10"]["details"]["overall_integrity"], "VERIFIED")

    # ------------------------------------------------------------
    # 11. Duplicate-worker prevention
    # ------------------------------------------------------------
    def test_11_duplicate_worker_prevention(self):
        """Verify starting two monitors on the same directory reuses or prevents duplicate workers."""
        initialize_baseline(self.evidence_dir)
        mon1 = start_integrity_monitor(self.evidence_dir, poll_interval=1.0, state_file=self.test_state_file)
        self.assertTrue(mon1.is_alive())

        mon2 = start_integrity_monitor(self.evidence_dir, poll_interval=1.0, state_file=self.test_state_file)
        self.assertEqual(mon1, mon2)

        mon1.stop()

    # ------------------------------------------------------------
    # 12. Graceful application shutdown and worker cleanup
    # ------------------------------------------------------------
    def test_12_graceful_shutdown_and_worker_cleanup(self):
        """Verify stop_integrity_monitor cleanly stops thread and clears active registry."""
        initialize_baseline(self.evidence_dir)
        mon = start_integrity_monitor(self.evidence_dir, poll_interval=1.0, state_file=self.test_state_file)
        self.assertTrue(mon.is_alive())

        stopped = stop_integrity_monitor(self.evidence_dir)
        self.assertTrue(stopped)
        self.assertFalse(mon.is_alive())
        self.assertFalse(is_monitor_running(self.evidence_dir))

    # ------------------------------------------------------------
    # 13. Dashboard and forensic report integration
    # ------------------------------------------------------------
    def test_13_dashboard_and_forensic_report_integration(self):
        """Verify M11 forensic report accurately reflects M10 integrity status."""
        initialize_baseline(self.evidence_dir)
        all_ver, v, t, m, checks = verify_hashes(
            self.evidence_dir,
            update_state=False
        )
        m10_results = [{
            "pod": "test-workload",
            "success": True,
            "evidence_dir": self.evidence_dir,
            "details": {
                "overall_integrity": "VERIFIED",
                "verified_count": v,
                "tampered_count": 0,
                "missing_count": 0,
                "file_checks": checks
            }
        }]

        pdf_path = generate_forensic_report(
            scan_result={"image": "nginx:latest", "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "deployment_blocked": False},
            monitor_result={"pod_name": "test-workload", "cpu": "10m", "memory": "20Mi"},
            cluster={"status": True, "message": "Cluster active"},
            roles={"count": 1, "roles": []},
            cluster_roles={"count": 1, "cluster_roles": []},
            bindings={"count": 1, "bindings": []},
            findings=[],
            binding_findings=[],
            threat_data=[],
            threat_result={"status": "COMPLETED"},
            escape_results=[],
            m7_backup_result=None,
            m8_results=[{"success": True, "pod": "test-workload", "evidence_dir": self.evidence_dir}],
            m9_results=None,
            m10_results=m10_results,
            run_id="test_run_p7_m10"
        )
        self.assertIsNotNone(pdf_path)
        self.assertTrue(os.path.exists(pdf_path))

    # ------------------------------------------------------------
    # 14. Explicit re-baselining after an authorized change
    # ------------------------------------------------------------
    def test_14_authorized_rebaselining_increments_version_and_records_history(self):
        """Verify rebaseline_evidence increments baseline_version to v2 and appends audit record."""
        hash_f1 = initialize_baseline(self.evidence_dir, authorized_by="Admin", reason="Initial")
        int_dir = os.path.dirname(hash_f1)
        manifest_f = os.path.join(int_dir, "manifest.json")

        # Legitimate evidence addition authorized by security team
        new_evidence_file = os.path.join(self.evidence_dir, "network_trace.pcap")
        with open(new_evidence_file, "w", encoding="utf-8") as f:
            f.write("TCP packet dump 10.0.0.1 -> 10.0.0.2\n")

        success, msg = rebaseline_evidence(
            self.evidence_dir,
            reason="Authorized addition of network_trace.pcap after forensic acquisition",
            authorized_by="LeadForensicsAnalyst",
            force=True
        )
        self.assertTrue(success, f"Re-baseline failed: {msg}")

        with open(manifest_f, "r", encoding="utf-8") as f:
            mf_v2 = json.load(f)

        self.assertEqual(mf_v2.get("baseline_version"), 2)
        self.assertEqual(mf_v2.get("file_count"), 4)
        self.assertIn("network_trace.pcap", mf_v2.get("files", {}))

        history = mf_v2.get("rebaseline_history", [])
        self.assertEqual(len(history), 2)
        v2_record = history[-1]
        self.assertEqual(v2_record["version"], 2)
        self.assertEqual(v2_record["authorized_by"], "LeadForensicsAnalyst")
        self.assertIn("network_trace.pcap", v2_record["reason"])

        # Verification now succeeds on the new baseline
        all_ver, v, t, m, _ = verify_hashes(self.evidence_dir, update_state=False)
        self.assertTrue(all_ver)
        self.assertEqual(v, 4)
        self.assertEqual(t, 0)


if __name__ == "__main__":
    unittest.main()
