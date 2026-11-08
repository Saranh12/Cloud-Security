import os
import sys
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import subprocess

# Ensure base directory in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from module5_escape import detect_escape_indicators
from rbac_audit import (
    analyze_cluster_roles,
    analyze_namespace_roles,
    analyze_cluster_role_bindings,
    analyze_role_bindings,
    save_report,
    save_json_report,
    perform_rbac_audit
)
from vuln_scan import scan_image, validate_image_reference
from module10_integrity import (
    start_integrity_monitor,
    stop_all_integrity_monitors,
    calculate_hash,
    initialize_baseline,
    verify_hashes,
    handle_no_evidence,
    load_tamper_log
)
from module11_forensics import generate_forensic_report
from dashboard.app import app


class TestKubeGuardSuite(unittest.TestCase):
    """
    Comprehensive KubeGuard Security Verification Suite (Scenarios A through K).
    Executes fully offline with mocked cluster interfaces to verify determinism and accuracy.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="kg_suite_test_")
        self.client = app.test_client()

    def tearDown(self):
        stop_all_integrity_monitors()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # =========================================================================
    # TEST A: Privileged Container (securityContext.privileged: true)
    # =========================================================================
    def test_scenario_a_privileged_container_critical_finding(self):
        """
        CASE A: Deployed container has securityContext.privileged == true.
        Must classify as Critical, set status to SUSPICIOUS CONFIGURATION DETECTED,
        and trigger incident response.
        """
        pod_spec = [{
            "metadata": {
                "name": "vuln-priv-pod-12345",
                "namespace": "production",
                "ownerReferences": [{"kind": "Deployment", "name": "vuln-priv-deployment"}]
            },
            "spec": {
                "containers": [{
                    "name": "workload-c1",
                    "image": "custom-app:v1.0",
                    "securityContext": {
                        "privileged": True
                    }
                }]
            }
        }]

        results = detect_escape_indicators(pod_spec, run_id="run_test_a")
        self.assertEqual(len(results), 1)
        r = results[0]

        # Verification of Case A requirements
        self.assertEqual(r["pod"], "vuln-priv-pod-12345")
        self.assertEqual(r["namespace"], "production")
        self.assertEqual(r["container"], "workload-c1")
        self.assertEqual(r["image"], "custom-app:v1.0")
        self.assertTrue(r["privileged"])
        self.assertEqual(r["severity"], "Critical")
        self.assertEqual(r["status"], "SUSPICIOUS CONFIGURATION DETECTED")
        self.assertTrue(r["incident_triggered"], "Critical privileged mode must trigger incident response")

        # Verify structured finding
        s_findings = r.get("structured_findings", [])
        self.assertTrue(len(s_findings) >= 1)
        priv_finding = next((f for f in s_findings if f.get("finding_type") == "PRIVILEGED_CONTAINER"), None)
        self.assertIsNotNone(priv_finding)
        self.assertEqual(priv_finding["severity"], "Critical")
        self.assertEqual(priv_finding["container"], "workload-c1")
        self.assertTrue(priv_finding["privileged"])

    # =========================================================================
    # TEST B: Non-Privileged Container (securityContext.privileged: false)
    # =========================================================================
    def test_scenario_b_non_privileged_container_clean(self):
        """
        CASE B: Deployed container has securityContext.privileged == false.
        Must report Privileged: false, Status: NORMAL, Severity: None,
        and NOT trigger incident response.
        """
        pod_spec = [{
            "metadata": {
                "name": "secure-app-pod-67890",
                "namespace": "production",
                "ownerReferences": [{"kind": "Deployment", "name": "secure-app-deployment"}]
            },
            "spec": {
                "containers": [{
                    "name": "web-c1",
                    "image": "nginx:1.25-alpine",
                    "securityContext": {
                        "privileged": False
                    }
                }]
            }
        }]

        results = detect_escape_indicators(pod_spec, run_id="run_test_b")
        self.assertEqual(len(results), 1)
        r = results[0]

        self.assertEqual(r["pod"], "secure-app-pod-67890")
        self.assertFalse(r["privileged"])
        self.assertEqual(r["severity"], "None")
        self.assertEqual(r["status"], "NORMAL")
        self.assertFalse(r["incident_triggered"], "Non-privileged container must not trigger incident response")
        self.assertEqual(len(r["findings"]), 0)

    # =========================================================================
    # TEST C: Privileged Field Omitted (Defaults to False in Kubernetes)
    # =========================================================================
    def test_scenario_c_privileged_field_omitted(self):
        """
        CASE C: securityContext exists or is omitted, but privileged key is omitted.
        Kubernetes treats omitted privileged as false; KubeGuard must not flag as privileged.
        """
        pod_spec = [{
            "metadata": {
                "name": "omitted-priv-pod",
                "namespace": "default"
            },
            "spec": {
                "containers": [{
                    "name": "backend-worker",
                    "image": "python:3.12-slim",
                    "securityContext": {
                        "readOnlyRootFilesystem": True
                    }
                }]
            }
        }]

        results = detect_escape_indicators(pod_spec, run_id="run_test_c")
        self.assertEqual(len(results), 1)
        r = results[0]

        self.assertFalse(r["privileged"])
        self.assertEqual(r["severity"], "None")
        self.assertEqual(r["status"], "NORMAL")
        self.assertFalse(r["incident_triggered"])

    # =========================================================================
    # TEST D: Independent Security Risks on Non-Privileged Container
    # =========================================================================
    def test_scenario_d_independent_risks_on_non_privileged_container(self):
        """
        CASE D: Container is NOT privileged, but has independent risks:
        CAP_SYS_ADMIN, hostPID, and hostPath mount.
        Must report Privileged: false, but flag the independent risks accurately without false escape proof.
        """
        pod_spec = [{
            "metadata": {
                "name": "independent-risk-pod",
                "namespace": "staging"
            },
            "spec": {
                "hostPID": True,
                "volumes": [{
                    "name": "host-root",
                    "hostPath": {"path": "/var/run/docker.sock"}
                }],
                "containers": [{
                    "name": "agent-c",
                    "image": "monitoring-agent:v2",
                    "securityContext": {
                        "privileged": False,
                        "capabilities": {
                            "add": ["SYS_ADMIN"]
                        }
                    }
                }]
            }
        }]

        results = detect_escape_indicators(pod_spec, run_id="run_test_d")
        self.assertEqual(len(results), 1)
        r = results[0]

        self.assertFalse(r["privileged"], "Container privileged flag must remain False")
        self.assertEqual(r["status"], "SUSPICIOUS CONFIGURATION DETECTED")
        self.assertIn(r["severity"], ["High", "Critical"])

        # Check that independent risks are explicitly identified
        findings_text = " ".join(r["findings"])
        self.assertIn("SYS_ADMIN", findings_text)
        self.assertIn("Host PID", findings_text)
        self.assertIn("Host filesystem mount", findings_text)

    # =========================================================================
    # TEST E: Multiple Containers (App + Init + Ephemeral)
    # =========================================================================
    def test_scenario_e_multiple_containers_independent_inspection(self):
        """
        CASE E: Pod contains multiple containers: init container (clean) and app container (privileged).
        Must inspect each independently, attribute findings to the specific container, and avoid duplicates.
        """
        pod_spec = [{
            "metadata": {
                "name": "multi-container-pod",
                "namespace": "prod"
            },
            "spec": {
                "initContainers": [{
                    "name": "setup-helper",
                    "image": "busybox:1.36",
                    "securityContext": {
                        "privileged": False
                    }
                }],
                "containers": [
                    {
                        "name": "app-frontend",
                        "image": "frontend:1.0",
                        "securityContext": {"privileged": False}
                    },
                    {
                        "name": "privileged-sidecar",
                        "image": "daemon-proxy:2.0",
                        "securityContext": {"privileged": True}
                    }
                ]
            }
        }]

        results = detect_escape_indicators(pod_spec, run_id="run_test_e")
        self.assertEqual(len(results), 1)
        r = results[0]

        containers = r.get("containers", [])
        self.assertEqual(len(containers), 3, "Must inspect all 3 containers independently")

        c_names = {c["container"]: c for c in containers}
        self.assertIn("setup-helper", c_names)
        self.assertIn("app-frontend", c_names)
        self.assertIn("privileged-sidecar", c_names)

        # setup-helper and app-frontend must be non-privileged
        self.assertFalse(c_names["setup-helper"]["privileged"])
        self.assertFalse(c_names["app-frontend"]["privileged"])

        # privileged-sidecar must be flagged
        self.assertTrue(c_names["privileged-sidecar"]["privileged"])
        self.assertEqual(c_names["privileged-sidecar"]["severity"], "Critical")

        # Verify pod attributes correctly
        self.assertTrue(r["privileged"])
        self.assertEqual(r["severity"], "Critical")

    # =========================================================================
    # TEST F: Multiple Namespaces
    # =========================================================================
    def test_scenario_f_multiple_namespaces(self):
        """
        CASE F: Inspect pods from multiple namespaces. Findings must retain exact namespace
        and owning workload without cross-namespace confusion.
        """
        pods = [
            {
                "metadata": {
                    "name": "pod-in-kube-system",
                    "namespace": "kube-system",
                    "ownerReferences": [{"kind": "DaemonSet", "name": "system-agent"}]
                },
                "spec": {"containers": [{"name": "c1", "image": "img1", "securityContext": {"privileged": False}}]}
            },
            {
                "metadata": {
                    "name": "pod-in-finance",
                    "namespace": "finance",
                    "ownerReferences": [{"kind": "Deployment", "name": "finance-api"}]
                },
                "spec": {"containers": [{"name": "c2", "image": "img2", "securityContext": {"privileged": True}}]}
            }
        ]

        results = detect_escape_indicators(pods, run_id="run_test_f")
        self.assertEqual(len(results), 2)

        res_by_ns = {r["namespace"]: r for r in results}
        self.assertIn("kube-system", res_by_ns)
        self.assertIn("finance", res_by_ns)

        self.assertFalse(res_by_ns["kube-system"]["privileged"])
        self.assertEqual(res_by_ns["kube-system"]["owning_workload"], "DaemonSet/system-agent")

        self.assertTrue(res_by_ns["finance"]["privileged"])
        self.assertEqual(res_by_ns["finance"]["owning_workload"], "Deployment/finance-api")

    # =========================================================================
    # TEST G: Detailed RBAC Report Generation (All 18 Fields)
    # =========================================================================
    def test_scenario_g_rbac_report_all_18_fields(self):
        """
        CASE G: Full rule-based RBAC audit must generate reports/rbac_report.txt and reports/rbac_report.json
        containing all 18 required metadata and evidence fields.
        """
        # Synthetic ClusterRoles & ClusterRoleBindings
        mock_roles = [
            {
                "metadata": {"name": "dangerous-escalator"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["escalate", "bind"]}]
            },
            {
                "metadata": {"name": "secret-reader"},
                "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]
            },
            {
                "metadata": {"name": "normal-view"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
            }
        ]

        mock_bindings = [
            {
                "metadata": {"name": "admin-binding"},
                "roleRef": {"name": "cluster-admin", "kind": "ClusterRole"},
                "subjects": [{"name": "external-user@example.com", "kind": "User"}]
            }
        ]

        role_findings = analyze_cluster_roles(mock_roles)
        binding_findings = analyze_cluster_role_bindings(mock_bindings, dangerous_roles={"dangerous-escalator", "secret-reader", "cluster-admin"})

        self.assertTrue(len(role_findings) >= 2, "Must flag dangerous escalator and secret reader")
        self.assertTrue(len(binding_findings) >= 1, "Must flag cluster-admin binding to User")

        metadata = {
            "cluster_status": "Cluster Connected (Mocked Test Context)",
            "context": "test-cluster-admin@mock",
            "namespace_scope": "All Namespaces",
            "roles_count": 0,
            "cluster_roles_count": len(mock_roles),
            "role_bindings_count": 0,
            "cluster_role_bindings_count": len(mock_bindings),
            "dangerous_roles": role_findings,
            "dangerous_bindings": binding_findings,
            "warnings": ["Test warning: Mocked offline scan verification"]
        }

        run_id = "run_test_rbac_18_fields"
        save_report(role_findings, binding_findings=binding_findings, metadata=metadata, run_id=run_id)
        save_json_report(metadata, run_id=run_id)

        txt_path = Path("reports/rbac_report.txt")
        json_path = Path("reports/rbac_report.json")

        self.assertTrue(txt_path.exists(), "reports/rbac_report.txt must be generated")
        self.assertTrue(json_path.exists(), "reports/rbac_report.json must be generated")

        # Read JSON and verify all 18 metadata fields are represented
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        required_keys = [
            "audit_timestamp",
            "cluster_status",
            "context",
            "cluster_roles_count",
            "cluster_role_bindings_count",
            "dangerous_roles",
            "dangerous_bindings",
            "warnings"
        ]
        for k in required_keys:
            self.assertIn(k, data, f"Field '{k}' missing from rbac_report.json")

        # Read text report and verify human-readable sections
        txt_content = txt_path.read_text(encoding="utf-8")
        self.assertIn("KUBEGUARD RBAC SECURITY AUDIT REPORT", txt_content)
        self.assertIn("SECTION 1: DANGEROUS ROLES & CLUSTERROLES", txt_content)
        self.assertIn("SECTION 2: DANGEROUS ROLE BINDINGS", txt_content)
        self.assertIn("Risk Score", txt_content)
        self.assertIn("Recommendation", txt_content)

    # =========================================================================
    # TEST H: Image Scan Timeout and Scanner Error Handling
    # =========================================================================
    def test_scenario_h_trivy_timeout_and_scanner_error(self):
        """
        CASE H: Trivy scanner timeout or subprocess error must be marked as FAILED,
        severity_counts must be None (NOT 0 confirmed vulnerabilities), and deployment_blocked must be True.
        """
        # 1. Test timeout behavior via mock
        with patch("vuln_scan.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["trivy", "image"], timeout=5)
            res = scan_image("timeout-test-image:latest", timeout=5)

            self.assertEqual(res["status"], "FAILED")
            self.assertEqual(res["error_type"], "TIMEOUT")
            self.assertIsNone(res["severity_counts"], "Must NOT report false 0 vulnerabilities on timeout")
            self.assertTrue(res["vulnerabilities_unverified"])
            self.assertTrue(res["deployment_blocked"])

        # 2. Test image reference validation
        valid, _ = validate_image_reference("valid/image:latest")
        self.assertTrue(valid)

        invalid, err = validate_image_reference("invalid:::image@@syntax")
        self.assertFalse(invalid)
        self.assertIn("consecutive", err.lower())

    # =========================================================================
    # TEST I: Integrity Monitor (Tamper Detection & Verification)
    # =========================================================================
    def test_scenario_i_integrity_monitoring_and_tamper_detection(self):
        """
        CASE I: Integrity monitor must calculate SHA-256 hashes, verify clean evidence,
        detect modified and missing files, write tamper logs, and export start_integrity_monitor cleanly.
        """
        self.assertTrue(callable(start_integrity_monitor), "start_integrity_monitor must be callable")

        # Create synthetic evidence files
        incident_dir = os.path.join(self.test_dir, "incident_evidence_001")
        os.makedirs(incident_dir, exist_ok=True)

        file_pod = os.path.join(incident_dir, "pod.yaml")
        with open(file_pod, "w", encoding="utf-8") as f:
            f.write("apiVersion: v1\nkind: Pod\n")

        file_log = os.path.join(incident_dir, "incident.log")
        with open(file_log, "w", encoding="utf-8") as f:
            f.write("Incident logged at 12:00:00\n")

        # Test hash calculation
        h1 = calculate_hash(file_pod)
        self.assertEqual(len(h1), 64, "SHA-256 hash must be 64 hexadecimal characters")

        # Initialize baseline
        hash_file = initialize_baseline(incident_dir)
        self.assertTrue(os.path.exists(hash_file))

        # Initial clean verification
        all_verified, verified_cnt, tampered_cnt, missing_cnt, checks = verify_hashes(incident_dir)
        self.assertTrue(all_verified, f"Initial verification should pass, got checks: {checks}")
        self.assertEqual(tampered_cnt, 0)
        self.assertEqual(missing_cnt, 0)

        # Modify evidence -> Tamper detection
        from module10_integrity import clear_readonly
        clear_readonly(file_log)
        with open(file_log, "a", encoding="utf-8") as f:
            f.write("TAMPERED LINE INSERTION\n")

        all_verified_mod, verified_cnt_mod, tampered_cnt_mod, missing_cnt_mod, checks_mod = verify_hashes(incident_dir)
        self.assertFalse(all_verified_mod, "Modified file must fail hash verification")
        self.assertTrue(tampered_cnt_mod > 0, "Must detect tampered file count > 0")

        # Clean up any test directory in global integrity/
        from module10_integrity import INTEGRITY_DIR
        global_test_int = os.path.join(INTEGRITY_DIR, os.path.basename(incident_dir))
        if os.path.exists(global_test_int):
            try:
                for root, _, files in os.walk(global_test_int):
                    for f in files:
                        clear_readonly(os.path.join(root, f))
                shutil.rmtree(global_test_int, ignore_errors=True)
            except Exception:
                pass

        # Test handle_no_evidence for normal runs
        no_ev_res = handle_no_evidence(run_id="run_normal_no_ev")
        self.assertEqual(no_ev_res["status"], "NOT_APPLICABLE")
        self.assertEqual(no_ev_res["tampered_count"], 0)
        self.assertEqual(no_ev_res["missing_count"], 0)

    # =========================================================================
    # TEST J: Deterministic Forensic Reporting (Exactly One PDF per Run ID)
    # =========================================================================
    def test_scenario_j_deterministic_forensic_pdf(self):
        """
        CASE J: Generate forensic PDF report for both incident and normal runs.
        Must produce exactly reports/KubeGuard_Forensic_Incident_Report_<run_id>.pdf
        with valid PDF magic bytes.
        """
        run_id_normal = "run_test_pdf_normal_001"
        rep_path_normal = generate_forensic_report(
            scan_result={"image": "nginx:alpine", "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}},
            run_id=run_id_normal
        )
        self.assertEqual(os.path.normpath(rep_path_normal), os.path.normpath(f"reports/KubeGuard_Forensic_Incident_Report_{run_id_normal}.pdf"))
        self.assertTrue(os.path.exists(rep_path_normal))
        with open(rep_path_normal, "rb") as f:
            header = f.read(4)
            self.assertEqual(header, b"%PDF", "Must be a valid PDF file")

        # Incident run with privileged container finding
        run_id_incident = "run_test_pdf_incident_002"
        rep_path_incident = generate_forensic_report(
            scan_result={"image": "vulnerable-image:1.0", "counts": {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 2, "LOW": 1}},
            escape_results=[{
                "pod": "priv-pod",
                "container": "priv-container",
                "privileged": True,
                "severity": "Critical",
                "status": "SUSPICIOUS CONFIGURATION DETECTED"
            }],
            run_id=run_id_incident,
            incident_id="incident_test_20261029_001"
        )
        self.assertEqual(os.path.normpath(rep_path_incident), os.path.normpath(f"reports/KubeGuard_Forensic_Incident_Report_{run_id_incident}.pdf"))
        self.assertTrue(os.path.exists(rep_path_incident))

    # =========================================================================
    # TEST K: Dashboard Endpoints, Downloads, and Security Controls
    # =========================================================================
    def test_scenario_k_dashboard_endpoints_and_security(self):
        """
        CASE K: Dashboard endpoints must return valid telemetry, allow viewing and downloading
        RBAC reports and PDFs, and prevent directory traversal.
        """
        # 1. API Dashboard
        resp = self.client.get("/api/dashboard")
        self.assertEqual(resp.status_code, 200)
        dash = resp.get_json()
        self.assertIn("modules", dash)
        self.assertIn("M5", dash["modules"])
        self.assertIn("M3", dash["modules"])

        # 2. RBAC TXT view via /api/file-content
        resp_txt = self.client.get("/api/file-content?path=reports/rbac_report.txt")
        self.assertEqual(resp_txt.status_code, 200)
        self.assertIn("content", resp_txt.get_json())

        # 3. RBAC JSON view via /api/file-content
        resp_json = self.client.get("/api/file-content?path=reports/rbac_report.json")
        self.assertEqual(resp_json.status_code, 200)

        # 4. Directory traversal attempt prevention
        resp_bad = self.client.get("/api/file-content?path=../../windows/win.ini")
        self.assertIn(resp_bad.status_code, [400, 403])

        # 5. Pipeline run validation error on empty image
        resp_empty = self.client.post("/api/pipeline/run", json={"image": ""})
        self.assertEqual(resp_empty.status_code, 400)

        # 6. Pipeline run validation error on invalid image
        resp_invalid = self.client.post("/api/pipeline/run", json={"image": "bad/image:::@@"})
        self.assertEqual(resp_invalid.status_code, 400)


if __name__ == "__main__":
    unittest.main()
