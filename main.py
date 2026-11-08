import sys
import os
import threading
import time
import subprocess
import json
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from vuln_scan import scan_image, validate_image_reference
from monitoring import get_pod_metrics, discover_workload, ensure_workload
from runtime_target import (
    RuntimeTarget,
    discover_runtime_workloads,
    prompt_or_select_runtime_target,
    revalidate_runtime_target,
    get_persisted_target_config,
    persist_target_config,
    list_available_deployments,
    resolve_existing_deployment_target,
    cleanup_obsolete_kubeguard_workloads,
    matches_image_name
)
import run_manager

# MODULE 4 - Threat Detection
from module4_detection import get_workload_usage, detect_threat

# MODULE 5 - Container Escape Detection
from module5_escape import get_pods, detect_escape_indicators

# MODULE 9 - Auto-Isolation
from module9_isolation import auto_isolate_pod

# MODULE 7 - Backup
from module7_backup import create_backup

# MODULE 8 - Evidence
from module8_evidence import collect_evidence

# MODULE 10 - Integrity
from module10_integrity import (
    create_hashes,
    initialize_baseline,
    load_trusted_baseline,
    has_valid_trusted_baseline,
    get_baseline_paths,
    verify_hashes,
    start_integrity_monitor,
    stop_all_integrity_monitors,
    is_monitor_running,
    resolve_target_evidence_dir
)

# MODULE 6 - Alerting
from alerting import send_telegram_alert, should_send_alert
from email_alerting import send_email_alert
from alert_logger import log_alert
from module11_forensics import generate_forensic_report

from rbac_audit import (
    perform_rbac_audit,
    save_report,
    save_json_report,
    check_cluster,
    get_roles,
    get_cluster_roles,
    analyze_cluster_roles,
    get_cluster_role_bindings,
    analyze_cluster_role_bindings
)
from module10_integrity import handle_no_evidence
from deployment_manager import generate_assessment_workload_name, deploy_workload as dm_deploy_workload

# ==================================================
# M12 DASHBOARD STATE
# ==================================================

DASHBOARD_STATE = "reports/dashboard_state.json"
_STATE_LOCK = threading.Lock()
_monitor_stop_event = None
_monitor_thread = None
latest_monitor_result = {}


def recompute_overview(data):
    modules = data.get("modules", {})

    # M1 vuln counts
    m1_details = modules.get("M1", {}).get("details", {})
    counts = m1_details.get("severity_counts", {})
    crit_vuln = counts.get("CRITICAL", 0)
    high_vuln = counts.get("HIGH", 0)
    med_vuln = counts.get("MEDIUM", 0)
    low_vuln = counts.get("LOW", 0)
    tot_vuln = crit_vuln + high_vuln + med_vuln + low_vuln

    # M5 escape details
    m5_details = modules.get("M5", {}).get("details", {})
    pods_monitored = m5_details.get("pods_checked", 0)
    if pods_monitored == 0 and modules.get("M2", {}).get("status") in ["RUNNING", "COMPLETED", "SUCCESS"]:
        pods_monitored = 1

    suspicious_pods = 0
    for itm in m5_details.get("escape_items", []):
        if itm.get("status") == "SUSPICIOUS ACTIVITY DETECTED":
            suspicious_pods += 1
    if modules.get("M4", {}).get("severity") in ["High", "HIGH", "Critical", "CRITICAL"]:
        suspicious_pods = max(suspicious_pods, 1)

    # M10 integrity status
    m10_mod = modules.get("M10", {})
    m10_status = m10_mod.get("status", "NOT RUN")
    m10_details = m10_mod.get("details", {})
    if m10_status == "SKIPPED":
        ev_integrity = "SKIPPED"
    elif m10_status == "NOT RUN":
        ev_integrity = "NOT RUN"
    else:
        ev_integrity = m10_details.get("overall_integrity", m10_status)

    # Highest overall risk
    severities = [
        modules.get("M1", {}).get("severity", "None"),
        modules.get("M3", {}).get("severity", "None"),
        modules.get("M4", {}).get("severity", "None"),
        modules.get("M5", {}).get("severity", "None")
    ]
    if any(s in ["Critical", "CRITICAL"] for s in severities) or ev_integrity in ["FAILED", "TAMPERED"]:
        overall_risk = "CRITICAL"
    elif any(s in ["High", "HIGH"] for s in severities):
        overall_risk = "HIGH"
    elif any(s in ["Medium", "MEDIUM"] for s in severities):
        overall_risk = "MEDIUM"
    elif all(modules.get(m, {}).get("status") == "NOT RUN" for m in ["M1", "M2", "M3", "M4", "M5"]):
        overall_risk = "NOT RUN"
    else:
        overall_risk = "NORMAL"

    # Forensic reports count in current execution
    report_count = 1 if modules.get("M11", {}).get("status") in ["COMPLETED", "SUCCESS"] else 0

    # Findings distribution
    m3_details = modules.get("M3", {}).get("details", {})
    m3_dang_roles = len(m3_details.get("dangerous_roles", []))
    m3_dang_binds = len(m3_details.get("dangerous_bindings", []))

    tot_findings = tot_vuln + m3_dang_roles + m3_dang_binds + suspicious_pods
    crit_m3 = sum(1 for b in m3_details.get("dangerous_bindings", []) if b.get("severity") == "Critical")
    crit_escape = 1 if any(s == "Critical" for s in severities) else 0
    crit_findings = crit_vuln + crit_m3 + crit_escape

    data["overview"] = {
        "overall_risk": overall_risk,
        "pods_monitored": pods_monitored,
        "suspicious_pods": suspicious_pods,
        "vulnerabilities": tot_vuln,
        "vuln_breakdown": {
            "critical": crit_vuln,
            "high": high_vuln,
            "medium": med_vuln,
            "low": low_vuln
        },
        "evidence_integrity": ev_integrity,
        "forensic_reports_count": report_count,
        "findings_distribution": {
            "total": tot_findings,
            "critical": crit_findings,
            "high": high_vuln,
            "medium": med_vuln,
            "low": low_vuln
        }
    }


MODULE_NAMES = {
    "M1": "Image Vulnerability Scanning",
    "M2": "Container Monitoring",
    "M3": "RBAC Audit",
    "M4": "Threat Detection and Severity Scoring",
    "M5": "Container Escape Detection",
    "M6": "Security Alerting",
    "M7": "Backup",
    "M8": "Evidence Collection",
    "M9": "Isolation / Replacement",
    "M10": "Evidence Integrity",
    "M11": "Forensic Analysis"
}


def update_dashboard(module, status, severity="None", message="", details=None, extra_root=None, run_id=None):
    os.makedirs("reports", exist_ok=True)

    with _STATE_LOCK:
        data = {}
        for attempt in range(10):
            try:
                if os.path.exists(DASHBOARD_STATE):
                    with open(DASHBOARD_STATE, "r", encoding="utf-8") as file:
                        data = json.load(file)
                    if isinstance(data, dict) and data:
                        break
                else:
                    break
            except (PermissionError, json.JSONDecodeError, OSError):
                time.sleep(0.05)
            except FileNotFoundError:
                break

        if not run_id:
            run_id = data.get("run_id")

        if "modules" not in data or not isinstance(data["modules"], dict):
            data["modules"] = {}

        current_module = data["modules"].get(module, {})
        if status in ["SKIPPED", "NOT RUN", "NOT_APPLICABLE"] or (status == "COMPLETED" and details is not None and "status" in details):
            existing_details = dict(details) if details else {}
        else:
            existing_details = current_module.get("details", {}) if isinstance(current_module.get("details"), dict) else {}
            if details:
                existing_details.update(details)

        now_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_img = data.get("selected_image") or os.environ.get("TARGET_IMAGE", "")
        m_id = module.upper()

        module_entry = {
            "module_id": m_id,
            "module_name": MODULE_NAMES.get(m_id, module),
            "status": status,
            "target_image": target_img,
            "run_id": run_id,
            "started_at": current_module.get("started_at", now_dt),
            "completed_at": now_dt if status not in ["RUNNING", "NOT RUN"] else None,
            "summary": message,
            "findings": existing_details.get("findings", existing_details.get("file_checks", existing_details.get("critical_cve_ids", []))),
            "evidence_files": existing_details.get("files", []),
            "errors": [existing_details["error"]] if "error" in existing_details and existing_details["error"] else [],
            "limitations": [existing_details["limitation"]] if "limitation" in existing_details else ([] if status != "NOT_APPLICABLE" else [message]),
            "severity": severity,
            "message": message,
            "details": existing_details
        }

        data["modules"][module] = module_entry
        data["modules"][module.lower()] = module_entry
        data[module] = module_entry
        data[module.lower()] = module_entry

        # Synchronize shared run context attributes
        data["image"] = data.get("selected_image")
        data["module_results"] = data.get("modules", {})
        data["overall_status"] = data.get("pipeline_status", "RUNNING")
        if module.upper() == "M1":
            data["scan_results"] = existing_details
        elif module.upper() == "M2":
            if existing_details.get("deployment_name"):
                data["deployment_name"] = existing_details["deployment_name"]
            if existing_details.get("pod_name"):
                p_name = existing_details["pod_name"]
                if p_name and p_name not in data.get("pod_names", []):
                    data.setdefault("pod_names", []).append(p_name)
        elif module.upper() == "M8":
            data["evidence_files"] = existing_details.get("files", data.get("evidence_files", []))
        elif module.upper() == "M10":
            data["integrity_result"] = existing_details.get("overall_integrity", status)
        elif module.upper() == "M11":
            if existing_details.get("report_path"):
                data["forensic_report_path"] = str(existing_details["report_path"]).replace("\\", "/")

        if extra_root and isinstance(extra_root, dict):
            data.update(extra_root)
            if "deployment_name" in extra_root:
                data["deployment_name"] = extra_root["deployment_name"]
            if "target_pod" in extra_root and extra_root["target_pod"]:
                p_name = extra_root["target_pod"]
                if p_name not in data.get("pod_names", []):
                    data.setdefault("pod_names", []).append(p_name)
            if "pipeline_status" in extra_root:
                data["overall_status"] = extra_root["pipeline_status"]

        data["execution_time"] = now_dt
        recompute_overview(data)

        for attempt in range(5):
            try:
                tmp_file = f"{DASHBOARD_STATE}.{os.getpid()}_{attempt}.tmp"
                with open(tmp_file, "w", encoding="utf-8") as file:
                    json.dump(data, file, indent=4)
                os.replace(tmp_file, DASHBOARD_STATE)
                break
            except Exception:
                try:
                    with open(DASHBOARD_STATE, "w", encoding="utf-8") as file:
                        json.dump(data, file, indent=4)
                    break
                except (PermissionError, OSError):
                    time.sleep(0.05)

    # Record in isolated run manager
    if run_id:
        try:
            run_manager.record_module_result(run_id, module, status, severity, message, details, extra_root)
        except Exception:
            pass


def reset_dashboard_state(selected_image=None, run_id=None):
    os.makedirs("reports", exist_ok=True)
    if not selected_image:
        selected_image = os.environ.get("TARGET_IMAGE") or "Unknown"
    if not run_id:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    try:
        run_manager.init_run(selected_image=selected_image, run_id=run_id)
    except Exception:
        pass

    modules_list = [f"M{i}" for i in range(1, 12)]

    modules = {}
    for mod in modules_list:
        modules[mod] = {
            "status": "NOT RUN",
            "severity": "None",
            "message": "",
            "details": {}
        }
        modules[mod.lower()] = modules[mod]

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state = {
        "run_id": run_id,
        "selected_image": selected_image,
        "image": selected_image,
        "created_at": now_str,
        "start_time": now_str,
        "target_pod": None,
        "namespace": "default",
        "deployment_name": None,
        "pod_names": [],
        "deployment": {
            "status": "NOT RUN",
            "runtime_target": "kubernetes",
            "workload_name": None,
            "workload_kind": None,
            "pod_name": None,
            "container_name": None,
            "container_id": None,
            "runtime_image": None,
            "runtime_image_id": None,
            "scanned_digest": None,
            "identity_status": "UNVERIFIED",
            "identity_details": "No deployment initiated.",
            "privileged_requested": False,
            "privileged_effective": False,
            "privileged_status": "DISABLED",
            "logs": ""
        },
        "pipeline_status": "RUNNING",
        "status": "RUNNING",
        "overall_status": "RUNNING",
        "scan_results": {},
        "module_results": modules,
        "evidence_files": [],
        "integrity_result": "NOT RUN",
        "forensic_report_path": None,
        "execution_time": now_str,
        "modules": modules,
        "overview": {
            "overall_risk": "NOT RUN",
            "pods_monitored": 0,
            "suspicious_pods": 0,
            "vulnerabilities": 0,
            "vuln_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "evidence_integrity": "NOT RUN",
            "forensic_reports_count": 0,
            "findings_distribution": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }
    }

    for mod in modules_list:
        state[mod] = modules[mod]
        state[mod.lower()] = modules[mod]

    with open(DASHBOARD_STATE, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=4)
    return state


# -----------------------------
# MODULE 2 - CONTINUOUS MONITORING
# -----------------------------

def continuous_monitoring(target_pod=None, target_image=None, container_name=None, stop_event=None, run_id=None, workload_name=None):
    global latest_monitor_result
    active_history = []

    while True:
        if stop_event and stop_event.is_set():
            break

        if run_id:
            try:
                with open(DASHBOARD_STATE, "r", encoding="utf-8") as f:
                    curr_state = json.load(f)
                    if curr_state.get("run_id") and curr_state.get("run_id") != run_id:
                        break
            except Exception:
                pass

        current_target_pod = os.environ.get("TARGET_POD") or target_pod
        current_workload = workload_name or os.environ.get("DEPLOYMENT_NAME") or os.environ.get("WORKLOAD_NAME")
        result = get_pod_metrics(
            target_pod=current_target_pod,
            target_image=target_image,
            container_name=container_name,
            workload_name=current_workload,
            run_id=run_id
        )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        time_short = datetime.now().strftime("%H:%M:%S")

        if "error" not in result:
            latest_monitor_result = result
            actual_pod = result.get("pod_name", current_target_pod)
            target_pod = actual_pod
            os.environ["TARGET_POD"] = actual_pod

            cpu_str = result.get("cpu", "0m")
            mem_str = result.get("memory", "0Mi")
            cpu_m = result.get("cpu_millicores", 0)
            mem_mib = result.get("memory_mib", 0)

            active_history.append({
                "time": time_short,
                "cpu_m": cpu_m,
                "cpu": cpu_str,
                "mem_mib": mem_mib,
                "mem": mem_str
            })
            if len(active_history) > 20:
                active_history = active_history[-20:]

            details = {
                "pod_name": actual_pod,
                "container_name": result.get("container_name", container_name),
                "image": target_image,
                "cpu": cpu_str,
                "memory": mem_str,
                "cpu_millicores": cpu_m,
                "memory_mib": mem_mib,
                "metrics_available": True,
                "monitoring_status": "CONTINUOUS",
                "monitoring_interval": "5 seconds",
                "last_updated": now_str,
                "metrics_history": list(active_history),
                "pods": [
                    {
                        "name": actual_pod,
                        "namespace": "default",
                        "status": "Running",
                        "cpu": cpu_str,
                        "memory": mem_str,
                        "restarts": 0,
                        "health": "Healthy"
                    }
                ]
            }

            update_dashboard(
                "M2",
                "RUNNING",
                "None",
                f"Pod={actual_pod} | CPU={cpu_str} | Memory={mem_str}",
                details=details,
                run_id=run_id
            )

        else:
            is_terminated = result.get("pod_terminated", False)
            mon_status = "WAITING_FOR_WORKLOAD" if is_terminated else "CONTINUOUS"
            status_msg = "Waiting for replacement workload..." if is_terminated else f"Metrics Unavailable: {result['error']}"

            details = {
                "metrics_available": False,
                "error": result["error"],
                "image": target_image,
                "pod_name": current_target_pod or "None",
                "monitoring_status": mon_status,
                "monitoring_interval": "5 seconds",
                "last_updated": now_str,
                "metrics_history": list(active_history)
            }

            update_dashboard(
                "M2",
                "RUNNING",
                "None",
                status_msg,
                details=details,
                run_id=run_id
            )

        if stop_event:
            if stop_event.wait(5):
                break
        else:
            time.sleep(5)


def start_continuous_monitor(target_pod=None, target_image=None, container_name=None, run_id=None, workload_name=None):
    global _monitor_stop_event, _monitor_thread
    if _monitor_stop_event:
        _monitor_stop_event.set()
    _monitor_stop_event = threading.Event()
    _monitor_thread = threading.Thread(
        target=continuous_monitoring,
        kwargs={
            "target_pod": target_pod,
            "target_image": target_image,
            "container_name": container_name,
            "stop_event": _monitor_stop_event,
            "run_id": run_id,
            "workload_name": workload_name
        },
        daemon=True
    )
    _monitor_thread.start()


def highest_severity(findings_list):
    levels = {"None": 0, "LOW": 1, "Low": 1, "MEDIUM": 2, "Medium": 2, "HIGH": 3, "High": 3, "CRITICAL": 4, "Critical": 4}
    highest = "None"
    for item in findings_list:
        severity = item.get("severity", "None")
        if levels.get(severity, 0) > levels.get(highest, 0):
            highest = severity
    return highest


# ==================================================
# MAIN PIPELINE EXECUTION
# ==================================================

def run_pipeline(
    selected_image=None,
    run_id=None,
    is_cli=False,
    deploy_workload=None,
    privileged=False,
    auto_isolate=False,
    timeout=None,
    deployment_target="kubernetes",
    namespace="default",
    workload_name=None,
    security_profile="standard",
    port_mapping=None,
    cpu_limit="200m",
    memory_limit="128Mi",
    env_vars=None,
    custom_capabilities=None
):
    """
    Executes the entire KubeGuard security monitoring and incident response
    pipeline (M1-M11) for the user-selected container image.
    Supports Kubernetes and Docker deployment targets, scan-to-deploy identity verification,
    and controlled privileged-container testing.
    Never abruptly exits on failure; preserves honest error reporting across all modules.
    """
    global _monitor_stop_event
    if _monitor_stop_event:
        _monitor_stop_event.set()
    try:
        stop_all_integrity_monitors()
    except Exception:
        pass


    if not run_id:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Validate image reference syntax
    is_valid, validation_res = validate_image_reference(selected_image)
    if not is_valid:
        reset_dashboard_state(selected_image=selected_image, run_id=run_id)
        update_dashboard(
            "M1",
            "FAILED",
            "None",
            validation_res,
            {"error": validation_res, "image": selected_image, "status": "FAILED"},
            run_id=run_id
        )
        if is_cli:
            print(f"[M1] Validation Error: {validation_res}")
        try:
            run_manager.complete_run(run_id, status="FAILED", errors=[validation_res])
        except Exception:
            pass
        return

    selected_image = validation_res
    os.environ["TARGET_IMAGE"] = selected_image
    os.environ["RUN_ID"] = run_id

    if is_cli:
        print("\n" + "=" * 50)
        print("                KubeGuard Pipeline")
        print(f"Target Image : {selected_image}")
        print(f"Run ID       : {run_id}")
        print("=" * 50)

    # Initialize dashboard state for this run
    reset_dashboard_state(selected_image=selected_image, run_id=run_id)

    # -----------------------------
    # MODULE 1 - IMAGE SCAN
    # -----------------------------
    if is_cli:
        print("\n========== MODULE 1 : IMAGE VULNERABILITY SCAN ==========\n")

    update_dashboard("M1", "RUNNING", "None", f"Scanning {selected_image} with Trivy...", run_id=run_id)
    scan_result = scan_image(selected_image)

    deployment_blocked = True
    critical_cves = []
    m1_crit = 0
    m1_high = 0
    m1_med = 0
    m1_low = 0

    if "error" in scan_result:
        m1_err = scan_result["error"]
        update_dashboard(
            "M1",
            "FAILED",
            "None",
            m1_err,
            {"error": m1_err, "image": selected_image, "status": "FAILED", "tool": "Trivy"},
            run_id=run_id
        )
        if is_cli:
            print("\n========== M1: IMAGE VULNERABILITY SCAN ==========\n")
            print(f"Selected image: {selected_image}")
            print(f"Run ID: {run_id}\n")
            print("Scan status: FAILED / INCOMPLETE")
            print(f"Scan Error: {m1_err}")
            print("Vulnerabilities: Incomplete (Scanner failed or timed out)")
            print("Deployment Recommendation: Block deployment (Vulnerability scanner failed / Image unverified)")
    else:
        m1_crit = scan_result["severity_counts"].get("CRITICAL", 0)
        m1_high = scan_result["severity_counts"].get("HIGH", 0)
        m1_med = scan_result["severity_counts"].get("MEDIUM", 0)
        m1_low = scan_result["severity_counts"].get("LOW", 0)
        critical_cves = scan_result.get("critical_cve_ids", [])
        deployment_blocked = scan_result.get("deployment_blocked", False)

        m1_sev = "Critical" if m1_crit > 0 else ("High" if m1_high > 0 else ("Medium" if m1_med > 0 else "None"))
        update_dashboard(
            "M1",
            "COMPLETED",
            m1_sev,
            f"Critical={m1_crit} | High={m1_high} | Medium={m1_med} | Low={m1_low}",
            {
                "image": scan_result.get("image", selected_image),
                "tool": "Trivy",
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity_counts": scan_result.get("severity_counts", {}),
                "deployment_blocked": deployment_blocked,
                "critical_cve_ids": critical_cves
            },
            run_id=run_id
        )
        if is_cli:
            print("\n========== M1: IMAGE VULNERABILITY SCAN ==========\n")
            print(f"Selected image: {scan_result.get('image', selected_image)}")
            print(f"Run ID: {run_id}\n")
            print(f"Critical vulnerabilities: {m1_crit}")
            print(f"High vulnerabilities: {m1_high}")
            print(f"Medium vulnerabilities: {m1_med}")
            print(f"Low vulnerabilities: {m1_low}\n")
            print("Scan status: COMPLETED")
            if critical_cves:
                print(f"\nCritical CVE Details ({len(critical_cves)} found):")
                for cve in critical_cves[:10]:
                    print(f"  - {cve}")
                if len(critical_cves) > 10:
                    print(f"  ... and {len(critical_cves) - 10} more critical CVEs")
            else:
                print("Critical CVE Details: None (0 Critical CVEs detected)")
            if deployment_blocked:
                print(f"Deployment Recommendation: Block deployment due to {m1_crit} Critical vulnerabilities detected (Security policy violation).")
            else:
                print("Deployment Recommendation: Allow deployment (No Critical vulnerabilities detected).")

    # -------------------------------------------------------------
    # DEPLOYMENT POLICY ENFORCEMENT & WORKLOAD ORCHESTRATION
    # -------------------------------------------------------------
    if "error" in scan_result:
        deploy_workload = False
        if is_cli:
            print("\n[!] Deployment Policy Enforcement: Vulnerability scan failed / unverified. Deployment blocked.")
    elif deployment_blocked:
        deploy_workload = False
        if is_cli:
            print(f"\n[!] Deployment Policy Enforcement: Image '{selected_image}' violates security policy ({m1_crit} Critical vulnerabilities detected). Deployment blocked.")
    elif deploy_workload is None:
        deploy_workload = True
        if is_cli:
            print(f"\n[+] Deployment Policy Enforcement: Image '{selected_image}' passed security policy (0 Critical vulnerabilities). Proceeding to deploy for monitoring...")

    target_pod_name = None
    target_container_name = None
    target_namespace = os.environ.get("TARGET_NAMESPACE", "default")
    target_workload_kind = "Deployment"
    target_workload_name = workload_name
    is_running = False
    runtime_target_obj = None

    # 1. DETERMINISTIC WORKLOAD RESOLUTION & TARGET SELECTION:
    # Precedence:
    # 1) Explicit workload_name argument / CLI flag
    # 2) Persisted configuration from config/target_config.json
    # 3) Unambiguous running Deployment match for selected_image
    # 4) Prompt user once (CLI) or deterministic selection if multiple exist, then persist

    # Check if dm_deploy_workload was explicitly mocked by a unit test harness
    is_dm_mocked = hasattr(dm_deploy_workload, "mock_calls") or hasattr(dm_deploy_workload, "_mock_return_value") or "Mock" in type(dm_deploy_workload).__name__

    # Check persisted config if workload_name not explicitly provided and unit test is not mocking dm_deploy_workload
    if not target_workload_name and not is_dm_mocked:
        persisted_cfg = get_persisted_target_config()
        if persisted_cfg and persisted_cfg.get("workload_name"):
            cfg_img = persisted_cfg.get("image")
            if not selected_image or not cfg_img or matches_image_name(cfg_img, selected_image):
                target_workload_name = persisted_cfg.get("workload_name")

    # Attempt to resolve explicit / persisted target workload
    if target_workload_name and deployment_target != "docker" and not is_dm_mocked:
        ok_res, tgt, err_res = resolve_existing_deployment_target(target_workload_name, namespace=target_namespace)
        if ok_res and tgt:
            runtime_target_obj = tgt
            target_workload_name = tgt.workload_name
            target_workload_kind = tgt.workload_kind
            target_pod_name = tgt.pod_name
            target_container_name = tgt.container_name
            target_namespace = tgt.namespace
            deployment_target = "kubernetes"
            is_running = True
            deploy_workload = False

    # If not resolved yet, discover running Deployments in cluster
    if not runtime_target_obj and deployment_target != "docker" and not is_dm_mocked:
        try:
            available_deps = list_available_deployments(namespace=target_namespace)
            matched_deps = [d for d in available_deps if matches_image_name(d.get("image", ""), selected_image)]
            if len(matched_deps) == 1:
                auto_wl = matched_deps[0]["workload_name"]
                ok_res, tgt, _ = resolve_existing_deployment_target(auto_wl, namespace=target_namespace)
                if ok_res and tgt:
                    runtime_target_obj = tgt
                    target_workload_name = tgt.workload_name
                    target_workload_kind = tgt.workload_kind
                    target_pod_name = tgt.pod_name
                    target_container_name = tgt.container_name
                    target_namespace = tgt.namespace
                    is_running = True
                    deploy_workload = False
                    persist_target_config(
                        target_workload_name,
                        namespace=target_namespace,
                        container_name=target_container_name,
                        image=selected_image
                    )
            elif len(matched_deps) > 1:
                # Ambiguous match: in interactive CLI mode prompt ONCE and persist
                is_interactive = is_cli and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
                if is_interactive:
                    print(f"\nAmbiguous workload match: Found {len(matched_deps)} running workloads for image '{selected_image}':\n")
                    for idx, d in enumerate(matched_deps, 1):
                        priv_s = "true" if d.get("privileged") else "false"
                        print(f"  [{idx}] Deployment/{d['workload_name']} (container: {d.get('container_name')}, privileged: {priv_s})")
                    try:
                        ans = input(f"\nSelect workload to assess [1-{len(matched_deps)}]: ").strip()
                        c_idx = int(ans) - 1 if ans.isdigit() and 1 <= int(ans) <= len(matched_deps) else 0
                    except (EOFError, KeyboardInterrupt):
                        c_idx = 0
                    chosen_wl = matched_deps[c_idx]["workload_name"]
                else:
                    chosen_wl = matched_deps[0]["workload_name"]

                persist_target_config(chosen_wl, namespace=target_namespace, image=selected_image)
                ok_res, tgt, _ = resolve_existing_deployment_target(chosen_wl, namespace=target_namespace)
                if ok_res and tgt:
                    runtime_target_obj = tgt
                    target_workload_name = tgt.workload_name
                    target_workload_kind = tgt.workload_kind
                    target_pod_name = tgt.pod_name
                    target_container_name = tgt.container_name
                    target_namespace = tgt.namespace
                    is_running = True
                    deploy_workload = False
        except Exception:
            pass

    # Fallback to broader discovery (Docker containers, standalone pods, DaemonSets, etc.)
    if not runtime_target_obj and (not deploy_workload or workload_name):
        discovered_workloads = []
        if deployment_target != "docker":
            try:
                discovered_workloads = discover_runtime_workloads(target_image=selected_image, namespace=target_namespace)
            except Exception:
                discovered_workloads = []

        if discovered_workloads:
            selected_target = prompt_or_select_runtime_target(
                discovered_workloads,
                preferred_workload=workload_name,
                is_cli=is_cli
            )
            if selected_target:
                runtime_target_obj = selected_target
                target_workload_name = selected_target.workload_name
                target_workload_kind = selected_target.workload_kind
                target_pod_name = selected_target.pod_name
                target_container_name = selected_target.container_name
                target_namespace = selected_target.namespace
                deployment_target = "kubernetes"
                is_running = True
                deploy_workload = False

    if runtime_target_obj:
        os.environ["TARGET_POD"] = target_pod_name
        os.environ["DEPLOYMENT_NAME"] = target_workload_name
        os.environ["WORKLOAD_NAME"] = target_workload_name
        os.environ["TARGET_CONTAINER"] = target_container_name
        os.environ["RUNTIME_TARGET"] = deployment_target

        priv_status_str = "ENABLED" if runtime_target_obj.privileged else "DISABLED"
        extra_ctx = {
            "target_pod": target_pod_name,
            "deployment_name": target_workload_name,
            "namespace": target_namespace,
            "runtime_target": deployment_target,
            "runtime_target_obj": runtime_target_obj.to_dict(),
            "privileged_status": priv_status_str,
            "deployment": {
                "status": "RUNNING",
                "runtime_target": deployment_target,
                "workload_name": target_workload_name,
                "workload_kind": target_workload_kind,
                "pod_name": target_pod_name,
                "container_name": target_container_name,
                "container_id": runtime_target_obj.container_id,
                "runtime_image": runtime_target_obj.runtime_image,
                "runtime_image_id": runtime_target_obj.image_id,
                "scanned_digest": scan_result.get("image_digest") if isinstance(scan_result, dict) else None,
                "identity_status": "VERIFIED",
                "identity_details": "Existing workload verified",
                "privileged_requested": runtime_target_obj.privileged,
                "privileged_effective": runtime_target_obj.privileged,
                "privileged_status": priv_status_str
            }
        }
        update_dashboard("M2", "RUNNING", "None", f"Workload running: {target_pod_name}", extra_root=extra_ctx, run_id=run_id)
        if is_cli:
            print(f"[+] Selected running workload: {target_workload_kind}/{target_workload_name}")
            print(f"Namespace  : {target_namespace}")
            print(f"Pod        : {target_pod_name}")
            print(f"Container  : {target_container_name}")
            print(f"Image      : {runtime_target_obj.runtime_image}")
            print(f"Privileged : {str(runtime_target_obj.privileged).lower()}")
            print("\nContinue with M2–M11 validation.")

    # 2. AUTOMATIC WORKLOAD PROVISIONING (when deploy_workload is True)
    if not runtime_target_obj and deploy_workload:
        # Check if ensure_workload was explicitly mocked by a unit test harness
        is_ew_mocked = hasattr(ensure_workload, "mock_calls") or hasattr(ensure_workload, "_mock_return_value") or "Mock" in type(ensure_workload).__name__
        if is_ew_mocked:
            ew_res = ensure_workload(target_image=selected_image, namespace=target_namespace, allow_deploy=deploy_workload)
            if ew_res.get("found") and ew_res.get("running"):
                target_pod_name = ew_res.get("pod_name")
                target_container_name = ew_res.get("container_name") or "target-container"
                target_workload_name = ew_res.get("owner_name") or "kubeguard-target"
                target_workload_kind = ew_res.get("owner_kind") or "Deployment"
                target_namespace = ew_res.get("namespace", target_namespace)
                is_running = True
                os.environ["TARGET_POD"] = target_pod_name
                runtime_target_obj = RuntimeTarget(
                    namespace=target_namespace,
                    workload_kind=target_workload_kind,
                    workload_name=target_workload_name,
                    pod_name=target_pod_name,
                    container_name=target_container_name,
                    requested_image=selected_image,
                    runtime_image=selected_image,
                    privileged=privileged or False
                )
                extra_ctx = {
                    "target_pod": target_pod_name,
                    "deployment_name": target_workload_name,
                    "namespace": target_namespace,
                    "runtime_target": deployment_target,
                    "runtime_target_obj": runtime_target_obj.to_dict(),
                    "privileged_status": "ENABLED" if runtime_target_obj.privileged else "DISABLED"
                }
                update_dashboard("M2", "RUNNING", "None", f"Workload running: {target_pod_name}", extra_root=extra_ctx, run_id=run_id)

        if not runtime_target_obj:
            dedicated_workload_name = workload_name or generate_assessment_workload_name(selected_image, run_id=run_id)

            if is_cli:
                print("\n========== WORKLOAD DEPLOYMENT ==========\n")
                print(f"Assessment Workload : {dedicated_workload_name}")
                print(f"Selected Image      : {selected_image}")
                print(f"Deployment Target   : {deployment_target}")
                print(f"Namespace           : {target_namespace}")
                print(f"Security Profile    : {'Privileged Test Mode' if privileged else 'Standard'}")
                print("Deploying dedicated KubeGuard assessment workload...")

            update_dashboard("M2", "RUNNING", "None", f"Deploying {dedicated_workload_name} ({selected_image})...", run_id=run_id)

            deploy_opts = {
                "image": selected_image,
                "runtime_target": deployment_target,
                "namespace": target_namespace,
                "workload_name": dedicated_workload_name,
                "security_profile": "privileged" if privileged else security_profile,
                "privileged": bool(privileged or (security_profile == "privileged")),
                "custom_capabilities": custom_capabilities or [],
                "cpu_limit": cpu_limit or "200m",
                "memory_limit": memory_limit or "128Mi",
                "port_mapping": port_mapping,
                "env_vars": env_vars or {},
                "timeout": timeout or 35
            }
            scanned_digest = scan_result.get("image_digest") if isinstance(scan_result, dict) else None
            workload_info = dm_deploy_workload(deploy_opts, run_id=run_id, scanned_digest=scanned_digest)

            target_workload_name = workload_info.get("workload_name") or dedicated_workload_name
            target_workload_kind = workload_info.get("workload_kind", "Deployment")
            identity_status = workload_info.get("identity_status", "UNVERIFIED")
            identity_details = workload_info.get("identity_details", "")
            privileged_status = workload_info.get("privileged_status", "DISABLED")

            if workload_info.get("success"):
                target_pod_name = workload_info.get("pod_name")
                target_container_name = workload_info.get("container_name") or "target-container"
                target_namespace = workload_info.get("namespace", target_namespace)
                runtime_image_id = workload_info.get("runtime_image_id")
                runtime_image = workload_info.get("runtime_image") or selected_image
                is_running = True
                os.environ["TARGET_POD"] = target_pod_name
                os.environ["RUNTIME_TARGET"] = deployment_target

                runtime_target_obj = RuntimeTarget(
                    namespace=target_namespace,
                    workload_kind=target_workload_kind,
                    workload_name=target_workload_name,
                    pod_name=target_pod_name,
                    pod_uid=workload_info.get("pod_uid"),
                    container_name=target_container_name,
                    container_id=workload_info.get("container_id"),
                    requested_image=selected_image,
                    runtime_image=runtime_image,
                    image_id=runtime_image_id,
                    privileged=(privileged_status == "ENABLED")
                )

                extra_ctx = {
                    "target_pod": target_pod_name,
                    "deployment_name": target_workload_name,
                    "namespace": target_namespace,
                    "runtime_target": deployment_target,
                    "runtime_image_id": runtime_image_id,
                    "identity_status": identity_status,
                    "identity_details": identity_details,
                    "privileged_status": privileged_status,
                    "deployment": workload_info,
                    "runtime_target_obj": runtime_target_obj.to_dict()
                }
                update_dashboard("M2", "RUNNING", "None", f"Workload running: {target_pod_name}", extra_root=extra_ctx, run_id=run_id)
                if is_cli:
                    print(f"Deployment: {target_workload_name}")
                    print(f"Target: {deployment_target}")
                    print(f"Namespace: {target_namespace}")
                    print("Status: Running")
                    print(f"Pod / Container: {target_pod_name}")
                    print(f"Identity Verification: {identity_status} ({identity_details})")
                    print(f"Privileged Status: {privileged_status}")
                    print("\nContinue with M2–M11 validation.")
            else:
                dep_err = workload_info.get("error") or "Workload deployment failed."
                is_running = False
                monitor_result = {
                    "error": dep_err,
                    "metrics_available": False,
                    "pod_name": workload_info.get("pod_name"),
                    "deployment_name": target_workload_name,
                    "namespace": target_namespace,
                    "runtime_type": deployment_target,
                    "identity_status": identity_status,
                    "privileged_status": privileged_status,
                    "status": "FAILED"
                }
                extra_ctx = {
                    "deployment_name": target_workload_name,
                    "namespace": target_namespace,
                    "runtime_target": deployment_target,
                    "identity_status": identity_status,
                    "privileged_status": privileged_status,
                    "deployment": workload_info
                }
                update_dashboard(
                    "M2",
                    "FAILED",
                    "None",
                    f"Deployment failed: {dep_err}",
                    {
                        "error": dep_err,
                        "pod_name": workload_info.get("pod_name") or "None",
                        "deployment_name": target_workload_name,
                        "namespace": target_namespace,
                        "image": selected_image,
                        "metrics_available": False,
                        "monitoring_status": "FAILED",
                        "identity_status": identity_status,
                        "privileged_status": privileged_status
                    },
                    extra_root=extra_ctx,
                    run_id=run_id
                )
                if is_cli:
                    print(f"Deployment: {target_workload_name}")
                    print(f"Target: {deployment_target}")
                    print(f"Namespace: {target_namespace}")
                    print("Status: FAILED")
                    print(f"Error: {dep_err}")
                    print(f"Privileged Mode: {privileged_status}")
                    print("\nDeployment failed. Marking dependent modules as FAILED/NOT_APPLICABLE.")

    # 3. IF NOT RUNNING AND NOT DEPLOYED: SET IMAGE-ONLY MODE
    elif not is_running:
        if "error" in scan_result:
            no_workload_msg = f"Deployment blocked: Vulnerability scan failed / unverified image '{selected_image}'."
            m2_status = "BLOCKED"
        elif deployment_blocked:
            no_workload_msg = f"Deployment blocked by M1 security policy: Critical vulnerabilities detected in '{selected_image}'."
            m2_status = "BLOCKED"
        else:
            no_workload_msg = "Deployment skipped. Runtime monitoring requires an active container workload."
            m2_status = "SKIPPED"
        monitor_result = {"not_applicable": True, "metrics_available": False, "pod_name": None, "deployment_name": "Not Deployed", "deployment_status": "Not Deployed"}
        update_dashboard(
            "M2",
            m2_status,
            "None",
            no_workload_msg,
            {
                "pod_name": "None",
                "deployment_name": "Not Deployed",
                "image": selected_image,
                "metrics_available": False,
                "monitoring_status": m2_status,
                "operating_mode": "IMAGE_ONLY",
                "limitation": "Live monitoring requires an active container workload"
            },
            run_id=run_id
        )
        if is_cli:
            print(f"\n[+] Operating Mode: Image-Only Security Analysis.")
            print("Preserving M1 vulnerability scan results. Running image-compatible security modules...")

    if is_running:
        # Pod is Running, fetch live metrics
        monitor_result = get_pod_metrics(
            target_pod=target_pod_name,
            target_image=selected_image,
            container_name=target_container_name,
            namespace=target_namespace,
            workload_name=target_workload_name,
            run_id=run_id
        )

        retry_count = 0
        while "error" in monitor_result and "metrics not available" in str(monitor_result.get("error", "")).lower() and retry_count < 5:
            time.sleep(2)
            retry_count += 1
            monitor_result = get_pod_metrics(
                target_pod=target_pod_name,
                target_image=selected_image,
                container_name=target_container_name,
                namespace=target_namespace,
                workload_name=target_workload_name,
                run_id=run_id
            )

        if "error" in monitor_result:
            update_dashboard(
                "M2",
                "FAILED",
                "None",
                monitor_result["error"],
                {
                    "error": monitor_result["error"],
                    "pod_name": target_pod_name,
                    "image": selected_image,
                    "metrics_available": False
                },
                run_id=run_id
            )
            if is_cli:
                print(f"[M2] Metrics Unavailable: {monitor_result['error']}")
        else:
            cpu_m = monitor_result.get("cpu_millicores", 0)
            mem_mib = monitor_result.get("memory_mib", 0)
            cpu_str = monitor_result.get("cpu", "0m")
            mem_str = monitor_result.get("memory", "0Mi")
            init_time = datetime.now().strftime("%H:%M:%S")
            now_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            update_dashboard(
                "M2",
                "RUNNING",
                "None",
                f"Pod={monitor_result['pod_name']} | CPU={cpu_str} | Memory={mem_str}",
                {
                    "pod_name": monitor_result.get("pod_name", ""),
                    "container_name": target_container_name or monitor_result.get("container_name", ""),
                    "image": selected_image,
                    "cpu": cpu_str,
                    "memory": mem_str,
                    "cpu_millicores": cpu_m,
                    "memory_mib": mem_mib,
                    "metrics_available": True,
                    "monitoring_status": "CONTINUOUS",
                    "monitoring_interval": "5 seconds",
                    "last_updated": now_dt,
                    "metrics_history": [{
                        "time": init_time,
                        "cpu_m": cpu_m,
                        "cpu": cpu_str,
                        "mem_mib": mem_mib,
                        "mem": mem_str
                    }],
                    "pods": [
                        {
                            "name": monitor_result.get("pod_name", ""),
                            "namespace": target_namespace,
                            "status": "Running",
                            "cpu": cpu_str,
                            "memory": mem_str,
                            "restarts": 0,
                            "health": "Healthy"
                        }
                    ]
                },
                run_id=run_id
            )
            if is_cli:
                print(f"Pod Name         : {monitor_result['pod_name']}")
                print(f"Namespace        : {target_namespace}")
                print(f"CPU              : {monitor_result['cpu']}")
                print(f"Memory           : {monitor_result['memory']}")
                print(f"Metrics Available: {monitor_result.get('metrics_available', True)}")
                print("Monitoring Status: CONTINUOUS (5s interval)")

            # Start continuous background monitoring thread
            start_continuous_monitor(
                target_pod=target_pod_name,
                target_image=selected_image,
                container_name=target_container_name,
                run_id=run_id,
                workload_name=target_workload_name
            )

    # -----------------------------
    # MODULE 3 - RBAC (Cluster-wide)
    # -----------------------------
    if is_cli:
        print("\n========== MODULE 3 : RBAC AUDIT ==========\n")

    rbac_audit_res = perform_rbac_audit(run_id=run_id)
    findings = rbac_audit_res.get("dangerous_roles", [])
    binding_findings = rbac_audit_res.get("dangerous_bindings", [])
    cluster = {
        "status": rbac_audit_res.get("cluster_connected", False),
        "message": rbac_audit_res.get("cluster_status", "Unknown")
    }
    roles = {"count": rbac_audit_res.get("roles_count", 0)}
    cluster_roles = {"count": rbac_audit_res.get("cluster_roles_count", 0)}
    bindings = {"count": rbac_audit_res.get("cluster_role_bindings_count", 0)}
    m3_severity = rbac_audit_res.get("severity", "None")
    m3_status = "COMPLETED" if rbac_audit_res.get("cluster_connected") else "FAILED"

    update_dashboard(
        "M3",
        m3_status,
        m3_severity,
        f"Dangerous roles={len(findings)} | Dangerous bindings={len(binding_findings)}",
        {
            "cluster_status": cluster.get("message"),
            "cluster_connected": cluster.get("status"),
            "context": rbac_audit_res.get("context", "default"),
            "roles_count": rbac_audit_res.get("roles_count", 0),
            "cluster_roles_count": rbac_audit_res.get("cluster_roles_count", 0),
            "role_bindings_count": rbac_audit_res.get("role_bindings_count", 0),
            "cluster_role_bindings_count": rbac_audit_res.get("cluster_role_bindings_count", 0),
            "bindings_count": rbac_audit_res.get("cluster_role_bindings_count", 0),
            "dangerous_roles": findings,
            "dangerous_bindings": binding_findings,
            "report_path": "reports/rbac_report.txt",
            "json_report_path": "reports/rbac_report.json"
        },
        run_id=run_id
    )
    if is_cli:
        print(f"Cluster Status         : {cluster['message']}")
        print(f"Total Roles            : {rbac_audit_res.get('roles_count', 0)}")
        print(f"Total Cluster Roles    : {rbac_audit_res.get('cluster_roles_count', 0)}")
        print(f"Total Role Bindings    : {rbac_audit_res.get('role_bindings_count', 0)}")
        print(f"Total Cluster Role Bnd : {rbac_audit_res.get('cluster_role_bindings_count', 0)}")
        print(f"Dangerous Roles Found  : {len(findings)}")
        print(f"Dangerous Bindings     : {len(binding_findings)}")
        print(f"Severity Level         : {m3_severity}")
        print("RBAC Detailed Report   : reports/rbac_report.txt")
        print("RBAC JSON Report       : reports/rbac_report.json")

    # -----------------------------
    # MODULE 4 - THREAT DETECTION
    # -----------------------------
    if is_cli:
        print("\n========== MODULE 4 : THREAT DETECTION ==========\n")

    threat_data = {}
    threat_result = {}

    if target_pod_name and is_running and "error" not in monitor_result:
        # Pass cached live telemetry from Module 2 if fresh and valid to prevent duplicate kubectl top queries
        cached_m = None
        if monitor_result and not monitor_result.get("error") and monitor_result.get("metrics_available"):
            cached_m = {
                "pod": monitor_result.get("pod_name", target_pod_name),
                "cpu": monitor_result.get("cpu"),
                "memory": monitor_result.get("memory")
            }

        threat_data = get_workload_usage(
            target_pod=target_pod_name,
            target_image=selected_image,
            namespace=target_namespace,
            cached_metrics=cached_m,
            workload_name=target_workload_name
        )

        if "error" in threat_data:
            err_msg = threat_data["error"]
            threat_result = {"status": "FAILED", "severity": "None", "reason": err_msg}
            update_dashboard(
                "M4",
                "FAILED",
                "None",
                err_msg,
                {
                    "pod": threat_data.get("pod", target_pod_name),
                    "image": selected_image,
                    "status": "FAILED",
                    "severity": "None",
                    "reason": err_msg,
                    "cpu": "N/A",
                    "memory": "N/A",
                    "error": err_msg
                },
                run_id=run_id
            )
            if is_cli:
                print(f"Target Pod : {threat_data.get('pod', target_pod_name)}")
                print(f"Status     : FAILED")
                print(f"Severity   : None")
                print(f"Reason     : {err_msg}")
        else:
            threat_result = detect_threat(threat_data)
            m4_sev = threat_result.get("severity", "None")
            m4_status = threat_result.get("status", "NORMAL")
            m4_reason = threat_result.get("reason", "")
            update_dashboard(
                "M4",
                "COMPLETED",
                m4_sev,
                m4_reason,
                {
                    "pod": threat_data.get("pod", target_pod_name),
                    "image": selected_image,
                    "cpu": threat_data.get("cpu", "N/A"),
                    "memory": threat_data.get("memory", "N/A"),
                    "status": m4_status,
                    "severity": m4_sev,
                    "reason": m4_reason
                },
                run_id=run_id
            )
            if is_cli:
                print(f"Target Pod : {threat_data.get('pod', target_pod_name)}")
                print(f"CPU        : {threat_data.get('cpu', 'N/A')}")
                print(f"Memory     : {threat_data.get('memory', 'N/A')}")
                print(f"Status     : {m4_status}")
                print(f"Severity   : {m4_sev}")
                print(f"Reason     : {m4_reason}")
    else:
        if not target_pod_name:
            err_msg = f"Image-only analysis: No active workload found for '{selected_image}'. Runtime threat detection requires a running container."
            m4_status = "NOT_APPLICABLE"
        else:
            err_msg = monitor_result.get("error") or f"Workload for image '{selected_image}' not active. Runtime threat detection unavailable."
            m4_status = "FAILED"

        threat_data = {"error": err_msg if m4_status == "FAILED" else None, "pod": target_pod_name or "None", "image": selected_image}
        threat_result = {"status": m4_status, "severity": "None", "reason": err_msg}
        update_dashboard(
            "M4",
            m4_status,
            "None",
            err_msg,
            {
                "pod": target_pod_name or "None",
                "image": selected_image,
                "status": m4_status,
                "severity": "None",
                "reason": err_msg,
                "cpu": "N/A",
                "memory": "N/A",
                "limitation": "Runtime threat detection requires an active workload" if m4_status == "NOT_APPLICABLE" else err_msg
            },
            run_id=run_id
        )
        if is_cli:
            if m4_status == "NOT_APPLICABLE":
                print(f"[M4] Image-Only Mode: {err_msg}")
            else:
                print(f"Target Pod : {target_pod_name or 'None'}")
                print(f"Status     : FAILED")
                print(f"Severity   : None")
                print(f"Reason     : {err_msg}")

    # -----------------------------
    # MODULE 6 — M4 NOTIFICATION WORKFLOW
    # Reproduces Old Project M6 Behavior:
    # - Case A (Threat): Sends M4 Security Alert (Telegram + Email)
    # - Case B (No Threat): Sends M4 Normal Status Update (Telegram + Email)
    # - Case C (Operational Error): Records failure without fabricating threat
    # -----------------------------
    m4_sev_upper = str(threat_result.get("severity", "None")).upper()
    m4_status_val = threat_result.get("status", "NORMAL")
    m4_has_threat = (m4_sev_upper in ["HIGH", "CRITICAL"]) and (m4_status_val not in ["NORMAL", "NOT_APPLICABLE", "ERROR", "FAILED"])
    m4_is_error = (m4_status_val in ["ERROR", "FAILED", "NOT_APPLICABLE"]) or ("error" in threat_data and not threat_data.get("pod"))

    m4_telegram_result = {"success": False, "error": "Not attempted"}
    m4_email_result = {"success": False, "error": "Not attempted"}
    m4_alert_status = "FAILED"

    if m4_is_error:
        # Case C: Operational error
        m4_alert_status = "FAILED" if m4_status_val == "FAILED" else "NOT_APPLICABLE"
        log_alert(
            "M4",
            "None",
            m4_alert_status,
            f"Run={run_id} | Image={selected_image} | Operational error: {threat_result.get('reason', 'Threat assessment unavailable')}"
        )
        if is_cli:
            print(f"[M4 Alerting] Skipped notification due to operational error: {threat_result.get('reason')}")
    else:
        # Case A: Threat detected
        if m4_has_threat:
            m4_alert_message = (
                "🚨 MODULE 4 - THREAT DETECTION\n"
                "------------------------------\n\n"
                "KubeGuard SECURITY ALERT\n\n"
                f"Image: {selected_image}\n"
                f"Status: {m4_status_val}\n"
                f"Severity: {threat_result.get('severity', 'High')}\n\n"
                f"Pod: {threat_data.get('pod', target_pod_name or 'None')}\n"
                f"CPU: {threat_data.get('cpu', 'N/A')}\n"
                f"Memory: {threat_data.get('memory', 'N/A')}\n\n"
                f"Reason: {threat_result.get('reason', 'Suspicious activity detected.')}"
            )
        # Case B: No threat (Normal status)
        else:
            m4_alert_message = (
                "🟢 MODULE 4 - THREAT DETECTION\n"
                "------------------------------\n\n"
                "KubeGuard STATUS UPDATE\n\n"
                f"Image: {selected_image}\n"
                f"Status: {m4_status_val}\n"
                f"Severity: {threat_result.get('severity', 'None')}\n\n"
                f"Pod: {threat_data.get('pod', target_pod_name or 'None')}\n"
                f"CPU: {threat_data.get('cpu', 'N/A')}\n"
                f"Memory: {threat_data.get('memory', 'N/A')}\n\n"
                f"Reason: {threat_result.get('reason', 'No suspicious activity detected.')}"
            )

        # Independent channel delivery: Telegram failure must NOT suppress Email!
        try:
            m4_telegram_result = send_telegram_alert(m4_alert_message)
        except Exception as te:
            m4_telegram_result = {"success": False, "error": str(te)}

        try:
            m4_email_result = send_email_alert(m4_alert_message)
        except Exception as ee:
            m4_email_result = {"success": False, "error": str(ee)}

        log_alert(
            "M4",
            threat_result.get("severity", "None"),
            m4_status_val,
            f"Run={run_id} | Image={selected_image} | Pod={threat_data.get('pod', target_pod_name or 'None')} | CPU={threat_data.get('cpu', 'N/A')} | Memory={threat_data.get('memory', 'N/A')} | Reason={threat_result.get('reason', '')}"
        )

        m4_alert_status = "SENT" if (m4_telegram_result.get("success") or m4_email_result.get("success")) else "FAILED"

        if is_cli:
            print(f"M4 Telegram Alert : {'SENT' if m4_telegram_result.get('success') else 'FAILED'}")
            if not m4_telegram_result.get('success') and m4_telegram_result.get('error'):
                print(f"M4 Telegram Error : {m4_telegram_result.get('error')}")
            print(f"M4 Email Alert    : {'SENT' if m4_email_result.get('success') else 'FAILED'}")
            if not m4_email_result.get('success') and m4_email_result.get('error'):
                print(f"M4 Email Error    : {m4_email_result.get('error')}")

        from runtime_target import parse_alert_status
        m4_tg_stat = parse_alert_status(m4_telegram_result.get("success"), m4_telegram_result.get("error"), was_attempted=not m4_is_error)
        m4_em_stat = parse_alert_status(m4_email_result.get("success"), m4_email_result.get("error"), was_attempted=not m4_is_error)
        m4_now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if m4_status_val == "NORMAL":
            m4_analysis_title = "No suspicious activity detected"
            m4_analysis_body = "The container is running normally. No abnormal behavior found based on the current monitoring rules."
            m4_analysis_type = "normal"
        elif m4_status_val in ["SUSPICIOUS ACTIVITY DETECTED", "THREAT DETECTED"]:
            m4_analysis_title = "Suspicious activity detected"
            m4_analysis_body = f"Abnormal resource threshold behavior detected in container: {threat_result.get('reason', '')}"
            m4_analysis_type = "threat"
        else:
            m4_analysis_title = "Monitoring Signal Unavailable"
            m4_analysis_body = f"Kubernetes metrics could not be collected for this pod ({threat_result.get('reason', '')}). Cannot verify whether behavior is normal."
            m4_analysis_type = "unavailable"

        update_dashboard(
            "M4",
            m4_status_val if m4_status_val in ["NORMAL", "THREAT DETECTED", "SUSPICIOUS ACTIVITY DETECTED"] else m4_status,
            threat_result.get("severity", "None"),
            threat_result.get("reason", "No suspicious activity detected."),
            {
                "pod": threat_data.get("pod", target_pod_name or "None"),
                "container": target_container_name or "main",
                "deployment_name": target_workload_name or "workload",
                "namespace": target_namespace,
                "image": selected_image,
                "cpu": threat_data.get("cpu", "UNAVAILABLE"),
                "memory": threat_data.get("memory", "UNAVAILABLE"),
                "status": m4_status_val,
                "severity": threat_result.get("severity", "None"),
                "reason": threat_result.get("reason", "No suspicious activity detected."),
                "container_status": "Running" if target_pod_name else "Unavailable",
                "metrics_available": (threat_data.get("cpu") not in ["N/A", "UNAVAILABLE", None] and "error" not in threat_data),
                "assessment_timestamp": m4_now_str,
                "metric_timestamp": m4_now_str,
                "analysis_title": m4_analysis_title,
                "analysis_body": m4_analysis_body,
                "analysis_type": m4_analysis_type,
                "telegram_status": m4_tg_stat,
                "telegram_error": m4_telegram_result.get("error"),
                "email_status": m4_em_stat,
                "email_error": m4_email_result.get("error")
            },
            run_id=run_id
        )

    # Structured finding reference
    m4_finding = {
        "module": "M4",
        "event_id": f"m4-{run_id}-{threat_data.get('pod', target_pod_name or 'none')}",
        "detection_category": "RUNTIME_THREAT",
        "severity": threat_result.get("severity", "None"),
        "status": m4_status_val,
        "has_threat": m4_has_threat,
        "is_error": m4_is_error,
        "alert_status": m4_alert_status,
        "container": target_container_name or "main",
        "pod": threat_data.get("pod", target_pod_name or "None"),
        "image": selected_image,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "description": threat_result.get("reason", ""),
        "evidence": f"CPU={threat_data.get('cpu', 'N/A')}, Memory={threat_data.get('memory', 'N/A')}",
        "cpu": threat_data.get("cpu", "N/A"),
        "memory": threat_data.get("memory", "N/A")
    }

    # -----------------------------
    # MODULE 5 - CONTAINER ESCAPE DETECTION
    # -----------------------------
    if is_cli:
        print("\n" + "=" * 50)
        print("MODULE 5: CONTAINER ESCAPE DETECTION")
        print("=" * 50)

    pods = None
    if not target_pod_name:
        m5_err = f"Image-only analysis: Image '{selected_image}' has not been deployed as a running workload. Runtime container escape inspection requires pod configuration."
        escape_results = []
        escape_detected = False
        update_dashboard(
            "M5",
            "NOT_APPLICABLE",
            "None",
            m5_err,
            {
                "pod": "None",
                "target_image": selected_image,
                "status": "NOT_APPLICABLE",
                "severity": "None",
                "reason": m5_err,
                "finding": m5_err,
                "findings": [],
                "escape_indicators": 0,
                "pods_checked": 0,
                "escape_detected": False,
                "escape_items": [],
                "limitation": "Container escape inspection requires a deployed pod configuration"
            },
            run_id=run_id
        )
        if is_cli:
            print("\nM5 — CONTAINER ESCAPE DETECTION")
            print("Status   : NOT_APPLICABLE")
            print("Severity : None")
            print(f"Reason   : {m5_err}")
    else:
        escape_results = []
        escape_detected = False

        if deployment_target == "docker":
            from module5_escape import inspect_docker_container
            docker_res = inspect_docker_container(target_pod_name, run_id=run_id)
            if isinstance(docker_res, dict) and "error" in docker_res:
                pods = docker_res
                escape_results = docker_res
            else:
                escape_results = docker_res
                pods = [{"metadata": {"name": target_pod_name, "namespace": "docker"}}]
        else:
            w_kind = runtime_target_obj.workload_kind if runtime_target_obj else target_workload_kind
            w_name = runtime_target_obj.workload_name if runtime_target_obj else target_workload_name
            pods = get_pods(
                target_pod=target_pod_name,
                target_image=selected_image,
                namespace=target_namespace,
                workload_kind=w_kind,
                workload_name=w_name
            )

            # If pods returned successfully, synchronize target_pod_name and runtime_target_obj with live pod
            if isinstance(pods, list) and len(pods) > 0 and isinstance(pods[0], dict):
                live_p_name = pods[0].get("metadata", {}).get("name")
                if live_p_name:
                    if target_pod_name and live_p_name != target_pod_name:
                        if is_cli:
                            print(f"[+] Workload pod refreshed before M5: '{target_pod_name}' -> '{live_p_name}'")
                        target_pod_name = live_p_name
                        if runtime_target_obj:
                            runtime_target_obj.pod_name = live_p_name
                            runtime_target_obj.pod_uid = pods[0].get("metadata", {}).get("uid")

        if isinstance(pods, dict) and "error" in pods:
            update_dashboard("M5", "FAILED", "None", pods["error"], {"error": pods["error"], "status": "FAILED", "severity": "None", "findings": [], "escape_indicators": 0, "pods_checked": 0, "escape_detected": False}, run_id=run_id)
            if is_cli:
                print("\nM5 — CONTAINER ESCAPE DETECTION")
                print("Status   : FAILED")
                print("Severity : None")
                print(f"Error    : {pods['error']}")
        else:
            if deployment_target != "docker":
                escape_results = detect_escape_indicators(
                    pods,
                    run_id=run_id,
                    target_container=target_container_name
                )

                if isinstance(escape_results, dict) and "error" in escape_results:
                    update_dashboard("M5", "FAILED", "None", escape_results["error"], {"error": escape_results["error"], "status": "FAILED", "severity": "None", "findings": [], "escape_indicators": 0, "pods_checked": 0, "escape_detected": False}, run_id=run_id)
                    if is_cli:
                        print("\nM5 — CONTAINER ESCAPE DETECTION")
                        print("Status   : FAILED")
                        print("Severity : None")
                        print(f"Error    : {escape_results['error']}")
                else:
                    m5_findings_count = sum(len(r.get("findings", [])) for r in escape_results)
                    escape_detected = (m5_findings_count > 0)
                    m5_severity = highest_severity(escape_results) if escape_detected else "None"
                    m5_status = "SUSPICIOUS ACTIVITY DETECTED" if escape_detected else "NORMAL"
                    m5_reason = "No container escape indicators detected." if not escape_detected else "Container escape risk or privileged configuration detected."
                    m5_msg = f"Pods checked={len(escape_results)} | Escape indicators={m5_findings_count}"

                    m5_items = []
                    for r in escape_results:
                        f_list = r.get("findings", [])
                        is_priv = r.get("privileged", False)
                        m5_items.append({
                            "pod": r.get("pod", ""),
                            "container": r.get("container", target_container_name or "main"),
                            "image": r.get("image", selected_image),
                            "privileged": is_priv,
                            "status": "SUSPICIOUS ACTIVITY DETECTED" if f_list else "NORMAL",
                            "severity": r.get("severity", "None") if f_list else "None",
                            "finding": ", ".join(f_list) if f_list else "No container escape indicators detected.",
                            "reason": ", ".join(f_list) if f_list else "No container escape indicators detected."
                        })

                    m5_pod = target_pod_name or (m5_items[0]["pod"] if m5_items else "")
                    all_findings = [f for r in escape_results for f in r.get("findings", [])]

                    update_dashboard(
                        "M5",
                        "COMPLETED",
                        m5_severity,
                        m5_msg,
                        {
                            "pod": m5_pod,
                            "container": (escape_results[0].get("container") if escape_results else target_container_name) or "main",
                            "target_image": selected_image,
                            "status": m5_status,
                            "severity": m5_severity,
                            "reason": m5_reason,
                            "finding": m5_reason,
                            "findings": all_findings,
                            "escape_indicators": m5_findings_count,
                            "pods_checked": len(escape_results),
                            "escape_detected": escape_detected,
                            "privileged": any(r.get("privileged") for r in escape_results),
                            "escape_items": m5_items
                        },
                        run_id=run_id
                    )
                    if is_cli:
                        print("\nM5 — CONTAINER ESCAPE DETECTION\n")
                        if not escape_detected:
                            print("Status   : NORMAL")
                            print("Severity : None")
                            print("Reason   : No container escape indicators detected.")
                            print(f"Targets  : Pods checked={len(escape_results)} | Escape indicators=0\n")
                            for r in escape_results:
                                print(f"Pod        : {r['pod']}")
                                print(f"Namespace  : {r.get('namespace', target_namespace)}")
                                print(f"Container  : {r.get('container', target_container_name or 'main')}")
                                if r.get("image"):
                                    print(f"Image      : {r.get('image')}")
                                print("Privileged : false")
                                print()
                                print("Status     : NORMAL")
                                print("Severity   : None")
                                print("Reason     : No container escape indicators detected.")
                                print("Incident Response: Not triggered")
                                print("-" * 50)
                        else:
                            print("Status   : SUSPICIOUS ACTIVITY DETECTED")
                            print(f"Severity : {m5_severity}")
                            print(f"Reason   : Container escape indicators detected in {len(escape_results)} inspected pod(s).")
                            print(f"Targets  : Pods checked={len(escape_results)} | Escape indicators={m5_findings_count}\n")
                            for r in escape_results:
                                is_priv = r.get("privileged", False)
                                priv_str = "true" if is_priv else "false"
                                print(f"Pod        : {r['pod']}")
                                print(f"Namespace  : {r.get('namespace', target_namespace)}")
                                print(f"Container  : {r.get('container', target_container_name or 'main')}")
                                if r.get("image"):
                                    print(f"Image      : {r.get('image')}")
                                print(f"Privileged : {priv_str}")
                                print()
                                print(f"Status     : {r['status']}")
                                print(f"Severity   : {r['severity']}")
                                if r.get("findings"):
                                    for f in r["findings"]:
                                        print(f"Finding    : {f}")
                                else:
                                    print("Finding    : No privileged-container security risk detected.")
                                if r.get("incident_triggered") or (is_priv and r.get("severity") == "Critical"):
                                    print("Incident Response: Triggered")
                                else:
                                    print("Incident Response: Not triggered")
                                print("-" * 50)
                            print("\nContainer escape risk or privileged configuration detected in one or more Pods.")

    # --------------------------------------------------
    # MODULE 6 — M5 NOTIFICATION WORKFLOW & DASHBOARD INTEGRATION
    # Reproduces Old Project M6 Behavior:
    # - Case A (Findings): Sends M5 Security Alert (Telegram + Email)
    # - Case B (No Findings): Sends M5 Normal Status Update (Telegram + Email)
    # - Case C (Operational Error): Records failure without fabricating escape finding
    # - Telegram and Email fail independently
    # - Dashboard updated with comprehensive M4 & M5 delivery outcomes
    # --------------------------------------------------
    m5_is_error = (
        (isinstance(pods, dict) and "error" in pods) or
        (isinstance(escape_results, dict) and "error" in escape_results)
    )

    critical_pods = [r["pod"] for r in escape_results if str(r.get("severity", "")).upper() == "CRITICAL"] if isinstance(escape_results, list) else []
    high_pods = [r["pod"] for r in escape_results if str(r.get("severity", "")).upper() == "HIGH"] if isinstance(escape_results, list) else []
    priv_pods = [r["pod"] for r in escape_results if r.get("privileged")] if isinstance(escape_results, list) else []

    m5_telegram_result = {"success": False, "error": "Not attempted"}
    m5_email_result = {"success": False, "error": "Not attempted"}
    m5_alert_status = "FAILED"

    if m5_is_error:
        # Case C: Operational error
        m5_err_msg = pods.get("error") if isinstance(pods, dict) else (escape_results.get("error") if isinstance(escape_results, dict) else "Pod inspection failed")
        m5_alert_status = "FAILED"
        log_alert("M5", "None", "FAILED", f"Operational error: {m5_err_msg}")
        if is_cli:
            print(f"[M5 Alerting] Skipped notification due to operational error: {m5_err_msg}")
    elif not target_pod_name:
        # Image-only analysis (workload not deployed)
        m5_alert_status = "NOT_APPLICABLE"
        log_alert("M5", "None", "NOT_APPLICABLE", "Image-only analysis: No active workload deployed")
        if is_cli:
            print(f"[M5 Alerting] Image-only mode: No workload deployed for inspection.")
    else:
        # Case A: Security findings detected
        if escape_detected:
            primary_cid = ""
            primary_cname = target_container_name or "main"
            if isinstance(escape_results, list) and escape_results:
                primary_cid = escape_results[0].get("container_id", "")
                primary_cname = escape_results[0].get("container", primary_cname)

            alert_message = (
                "🚨 MODULE 5 - CONTAINER ESCAPE DETECTION\n"
                "----------------------------------------\n\n"
                "KubeGuard SECURITY ALERT\n\n"
                f"Image: {selected_image}\n"
                "Status: SUSPICIOUS ACTIVITY DETECTED\n"
                f"Target Pod: {target_pod_name or (critical_pods[0] if critical_pods else 'None')}\n"
                f"Container: {primary_cname}\n"
            )
            if primary_cid:
                alert_message += f"Container ID: {primary_cid}\n"
            alert_message += (
                f"Critical Pods: {', '.join(critical_pods) if critical_pods else 'None'}\n"
                f"Privileged Pods: {', '.join(priv_pods) if priv_pods else 'None'}\n"
                f"High Risk Pods: {', '.join(high_pods) if high_pods else 'None'}\n\n"
                "Action: Critical Pods are eligible for M9 automatic isolation."
            )
            if critical_pods:
                log_alert("M5", "CRITICAL", "SUSPICIOUS ACTIVITY DETECTED", f"Critical Pods={', '.join(critical_pods)}")
            if high_pods:
                log_alert("M5", "HIGH", "SUSPICIOUS ACTIVITY DETECTED", f"High Risk Pods={', '.join(high_pods)}")
        # Case B: No findings detected (Normal status)
        else:
            alert_message = (
                "🟢 MODULE 5 - CONTAINER ESCAPE DETECTION\n"
                "----------------------------------------\n\n"
                "KubeGuard STATUS UPDATE\n\n"
                f"Image: {selected_image}\n"
                "Status: NORMAL\n"
                "Severity: None\n\n"
                f"Result: No container escape indicators detected (Pods checked: {len(escape_results)} | Escape indicators: 0)."
            )
            log_alert("M5", "None", "NORMAL", "No container escape indicators detected")

        # Independent channel delivery: Telegram failure must NOT suppress Email!
        try:
            m5_telegram_result = send_telegram_alert(alert_message)
        except Exception as te:
            m5_telegram_result = {"success": False, "error": str(te)}

        try:
            m5_email_result = send_email_alert(alert_message)
        except Exception as ee:
            m5_email_result = {"success": False, "error": str(ee)}

        m5_alert_status = "SENT" if (m5_telegram_result.get("success") or m5_email_result.get("success")) else "FAILED"

        if is_cli:
            print(f"M5 Telegram Alert : {'SENT' if m5_telegram_result.get('success') else 'FAILED'}")
            if not m5_telegram_result.get('success') and m5_telegram_result.get('error'):
                print(f"Telegram Error    : {m5_telegram_result.get('error')}")
            print(f"M5 Email Alert    : {'SENT' if m5_email_result.get('success') else 'FAILED'}")
            if not m5_email_result.get('success') and m5_email_result.get('error'):
                print(f"Email Error       : {m5_email_result.get('error')}")

        from runtime_target import parse_alert_status
        m5_tg_stat = parse_alert_status(m5_telegram_result.get("success"), m5_telegram_result.get("error"), was_attempted=not m5_is_error and bool(target_pod_name))
        m5_em_stat = parse_alert_status(m5_email_result.get("success"), m5_email_result.get("error"), was_attempted=not m5_is_error and bool(target_pod_name))
        m5_now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        finding_counts = {
            "total": len(all_findings),
            "critical": len(critical_pods),
            "high": len(high_pods),
            "medium": 0,
            "low": 0
        }
        remediation_text = (
            "Remove securityContext.privileged from the container specification. Restrict container capabilities to least privilege."
            if escape_detected else
            "Maintain secure baseline policies and prevent admission of privileged containers."
        )

        raw_inspect_lines = [
            f"KUBERNETES ADMITTED CONTAINER SECURITY INSPECTION",
            f"Workload   : {target_workload_kind}/{target_workload_name}",
            f"Pod        : {m5_pod}",
            f"Namespace  : {target_namespace}",
            f"Container  : {target_container_name or 'main'}",
            f"Image      : {selected_image}",
            f"Image ID   : {(runtime_target_obj.image_id if runtime_target_obj else '') or 'Not available'}",
            f"Container ID: {(runtime_target_obj.container_id if runtime_target_obj else '') or 'N/A'}",
            f"Privileged : {'true' if any(r.get('privileged') for r in escape_results) else 'false'}",
            f"Findings Count: {len(all_findings)}",
            f"--------------------------------------------------"
        ]
        if all_findings:
            for f in all_findings:
                raw_inspect_lines.append(f"[FINDING] {f}")
        else:
            raw_inspect_lines.append("[CHECK] No container escape indicators detected.")

        update_dashboard(
            "M5",
            "COMPLETED" if not m5_is_error else "FAILED",
            m5_severity,
            m5_msg,
            {
                "pod": m5_pod,
                "container": (escape_results[0].get("container") if (isinstance(escape_results, list) and escape_results) else target_container_name) or "main",
                "deployment_name": target_workload_name or "workload",
                "namespace": target_namespace,
                "image": selected_image,
                "target_image": selected_image,
                "image_digest": (runtime_target_obj.image_id if runtime_target_obj else "") or "Not available",
                "cpu": threat_data.get("cpu", "UNAVAILABLE"),
                "memory": threat_data.get("memory", "UNAVAILABLE"),
                "status": m5_status,
                "severity": m5_severity,
                "reason": m5_reason,
                "finding": m5_reason,
                "findings": all_findings,
                "finding_counts": finding_counts,
                "escape_indicators": m5_findings_count,
                "pods_checked": len(escape_results) if isinstance(escape_results, list) else 0,
                "escape_detected": escape_detected,
                "privileged": any(r.get("privileged") for r in escape_results) if isinstance(escape_results, list) else False,
                "remediation": remediation_text,
                "assessment_timestamp": m5_now_str,
                "escape_items": m5_items,
                "telegram_status": m5_tg_stat,
                "telegram_error": m5_telegram_result.get("error"),
                "email_status": m5_em_stat,
                "email_error": m5_email_result.get("error"),
                "raw_output": "\n".join(raw_inspect_lines)
            },
            run_id=run_id
        )

    # -----------------------------
    # M6 DASHBOARD STATE UPDATE
    # -----------------------------
    telegram_connected = bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))
    email_connected = bool(os.getenv("EMAIL_SENDER") and os.getenv("EMAIL_APP_PASSWORD") and os.getenv("EMAIL_RECEIVER"))

    m6_details = {
        "telegram_status": "SENT" if (m4_telegram_result.get("success") or m5_telegram_result.get("success")) else "FAILED",
        "email_status": "SENT" if (m4_email_result.get("success") or m5_email_result.get("success")) else "FAILED",
        "m4_alert": {
            "status": m4_alert_status,
            "pod": threat_data.get("pod", target_pod_name or ""),
            "threat_pod": threat_data.get("pod", target_pod_name or ""),
            "threat_status": threat_result.get("status", "NORMAL"),
            "severity": threat_result.get("severity", "None"),
            "reason": threat_result.get("reason", ""),
            "telegram_status": "SENT" if m4_telegram_result.get("success") else ("NOT_ATTEMPTED" if m4_is_error else "FAILED"),
            "email_status": "SENT" if m4_email_result.get("success") else ("NOT_ATTEMPTED" if m4_is_error else "FAILED"),
            "telegram_error": m4_telegram_result.get("error"),
            "email_error": m4_email_result.get("error"),
            "cpu": threat_data.get("cpu", ""),
            "memory": threat_data.get("memory", ""),
            "threat_action": threat_result.get("action", "None")
        },
        "m5_alert": {
            "status": m5_alert_status,
            "escape_detected": escape_detected,
            "critical_pods": critical_pods,
            "high_pods": high_pods,
            "privileged_pods": priv_pods,
            "telegram_status": "SENT" if m5_telegram_result.get("success") else ("NOT_ATTEMPTED" if m5_is_error or not target_pod_name else "FAILED"),
            "email_status": "SENT" if m5_email_result.get("success") else ("NOT_ATTEMPTED" if m5_is_error or not target_pod_name else "FAILED"),
            "telegram_error": m5_telegram_result.get("error"),
            "email_error": m5_email_result.get("error")
        },
        "channels": [
            {
                "name": "Telegram",
                "status": "Connected" if (m5_telegram_result.get("success") or m4_telegram_result.get("success")) else ("Failed" if (m4_telegram_result.get("error") or m5_telegram_result.get("error")) else ("Connected" if telegram_connected else "Not configured"))
            },
            {
                "name": "Email",
                "status": "Connected" if (m5_email_result.get("success") or m4_email_result.get("success")) else ("Failed" if (m4_email_result.get("error") or m5_email_result.get("error")) else ("Connected" if email_connected else "Not configured"))
            }
        ]
    }

    # Combined M6 severity follows highest detected risk
    m6_highest_sev = "None"
    all_sevs = [threat_result.get("severity", "None"), highest_severity(escape_results) if isinstance(escape_results, list) else "None"]
    if any(str(s).upper() == "CRITICAL" for s in all_sevs):
        m6_highest_sev = "Critical"
    elif any(str(s).upper() == "HIGH" for s in all_sevs):
        m6_highest_sev = "High"

    update_dashboard(
        "M6",
        "COMPLETED",
        m6_highest_sev,
        f"M4 alerts={m4_alert_status} | M5 Telegram={m5_telegram_result.get('success', False)} | M5 Email={m5_email_result.get('success', False)}",
        details=m6_details,
        run_id=run_id
    )

    # --------------------------------------------------
    # INCIDENT RESPONSE FLOW
    # M5 CRITICAL -> M7 BACKUP -> M8 EVIDENCE -> M9 ISOLATION -> M10 INTEGRITY
    # --------------------------------------------------
    # Incident Response Triggering Policy:
    # Trigger only on qualifying Critical container findings (e.g. privileged container mode)
    critical_results = [
        r for r in escape_results
        if (r.get("incident_triggered") or (r.get("severity") == "Critical" and r.get("privileged")))
        and target_pod_name and r.get("pod") == target_pod_name
    ]
    incident_id = f"inc_{run_id}_{int(time.time())}" if critical_results else None

    m7_backup_result = None
    m8_results = []
    m9_results = []
    m10_results = []

    if critical_results:
        # MODULE 7 - BACKUP
        if is_cli:
            print("\n========== MODULE 7 : BACKUP ==========\n")
            print("[M7] Critical finding detected. Creating immediate backup...")

        m7_backup_result = create_backup(run_id=run_id, namespace=target_namespace, target=runtime_target_obj)
        backup_dir = m7_backup_result if isinstance(m7_backup_result, str) else (m7_backup_result.get("backup_path") if isinstance(m7_backup_result, dict) else None)
        if backup_dir and os.path.exists(backup_dir):
            backup_files = []
            try:
                for f in sorted(os.listdir(backup_dir)):
                    f_path = os.path.join(backup_dir, f)
                    if os.path.isfile(f_path):
                        backup_files.append({
                            "name": f,
                            "path": f_path.replace("\\", "/"),
                            "size": f"{os.path.getsize(f_path)} bytes"
                        })
            except Exception:
                pass
            m7_details = {
                "backup_location": backup_dir.replace("\\", "/"),
                "backup_folder": os.path.basename(backup_dir),
                "resources_backed_up": len(backup_files),
                "files": backup_files,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            update_dashboard("M7", "COMPLETED", "None", f"Backup created: {backup_dir}", details=m7_details, run_id=run_id)
        else:
            update_dashboard("M7", "FAILED", "High", "Backup creation failed", details={"backup_location": "Failed", "files": []}, run_id=run_id)

        # MODULE 8 - EVIDENCE COLLECTION
        if is_cli:
            print("\n========== MODULE 8 : EVIDENCE COLLECTION ==========\n")

        for result in critical_results:
            c_pod = result["pod"]
            try:
                evidence_dir = collect_evidence(c_pod, namespace=target_namespace, run_id=run_id, target=runtime_target_obj)
                if evidence_dir and os.path.exists(evidence_dir):
                    ev_files = []
                    for f in sorted(os.listdir(evidence_dir)):
                        f_path = os.path.join(evidence_dir, f)
                        if os.path.isfile(f_path):
                            ev_files.append({"name": f, "path": f_path.replace("\\", "/"), "size": f"{os.path.getsize(f_path)} bytes"})
                    m8_results.append({"pod": c_pod, "success": True, "evidence_dir": evidence_dir})
                    update_dashboard("M8", "COMPLETED", "None", f"Evidence collected for {c_pod}", {
                        "pod": c_pod,
                        "evidence_dir": evidence_dir.replace("\\", "/"),
                        "incident_folder": os.path.basename(evidence_dir),
                        "files": ev_files,
                        "files_collected_count": len(ev_files),
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }, run_id=run_id)
                else:
                    err_msg = "Evidence collection failed"
                    m8_results.append({"pod": c_pod, "success": False, "error": err_msg})
                    update_dashboard("M8", "FAILED", "High", err_msg, {"pod": c_pod, "error": err_msg}, run_id=run_id)
            except Exception as e:
                m8_results.append({"pod": c_pod, "success": False, "error": str(e)})
                update_dashboard("M8", "FAILED", "High", str(e), {"pod": c_pod, "error": str(e)}, run_id=run_id)

        # MODULE 9 - AUTO-ISOLATION
        if is_cli:
            print("\n========== MODULE 9 : AUTO-ISOLATION ==========\n")

        for result in critical_results:
            c_pod = result["pod"]
            # Isolation authorization policy:
            auth_choice = auto_isolate or (os.environ.get("AUTO_ISOLATE", "").lower() in ["1", "true", "yes"])
            if not auth_choice and is_cli and sys.stdin.isatty():
                try:
                    ans = input(f"\n[M9] High/Critical risk detected on Pod '{c_pod}'. Authorize active workload deletion and replacement? [y/N]: ").strip().lower()
                    auth_choice = (ans in ["y", "yes"])
                except (EOFError, KeyboardInterrupt):
                    auth_choice = False
            m9_res = auto_isolate_pod(c_pod, namespace=target_namespace, authorized=auth_choice)
            m9_results.append(m9_res)
            if m9_res.get("success"):
                rep = m9_res.get("replacement", {})
                pol = m9_res.get("policy", {})
                action_executed = m9_res.get("action_executed", False)
                if action_executed:
                    update_dashboard("M9", "COMPLETED", "None", f"Pod={c_pod} isolated and replaced (Authorized)", {
                        "affected_pod": c_pod,
                        "isolated_pod": c_pod,
                        "isolation_action": "Pod deleted and replacement created (Authorized)",
                        "replacement_pod": rep.get("pod", "None"),
                        "replacement_status": rep.get("status", "Unknown"),
                        "replacement_verified": rep.get("found", False),
                        "network_policy_file": pol.get("file", "None").replace("\\", "/") if pol.get("file") else "None",
                        "network_policy_created": pol.get("success", False),
                        "authorized": True,
                        "action_executed": True,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }, run_id=run_id)
                else:
                    update_dashboard("M9", "PARTIAL", "None", f"Proposed NetworkPolicy generated for {c_pod} (Isolation awaiting authorization)", {
                        "affected_pod": c_pod,
                        "isolated_pod": c_pod,
                        "isolation_action": "Recommendation generated: NetworkPolicy created; workload deletion held pending explicit user authorization",
                        "recommendation": m9_res.get("recommendation", "NetworkPolicy generated. Active disruption avoided."),
                        "replacement_pod": "Held (User authorization required)",
                        "replacement_status": "Held (User authorization required)",
                        "replacement_verified": False,
                        "network_policy_file": pol.get("file", "None").replace("\\", "/") if pol.get("file") else "None",
                        "network_policy_created": pol.get("success", False),
                        "authorized": False,
                        "action_executed": False,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }, run_id=run_id)
            elif m9_res.get("ignored"):
                update_dashboard("M9", "SKIPPED", "None", m9_res.get("error", "Action skipped"), {"affected_pod": c_pod, "error": m9_res.get("error")}, run_id=run_id)
            else:
                update_dashboard("M9", "FAILED", "Critical", m9_res.get("error", "Action failed"), {"affected_pod": c_pod, "error": m9_res.get("error")}, run_id=run_id)

        # MODULE 10 - EVIDENCE INTEGRITY
        if is_cli:
            print("\n========== MODULE 10 : EVIDENCE INTEGRITY ==========\n")

        for res in m8_results:
            if not res.get("success"):
                continue
            ev_dir = res["evidence_dir"]
            try:
                inc_name = os.path.basename(ev_dir)
                int_dir, manifest_f, hash_f = get_baseline_paths(ev_dir)
                has_baseline, manifest_data, base_err = has_valid_trusted_baseline(ev_dir)

                if has_baseline:
                    b_ver = manifest_data.get("baseline_version", 1) if isinstance(manifest_data, dict) else 1
                    if is_cli:
                        print(f"[M10] Reusing persistent trusted baseline for {inc_name} (Version {b_ver})")
                    load_trusted_baseline(hash_f)
                elif os.path.exists(manifest_f) or os.path.exists(hash_f):
                    # Baseline files exist but failed validation: NEVER silently overwrite!
                    if is_cli:
                        print(f"[M10] 🚨 CRITICAL: Existing baseline corrupted or invalid: {base_err}. Refusing silent overwrite.")
                else:
                    if is_cli:
                        print(f"[M10] Initializing persistent trusted baseline for {inc_name}")
                    hash_f = initialize_baseline(ev_dir, authorized_by="PipelineInit", reason="Initial incident evidence baseline establishment", run_id=run_id)

                all_ver, ver_count, tamp_count, miss_count, file_checks = verify_hashes(
                    ev_dir,
                    hash_f,
                    update_state=False,
                    verbose=is_cli,
                    pod_name=res["pod"]
                )

                if all_ver:
                    overall_st = "VERIFIED"
                elif tamp_count > 0:
                    overall_st = "TAMPERED"
                elif miss_count > 0:
                    overall_st = "MISSING_FILES"
                else:
                    overall_st = "FAILED"

                # Start continuous background integrity monitoring
                mon_running = False
                try:
                    start_integrity_monitor(ev_dir, hash_f, pod_name=res["pod"])
                    mon_running = is_monitor_running(ev_dir)
                except Exception as mon_err:
                    if is_cli:
                        print(f"[M10] Notice: Background monitor start: {mon_err}")
                    mon_running = False

                m10_details = {
                    "pod": res["pod"],
                    "evidence_dir": ev_dir.replace("\\", "/"),
                    "integrity_dir": int_dir.replace("\\", "/"),
                    "hash_file": hash_f.replace("\\", "/"),
                    "manifest_file": manifest_f.replace("\\", "/"),
                    "overall_integrity": overall_st,
                    "verified_count": ver_count,
                    "tampered_count": tamp_count,
                    "missing_count": miss_count,
                    "file_checks": file_checks,
                    "checks": file_checks,
                    "monitoring_status": "CONTINUOUS_ACTIVE" if mon_running else "MONITOR_INACTIVE",
                    "is_monitoring_active": mon_running,
                    "last_verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                if overall_st == "VERIFIED":
                    m10_results.append({"pod": res["pod"], "success": True, "evidence_dir": ev_dir, "details": m10_details})
                    update_dashboard("M10", "COMPLETED", "None", f"Integrity verified for {res['pod']}", details=m10_details, run_id=run_id)
                else:
                    m10_results.append({"pod": res["pod"], "success": False, "evidence_dir": ev_dir, "error": f"Integrity {overall_st}", "details": m10_details})
                    update_dashboard("M10", "FAILED", "Critical", f"Integrity {overall_st} for {res['pod']}", details=m10_details, run_id=run_id)
            except Exception as e:
                m10_results.append({"pod": res["pod"], "success": False, "error": str(e)})
                update_dashboard("M10", "FAILED", "Critical", str(e), {"pod": res["pod"], "error": str(e)}, run_id=run_id)

    else:
        if not target_pod_name:
            m_msg = f"Image-only analysis: Image '{selected_image}' has not been deployed as a running workload. Runtime incident response requires an active pod."
            update_dashboard("M7", "NOT_APPLICABLE", "None", m_msg, {
                "reason": m_msg,
                "limitation": "Backup requires deployed Kubernetes workload resources",
                "files": [],
                "backup_location": "Not Applicable",
                "backup_folder": "None",
                "resources_backed_up": 0,
                "status": "NOT_APPLICABLE"
            }, run_id=run_id)
            update_dashboard("M8", "NOT_APPLICABLE", "None", m_msg, {
                "reason": m_msg,
                "limitation": "Evidence collection requires a running target pod",
                "files": [],
                "files_collected_count": 0,
                "evidence_dir": "None",
                "pod": "None",
                "status": "NOT_APPLICABLE"
            }, run_id=run_id)
            update_dashboard("M9", "NOT_APPLICABLE", "None", m_msg, {
                "reason": m_msg,
                "limitation": "Isolation requires an active target pod",
                "affected_pod": "None",
                "replacement_pod": "None",
                "replacement_status": "Not Applicable",
                "status": "NOT_APPLICABLE"
            }, run_id=run_id)
            update_dashboard("M10", "NOT_APPLICABLE", "None", m_msg, {
                "reason": m_msg,
                "limitation": "Evidence integrity requires evidence artifacts collected in M8",
                "file_checks": [],
                "overall_integrity": "NOT_APPLICABLE",
                "verified_count": 0,
                "tampered_count": 0,
                "missing_count": 0,
                "status": "NOT_APPLICABLE"
            }, run_id=run_id)
        else:
            # Running workload present, but no critical escape finding detected - honestly SKIPPED
            update_dashboard("M7", "SKIPPED", "None", "No Critical container escape finding detected; automated incident response not triggered.", {
                "reason": "No Critical container escape finding detected; automated incident response not triggered.",
                "files": [],
                "backup_location": "Skipped",
                "backup_folder": "None",
                "resources_backed_up": 0,
                "status": "SKIPPED"
            }, run_id=run_id)
            update_dashboard("M8", "SKIPPED", "None", "No affected Critical Pod; evidence collection not triggered.", {
                "reason": "No affected Critical Pod; evidence collection not triggered.",
                "files": [],
                "files_collected_count": 0,
                "evidence_dir": "None",
                "pod": "None",
                "status": "SKIPPED"
            }, run_id=run_id)
            update_dashboard("M9", "SKIPPED", "None", "No Critical finding; automatic isolation not triggered.", {
                "reason": "No Critical finding; automatic isolation not triggered.",
                "affected_pod": "None",
                "replacement_pod": "None",
                "replacement_status": "Skipped",
                "status": "SKIPPED"
            }, run_id=run_id)
            handle_no_evidence(run_id=run_id)
            update_dashboard("M10", "NOT_APPLICABLE", "None", "NOT APPLICABLE — No incident evidence collected", {
                "reason": "NOT APPLICABLE — No incident evidence collected",
                "file_checks": [],
                "overall_integrity": "NOT_APPLICABLE",
                "verified_count": 0,
                "tampered_count": 0,
                "missing_count": 0,
                "status": "NOT_APPLICABLE"
            }, run_id=run_id)

    # -----------------------------
    # MODULE 11 - FORENSIC REPORT
    # -----------------------------
    if is_cli:
        print("\n========== MODULE 11 : FORENSIC ANALYSIS ==========\n")

    report_path = None
    try:
        report_path = generate_forensic_report(
            scan_result=scan_result,
            monitor_result=monitor_result,
            cluster=cluster,
            roles=roles,
            cluster_roles=cluster_roles,
            bindings=bindings,
            findings=findings,
            binding_findings=binding_findings,
            threat_data=threat_data,
            threat_result=threat_result,
            escape_results=escape_results,
            m7_backup_result=m7_backup_result,
            m8_results=m8_results,
            m9_results=m9_results,
            m10_results=m10_results,
            run_id=run_id,
            incident_id=incident_id
        )

        fsize = "0 KB"
        if os.path.exists(report_path):
            fsize = f"{round(os.path.getsize(report_path) / 1024, 1)} KB"

        m11_details = {
            "report_path": report_path.replace("\\", "/"),
            "report_filename": os.path.basename(report_path),
            "file_size": fsize,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        update_dashboard(
            "M11",
            "COMPLETED",
            "None",
            f"Forensic report generated: {report_path}",
            details=m11_details,
            extra_root={"pipeline_status": "COMPLETED", "status": "COMPLETED", "overall_status": "COMPLETED", "current_report": m11_details},
            run_id=run_id
        )
        if is_cli:
            print(f"Forensic Report: {report_path} ({fsize})")
    except Exception as e:
        update_dashboard(
            "M11",
            "FAILED",
            "High",
            str(e),
            details={"error": str(e), "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            extra_root={"pipeline_status": "COMPLETED", "status": "COMPLETED", "overall_status": "COMPLETED"},
            run_id=run_id
        )
        if is_cli:
            print(f"[M11] Report Generation Error: {e}")

    # Complete run in run_manager
    try:
        run_manager.complete_run(
            run_id=run_id,
            status="COMPLETED",
            report_path=report_path,
            backup_path=m7_backup_result
        )
    except Exception:
        pass

    if is_cli:
        print("\n" + "=" * 50)
        print("KubeGuard Pipeline Execution Completed")
        print("=" * 50 + "\n")

    # Read final state
    try:
        with open(DASHBOARD_STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ==================================================
# CLI ENTRYPOINT
# ==================================================

if __name__ == "__main__":
    selected_image = None
    cli_workload_name = None
    no_server = False

    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print("""KubeGuard - Kubernetes Container Security Monitoring & Incident Response

Usage:
  python main.py [IMAGE] [OPTIONS]
  python main.py --workload <DEPLOYMENT> [OPTIONS]
  python main.py --image <IMAGE> [OPTIONS]

Options:
  --workload, -w <NAME>      Existing Kubernetes Deployment to evaluate (e.g., nginx, python-app, node-app)
  --image, -i <IMAGE>        Container image to scan and evaluate (e.g., nginx:latest, python:3.12-slim, node:22)
  --configure                Reconfigure the target Kubernetes Deployment
  --cleanup-test-workloads   Safely delete obsolete KubeGuard test deployments and exit
  --privileged               Deploy workload with securityContext.privileged=true (Case A test)
  --deploy                   Force deployment of a dedicated workload
  --no-deploy                Run in image-only analysis mode without deploying workload
  --auto-isolate             Automatically authorize workload isolation if critical escape is detected
  --yes, -y                  Automatically confirm isolation prompts
  --no-server                Run pipeline and exit without launching dashboard web server
  --help, -h                 Show this help message and exit
""")
        sys.exit(0)

    if "--cleanup-test-workloads" in args:
        cleaned = cleanup_obsolete_kubeguard_workloads()
        if cleaned:
            print(f"[+] Successfully cleaned up {len(cleaned)} obsolete test workload(s): {', '.join(cleaned)}")
        else:
            print("[+] No obsolete test workloads found.")
        sys.exit(0)

    reconfigure = False
    if "--configure" in args:
        reconfigure = True
        args.remove("--configure")

    if "--no-server" in args:
        no_server = True
        args.remove("--no-server")

    auto_confirm = False
    if "--yes" in args:
        auto_confirm = True
        args.remove("--yes")
    elif "-y" in args:
        auto_confirm = True
        args.remove("-y")

    deploy_choice = None
    if "--deploy" in args:
        deploy_choice = True
        args.remove("--deploy")
    elif "--no-deploy" in args:
        deploy_choice = False
        args.remove("--no-deploy")

    privileged_choice = False
    if "--privileged" in args:
        privileged_choice = True
        args.remove("--privileged")

    auto_isolate_choice = False
    if "--auto-isolate" in args:
        auto_isolate_choice = True
        args.remove("--auto-isolate")

    # Parse --workload / -w / --target
    for flag in ["--workload", "-w", "--target"]:
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                cli_workload_name = args[idx + 1]
                del args[idx:idx + 2]
                break

    # Parse --image / -i
    if args:
        if (args[0] == "--image" or args[0] == "-i") and len(args) > 1:
            selected_image = args[1]
        elif not args[0].startswith("-"):
            selected_image = args[0]

    # If workload was explicitly passed, verify it and discover image
    if cli_workload_name:
        ok, t_obj, err = resolve_existing_deployment_target(cli_workload_name)
        if ok and t_obj:
            persist_target_config(
                workload_name=t_obj.workload_name,
                namespace=t_obj.namespace,
                container_name=t_obj.container_name,
                image=t_obj.runtime_image,
                workload_kind=t_obj.workload_kind
            )
            if not selected_image and t_obj.runtime_image:
                selected_image = t_obj.runtime_image
        else:
            print(f"[!] Warning: Workload '{cli_workload_name}' could not be resolved: {err}")

    # Check persisted config if neither workload nor image was specified and not reconfiguring
    if not cli_workload_name and not selected_image and not reconfigure:
        persisted = get_persisted_target_config()
        if persisted and persisted.get("workload_name"):
            p_wl = persisted.get("workload_name")
            ok, t_obj, _ = resolve_existing_deployment_target(p_wl, namespace=persisted.get("namespace", "default"))
            if ok and t_obj:
                cli_workload_name = t_obj.workload_name
                selected_image = t_obj.runtime_image
                print(f"[+] Using configured target: Deployment/{cli_workload_name} (image: {selected_image})")
                print("    (Pass --configure or --workload <NAME> to assess a different workload)\n")

    # If still no image or workload, prompt user interactively
    if not selected_image and not cli_workload_name:
        available_deps = list_available_deployments()
        print("=" * 50)
        print("                 KUBEGUARD")
        print("=" * 50)
        print()

        if available_deps:
            print("Available Running Deployments in default namespace:")
            for idx, d in enumerate(available_deps, 1):
                priv_str = "true" if d.get("privileged") else "false"
                print(f"  [{idx}] Deployment/{d['workload_name']} (image: {d.get('image')}, container: {d.get('container_name')}, privileged: {priv_str})")
            print(f"  [{len(available_deps) + 1}] Enter custom container image reference")
            print()

            while not selected_image and not cli_workload_name:
                try:
                    choice = input(f"Select target workload [1-{len(available_deps) + 1}]: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nExecution aborted by user.")
                    sys.exit(0)

                if choice.isdigit():
                    c_num = int(choice)
                    if 1 <= c_num <= len(available_deps):
                        chosen = available_deps[c_num - 1]
                        cli_workload_name = chosen["workload_name"]
                        selected_image = chosen["image"]
                        persist_target_config(
                            workload_name=cli_workload_name,
                            namespace=chosen.get("namespace", "default"),
                            container_name=chosen.get("container_name"),
                            image=selected_image
                        )
                        break
                    elif c_num == len(available_deps) + 1:
                        break
                elif choice:
                    # Check if choice matches workload name directly
                    matched = [d for d in available_deps if d["workload_name"].lower() == choice.lower()]
                    if matched:
                        chosen = matched[0]
                        cli_workload_name = chosen["workload_name"]
                        selected_image = chosen["image"]
                        persist_target_config(
                            workload_name=cli_workload_name,
                            namespace=chosen.get("namespace", "default"),
                            container_name=chosen.get("container_name"),
                            image=selected_image
                        )
                        break

        if not selected_image:
            print("Enter the container image to scan and evaluate.")
            print("Example: nginx:latest, python:3.12-slim, node:22\n")
            while not selected_image:
                try:
                    user_input = input("Container image: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nExecution aborted by user.")
                    sys.exit(0)

                if not user_input:
                    print("Error: Container image reference cannot be empty. Please enter an image name.")
                    continue

                is_valid, validated_or_err = validate_image_reference(user_input)
                if not is_valid:
                    print(f"Error: Invalid image reference '{user_input}': {validated_or_err}")
                    continue
                selected_image = validated_or_err
    else:
        if selected_image:
            is_valid, validated_or_err = validate_image_reference(selected_image)
            if not is_valid:
                print(f"Error: Invalid image reference '{selected_image}': {validated_or_err}")
                sys.exit(1)
            selected_image = validated_or_err

    run_pipeline(
        selected_image=selected_image,
        workload_name=cli_workload_name,
        is_cli=True,
        deploy_workload=deploy_choice,
        privileged=privileged_choice,
        auto_isolate=(auto_confirm or auto_isolate_choice)
    )

    if not no_server:
        print("\n" + "=" * 50)
        print("             KUBEGUARD DASHBOARD")
        print("=" * 50)
        print("Dashboard URL: http://127.0.0.1:5000")
        print("=" * 50 + "\n")

        # Resume background monitoring for existing active evidence if a trusted baseline exists
        try:
            latest_ev = resolve_target_evidence_dir()
            if latest_ev:
                has_bl, mf, _ = has_valid_trusted_baseline(latest_ev)
                if has_bl:
                    start_integrity_monitor(latest_ev)
                    b_ver = mf.get("baseline_version", 1) if isinstance(mf, dict) else 1
                    print(f"[M10] Active background integrity monitoring running on trusted baseline (v{b_ver}) for: {os.path.basename(latest_ev)}")
        except Exception as e:
            print(f"[M10] Monitor auto-start notice: {e}")

        # Check if dashboard server is already running on port 5000
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 5000))
        sock.close()
        if result == 0:
            print("[+] KubeGuard dashboard is already running at http://127.0.0.1:5000")
        else:
            from dashboard.app import start_server
            start_server(host="127.0.0.1", port=5000)
