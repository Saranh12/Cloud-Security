import os
import json
import threading
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RUNS_DIR = BASE_DIR / "runs"
INDEX_FILE = RUNS_DIR / "runs_index.json"
_RUN_LOCK = threading.Lock()


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def recompute_overview(data):
    """
    Computes overall risk, monitored pods, vulnerabilities breakdown,
    integrity status, and findings distribution based on actual module results.
    """
    modules = data.get("modules", {})

    # M1 vuln counts
    m1_details = modules.get("M1", {}).get("details", {})
    counts = m1_details.get("severity_counts", {})
    crit_vuln = int(counts.get("CRITICAL", 0))
    high_vuln = int(counts.get("HIGH", 0))
    med_vuln = int(counts.get("MEDIUM", 0))
    low_vuln = int(counts.get("LOW", 0))
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
    elif all(modules.get(m, {}).get("status") in ["NOT RUN", "SKIPPED"] for m in ["M1", "M2", "M3", "M4", "M5"]):
        overall_risk = "NOT RUN"
    else:
        overall_risk = "NORMAL"

    report_count = 1 if modules.get("M11", {}).get("status") in ["COMPLETED", "SUCCESS"] else 0

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


def init_run(selected_image, run_id=None):
    """
    Initializes a new isolated run directory and its metadata.
    Creates:
      runs/<run-id>/
        run_metadata.json
        module_results/
        evidence/
        integrity/
        reports/
        logs/
    """
    with _RUN_LOCK:
        _ensure_dir(RUNS_DIR)

        if not run_id:
            run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        run_path = RUNS_DIR / run_id
        _ensure_dir(run_path)
        _ensure_dir(run_path / "module_results")
        _ensure_dir(run_path / "evidence")
        _ensure_dir(run_path / "integrity")
        _ensure_dir(run_path / "reports")
        _ensure_dir(run_path / "logs")

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
        metadata = {
            "run_id": run_id,
            "selected_image": selected_image,
            "image": selected_image,
            "created_at": now_str,
            "start_time": now_str,
            "target_pod": None,
            "namespace": "default",
            "deployment_name": None,
            "pod_names": [],
            "pipeline_status": "RUNNING",
            "status": "RUNNING",
            "overall_status": "RUNNING",
            "scan_results": {},
            "module_results": modules,
            "evidence_files": [],
            "integrity_result": "NOT RUN",
            "forensic_report_path": None,
            "completion_time": None,
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
            },
            "evidence_locations": [],
            "integrity_results": {},
            "report_location": None,
            "backup_location": None,
            "limitations": [],
            "errors": []
        }

        # Normalize root keys for backward compatibility
        for mod in modules_list:
            metadata[mod] = modules[mod]
            metadata[mod.lower()] = modules[mod]

        meta_file = run_path / "run_metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4)

        # Update runs_index.json
        _update_index(run_id, selected_image, now_str, "RUNNING", "NOT RUN", None)

        return run_id, metadata


def record_module_result(run_id, module, status, severity="None", message="", details=None, extra_root=None):
    """
    Atomically records a module's execution result in runs/<run_id>/run_metadata.json
    and runs/<run_id>/module_results/<module>.json.
    """
    with _RUN_LOCK:
        run_path = RUNS_DIR / run_id
        meta_file = run_path / "run_metadata.json"

        data = {}
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}

        if "modules" not in data or not isinstance(data["modules"], dict):
            data["modules"] = {}

        current_module = data["modules"].get(module, {})
        if status in ["SKIPPED", "NOT RUN"]:
            existing_details = dict(details) if details else {}
        else:
            existing_details = current_module.get("details", {}) if isinstance(current_module.get("details"), dict) else {}
            if details:
                existing_details.update(details)

        module_entry = {
            "status": status,
            "severity": severity,
            "message": message,
            "details": existing_details
        }

        data["modules"][module] = module_entry
        data["modules"][module.lower()] = module_entry
        data[module] = module_entry
        data[module.lower()] = module_entry

        # Keep shared run context in sync
        data["image"] = data.get("selected_image")
        data["module_results"] = data.get("modules", {})
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

        if extra_root and isinstance(extra_root, dict):
            data.update(extra_root)
            if "deployment_name" in extra_root:
                data["deployment_name"] = extra_root["deployment_name"]
            if "target_pod" in extra_root and extra_root["target_pod"]:
                p_name = extra_root["target_pod"]
                if p_name not in data.get("pod_names", []):
                    data.setdefault("pod_names", []).append(p_name)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["execution_time"] = now_str
        recompute_overview(data)

        # Save module result snapshot
        mod_file = run_path / "module_results" / f"{module.lower()}.json"
        try:
            with open(mod_file, "w", encoding="utf-8") as f:
                json.dump(module_entry, f, indent=4)
        except Exception:
            pass

        # Atomic write of run_metadata.json
        try:
            tmp_meta = run_path / "run_metadata.tmp"
            with open(tmp_meta, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            os.replace(tmp_meta, meta_file)
        except Exception:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

        # Update index
        overall_risk = data.get("overview", {}).get("overall_risk", "NOT RUN")
        rep_loc = data.get("report_location")
        _update_index(run_id, data.get("selected_image"), data.get("start_time"), data.get("status", "RUNNING"), overall_risk, rep_loc)

        return data


def complete_run(run_id, status="COMPLETED", limitations=None, errors=None, report_path=None, backup_path=None):
    """
    Marks a run as completed (or failed) and records final artifacts.
    """
    with _RUN_LOCK:
        run_path = RUNS_DIR / run_id
        meta_file = run_path / "run_metadata.json"

        data = {}
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["completion_time"] = now_str
        data["status"] = status
        data["pipeline_status"] = status
        data["overall_status"] = status

        if limitations:
            data.setdefault("limitations", []).extend(limitations)
        if errors:
            data.setdefault("errors", []).extend(errors)
        if report_path:
            norm_rep = str(report_path).replace("\\", "/")
            data["report_location"] = norm_rep
            data["forensic_report_path"] = norm_rep
            data["report_path"] = norm_rep
        if backup_path:
            data["backup_location"] = str(backup_path).replace("\\", "/")

        recompute_overview(data)

        try:
            tmp_meta = run_path / "run_metadata.tmp"
            with open(tmp_meta, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            os.replace(tmp_meta, meta_file)
        except Exception:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

        overall_risk = data.get("overview", {}).get("overall_risk", "NORMAL")
        _update_index(run_id, data.get("selected_image"), data.get("start_time"), status, overall_risk, data.get("report_location"), completion_time=now_str)

        return data


def _update_index(run_id, image, start_time, status, overall_risk, report_path, completion_time=None):
    """Updates the master runs_index.json file."""
    _ensure_dir(RUNS_DIR)
    runs = []
    if INDEX_FILE.exists():
        try:
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                runs = json.load(f)
                if not isinstance(runs, list):
                    runs = []
        except Exception:
            runs = []

    # Update or insert entry
    found = False
    for r in runs:
        if r.get("run_id") == run_id:
            r["status"] = status
            r["overall_risk"] = overall_risk
            if report_path:
                r["report_path"] = str(report_path).replace("\\", "/")
            if completion_time:
                r["completion_time"] = completion_time
            found = True
            break

    if not found:
        entry = {
            "run_id": run_id,
            "image": image,
            "start_time": start_time,
            "completion_time": completion_time,
            "status": status,
            "overall_risk": overall_risk,
            "report_path": str(report_path).replace("\\", "/") if report_path else None
        }
        runs.insert(0, entry)

    try:
        tmp_idx = RUNS_DIR / "runs_index.tmp"
        with open(tmp_idx, "w", encoding="utf-8") as f:
            json.dump(runs, f, indent=4)
        os.replace(tmp_idx, INDEX_FILE)
    except Exception:
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(runs, f, indent=4)


def list_runs():
    """Returns sorted list of all runs recorded."""
    with _RUN_LOCK:
        if INDEX_FILE.exists():
            try:
                with open(INDEX_FILE, "r", encoding="utf-8") as f:
                    runs = json.load(f)
                    if isinstance(runs, list):
                        return runs
            except Exception:
                pass
        # Fallback: scan RUNS_DIR
        runs = []
        if RUNS_DIR.exists():
            for item in sorted(RUNS_DIR.iterdir(), reverse=True):
                if item.is_dir() and (item / "run_metadata.json").exists():
                    try:
                        with open(item / "run_metadata.json", "r", encoding="utf-8") as f:
                            d = json.load(f)
                            runs.append({
                                "run_id": d.get("run_id", item.name),
                                "image": d.get("selected_image", "Unknown"),
                                "start_time": d.get("start_time"),
                                "completion_time": d.get("completion_time"),
                                "status": d.get("status", "COMPLETED"),
                                "overall_risk": d.get("overview", {}).get("overall_risk", "NORMAL"),
                                "report_path": d.get("report_location")
                            })
                    except Exception:
                        pass
        return runs


def get_run(run_id):
    """Retrieves full run metadata for a specific run ID."""
    with _RUN_LOCK:
        meta_file = RUNS_DIR / run_id / "run_metadata.json"
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                return {"error": str(e)}
        return None
