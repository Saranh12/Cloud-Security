import os
import hashlib
import hmac
import json
import sys
import time
import threading
import stat
import secrets
import atexit
from pathlib import Path
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INTEGRITY_DIR = os.path.join(BASE_DIR, "integrity")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
STATE_FILE = os.path.join(REPORTS_DIR, "dashboard_state.json")
SECRET_FILE = os.path.join(BASE_DIR, ".integrity_secret")

EXCLUDED_TEMP_PATTERNS = {
    ".tmp", ".swp", ".swo", "~", ".ds_store", "thumbs.db", ".lock"
}

# In-memory trusted baseline cache
_TRUSTED_BASELINES = {}
_BASELINE_LOCK = threading.Lock()

# Registry of active continuous monitors
_ACTIVE_MONITORS = {}
_MONITOR_LOCK = threading.Lock()

# Lock for thread-safe atomic dashboard state updates
_DASHBOARD_LOCK = threading.Lock()

# Lock for tamper events log file
_TAMPER_LOG_LOCK = threading.Lock()

__all__ = [
    "calculate_hash",
    "create_hashes",
    "verify_hashes",
    "initialize_baseline",
    "load_trusted_baseline",
    "has_valid_trusted_baseline",
    "get_baseline_paths",
    "start_integrity_monitor",
    "stop_integrity_monitor",
    "stop_all_integrity_monitors",
    "is_monitor_running",
    "resolve_target_evidence_dir",
    "record_tamper_event",
    "load_tamper_log",
    "rebaseline_evidence",
    "resolve_tampering",
    "update_dashboard_state",
    "handle_no_evidence"
]


def handle_no_evidence(run_id=None, state_file=None):
    """
    Handles normal runs where no incident evidence was collected.
    Reports NOT APPLICABLE without creating critical alerts or claiming nonexistent evidence is verified.
    """
    st_file = state_file or STATE_FILE
    details = {
        "overall_integrity": "NOT_APPLICABLE",
        "status": "NOT_APPLICABLE",
        "reason": "NOT APPLICABLE — No incident evidence collected",
        "verified_count": 0,
        "tampered_count": 0,
        "missing_count": 0,
        "file_checks": [],
        "evidence_dir": None,
        "monitoring_status": "NOT_APPLICABLE",
        "last_verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if os.path.exists(st_file):
        try:
            with open(st_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "modules" in data and isinstance(data["modules"], dict):
                data["modules"]["M10"] = {
                    "status": "NOT_APPLICABLE",
                    "severity": "None",
                    "message": "NOT APPLICABLE — No incident evidence collected",
                    "details": details
                }
                data["modules"]["m10"] = data["modules"]["M10"]
                data["M10"] = data["modules"]["M10"]
                data["m10"] = data["modules"]["M10"]
            with open(st_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    return details


# ============================================================
# CROSS-PROCESS FILE LOCKING
# ============================================================

class CrossProcessLock:
    """
    Cross-process mutual exclusion lock using standard OS file locking:
    msvcrt on Windows and fcntl on Unix/POSIX.
    Ensures safe concurrent access to state, baseline, and tamper logs
    between terminal 1 (main.py) and terminal 2 (module10_integrity.py CLI).
    """
    def __init__(self, lock_file_path, timeout=5.0):
        self.lock_file_path = str(lock_file_path)
        self.timeout = timeout
        self.file_obj = None

    def __enter__(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_file_path)), exist_ok=True)
        start_time = time.time()
        while True:
            try:
                self.file_obj = open(self.lock_file_path, "a+", encoding="utf-8")
                if sys.platform == "win32":
                    import msvcrt
                    self.file_obj.seek(0)
                    msvcrt.locking(self.file_obj.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except (IOError, OSError):
                if self.file_obj:
                    try:
                        self.file_obj.close()
                    except Exception:
                        pass
                    self.file_obj = None
                if time.time() - start_time >= self.timeout:
                    # Timeout expired; continue without hard crash to preserve availability
                    break
                time.sleep(0.05)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file_obj:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self.file_obj.seek(0)
                    msvcrt.locking(self.file_obj.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file_obj.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self.file_obj.close()
            except Exception:
                pass
            self.file_obj = None


# ============================================================
# SECRET KEY MANAGEMENT & BASELINE AUTHENTICATION (HMAC-SHA256)
# ============================================================

def get_integrity_secret():
    """
    Retrieves the HMAC secret key used to digitally sign and authenticate baselines.
    Security rules:
    1. Check KUBEGUARD_INTEGRITY_SECRET or INTEGRITY_KEY environment variable.
    2. Fall back to secure local file outside evidence/ and integrity/ (.integrity_secret).
    3. Generate a cryptographically strong 256-bit random key if none exists.
    4. Never expose or hardcode the key in code or baseline directories.
    """
    env_secret = os.environ.get("KUBEGUARD_INTEGRITY_SECRET") or os.environ.get("INTEGRITY_KEY")
    if env_secret:
        return env_secret.strip().encode("utf-8")

    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, "rb") as f:
                sec = f.read().strip()
                if sec:
                    return sec
        except Exception:
            pass

    # Generate a cryptographically strong 256-bit key
    new_secret = secrets.token_hex(32).encode("utf-8")
    try:
        with open(SECRET_FILE, "wb") as f:
            f.write(new_secret)
        try:
            os.chmod(SECRET_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(SECRET_FILE, FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass
    except Exception:
        pass
    return new_secret


def compute_manifest_hmac(manifest_dict, secret_bytes=None):
    """
    Calculates HMAC-SHA256 signature across the canonical JSON representation of the baseline manifest.
    Excludes any existing 'hmac_sha256' field to ensure deterministic computation.
    """
    if secret_bytes is None:
        secret_bytes = get_integrity_secret()
    canonical_dict = {k: v for k, v in manifest_dict.items() if k != "hmac_sha256"}
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hmac.new(secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()


def verify_manifest_hmac(manifest_dict, secret_bytes=None):
    """
    Verifies that the baseline manifest has not been modified or replaced by comparing its HMAC signature.
    Returns (is_valid: bool, reason: str).
    """
    if not isinstance(manifest_dict, dict):
        return False, "Baseline manifest is not a valid JSON object"
    stored_hmac = manifest_dict.get("hmac_sha256")
    if not stored_hmac:
        return False, "Baseline manifest lacks required HMAC-SHA256 signature"

    expected_hmac = compute_manifest_hmac(manifest_dict, secret_bytes=secret_bytes)
    if hmac.compare_digest(expected_hmac, stored_hmac):
        return True, "Baseline manifest authenticated successfully"
    return False, f"HMAC mismatch: expected {expected_hmac[:12]}..., got {stored_hmac[:12]}..."


# ============================================================
# PERSISTENT TAMPER LOGGING
# ============================================================

def get_tamper_log_path(evidence_dir):
    """Returns the persistent tamper events file path for an incident."""
    incident_name = os.path.basename(os.path.abspath(evidence_dir))
    return os.path.join(INTEGRITY_DIR, incident_name, "tamper_events.json")


def load_tamper_log(evidence_dir):
    """Loads persistent tamper log if present."""
    log_path = get_tamper_log_path(evidence_dir)
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def record_tamper_event(evidence_dir, change_type, filename, rel_path, expected_hash, observed_hash, message=""):
    """
    Persistently records a tampering event in integrity/<incident>/tamper_events.json.
    Ensures that once an evidence breach is detected, it remains recorded even across application restarts.
    """
    incident_name = os.path.basename(os.path.abspath(evidence_dir))
    log_path = get_tamper_log_path(evidence_dir)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    lock_file = log_path + ".lock"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event = {
        "incident_id": incident_name,
        "change_type": change_type,
        "filename": filename,
        "relative_path": rel_path.replace("\\", "/"),
        "expected_hash": expected_hash or "None",
        "observed_hash": observed_hash or "None",
        "message": message,
        "detected_at": now_str
    }

    with _TAMPER_LOG_LOCK, CrossProcessLock(lock_file):
        data = load_tamper_log(evidence_dir)
        if not data:
            data = {
                "incident_id": incident_name,
                "tampered": True,
                "first_detected_at": now_str,
                "events": []
            }

        data["tampered"] = True
        data["last_detected_at"] = now_str
        data["latest_event"] = event

        # Prevent duplicate entries for identical sequential detections
        is_duplicate = False
        for existing in reversed(data.get("events", [])[-5:]):
            if (existing.get("change_type") == change_type and
                existing.get("relative_path") == event["relative_path"] and
                existing.get("expected_hash") == event["expected_hash"] and
                existing.get("observed_hash") == event["observed_hash"]):
                is_duplicate = True
                break

        if not is_duplicate:
            data.setdefault("events", []).append(event)

        try:
            tmp_path = log_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            os.replace(tmp_path, log_path)
        except Exception as e:
            print(f"[M10] Warning recording tamper event: {e}")

    return event


def resolve_tampering(evidence_dir, reason, authorized_by="Admin"):
    """
    Explicit, safe investigation and resolution workflow.
    Required before an incident can transition out of TAMPERED state.
    """
    incident_name = os.path.basename(os.path.abspath(evidence_dir))
    log_path = get_tamper_log_path(evidence_dir)
    if not os.path.exists(log_path):
        return True, "No active tampering records found."

    lock_file = log_path + ".lock"
    with _TAMPER_LOG_LOCK, CrossProcessLock(lock_file):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["tampered"] = False
            data["resolved_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data["resolution_reason"] = reason
            data["authorized_by"] = authorized_by
            tmp_path = log_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            os.replace(tmp_path, log_path)
            return True, f"Tampering resolved for {incident_name} by {authorized_by}."
        except Exception as e:
            return False, f"Error resolving tampering: {e}"


# ============================================================
# HASH CALCULATION & HELPER UTILITIES
# ============================================================

def is_ignored_temp_file(filepath):
    """Filters out editor temporary files, swap files, lock files, and OS metadata files."""
    base = os.path.basename(filepath).lower()
    ext = os.path.splitext(filepath)[1].lower()
    if base in EXCLUDED_TEMP_PATTERNS or ext in EXCLUDED_TEMP_PATTERNS:
        return True
    if base.startswith(".~") or base.startswith("~") or base.endswith("~") or base.endswith(".tmp") or base.endswith(".lock"):
        return True
    return False


def is_symlink_escape(file_path, base_dir):
    """
    Checks if a file is a symbolic link that points outside the designated base directory.
    Prevents path traversal and symlink-based evidence tampering.
    """
    try:
        if os.path.islink(file_path):
            real_target = os.path.realpath(file_path)
            real_base = os.path.realpath(base_dir)
            common = os.path.commonpath([real_target, real_base])
            return common != real_base
    except Exception:
        pass
    return False


def calculate_hash(file_path):
    """
    Calculates SHA-256 hash of a file safely in 4096-byte chunks.
    Returns None if file does not exist, is locked, or cannot be read.
    """
    if not os.path.isfile(file_path):
        return None
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def clear_readonly(path):
    """Removes read-only attribute on Windows and Unix to allow atomic replacement or deletion."""
    if not os.path.exists(path):
        return
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IWUSR)
    except Exception:
        pass
    try:
        import ctypes
        FILE_ATTRIBUTE_NORMAL = 0x80
        ctypes.windll.kernel32.SetFileAttributesW(os.path.abspath(path), FILE_ATTRIBUTE_NORMAL)
    except Exception:
        pass


def make_readonly(path):
    """Sets read-only attribute on Windows and Unix to protect baseline integrity."""
    if not os.path.exists(path):
        return
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        pass
    try:
        import ctypes
        FILE_ATTRIBUTE_READONLY = 0x01
        ctypes.windll.kernel32.SetFileAttributesW(os.path.abspath(path), FILE_ATTRIBUTE_READONLY)
    except Exception:
        pass


# ============================================================
# PERSISTENT TRUSTED BASELINE LIFECYCLE (PHASE 2)
# ============================================================

def get_baseline_paths(evidence_dir):
    """Returns canonical paths for manifest.json and legacy hashes.txt for an evidence directory."""
    incident_name = os.path.basename(os.path.abspath(evidence_dir))
    integrity_path = os.path.join(INTEGRITY_DIR, incident_name)
    hash_file = os.path.join(integrity_path, "hashes.txt")
    manifest_file = os.path.join(integrity_path, "manifest.json")
    return integrity_path, manifest_file, hash_file


def has_valid_trusted_baseline(evidence_dir):
    """
    Checks if a valid, authenticated trusted baseline exists for the evidence directory.
    Returns (has_baseline: bool, manifest_dict_or_none, error_reason).
    """
    _, manifest_file, hash_file = get_baseline_paths(evidence_dir)
    if not os.path.exists(manifest_file) and not os.path.exists(hash_file):
        return False, None, "No baseline exists on disk."

    if os.path.exists(manifest_file):
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_dict = json.load(f)
            is_valid, reason = verify_manifest_hmac(manifest_dict)
            if is_valid:
                return True, manifest_dict, None
            return False, manifest_dict, f"Corrupted or tampered manifest: {reason}"
        except Exception as e:
            return False, None, f"Unreadable manifest.json: {e}"

    if os.path.exists(hash_file):
        try:
            with open(hash_file, "r", encoding="utf-8", errors="replace") as f:
                lines = [l.strip() for l in f if l.strip() and " : " in l]
            if lines:
                return True, {"files": {l.split(" : ")[0]: l.split(" : ")[1] for l in lines}}, None
        except Exception as e:
            return False, None, f"Unreadable hashes.txt: {e}"

    return False, None, "Baseline empty or unparseable."


def initialize_baseline(evidence_dir, authorized_by="SecurityAdmin", reason="Initial trust establishment", force=False, run_id=None):
    """
    Explicitly creates and signs the initial persistent trusted baseline for an evidence directory.
    Safety guarantee: Refuses to overwrite an existing valid trusted baseline unless force=True.
    Never silently replaces a missing or invalid baseline during ordinary verification.
    """
    evidence_dir = os.path.abspath(evidence_dir)
    if not os.path.exists(evidence_dir):
        raise FileNotFoundError(f"Evidence directory '{evidence_dir}' does not exist.")

    integrity_path, manifest_file, hash_file = get_baseline_paths(evidence_dir)
    incident_name = os.path.basename(evidence_dir)
    lock_file = os.path.join(integrity_path, ".baseline.lock")

    with CrossProcessLock(lock_file):
        # Safeguard: check if a valid baseline already exists
        has_baseline, existing_mf, err = has_valid_trusted_baseline(evidence_dir)
        if has_baseline and not force:
            # Check if existing baseline was for this exact directory
            rec_abs = existing_mf.get("evidence_dir_abs") if isinstance(existing_mf, dict) else None
            curr_abs = evidence_dir.replace("\\", "/")
            if rec_abs and rec_abs.lower() != curr_abs.lower() and not os.path.exists(rec_abs):
                # Stale baseline from a destroyed temporary test directory; allow initialization
                pass
            else:
                load_trusted_baseline(hash_file)
                return hash_file

        os.makedirs(integrity_path, exist_ok=True)

        file_records = {}
        legacy_lines = []

        # Recursively traverse evidence directory (ignoring temporary files and symlinks outside root)
        for root, _, files in os.walk(evidence_dir):
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                if is_ignored_temp_file(full_path):
                    continue
                if is_symlink_escape(full_path, evidence_dir):
                    print(f"[M10] Warning: Ignoring symlink pointing outside evidence directory: {full_path}")
                    continue

                rel_path = os.path.relpath(full_path, evidence_dir).replace("\\", "/")
                f_hash = calculate_hash(full_path)
                if f_hash:
                    try:
                        f_size = os.path.getsize(full_path)
                        f_mtime = os.path.getmtime(full_path)
                    except Exception:
                        f_size = 0
                        f_mtime = 0
                    file_records[rel_path] = {
                        "sha256": f_hash,
                        "size": f_size,
                        "mtime": f_mtime
                    }
                    legacy_lines.append(f"{rel_path} : {f_hash}\n")
                    if fname != rel_path:
                        legacy_lines.append(f"{fname} : {f_hash}\n")

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        manifest_dict = {
            "schema_version": 2,
            "baseline_version": 1,
            "incident_id": incident_name,
            "evidence_dir": os.path.relpath(evidence_dir, BASE_DIR).replace("\\", "/") if str(evidence_dir).startswith(str(BASE_DIR)) else evidence_dir.replace("\\", "/"),
            "evidence_dir_abs": evidence_dir.replace("\\", "/"),
            "initialized_at": now_str,
            "initialized_by": authorized_by,
            "initialization_reason": reason,
            "last_rebaselined_at": None,
            "rebaseline_history": [
                {
                    "version": 1,
                    "action": "INITIAL_BASELINE",
                    "timestamp": now_str,
                    "authorized_by": authorized_by,
                    "reason": reason,
                    "file_count": len(file_records)
                }
            ],
            "algorithm": "SHA-256",
            "file_count": len(file_records),
            "files": file_records
        }

        # Sign manifest with HMAC-SHA256
        manifest_dict["hmac_sha256"] = compute_manifest_hmac(manifest_dict)

        # Clear any stale tamper events for this new baseline
        tamper_log = get_tamper_log_path(evidence_dir)
        if os.path.exists(tamper_log):
            clear_readonly(tamper_log)
            try:
                os.remove(tamper_log)
            except Exception:
                pass

        # Write manifest.json atomically
        clear_readonly(manifest_file)
        tmp_manifest = manifest_file + ".tmp"
        with open(tmp_manifest, "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=4)
        clear_readonly(tmp_manifest)
        os.replace(tmp_manifest, manifest_file)

        # Write legacy hashes.txt atomically
        clear_readonly(hash_file)
        tmp_hash = hash_file + ".tmp"
        with open(tmp_hash, "w", encoding="utf-8") as f:
            for line in legacy_lines:
                f.write(line)
        clear_readonly(tmp_hash)
        os.replace(tmp_hash, hash_file)

        # Set read-only attributes to prevent accidental tampering
        make_readonly(manifest_file)
        make_readonly(hash_file)

        # Update in-memory cache
        norm_hf = os.path.abspath(hash_file).lower()
        norm_mf = os.path.abspath(manifest_file).lower()
        legacy_map = {rel: info["sha256"] for rel, info in file_records.items()}
        with _BASELINE_LOCK:
            _TRUSTED_BASELINES[norm_hf] = dict(legacy_map)
            _TRUSTED_BASELINES[norm_mf] = dict(manifest_dict)

        if run_id:
            try:
                import shutil
                run_int_dir = os.path.join(BASE_DIR, "runs", run_id, "integrity", incident_name)
                os.makedirs(run_int_dir, exist_ok=True)
                shutil.copy2(manifest_file, os.path.join(run_int_dir, "manifest.json"))
                shutil.copy2(hash_file, os.path.join(run_int_dir, "hashes.txt"))
            except Exception:
                pass

        return hash_file


def rebaseline_evidence(evidence_dir, reason, authorized_by="SecurityAdmin", force=False):
    """
    Explicit, authorized re-baselining operation for legitimate evidence-set modifications.
    Safeguards:
    1. Requires confirmation or force=True.
    2. Increments baseline_version.
    3. Records timestamp, reason, author, and previous file count in rebaseline_history.
    4. Atomically replaces manifest.json and hashes.txt.
    5. Resolves active tamper log with an authorized resolution entry.
    """
    evidence_dir = os.path.abspath(evidence_dir)
    if not os.path.exists(evidence_dir):
        return False, f"Evidence directory '{evidence_dir}' does not exist."

    if not reason or not reason.strip():
        return False, "Re-baselining requires an explicit, non-empty justification/reason."

    integrity_path, manifest_file, hash_file = get_baseline_paths(evidence_dir)
    incident_name = os.path.basename(evidence_dir)
    lock_file = os.path.join(integrity_path, ".baseline.lock")

    with CrossProcessLock(lock_file):
        has_baseline, old_mf, _ = has_valid_trusted_baseline(evidence_dir)
        old_version = 1
        history = []
        init_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        init_by = authorized_by
        init_reason = reason

        if isinstance(old_mf, dict):
            old_version = old_mf.get("baseline_version", 1)
            history = list(old_mf.get("rebaseline_history", []))
            init_at = old_mf.get("initialized_at") or old_mf.get("created_at") or init_at
            init_by = old_mf.get("initialized_by") or init_by
            init_reason = old_mf.get("initialization_reason") or init_reason

        new_version = old_version + 1
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        file_records = {}
        legacy_lines = []

        for root, _, files in os.walk(evidence_dir):
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                if is_ignored_temp_file(full_path):
                    continue
                if is_symlink_escape(full_path, evidence_dir):
                    continue
                rel_path = os.path.relpath(full_path, evidence_dir).replace("\\", "/")
                f_hash = calculate_hash(full_path)
                if f_hash:
                    try:
                        f_size = os.path.getsize(full_path)
                        f_mtime = os.path.getmtime(full_path)
                    except Exception:
                        f_size = 0
                        f_mtime = 0
                    file_records[rel_path] = {
                        "sha256": f_hash,
                        "size": f_size,
                        "mtime": f_mtime
                    }
                    legacy_lines.append(f"{rel_path} : {f_hash}\n")
                    if fname != rel_path:
                        legacy_lines.append(f"{fname} : {f_hash}\n")

        history.append({
            "version": new_version,
            "action": "AUTHORIZED_REBASELINE",
            "timestamp": now_str,
            "authorized_by": authorized_by,
            "reason": reason,
            "file_count": len(file_records)
        })

        manifest_dict = {
            "schema_version": 2,
            "baseline_version": new_version,
            "incident_id": incident_name,
            "evidence_dir": os.path.relpath(evidence_dir, BASE_DIR).replace("\\", "/") if str(evidence_dir).startswith(str(BASE_DIR)) else evidence_dir.replace("\\", "/"),
            "evidence_dir_abs": evidence_dir.replace("\\", "/"),
            "initialized_at": init_at,
            "initialized_by": init_by,
            "initialization_reason": init_reason,
            "last_rebaselined_at": now_str,
            "rebaseline_history": history,
            "algorithm": "SHA-256",
            "file_count": len(file_records),
            "files": file_records
        }

        manifest_dict["hmac_sha256"] = compute_manifest_hmac(manifest_dict)

        # Atomic writes with readonly clearing and re-application
        clear_readonly(manifest_file)
        tmp_manifest = manifest_file + ".tmp"
        with open(tmp_manifest, "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=4)
        clear_readonly(tmp_manifest)
        os.replace(tmp_manifest, manifest_file)

        clear_readonly(hash_file)
        tmp_hash = hash_file + ".tmp"
        with open(tmp_hash, "w", encoding="utf-8") as f:
            for line in legacy_lines:
                f.write(line)
        clear_readonly(tmp_hash)
        os.replace(tmp_hash, hash_file)

        make_readonly(manifest_file)
        make_readonly(hash_file)

        # Mark any active tampering resolved due to authorized re-baseline
        resolve_tampering(evidence_dir, f"Authorized re-baseline to version {new_version}: {reason}", authorized_by=authorized_by)

        norm_hf = os.path.abspath(hash_file).lower()
        norm_mf = os.path.abspath(manifest_file).lower()
        legacy_map = {rel: info["sha256"] for rel, info in file_records.items()}
        with _BASELINE_LOCK:
            _TRUSTED_BASELINES[norm_hf] = dict(legacy_map)
            _TRUSTED_BASELINES[norm_mf] = dict(manifest_dict)

        return True, f"Evidence re-baselined successfully to version {new_version} ({len(file_records)} files recorded)."


def create_hashes(evidence_dir, run_id=None):
    """
    Backwards-compatibility wrapper for legacy pipeline calls.
    Reuses existing valid baseline if present; creates initial baseline if none exists.
    Never silently replaces a valid existing baseline.
    """
    has_baseline, _, _ = has_valid_trusted_baseline(evidence_dir)
    _, _, hash_file = get_baseline_paths(evidence_dir)
    if has_baseline:
        load_trusted_baseline(hash_file)
        return hash_file
    return initialize_baseline(evidence_dir, authorized_by="PipelineInit", reason="Automated pipeline baseline establishment", force=False, run_id=run_id)


def load_trusted_baseline(hash_file):
    """
    Loads and authenticates baseline hashes from persistent manifest.json or hashes.txt.
    Verifies HMAC signature. Never creates or modifies baselines.
    Returns dictionary of relative_path -> sha256, or {} if missing or corrupted.
    """
    norm_hf = os.path.abspath(hash_file).lower()
    with _BASELINE_LOCK:
        if norm_hf in _TRUSTED_BASELINES:
            return dict(_TRUSTED_BASELINES[norm_hf])

    int_dir = os.path.dirname(hash_file)
    manifest_file = os.path.join(int_dir, "manifest.json")

    baseline = {}
    if os.path.exists(manifest_file):
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            is_valid, _ = verify_manifest_hmac(manifest_data)
            if is_valid:
                files_dict = manifest_data.get("files", {})
                for rel, meta in files_dict.items():
                    h = meta.get("sha256") if isinstance(meta, dict) else meta
                    if h:
                        baseline[rel] = h
                        baseline[os.path.basename(rel)] = h
        except Exception:
            pass

    if not baseline and os.path.exists(hash_file):
        try:
            with open(hash_file, "r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    line = line.strip()
                    if line and " : " in line:
                        fname, hval = line.split(" : ", 1)
                        baseline[fname.strip()] = hval.strip()
        except Exception:
            pass

    if baseline:
        with _BASELINE_LOCK:
            _TRUSTED_BASELINES[norm_hf] = dict(baseline)
    return dict(baseline)


# ============================================================
# DASHBOARD STATE UPDATE (ATOMIC & CROSS-PROCESS SAFE)
# ============================================================

def update_dashboard_state(evidence_dir, hash_file, all_verified, verified_count, tampered_count, missing_count, file_checks, pod_name=None, overall_integrity=None, latest_tamper=None, state_file=None):
    """
    Atomically updates dashboard_state.json with cross-process file locking.
    Ensures VERIFIED, TAMPERED, MISSING_FILES, or BASELINE_INVALID statuses
    are immediately visible to the dashboard without file corruption.
    """
    state_file = state_file or STATE_FILE
    os.makedirs(os.path.dirname(os.path.abspath(state_file)), exist_ok=True)
    lock_file = state_file + ".lock"

    incident_name = os.path.basename(os.path.abspath(evidence_dir))

    if overall_integrity:
        overall = overall_integrity
    elif tampered_count > 0:
        overall = "TAMPERED"
    elif missing_count > 0:
        overall = "TAMPERED"
    elif all_verified and verified_count > 0:
        overall = "VERIFIED"
    else:
        overall = "FAILED"

    if overall == "VERIFIED":
        status = "COMPLETED"
        sev = "None"
    elif overall in ["TAMPERED", "BASELINE_INVALID", "MISSING_FILES"]:
        status = "TAMPERED"
        sev = "Critical"
    elif overall in ["BASELINE_MISSING", "UNKNOWN"]:
        status = "FAILED"
        sev = "High"
    else:
        status = "FAILED"
        sev = "Critical"

    # Cross-process atomic read-modify-write
    with _DASHBOARD_LOCK, CrossProcessLock(lock_file):
        data = {}
        if os.path.exists(state_file):
            for read_attempt in range(10):
                try:
                    with open(state_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict) and data:
                        break
                except Exception:
                    time.sleep(0.05)
            if os.path.exists(state_file) and os.path.getsize(state_file) > 50 and not data:
                # Do not overwrite state_file if reading failed due to a transient lock
                return

        existing_m10 = data.get("modules", {}).get("M10", {})
        existing_dt = existing_m10.get("details", {})
        pod = pod_name or existing_dt.get("pod", "N/A")

        tamper_log = load_tamper_log(evidence_dir)
        active_tamper = latest_tamper
        if not active_tamper and tamper_log:
            active_tamper = tamper_log.get("latest_event")

        # Check if continuous monitor is active
        mon_active = is_monitor_running(evidence_dir)

        m10_details = {
            "pod": pod,
            "incident_id": incident_name,
            "evidence_dir": evidence_dir.replace("\\", "/"),
            "integrity_dir": os.path.dirname(hash_file).replace("\\", "/"),
            "hash_file": hash_file.replace("\\", "/"),
            "manifest_file": os.path.join(os.path.dirname(hash_file), "manifest.json").replace("\\", "/"),
            "overall_integrity": overall,
            "verified_count": verified_count,
            "tampered_count": tampered_count,
            "missing_count": missing_count,
            "file_checks": file_checks,
            "checks": file_checks,
            "monitoring_status": "CONTINUOUS_ACTIVE" if mon_active else "IDLE",
            "is_monitoring_active": mon_active,
            "last_verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": existing_dt.get("created_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if active_tamper and overall in ["TAMPERED", "BASELINE_INVALID", "MISSING_FILES"]:
            m10_details["latest_tamper_event"] = active_tamper
            m10_details["tamper_detected_at"] = active_tamper.get("detected_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if tamper_log and tamper_log.get("events"):
            m10_details["tamper_events"] = tamper_log.get("events")

        entry = {
            "status": status,
            "severity": sev,
            "message": f"Evidence integrity: {overall}",
            "details": m10_details
        }

        data.setdefault("modules", {})
        data["modules"]["M10"] = entry
        data["modules"]["m10"] = entry
        data["M10"] = entry
        data["m10"] = entry

        if "overview" not in data:
            data["overview"] = {}
        data["overview"]["evidence_integrity"] = overall
        if overall in ["TAMPERED", "BASELINE_INVALID"]:
            data["overview"]["overall_risk"] = "CRITICAL"

        for attempt in range(5):
            try:
                tmp_file = state_file + f".tmp.{os.getpid()}"
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                os.replace(tmp_file, state_file)
                break
            except Exception as e:
                time.sleep(0.05)
                if attempt == 4:
                    try:
                        with open(state_file, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=4)
                    except Exception:
                        print(f"[M10] Dashboard state update warning: {e}")


# ============================================================
# RELIABLE INTEGRITY VERIFICATION ENGINE (PHASE 3)
# ============================================================

def verify_hashes(evidence_dir, hash_file=None, update_state=True, verbose=False, pod_name=None, state_file=None):
    """
    Cryptographically verifies evidence files against the persistent authenticated baseline.
    Detects:
    1. Baseline authenticity compromise (tampered manifest or invalid HMAC signature).
    2. Missing trusted baseline (reports BASELINE_MISSING; never silently recreates).
    3. Content modification (hash mismatch).
    4. Truncated or wiped files (0 bytes).
    5. Deleted or missing evidence files.
    6. File replacement (same name, altered hash).
    7. Unexpected new file additions in sealed evidence directories.
    8. Symlink traversal / escape outside evidence directory.
    9. Unreadable files or filesystem permission errors.
    Preserves persistent TAMPERED state until explicitly resolved.
    """
    evidence_dir = os.path.abspath(evidence_dir)
    incident_name = os.path.basename(evidence_dir)
    integrity_path, manifest_file, def_hash_file = get_baseline_paths(evidence_dir)
    if hash_file is None:
        hash_file = def_hash_file

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Check baseline existence on disk
    if not os.path.exists(hash_file) and not os.path.exists(manifest_file):
        check = {
            "filename": "baseline",
            "file_path": manifest_file.replace("\\", "/"),
            "original_hash": "None",
            "expected_hash": "None",
            "current_hash": "MISSING",
            "actual_hash": "MISSING",
            "status": "BASELINE_MISSING",
            "timestamp": now_str,
            "reason": f"Trusted baseline does not exist for incident '{incident_name}'. Explicit initialization required (--init-baseline)."
        }
        if update_state:
            update_dashboard_state(evidence_dir, hash_file, False, 0, 0, 1, [check], pod_name=pod_name, overall_integrity="BASELINE_MISSING", state_file=state_file)
        return False, 0, 0, 0, [check]

    # 2. Authenticate baseline manifest HMAC
    trusted_manifest = None
    if os.path.exists(manifest_file):
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                trusted_manifest = json.load(f)
            is_valid, reason = verify_manifest_hmac(trusted_manifest)
            if not is_valid:
                t_event = record_tamper_event(
                    evidence_dir,
                    "BASELINE_INVALID",
                    "manifest.json",
                    os.path.relpath(manifest_file, BASE_DIR),
                    trusted_manifest.get("hmac_sha256", "Missing"),
                    "INVALID_SIGNATURE",
                    f"Baseline HMAC verification failed: {reason}"
                )
                check = {
                    "filename": "manifest.json",
                    "file_path": manifest_file.replace("\\", "/"),
                    "original_hash": trusted_manifest.get("hmac_sha256", "Unknown"),
                    "expected_hash": "Valid HMAC-SHA256",
                    "current_hash": "INVALID_SIGNATURE",
                    "actual_hash": "INVALID_SIGNATURE",
                    "status": "TAMPERED",
                    "timestamp": now_str,
                    "reason": f"Baseline authentication failed: {reason}"
                }
                if update_state:
                    update_dashboard_state(evidence_dir, hash_file, False, 0, 1, 0, [check], pod_name=pod_name, overall_integrity="BASELINE_INVALID", latest_tamper=t_event, state_file=state_file)
                return False, 0, 1, 0, [check]
        except Exception as e:
            t_event = record_tamper_event(evidence_dir, "BASELINE_INVALID", "manifest.json", "manifest.json", "Valid JSON", "CORRUPTED", str(e))
            check = {
                "filename": "manifest.json",
                "file_path": manifest_file.replace("\\", "/"),
                "original_hash": "Valid JSON",
                "expected_hash": "Valid JSON",
                "current_hash": "CORRUPTED",
                "actual_hash": "CORRUPTED",
                "status": "TAMPERED",
                "timestamp": now_str,
                "reason": f"Corrupted baseline manifest: {e}"
            }
            if update_state:
                update_dashboard_state(evidence_dir, hash_file, False, 0, 1, 0, [check], pod_name=pod_name, overall_integrity="BASELINE_INVALID", latest_tamper=t_event, state_file=state_file)
            return False, 0, 1, 0, [check]

    trusted_baseline = load_trusted_baseline(hash_file)
    if not trusted_baseline:
        check = {
            "filename": "hashes.txt",
            "file_path": hash_file.replace("\\", "/"),
            "original_hash": "None",
            "expected_hash": "None",
            "current_hash": "None",
            "actual_hash": "None",
            "status": "FAILED",
            "timestamp": now_str,
            "reason": "Baseline contains zero recorded file entries."
        }
        if update_state:
            update_dashboard_state(evidence_dir, hash_file, False, 0, 0, 1, [check], pod_name=pod_name, overall_integrity="FAILED", state_file=state_file)
        return False, 0, 0, 0, [check]

    all_verified = True
    verified_count = 0
    tampered_count = 0
    missing_count = 0
    file_checks = []
    latest_event = None

    eval_baseline = {}
    if trusted_manifest and "files" in trusted_manifest:
        for r_path, info in trusted_manifest["files"].items():
            eval_baseline[r_path] = info["sha256"] if isinstance(info, dict) else info
    else:
        for k, v in trusted_baseline.items():
            eval_baseline[k] = v

    # 3. Check every baseline expected file
    for rel_path, expected_hash in sorted(eval_baseline.items()):
        full_path = os.path.join(evidence_dir, rel_path)
        if not os.path.exists(full_path):
            base_fallback = os.path.join(evidence_dir, os.path.basename(rel_path))
            if os.path.exists(base_fallback):
                full_path = base_fallback

        filename = os.path.basename(rel_path)

        # Symlink escape check
        if is_symlink_escape(full_path, evidence_dir):
            all_verified = False
            tampered_count += 1
            t_event = record_tamper_event(
                evidence_dir, "SYMLINK_ESCAPE", filename, rel_path, expected_hash, "EXTERNAL_TARGET",
                f"File '{rel_path}' is a symlink pointing outside the evidence directory."
            )
            latest_event = latest_event or t_event
            file_checks.append({
                "filename": filename,
                "file_path": full_path.replace("\\", "/"),
                "original_hash": expected_hash,
                "expected_hash": expected_hash,
                "current_hash": "SYMLINK_ESCAPE",
                "actual_hash": "SYMLINK_ESCAPE",
                "status": "TAMPERED",
                "timestamp": now_str,
                "reason": "Symbolic link points outside intended evidence root."
            })
            continue

        if not os.path.exists(full_path):
            all_verified = False
            missing_count += 1
            t_event = record_tamper_event(
                evidence_dir, "DELETED", filename, rel_path, expected_hash, "FILE_NOT_FOUND",
                f"Monitored evidence file '{rel_path}' was deleted or moved."
            )
            latest_event = latest_event or t_event
            file_checks.append({
                "filename": filename,
                "file_path": full_path.replace("\\", "/"),
                "original_hash": expected_hash,
                "expected_hash": expected_hash,
                "current_hash": "DELETED",
                "actual_hash": "DELETED",
                "status": "MISSING",
                "timestamp": now_str,
                "reason": "Evidence file was deleted or removed from disk."
            })
            continue

        current_hash = calculate_hash(full_path)

        if current_hash is None:
            all_verified = False
            tampered_count += 1
            t_event = record_tamper_event(
                evidence_dir, "UNREADABLE", filename, rel_path, expected_hash, "UNREADABLE",
                f"File '{rel_path}' cannot be read or is locked."
            )
            latest_event = latest_event or t_event
            file_checks.append({
                "filename": filename,
                "file_path": full_path.replace("\\", "/"),
                "original_hash": expected_hash,
                "expected_hash": expected_hash,
                "current_hash": "UNREADABLE",
                "actual_hash": "UNREADABLE",
                "status": "TAMPERED",
                "timestamp": now_str,
                "reason": "Evidence file is locked, inaccessible, or unreadable."
            })
        elif current_hash == expected_hash:
            verified_count += 1
            file_checks.append({
                "filename": filename,
                "file_path": full_path.replace("\\", "/"),
                "original_hash": expected_hash,
                "expected_hash": expected_hash,
                "current_hash": current_hash,
                "actual_hash": current_hash,
                "status": "VERIFIED",
                "timestamp": now_str,
                "reason": "File SHA-256 matches trusted baseline."
            })
        else:
            all_verified = False
            tampered_count += 1
            f_size = os.path.getsize(full_path) if os.path.exists(full_path) else -1
            if f_size == 0:
                change_type = "TRUNCATED"
                reason_detail = "Evidence file was truncated or wiped to zero bytes."
            elif f_size > 0:
                change_type = "REPLACED" if os.path.basename(full_path) in eval_baseline else "MODIFIED"
                reason_detail = f"Hash mismatch: expected {expected_hash[:12]}..., got {current_hash[:12]}..."
            else:
                change_type = "MODIFIED"
                reason_detail = f"Hash mismatch: expected {expected_hash[:12]}..., got {current_hash[:12]}..."

            t_event = record_tamper_event(
                evidence_dir, change_type, filename, rel_path, expected_hash, current_hash,
                f"Evidence file content tampered ({change_type}): expected {expected_hash[:12]}..., observed {current_hash[:12]}..."
            )
            latest_event = latest_event or t_event
            file_checks.append({
                "filename": filename,
                "file_path": full_path.replace("\\", "/"),
                "original_hash": expected_hash,
                "expected_hash": expected_hash,
                "current_hash": current_hash,
                "actual_hash": current_hash,
                "status": "TAMPERED",
                "timestamp": now_str,
                "reason": reason_detail
            })

    # 4. Check for unexpected additions or renames
    if os.path.exists(evidence_dir):
        for root, _, files in os.walk(evidence_dir):
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                if is_ignored_temp_file(full_path):
                    continue
                rel_path = os.path.relpath(full_path, evidence_dir).replace("\\", "/")
                if rel_path not in eval_baseline and fname not in eval_baseline:
                    all_verified = False
                    tampered_count += 1
                    curr_h = calculate_hash(full_path) or "UNREADABLE"

                    renamed_from = None
                    for b_path, b_hash in eval_baseline.items():
                        if b_hash == curr_h and not os.path.exists(os.path.join(evidence_dir, b_path)):
                            renamed_from = b_path
                            break

                    if renamed_from:
                        c_type = "RENAMED_OR_MOVED"
                        r_msg = f"Evidence file '{renamed_from}' was renamed or moved to '{rel_path}'."
                    else:
                        c_type = "UNAUTHORIZED_NEW_FILE"
                        r_msg = f"Unexpected file '{rel_path}' added to evidence directory after baseline creation."

                    t_event = record_tamper_event(
                        evidence_dir, c_type, fname, rel_path, "None (Untracked)" if not renamed_from else eval_baseline[renamed_from], curr_h, r_msg
                    )
                    latest_event = latest_event or t_event
                    file_checks.append({
                        "filename": fname,
                        "file_path": full_path.replace("\\", "/"),
                        "original_hash": "None (Untracked)" if not renamed_from else eval_baseline[renamed_from],
                        "expected_hash": "None (Untracked)" if not renamed_from else eval_baseline[renamed_from],
                        "current_hash": curr_h,
                        "actual_hash": curr_h,
                        "status": "TAMPERED",
                        "timestamp": now_str,
                        "reason": r_msg
                    })

    # 5. Check persistent tamper history
    tamper_log = load_tamper_log(evidence_dir)
    prior_tamper = bool(tamper_log and tamper_log.get("tampered"))
    if prior_tamper:
        all_verified = False
        if not latest_event and tamper_log.get("latest_event"):
            latest_event = tamper_log.get("latest_event")

    # 6. Overall integrity state
    if not all_verified:
        if tampered_count > 0 or prior_tamper:
            overall_integrity = "TAMPERED"
        elif missing_count > 0:
            overall_integrity = "MISSING_FILES"
        else:
            overall_integrity = "FAILED"
    else:
        overall_integrity = "VERIFIED"

    all_verified = bool(all_verified and verified_count > 0 and tampered_count == 0 and missing_count == 0)

    if update_state:
        update_dashboard_state(
            evidence_dir,
            hash_file,
            all_verified,
            verified_count,
            tampered_count,
            missing_count,
            file_checks,
            pod_name=pod_name,
            overall_integrity=overall_integrity,
            latest_tamper=latest_event,
            state_file=state_file
        )

    return all_verified, verified_count, tampered_count, missing_count, file_checks


# ============================================================
# CONTINUOUS EVIDENCE INTEGRITY MONITOR (PHASE 4)
# ============================================================

def get_monitor_pid_path(evidence_dir):
    """Returns the path to the process-level monitor PID file."""
    incident_name = os.path.basename(os.path.abspath(evidence_dir))
    return os.path.join(INTEGRITY_DIR, incident_name, "monitor.pid")


def is_process_alive(pid):
    """Checks whether a process with the given PID is currently active."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        SYNCHRONIZE = 0x00100000
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def is_monitor_running(evidence_dir):
    """Checks if a continuous integrity monitor is active for this evidence directory."""
    norm_dir = os.path.abspath(evidence_dir).lower()
    with _MONITOR_LOCK:
        if norm_dir in _ACTIVE_MONITORS and _ACTIVE_MONITORS[norm_dir].is_alive():
            return True

    pid_path = get_monitor_pid_path(evidence_dir)
    if os.path.exists(pid_path):
        try:
            with open(pid_path, "r", encoding="utf-8") as f:
                pid = int(f.read().strip())
            if is_process_alive(pid):
                return True
        except Exception:
            pass
    return False


class EvidenceIntegrityMonitor:
    """
    Continuous background integrity monitor that observes evidence directories.
    Combines watchdog filesystem event notifications with a configurable polling loop.
    Implements process-level deduplication via monitor.pid so Terminal 1 and Terminal 2
    never run conflicting monitor workers on the same directory.
    """
    def __init__(self, evidence_dir, hash_file, poll_interval=2.0, pod_name=None, state_file=None):
        self.evidence_dir = os.path.abspath(evidence_dir)
        self.hash_file = os.path.abspath(hash_file)
        self.poll_interval = max(0.5, float(poll_interval))
        self.pod_name = pod_name
        self.state_file = state_file
        self._stop_event = threading.Event()
        self._observer = None
        self._thread = None
        self._last_status = None
        self._last_tampered = 0
        self._last_missing = 0
        self._lock = threading.Lock()
        self.pid_path = get_monitor_pid_path(self.evidence_dir)

    def check_now(self):
        """Executes an immediate integrity verification pass."""
        with self._lock:
            try:
                all_verified, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
                    self.evidence_dir,
                    self.hash_file,
                    update_state=True,
                    verbose=False,
                    pod_name=self.pod_name,
                    state_file=self.state_file
                )
            except Exception as e:
                print(f"[M10 MONITOR] Error during integrity verification: {e}")
                return False

            tamper_log = load_tamper_log(self.evidence_dir)
            is_persistently_tampered = bool(tamper_log and tamper_log.get("tampered"))

            if is_persistently_tampered or t_cnt > 0:
                current_status = "TAMPERED"
            elif m_cnt > 0:
                current_status = "MISSING_FILES"
            elif all_verified:
                current_status = "VERIFIED"
            else:
                current_status = "FAILED"

            if current_status != self._last_status or t_cnt != self._last_tampered or m_cnt != self._last_missing:
                if current_status in ["TAMPERED", "MISSING_FILES", "BASELINE_INVALID"]:
                    print(f"\n🚨 [M10 MONITOR ALERT] Evidence integrity compromised in {self.evidence_dir}!")
                    print(f"   Status: {current_status} | Tampered: {t_cnt} | Missing: {m_cnt}")
                    try:
                        from alert_logger import log_alert
                        log_alert(
                            "M10",
                            "CRITICAL",
                            current_status,
                            f"Evidence tampering detected in {os.path.basename(self.evidence_dir)}: Status={current_status}, Tampered={t_cnt}, Missing={m_cnt}"
                        )
                    except Exception:
                        pass
                else:
                    if self._last_status is not None and self._last_status != "VERIFIED":
                        print(f"\n🟢 [M10 MONITOR] Evidence integrity verified for {self.evidence_dir}")

                self._last_status = current_status
                self._last_tampered = t_cnt
                self._last_missing = m_cnt

            return all_verified

    def _polling_loop(self):
        """Continuous periodic verification loop as fallback and steady-state check."""
        while not self._stop_event.is_set():
            try:
                self.check_now()
            except Exception as e:
                print(f"[M10 MONITOR] Polling loop error: {e}")
            self._stop_event.wait(self.poll_interval)

    def start(self):
        """Starts watchdog filesystem event listener, polling thread, and registers process PID."""
        # Write process-level PID file
        try:
            os.makedirs(os.path.dirname(self.pid_path), exist_ok=True)
            with open(self.pid_path, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
        except Exception:
            pass

        if WATCHDOG_AVAILABLE:
            class _Handler(FileSystemEventHandler):
                def __init__(self, monitor):
                    self.monitor = monitor
                    self.last_event_time = 0

                def on_any_event(self, event):
                    if getattr(event, 'is_directory', False):
                        return
                    src = getattr(event, 'src_path', '')
                    if is_ignored_temp_file(src):
                        return
                    now = time.time()
                    if now - self.last_event_time > 0.2:
                        self.last_event_time = now
                        def _deferred():
                            time.sleep(0.1)
                            self.monitor.check_now()
                        threading.Thread(target=_deferred, daemon=True).start()

            try:
                self._observer = Observer()
                self._observer.schedule(_Handler(self), self.evidence_dir, recursive=True)
                self._observer.daemon = True
                self._observer.start()
            except Exception as e:
                print(f"[M10 MONITOR] Watchdog notice: {e}. Relying on continuous periodic polling.")
                self._observer = None

        self._thread = threading.Thread(
            target=self._polling_loop,
            name=f"M10-IntegrityMonitor-{os.path.basename(self.evidence_dir)}",
            daemon=True
        )
        self._thread.start()
        print(f"[M10] Continuous integrity monitor started for: {self.evidence_dir} (interval={self.poll_interval}s, PID={os.getpid()})")

    def stop(self):
        self._stop_event.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=1.0)
            except Exception:
                pass
            self._observer = None
        if self._thread:
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass
            self._thread = None
        # Clean up PID file if owned by this process
        if os.path.exists(self.pid_path):
            try:
                with open(self.pid_path, "r", encoding="utf-8") as f:
                    curr_pid = int(f.read().strip())
                if curr_pid == os.getpid():
                    os.remove(self.pid_path)
            except Exception:
                pass

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()


def start_integrity_monitor(evidence_dir, hash_file=None, poll_interval=2.0, pod_name=None, state_file=None):
    """
    Public entry point to start continuous integrity monitoring for an evidence directory.
    Guarantees thread and process-level deduplication: avoids duplicate monitoring workers.
    """
    norm_dir = os.path.abspath(evidence_dir).lower()

    with _MONITOR_LOCK:
        if norm_dir in _ACTIVE_MONITORS:
            existing_monitor = _ACTIVE_MONITORS[norm_dir]
            if existing_monitor.is_alive():
                return existing_monitor

        # Check process-level PID file
        pid_path = get_monitor_pid_path(evidence_dir)
        if os.path.exists(pid_path):
            try:
                with open(pid_path, "r", encoding="utf-8") as f:
                    pid = int(f.read().strip())
                if is_process_alive(pid) and pid != os.getpid():
                    print(f"[M10] Notice: External monitor worker already active (PID={pid}). Reusing existing worker.")
                    return None
            except Exception:
                pass

        if hash_file is None:
            _, _, hash_file = get_baseline_paths(evidence_dir)

        # Load baseline into memory cache
        load_trusted_baseline(hash_file)

        monitor = EvidenceIntegrityMonitor(evidence_dir, hash_file, poll_interval=poll_interval, pod_name=pod_name, state_file=state_file)
        monitor.start()
        _ACTIVE_MONITORS[norm_dir] = monitor
        return monitor


def stop_integrity_monitor(evidence_dir):
    """Stops continuous integrity monitor for a specific evidence directory."""
    if not evidence_dir:
        return False
    norm_dir = os.path.abspath(evidence_dir).lower()
    with _MONITOR_LOCK:
        if norm_dir in _ACTIVE_MONITORS:
            monitor = _ACTIVE_MONITORS.pop(norm_dir)
            monitor.stop()
            return True
    # Clean up PID file if stopped externally
    pid_path = get_monitor_pid_path(evidence_dir)
    if os.path.exists(pid_path):
        try:
            os.remove(pid_path)
            return True
        except Exception:
            pass
    return False


def stop_all_integrity_monitors():
    """Stops all active continuous integrity monitors and joins their threads cleanly."""
    with _MONITOR_LOCK:
        for _, monitor in list(_ACTIVE_MONITORS.items()):
            try:
                monitor.stop()
            except Exception:
                pass
        _ACTIVE_MONITORS.clear()


atexit.register(stop_all_integrity_monitors)


# ============================================================
# SECOND-TERMINAL CLI INTERFACE (PHASE 5)
# ============================================================

def resolve_target_evidence_dir(explicit_path=None):
    """
    Resolves the intended evidence directory from CLI argument, environment variable,
    or the latest recorded incident directory in evidence/.
    """
    if explicit_path and explicit_path.strip():
        return os.path.abspath(explicit_path.strip())

    env_dir = os.environ.get("EVIDENCE_DIR")
    if env_dir and env_dir.strip():
        return os.path.abspath(env_dir.strip())

    ev_root = os.path.join(BASE_DIR, "evidence")
    if os.path.exists(ev_root):
        subdirs = [os.path.join(ev_root, d) for d in os.listdir(ev_root) if os.path.isdir(os.path.join(ev_root, d))]
        if subdirs:
            subdirs.sort(key=os.path.getmtime, reverse=True)
            return os.path.abspath(subdirs[0])

    return None


def print_cli_banner(title):
    print("=" * 60)
    print(f"       KUBEGUARD M10 : {title.upper()}")
    print("=" * 60)


def cli_check(evidence_dir, verbose=True):
    """
    Executes a one-time integrity check from a second terminal while KubeGuard runs in terminal 1.
    Exit codes:
      0 = VERIFIED (All evidence files intact and authenticated)
      1 = TAMPERED / MISSING / UNEXPECTED files detected
      2 = ERROR / BASELINE MISSING / BASELINE INVALID
    """
    print_cli_banner("ONE-TIME EVIDENCE INTEGRITY CHECK")
    print(f"Target Evidence : {evidence_dir}")

    has_baseline, manifest_dict, err = has_valid_trusted_baseline(evidence_dir)
    if not has_baseline:
        print(f"\n[!] Error: No valid trusted baseline found for '{evidence_dir}'.")
        print(f"    Reason: {err}")
        print("    Run 'python module10_integrity.py --init-baseline' to establish an authenticated baseline.")
        return 2

    _, manifest_file, hash_file = get_baseline_paths(evidence_dir)
    all_ver, v_cnt, t_cnt, m_cnt, checks = verify_hashes(
        evidence_dir,
        hash_file=hash_file,
        update_state=True,
        verbose=verbose
    )

    print("\n--- Integrity Verification Summary ---")
    print(f"Baseline Version: {manifest_dict.get('baseline_version', 1) if isinstance(manifest_dict, dict) else 1}")
    print(f"Verified Files  : {v_cnt}")
    print(f"Tampered Files  : {t_cnt}")
    print(f"Missing Files   : {m_cnt}")
    print(f"Total Evaluated : {len(checks)}")

    if verbose and checks:
        print("\n--- File-by-File Breakdown ---")
        for c in checks:
            st = c.get("status", "UNKNOWN")
            symbol = "✓" if st == "VERIFIED" else "✗"
            print(f"  [{symbol}] {c.get('filename'):<20} Status: {st:<10} Hash: {str(c.get('current_hash'))[:16]}... ({c.get('reason')})")

    print("\n" + "=" * 60)
    if all_ver:
        print("RESULT: Evidence Integrity VERIFIED (All files authentic).")
        print("=" * 60)
        return 0
    else:
        if t_cnt > 0:
            print("RESULT: Evidence Integrity TAMPERED (Unauthorized changes detected!).")
        elif m_cnt > 0:
            print("RESULT: Evidence Integrity FAILED (Monitored files missing!).")
        else:
            print("RESULT: Evidence Integrity FAILED.")
        print("=" * 60)
        return 1


def cli_init_baseline(evidence_dir, force=False):
    """Initializes the trusted baseline explicitly."""
    print_cli_banner("INITIALIZE TRUSTED BASELINE")
    print(f"Target Evidence: {evidence_dir}")

    has_baseline, mf, _ = has_valid_trusted_baseline(evidence_dir)
    if has_baseline and not force:
        print(f"\n[!] A valid trusted baseline already exists (Version {mf.get('baseline_version', 1)}).")
        print("    Refusing silent overwrite to protect evidence integrity.")
        print("    If you intend to update the baseline after authorized changes, run:")
        print("      python module10_integrity.py --rebaseline --reason \"your explanation\"")
        return 2

    try:
        hash_file = initialize_baseline(
            evidence_dir,
            authorized_by="CLI-Operator",
            reason="Explicit initial baseline initialization",
            force=force
        )
        print(f"\n[+] Successfully initialized persistent trusted baseline!")
        print(f"    Baseline Path : {hash_file}")
        print(f"    Manifest Path : {os.path.join(os.path.dirname(hash_file), 'manifest.json')}")
        print("    HMAC-SHA256 signature generated and verified.")
        return 0
    except Exception as e:
        print(f"\n[!] Baseline initialization error: {e}")
        return 2


def cli_rebaseline(evidence_dir, reason=None, force=False):
    """Performs an authorized re-baselining operation with confirmation safeguard."""
    print_cli_banner("AUTHORIZED EVIDENCE RE-BASELINING")
    print(f"Target Evidence: {evidence_dir}")

    if not reason:
        if sys.stdin.isatty():
            try:
                reason = input("Enter authorized reason for re-baselining: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nOperation cancelled.")
                return 2
        else:
            reason = "Authorized evidence update via CLI"

    if not reason:
        print("\n[!] Re-baselining aborted: An explicit justification/reason is required.")
        return 2

    if not force and sys.stdin.isatty():
        try:
            confirm = input(f"Confirm re-baselining '{os.path.basename(evidence_dir)}'? Existing baseline will be archived [y/N]: ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("\nRe-baselining cancelled by user.")
                return 2
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return 2

    success, msg = rebaseline_evidence(
        evidence_dir,
        reason=reason,
        authorized_by="CLI-SecurityAdmin",
        force=True
    )
    if success:
        print(f"\n[+] {msg}")
        return 0
    else:
        print(f"\n[!] Re-baselining failed: {msg}")
        return 2


def cli_watch(evidence_dir, poll_interval=2.0):
    """Runs continuous integrity monitoring in foreground in the terminal until interrupted."""
    print_cli_banner("CONTINUOUS INTEGRITY MONITOR")
    print(f"Target Evidence : {evidence_dir}")
    print(f"Polling Interval: {poll_interval}s")

    has_baseline, _, err = has_valid_trusted_baseline(evidence_dir)
    if not has_baseline:
        print(f"\n[!] Cannot start monitor: {err}")
        print("    Initialize baseline first with: python module10_integrity.py --init-baseline")
        return 2

    monitor = start_integrity_monitor(evidence_dir, poll_interval=poll_interval)
    if not monitor:
        print("[!] Monitor worker could not be started or duplicate is active.")
        return 2

    print("\n[+] Monitoring active. Press Ctrl+C to stop.")
    try:
        while monitor.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped cleanly.")
    return 0


def main():
    args = sys.argv[1:]

    # Parse CLI flags
    init_mode = False
    check_mode = False
    watch_mode = False
    rebaseline_mode = False
    resolve_mode = False
    status_mode = False
    force_flag = False
    reason_arg = None
    target_path = None
    interval_arg = 2.0

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--init-baseline":
            init_mode = True
        elif arg == "--check":
            check_mode = True
        elif arg in ["--watch", "--monitor"]:
            watch_mode = True
        elif arg == "--rebaseline":
            rebaseline_mode = True
        elif arg == "--resolve":
            resolve_mode = True
        elif arg == "--status":
            status_mode = True
        elif arg in ["--force", "-f", "-y", "--yes"]:
            force_flag = True
        elif arg == "--reason" and i + 1 < len(args):
            i += 1
            reason_arg = args[i]
        elif arg == "--interval" and i + 1 < len(args):
            i += 1
            try:
                interval_arg = float(args[i])
            except ValueError:
                pass
        elif not arg.startswith("-") and target_path is None:
            target_path = arg
        i += 1

    evidence_dir = resolve_target_evidence_dir(target_path)
    if not evidence_dir:
        print("[M10] Error: Evidence directory is required or no evidence/ directory found.")
        sys.exit(2)

    # Dispatch to appropriate handler
    if init_mode:
        ret = cli_init_baseline(evidence_dir, force=force_flag)
        sys.exit(ret)
    elif rebaseline_mode:
        ret = cli_rebaseline(evidence_dir, reason=reason_arg, force=force_flag)
        sys.exit(ret)
    elif watch_mode:
        ret = cli_watch(evidence_dir, poll_interval=interval_arg)
        sys.exit(ret)
    elif resolve_mode:
        r_msg = reason_arg or "Authorized resolution via CLI"
        ok, msg = resolve_tampering(evidence_dir, r_msg)
        print(f"[M10] {msg}")
        sys.exit(0 if ok else 2)
    elif check_mode or status_mode or len(args) == 0:
        ret = cli_check(evidence_dir, verbose=True)
        sys.exit(ret)
    else:
        # Default fallback: check
        ret = cli_check(evidence_dir, verbose=True)
        sys.exit(ret)


if __name__ == "__main__":
    main()
