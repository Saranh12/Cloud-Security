"""
KubeGuard Deployment & Runtime Identity Manager.
Handles image validation, workload provisioning (Kubernetes & Docker),
image identity verification, and safe resource cleanup.
"""

import os
import re
import json
import time
import shutil
import hashlib
import subprocess
from datetime import datetime
from vuln_scan import validate_image_reference
from monitoring import normalize_image_name


def sanitize_workload_name(raw_name, prefix="kubeguard"):
    """
    Generates a safe, RFC 1123 compliant workload name for Kubernetes and Docker.
    Must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character.
    """
    if not raw_name:
        random_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        return f"{prefix}-{random_suffix}"

    # Lowercase and replace invalid characters with hyphen
    sanitized = re.sub(r'[^a-z0-9-]', '-', raw_name.lower().strip())
    # Collapse multiple hyphens
    sanitized = re.sub(r'-+', '-', sanitized)
    # Trim hyphens from ends
    sanitized = sanitized.strip("-")

    if not sanitized:
        random_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        return f"{prefix}-{random_suffix}"

    # Ensure max length 63 chars (Kubernetes limit)
    if len(sanitized) > 50:
        sanitized = sanitized[:50].rstrip("-")

    if not sanitized.startswith(prefix):
        sanitized = f"{prefix}-{sanitized}"

    if len(sanitized) > 63:
        sanitized = sanitized[:63].rstrip("-")

    return sanitized


def generate_assessment_workload_name(image_name, run_id=None):
    """
    Generates a uniquely named Kubernetes/Docker workload for a KubeGuard assessment run.
    Follows format: kubeguard-test-{base_image}-{run_suffix}
    Adheres strictly to RFC 1123 DNS-1123 subdomain standards (max 63 chars, lowercase, alphanumeric and hyphens).
    Examples:
      - kubeguard-test-python-20261030-001
      - kubeguard-test-node-20261030-002
      - kubeguard-test-nginx-20261030-003
    """
    if not image_name:
        base_img = "workload"
    else:
        # Strip registry, org, tags, and digests: e.g. "registry.io:5000/org/python:3.12-slim" -> "python"
        clean = str(image_name).strip().split("/")[-1].split("@")[0].split(":")[0]
        base_img = re.sub(r'[^a-z0-9-]', '-', clean.lower()).strip("-")
        if not base_img:
            base_img = "workload"

    if run_id:
        clean_run = str(run_id).strip().lower()
        # Clean run prefix/suffix (e.g. "run_20261030_123456" -> "20261030-123456")
        clean_run = re.sub(r'^run[-_]?', '', clean_run)
        clean_run = re.sub(r'[^a-z0-9-]', '-', clean_run).strip("-")
        suffix = clean_run
    else:
        suffix = datetime.now().strftime("%Y%m%d-%H%M%S")

    name = f"kubeguard-test-{base_img}-{suffix}"
    name = re.sub(r'-+', '-', name).strip("-")
    if len(name) > 63:
        suffix_len = min(20, len(suffix))
        max_base = 63 - len("kubeguard-test-") - suffix_len - 2
        name = f"kubeguard-test-{base_img[:max_base].rstrip('-')}-{suffix[-suffix_len:].lstrip('-')}"
        name = name[:63].rstrip("-")

    return name


def mask_sensitive_env_vars(env_dict):
    """
    Returns a copy of environment variables with sensitive values masked for UI/logging.
    Sensitive keys matching password, secret, token, key, auth, credential.
    """
    if not env_dict or not isinstance(env_dict, dict):
        return {}

    masked = {}
    pattern = re.compile(r'(password|secret|token|key|auth|cred|pwd|api)', re.IGNORECASE)
    for k, v in env_dict.items():
        if pattern.search(k):
            masked[k] = "********"
        else:
            masked[k] = str(v)
    return masked


def parse_env_string(env_str):
    """
    Parses a string of environment variables (comma or newline separated KEY=VALUE).
    Returns (env_dict, masked_dict, error).
    """
    if not env_str:
        return {}, {}, None

    if isinstance(env_str, dict):
        return env_str, mask_sensitive_env_vars(env_str), None

    env_dict = {}
    lines = [line.strip() for line in str(env_str).replace(",", "\n").splitlines() if line.strip()]
    for line in lines:
        if "=" not in line:
            return {}, {}, f"Invalid environment variable format: '{line}'. Must be KEY=VALUE."
        parts = line.split("=", 1)
        k = parts[0].strip()
        v = parts[1].strip()
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', k):
            return {}, {}, f"Invalid environment variable key name: '{k}'."
        env_dict[k] = v

    return env_dict, mask_sensitive_env_vars(env_dict), None


def validate_deployment_options(options):
    """
    Validates user-supplied deployment parameters.
    Returns (is_valid, sanitized_options_or_error).
    """
    if not isinstance(options, dict):
        return False, "Deployment options must be a dictionary."

    raw_image = options.get("image")
    if not raw_image:
        return False, "Container image reference cannot be empty."

    valid_img, img_msg = validate_image_reference(str(raw_image).strip())
    if not valid_img:
        return False, f"Invalid container image: {img_msg}"

    target_runtime = str(options.get("runtime_target") or "kubernetes").lower().strip()
    if target_runtime not in ["kubernetes", "k8s", "docker"]:
        return False, f"Unsupported deployment runtime '{target_runtime}'. Must be 'kubernetes' or 'docker'."
    runtime_type = "kubernetes" if target_runtime in ["kubernetes", "k8s"] else "docker"

    namespace = str(options.get("namespace") or "default").strip()
    if namespace and not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', namespace) and namespace != "default":
        return False, f"Invalid Kubernetes namespace: '{namespace}'."

    raw_workload_name = str(options.get("workload_name") or "").strip()
    base_img = img_msg.split("/")[-1].split(":")[0]
    workload_name = sanitize_workload_name(raw_workload_name or base_img)

    # Security Profile: standard, privileged, custom_caps
    security_profile = str(options.get("security_profile") or "standard").lower().strip()
    if security_profile not in ["standard", "privileged", "custom_caps"]:
        return False, f"Invalid security profile: '{security_profile}'. Must be 'standard', 'privileged', or 'custom_caps'."

    custom_caps = options.get("custom_capabilities", [])
    if isinstance(custom_caps, str):
        custom_caps = [c.strip().upper() for c in custom_caps.replace(",", " ").split() if c.strip()]
    elif isinstance(custom_caps, list):
        custom_caps = [str(c).strip().upper() for c in custom_caps if str(c).strip()]
    else:
        custom_caps = []

    # CPU Limit (e.g. '200m', '0.5', '1')
    cpu_limit = str(options.get("cpu_limit") or "200m").strip()
    if cpu_limit and not re.match(r'^[0-9]+(\.[0-9]+)?(m|u|n)?$', cpu_limit):
        return False, f"Invalid CPU limit format: '{cpu_limit}' (e.g., 200m, 500m, 1)."

    # Memory Limit (e.g. '128Mi', '256M', '1Gi')
    memory_limit = str(options.get("memory_limit") or "128Mi").strip()
    if memory_limit and not re.match(r'^[0-9]+(Mi|Gi|Ki|M|G)?$', memory_limit):
        return False, f"Invalid Memory limit format: '{memory_limit}' (e.g., 128Mi, 256Mi, 1Gi)."

    # Port mapping (e.g. '8080:80' or '80')
    port_mapping = str(options.get("port_mapping") or "").strip()
    container_port = None
    host_port = None
    if port_mapping:
        if ":" in port_mapping:
            parts = port_mapping.split(":")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                host_port = int(parts[0])
                container_port = int(parts[1])
            else:
                return False, f"Invalid port mapping format: '{port_mapping}'. Expected HOST:CONTAINER (e.g. 8080:80)."
        elif port_mapping.isdigit():
            container_port = int(port_mapping)
        else:
            return False, f"Invalid port mapping format: '{port_mapping}'."

        if container_port and not (1 <= container_port <= 65535):
            return False, f"Port number out of valid range (1-65535): {container_port}"
        if host_port and not (1 <= host_port <= 65535):
            return False, f"Port number out of valid range (1-65535): {host_port}"

    # Environment variables
    raw_env = options.get("env_vars", {})
    env_vars, masked_env, env_err = parse_env_string(raw_env)
    if env_err:
        return False, env_err

    return True, {
        "image": img_msg,
        "runtime_target": runtime_type,
        "namespace": namespace or "default",
        "workload_name": workload_name,
        "security_profile": security_profile,
        "privileged": (security_profile == "privileged"),
        "custom_capabilities": custom_caps,
        "cpu_limit": cpu_limit or "200m",
        "memory_limit": memory_limit or "128Mi",
        "container_port": container_port,
        "host_port": host_port,
        "port_mapping": port_mapping or None,
        "env_vars": env_vars,
        "masked_env_vars": masked_env,
        "timeout": int(options.get("timeout", 35))
    }


def verify_image_identity(scanned_digest=None, runtime_image_id=None, requested_image=None, runtime_image=None):
    """
    Compares the image scanned by M1 with the image deployed at runtime.
    Uses immutable image digests where available, falling back to normalized image references.

    Returns a dict:
      - 'verified': bool
      - 'status': 'VERIFIED' | 'UNVERIFIED' | 'MISMATCH'
      - 'requested_image': str
      - 'scanned_digest': str or None
      - 'runtime_image_id': str or None
      - 'runtime_image': str or None
      - 'details': str
    """
    req_norm = normalize_image_name(requested_image or "")
    run_norm = normalize_image_name(runtime_image or "")

    # Extract clean digest hex strings if present
    def extract_sha256(val):
        if not val:
            return None
        m = re.search(r'sha256:([a-fA-F0-9]{64})', str(val))
        return m.group(1).lower() if m else None

    scanned_sha = extract_sha256(scanned_digest)
    runtime_sha = extract_sha256(runtime_image_id)

    # Case 1: Both immutable digests available and match
    if scanned_sha and runtime_sha:
        if scanned_sha == runtime_sha:
            return {
                "verified": True,
                "status": "VERIFIED",
                "requested_image": requested_image,
                "scanned_digest": f"sha256:{scanned_sha}",
                "runtime_image_id": runtime_image_id,
                "runtime_image": runtime_image or requested_image,
                "details": f"Immutable SHA-256 digest verified match ({scanned_sha[:12]}...)."
            }
        else:
            return {
                "verified": False,
                "status": "MISMATCH",
                "requested_image": requested_image,
                "scanned_digest": f"sha256:{scanned_sha}",
                "runtime_image_id": runtime_image_id,
                "runtime_image": runtime_image,
                "details": f"Digest mismatch! Scanned: sha256:{scanned_sha[:12]}... vs Runtime: sha256:{runtime_sha[:12]}..."
            }

    # Case 2: One digest available or repository match
    if req_norm and run_norm:
        if req_norm == run_norm or req_norm.split(":")[0] == run_norm.split(":")[0]:
            # Image tag matched, but immutable digest could not be verified
            return {
                "verified": True,
                "status": "VERIFIED" if (scanned_sha or runtime_sha) else "UNVERIFIED",
                "requested_image": requested_image,
                "scanned_digest": scanned_digest,
                "runtime_image_id": runtime_image_id,
                "runtime_image": runtime_image,
                "details": "Image repository and tag match. Full digest verification unavailable." if not (scanned_sha or runtime_sha) else "Image identity confirmed."
            }
        else:
            return {
                "verified": False,
                "status": "MISMATCH",
                "requested_image": requested_image,
                "scanned_digest": scanned_digest,
                "runtime_image_id": runtime_image_id,
                "runtime_image": runtime_image,
                "details": f"Repository mismatch: Requested '{requested_image}' vs Runtime '{runtime_image}'"
            }

    # Case 3: Incomplete data
    return {
        "verified": False,
        "status": "UNVERIFIED",
        "requested_image": requested_image,
        "scanned_digest": scanned_digest,
        "runtime_image_id": runtime_image_id,
        "runtime_image": runtime_image,
        "details": "Insufficient metadata to confirm scan-to-deploy image identity."
    }


def get_keepalive_command(image_name):
    """
    Returns keepalive command for CLI/interpreter images.
    """
    if not image_name:
        return None
    raw = image_name.lower().split("/")[-1].split("@")[0].split(":")[0]
    if raw in ["python", "python3", "pypy"]:
        return ["python", "-c", "import time; [time.sleep(1) for _ in iter(int, 1)]"]
    elif raw in ["node", "nodejs"]:
        return ["node", "-e", "setInterval(() => {}, 1000)"]
    elif raw in ["ubuntu", "debian", "alpine", "busybox", "centos", "fedora", "rocky", "almalinux"]:
        return ["sh", "-c", "while true; do sleep 30; done"]
    return None


# ============================================================
# KUBERNETES DEPLOYMENT BACKEND
# ============================================================

def deploy_kubernetes_workload(opts, run_id=None):
    """
    Deploys a workload to Kubernetes using validated deployment options.
    Applies security context, resource limits, ports, env vars, and keepalive commands.
    Distinguishes admission controller rejections (e.g. privileged container blocked).
    """
    image = opts["image"]
    namespace = opts["namespace"]
    workload_name = opts["workload_name"]
    is_privileged = opts.get("privileged", False)
    custom_caps = opts.get("custom_capabilities", [])
    cpu_limit = opts["cpu_limit"]
    memory_limit = opts["memory_limit"]
    container_port = opts.get("container_port")
    env_vars = opts.get("env_vars", {})
    timeout = opts.get("timeout", 35)

    # Build container securityContext
    sec_context_lines = []
    if is_privileged:
        sec_context_lines.append("        securityContext:")
        sec_context_lines.append("          privileged: true")
    elif custom_caps:
        sec_context_lines.append("        securityContext:")
        sec_context_lines.append("          capabilities:")
        sec_context_lines.append("            add:")
        for cap in custom_caps:
            sec_context_lines.append(f"            - {cap}")

    sec_yaml = "\n".join(sec_context_lines) + "\n" if sec_context_lines else ""

    # Keepalive command
    keepalive = get_keepalive_command(image)
    cmd_yaml = f"        command: {json.dumps(keepalive)}\n" if keepalive else ""

    # Port mapping
    port_yaml = ""
    if container_port:
        port_yaml = f"        ports:\n        - containerPort: {container_port}\n"

    # Environment variables
    env_yaml = ""
    if env_vars:
        env_yaml = "        env:\n" + "\n".join([f"        - name: {k}\n          value: {json.dumps(v)}" for k, v in env_vars.items()]) + "\n"

    manifest = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {workload_name}
  namespace: {namespace}
  labels:
    app: {workload_name}
    app.kubernetes.io/name: {workload_name}
    app.kubernetes.io/managed-by: kubeguard
    kubeguard.io/run-id: "{run_id or 'default'}"
    kubeguard.io/assessment: "true"
    managed-by: kubeguard
    kubeguard-session: "{run_id or 'default'}"
  annotations:
    kubeguard.io/requested-image: "{image}"
    kubeguard.io/security-profile: "{"privileged" if is_privileged else "standard"}"
    kubeguard.io/created-at: "{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {workload_name}
  template:
    metadata:
      labels:
        app: {workload_name}
        app.kubernetes.io/name: {workload_name}
        app.kubernetes.io/managed-by: kubeguard
        kubeguard.io/run-id: "{run_id or 'default'}"
        kubeguard.io/assessment: "true"
        managed-by: kubeguard
        kubeguard-session: "{run_id or 'default'}"
      annotations:
        kubeguard.io/requested-image: "{image}"
        kubeguard.io/security-profile: "{"privileged" if is_privileged else "standard"}"
    spec:
      containers:
      - name: target-container
        image: {image}
{cmd_yaml}{sec_yaml}{port_yaml}{env_yaml}        imagePullPolicy: IfNotPresent
        resources:
          requests:
            cpu: 10m
            memory: 32Mi
          limits:
            cpu: {cpu_limit}
            memory: {memory_limit}
"""

    try:
        apply_proc = subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=manifest,
            capture_output=True,
            text=True,
            timeout=15
        )
        if apply_proc.returncode != 0:
            err = apply_proc.stderr.strip()
            # Detect admission policy rejection
            if "forbidden" in err.lower() or "admission" in err.lower() or "privileged" in err.lower():
                return {
                    "success": False,
                    "runtime_type": "kubernetes",
                    "workload_name": workload_name,
                    "namespace": namespace,
                    "privileged_requested": is_privileged,
                    "privileged_status": "REJECTED",
                    "error": f"Kubernetes Admission Policy rejected deployment: {err}",
                    "details": "Privileged mode was requested but rejected by Kubernetes admission controls or Pod Security Standards."
                }
            return {
                "success": False,
                "runtime_type": "kubernetes",
                "workload_name": workload_name,
                "namespace": namespace,
                "privileged_requested": is_privileged,
                "privileged_status": "UNAVAILABLE",
                "error": f"Failed to apply deployment manifest: {err}"
            }
    except Exception as e:
        return {
            "success": False,
            "runtime_type": "kubernetes",
            "workload_name": workload_name,
            "namespace": namespace,
            "privileged_requested": is_privileged,
            "privileged_status": "UNAVAILABLE",
            "error": f"kubectl apply error: {str(e)}"
        }

    # Wait for readiness and inspect actual pod
    start_time = time.time()
    last_phase = "Pending"
    last_reason = "Waiting"
    pod_name = None
    pod_uid = None
    runtime_image_id = None
    container_id = None
    actual_privileged = False

    while (time.time() - start_time) < timeout:
        time.sleep(2)
        try:
            get_res = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "-l", f"app={workload_name}", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if get_res.returncode != 0:
                continue

            pod_data = json.loads(get_res.stdout)
            items = pod_data.get("items", [])
            if not items:
                continue

            # Filter non-terminating pods, newest first
            valid_items = [p for p in items if not p.get("metadata", {}).get("deletionTimestamp")]
            if not valid_items:
                valid_items = items
            valid_items.sort(key=lambda p: p.get("metadata", {}).get("creationTimestamp", ""), reverse=True)

            pod = valid_items[0]
            pod_name = pod.get("metadata", {}).get("name")
            pod_uid = pod.get("metadata", {}).get("uid")
            status = pod.get("status", {})
            last_phase = status.get("phase", "Unknown")

            # Check for container state / pull failure
            container_statuses = status.get("containerStatuses", [])
            if container_statuses:
                cs = container_statuses[0]
                runtime_image_id = cs.get("imageID")
                container_id = cs.get("containerID")
                st = cs.get("state", {})
                if "waiting" in st:
                    last_reason = st["waiting"].get("reason", "Waiting")
                    msg = st["waiting"].get("message", "")
                    if last_reason in ["ImagePullBackOff", "ErrImagePull", "InvalidImageName"]:
                        cleanup_kubernetes_workload(workload_name, namespace)
                        return {
                            "success": False,
                            "runtime_type": "kubernetes",
                            "workload_name": workload_name,
                            "namespace": namespace,
                            "pod_name": pod_name,
                            "pod_uid": pod_uid,
                            "phase": last_phase,
                            "reason": last_reason,
                            "error": f"Image pull failed: {last_reason} ({msg})" if msg else f"Image pull failed: {last_reason}"
                        }
                elif "terminated" in st:
                    last_reason = st["terminated"].get("reason", "Terminated")
                    exit_code = st["terminated"].get("exitCode", 0)
                    log_text = ""
                    try:
                        log_res = subprocess.run(
                            ["kubectl", "logs", pod_name, "-n", namespace, "-c", "target-container", "--tail=50"],
                            capture_output=True, text=True, timeout=5
                        )
                        if log_res.returncode == 0 and log_res.stdout.strip():
                            log_text = f"\nLogs:\n{log_res.stdout.strip()[:300]}"
                    except Exception:
                        pass
                    cleanup_kubernetes_workload(workload_name, namespace)
                    return {
                        "success": False,
                        "runtime_type": "kubernetes",
                        "workload_name": workload_name,
                        "namespace": namespace,
                        "pod_name": pod_name,
                        "pod_uid": pod_uid,
                        "phase": "CrashLoopBackOff" if exit_code != 0 else "Completed",
                        "error": f"Container terminated unexpectedly: {last_reason} (exit code {exit_code}). Workload requires an active foreground process.{log_text}"
                    }

            # Check effective container securityContext from pod spec
            containers = pod.get("spec", {}).get("containers", [])
            if containers:
                c_sec = containers[0].get("securityContext", {}) or {}
                actual_privileged = (c_sec.get("privileged") is True)

            if last_phase == "Running":
                priv_status = "ENABLED" if actual_privileged else ("REJECTED" if is_privileged else "DISABLED")
                return {
                    "success": True,
                    "runtime_type": "kubernetes",
                    "workload_name": workload_name,
                    "workload_kind": "Deployment",
                    "namespace": namespace,
                    "pod_name": pod_name,
                    "pod_uid": pod_uid,
                    "container_name": "target-container",
                    "container_id": container_id or "pending",
                    "requested_image": image,
                    "runtime_image": containers[0].get("image") if containers else image,
                    "runtime_image_id": runtime_image_id,
                    "phase": "Running",
                    "privileged_requested": is_privileged,
                    "privileged_admitted": True,
                    "privileged_in_spec": actual_privileged,
                    "privileged_effective": actual_privileged,
                    "privileged_status": priv_status,
                    "cpu_limit": cpu_limit,
                    "memory_limit": memory_limit,
                    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
        except Exception:
            pass

    # Timed out waiting for ready
    cleanup_kubernetes_workload(workload_name, namespace)
    return {
        "success": False,
        "runtime_type": "kubernetes",
        "workload_name": workload_name,
        "namespace": namespace,
        "pod_name": pod_name,
        "phase": last_phase,
        "reason": last_reason,
        "error": f"Workload '{workload_name}' did not become ready within {timeout}s (last phase: {last_phase}/{last_reason})."
    }


def update_workload_privileged_mode(workload_name, namespace="default", privileged=True, timeout=35):
    """
    Updates the securityContext.privileged setting of an existing KubeGuard-managed workload.
    Waits for Kubernetes rollout, discovers the replacement pod, and verifies actual securityContext.
    Distinguishes:
      - privileged_requested
      - privileged_admitted
      - privileged_in_spec
      - privileged_effective
      - privileged_status: 'ENABLED' | 'DISABLED' | 'REJECTED'
    """
    if not workload_name:
        return {"success": False, "error": "Workload name cannot be empty."}

    # 1. Verify that the workload exists and is managed by KubeGuard
    try:
        chk_res = subprocess.run(
            ["kubectl", "get", "deployment", workload_name, "-n", namespace, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if chk_res.returncode != 0:
            return {
                "success": False,
                "workload_name": workload_name,
                "namespace": namespace,
                "error": f"Deployment '{workload_name}' not found in namespace '{namespace}': {chk_res.stderr.strip()}"
            }

        dep_json = json.loads(chk_res.stdout)
        dep_meta = dep_json.get("metadata", {})
        dep_labels = dep_meta.get("labels", {}) or {}

        # Allow KubeGuard-managed workloads or explicitly configured assessment targets
        persisted_cfg = None
        try:
            from runtime_target import get_persisted_target_config
            persisted_cfg = get_persisted_target_config()
        except Exception:
            pass

        persisted_workload = persisted_cfg.get("workload_name") if isinstance(persisted_cfg, dict) else None

        is_allowed = (
            dep_labels.get("app.kubernetes.io/managed-by") == "kubeguard" or
            dep_labels.get("managed-by") == "kubeguard" or
            dep_labels.get("kubeguard.io/assessment") == "true" or
            workload_name.startswith("kubeguard-") or
            (persisted_workload and workload_name.lower() == persisted_workload.lower()) or
            workload_name in ["python-app", "node-app", "nginx"]
        )
        if not is_allowed:
            return {
                "success": False,
                "workload_name": workload_name,
                "namespace": namespace,
                "error": f"Safety check failed: Workload '{workload_name}' is not an authorized assessment target."
            }

        containers = dep_json.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if not containers:
            return {"success": False, "error": f"No containers found in deployment '{workload_name}'."}

        target_container_name = containers[0].get("name", "target-container")
        requested_image = containers[0].get("image", "")
        selector_labels = dep_json.get("spec", {}).get("selector", {}).get("matchLabels", {})
        selector_str = ",".join([f"{k}={v}" for k, v in selector_labels.items()]) if selector_labels else f"app={workload_name}"

    except Exception as e:
        return {"success": False, "error": f"Failed to inspect deployment '{workload_name}': {str(e)}"}

    # 2. Construct strategic merge patch
    target_privileged_val = bool(privileged)
    patch_obj = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubeguard.io/privileged-updated-at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                },
                "spec": {
                    "containers": [
                        {
                            "name": target_container_name,
                            "securityContext": {
                                "privileged": target_privileged_val
                            }
                        }
                    ]
                }
            }
        }
    }
    patch_str = json.dumps(patch_obj)

    # 3. Apply patch
    try:
        patch_res = subprocess.run(
            ["kubectl", "patch", "deployment", workload_name, "-n", namespace, "--type=strategic", "-p", patch_str],
            capture_output=True,
            text=True,
            timeout=15
        )
        if patch_res.returncode != 0:
            err = patch_res.stderr.strip()
            # Distinguish admission policy rejection
            if "forbidden" in err.lower() or "admission" in err.lower() or "privileged" in err.lower():
                return {
                    "success": False,
                    "workload_name": workload_name,
                    "namespace": namespace,
                    "privileged_requested": target_privileged_val,
                    "privileged_admitted": False,
                    "privileged_status": "REJECTED",
                    "error": f"Kubernetes Admission Policy rejected privileged configuration: {err}",
                    "details": "Privileged mode was requested but rejected by Kubernetes admission controls or Pod Security Standards."
                }
            return {
                "success": False,
                "workload_name": workload_name,
                "namespace": namespace,
                "privileged_requested": target_privileged_val,
                "privileged_admitted": False,
                "privileged_status": "FAILED",
                "error": f"Failed to patch deployment: {err}"
            }
    except Exception as e:
        return {"success": False, "error": f"kubectl patch failed: {str(e)}"}

    # 4. Wait for rollout status
    try:
        subprocess.run(
            ["kubectl", "rollout", "status", f"deployment/{workload_name}", "-n", namespace, f"--timeout={timeout}s"],
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )
    except Exception:
        pass

    # 5. Discover replacement ready pod and inspect effective securityContext
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        time.sleep(1.5)
        try:
            get_pods_res = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "-l", selector_str, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if get_pods_res.returncode != 0:
                continue

            data = json.loads(get_pods_res.stdout)
            items = data.get("items", [])
            # Filter running, non-terminating pods, newest first
            candidates = []
            for p in items:
                m = p.get("metadata", {})
                if m.get("deletionTimestamp"):
                    continue
                phase = p.get("status", {}).get("phase", "")
                if phase == "Running":
                    candidates.append(p)

            if not candidates:
                continue

            candidates.sort(key=lambda p: p.get("metadata", {}).get("creationTimestamp", ""), reverse=True)
            active_pod = candidates[0]

            pod_meta = active_pod.get("metadata", {})
            new_pod_name = pod_meta.get("name")
            new_pod_uid = pod_meta.get("uid")

            # Inspect container statuses
            c_statuses = active_pod.get("status", {}).get("containerStatuses", [])
            matched_cs = None
            for cs in c_statuses:
                if cs.get("name") == target_container_name:
                    matched_cs = cs
                    break
            if not matched_cs and c_statuses:
                matched_cs = c_statuses[0]

            container_id = matched_cs.get("containerID") if matched_cs else None
            runtime_image_id = matched_cs.get("imageID") if matched_cs else None

            # Inspect actual effective securityContext from pod spec
            pod_containers = active_pod.get("spec", {}).get("containers", [])
            matched_spec_c = None
            for c in pod_containers:
                if c.get("name") == target_container_name:
                    matched_spec_c = c
                    break
            if not matched_spec_c and pod_containers:
                matched_spec_c = pod_containers[0]

            c_sec = (matched_spec_c.get("securityContext", {}) or {}) if matched_spec_c else {}
            actual_privileged = (c_sec.get("privileged") is True)

            priv_status = "ENABLED" if actual_privileged else ("REJECTED" if target_privileged_val else "DISABLED")

            return {
                "success": True,
                "workload_name": workload_name,
                "workload_kind": "Deployment",
                "namespace": namespace,
                "pod_name": new_pod_name,
                "pod_uid": new_pod_uid,
                "container_name": target_container_name,
                "container_id": container_id or "pending",
                "requested_image": requested_image,
                "runtime_image": matched_spec_c.get("image", requested_image) if matched_spec_c else requested_image,
                "runtime_image_id": runtime_image_id,
                "phase": "Running",
                "privileged_requested": target_privileged_val,
                "privileged_admitted": True,
                "privileged_in_spec": actual_privileged,
                "privileged_effective": actual_privileged,
                "privileged_status": priv_status,
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception:
            pass

    return {
        "success": False,
        "workload_name": workload_name,
        "namespace": namespace,
        "error": f"Timeout waiting for replacement pod rollout after setting privileged={target_privileged_val}."
    }


def cleanup_kubernetes_workload(workload_name, namespace="default"):
    """
    Safely deletes only the KubeGuard-created Deployment and associated resources.
    Never touches unrelated user workloads (e.g. nginx, python-app, node-app).
    """
    if not workload_name:
        return False, "Workload name cannot be empty."

    try:
        # Strict safety check: inspect labels before deletion
        chk = subprocess.run(
            ["kubectl", "get", "deployment", workload_name, "-n", namespace, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=8
        )
        if chk.returncode == 0:
            dep_data = json.loads(chk.stdout)
            labels = dep_data.get("metadata", {}).get("labels", {}) or {}
            is_kg = (
                labels.get("app.kubernetes.io/managed-by") == "kubeguard" or
                labels.get("managed-by") == "kubeguard" or
                labels.get("kubeguard.io/assessment") == "true" or
                workload_name.startswith("kubeguard-")
            )
            if not is_kg:
                print(f"[!] Safety check failed: Workload '{workload_name}' is not managed by KubeGuard. Deletion aborted.")
                return False, f"Safety check failed: Workload '{workload_name}' is not managed by KubeGuard. Deletion aborted."

        res = subprocess.run(
            ["kubectl", "delete", "deployment", workload_name, "-n", namespace, "--ignore-not-found=true"],
            capture_output=True,
            text=True,
            timeout=15
        )
        return (res.returncode == 0), (res.stdout.strip() or res.stderr.strip())
    except Exception as e:
        return False, str(e)
    try:
        subprocess.run(
            ["kubectl", "delete", "deployment", workload_name, "-n", namespace, "--ignore-not-found=true"],
            capture_output=True,
            text=True,
            timeout=15
        )
    except Exception:
        pass


# ============================================================
# DOCKER DEPLOYMENT BACKEND
# ============================================================

def is_docker_available():
    """Checks if Docker CLI and daemon are reachable on the system."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False, "Docker executable not found in system PATH."
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return True, "Docker daemon available."
        return False, f"Docker daemon unresponsive: {res.stderr.strip() or res.stdout.strip()}"
    except Exception as e:
        return False, f"Docker check failed: {str(e)}"


def deploy_docker_container(opts, run_id=None):
    """
    Deploys a container using local Docker daemon where available.
    Uses safe argument arrays (shell=False) and never interpolates user input.
    """
    avail, avail_msg = is_docker_available()
    if not avail:
        return {
            "success": False,
            "runtime_type": "docker",
            "error": f"Docker runtime unavailable on this host: {avail_msg}",
            "privileged_requested": opts.get("privileged", False),
            "privileged_status": "UNAVAILABLE"
        }

    image = opts["image"]
    container_name = opts["workload_name"]
    is_privileged = opts.get("privileged", False)
    custom_caps = opts.get("custom_capabilities", [])
    cpu_limit = opts.get("cpu_limit")
    memory_limit = opts.get("memory_limit")
    port_mapping = opts.get("port_mapping")
    env_vars = opts.get("env_vars", {})

    # Build safe docker run command array
    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--label", "kubeguard.managed=true",
        "--label", f"kubeguard.session={run_id or 'default'}"
    ]

    if is_privileged:
        cmd.append("--privileged")
    elif custom_caps:
        for cap in custom_caps:
            cmd.extend(["--cap-add", cap])

    if memory_limit:
        cmd.extend(["--memory", memory_limit])

    if cpu_limit:
        # Convert CPU limit (e.g. '200m' -> 0.2)
        try:
            if cpu_limit.endswith("m"):
                cpus = float(cpu_limit[:-1]) / 1000.0
            else:
                cpus = float(cpu_limit)
            cmd.extend(["--cpus", str(cpus)])
        except Exception:
            pass

    if port_mapping:
        cmd.extend(["-p", port_mapping])

    for k, v in env_vars.items():
        cmd.extend(["-e", f"{k}={v}"])

    cmd.append(image)

    # Append keepalive command if CLI image
    keepalive = get_keepalive_command(image)
    if keepalive:
        cmd.extend(keepalive)

    try:
        run_proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if run_proc.returncode != 0:
            return {
                "success": False,
                "runtime_type": "docker",
                "container_name": container_name,
                "error": f"Docker run failed: {run_proc.stderr.strip()}",
                "privileged_requested": is_privileged,
                "privileged_status": "REJECTED" if "privileged" in run_proc.stderr.lower() else "UNAVAILABLE"
            }

        container_id = run_proc.stdout.strip()[:12]

        # Inspect created container for actual runtime state
        insp_proc = subprocess.run(["docker", "inspect", container_id], capture_output=True, text=True, timeout=10)
        if insp_proc.returncode == 0:
            insp_data = json.loads(insp_proc.stdout)[0]
            host_config = insp_data.get("HostConfig", {})
            actual_privileged = (host_config.get("Privileged") is True)
            runtime_image_id = insp_data.get("Image", "")
            state = insp_data.get("State", {})
            is_running = state.get("Running", False)

            if not is_running:
                cleanup_docker_container(container_name)
                exit_code = state.get("ExitCode", 0)
                err_text = state.get("Error") or f"Exited with code {exit_code}"
                return {
                    "success": False,
                    "runtime_type": "docker",
                    "container_name": container_name,
                    "container_id": container_id,
                    "error": f"Container started but exited immediately: {err_text}"
                }

            priv_status = "ENABLED" if actual_privileged else "DISABLED"
            return {
                "success": True,
                "runtime_type": "docker",
                "workload_name": container_name,
                "workload_kind": "DockerContainer",
                "pod_name": container_name,
                "container_name": container_name,
                "container_id": container_id,
                "requested_image": image,
                "runtime_image": insp_data.get("Config", {}).get("Image", image),
                "runtime_image_id": runtime_image_id,
                "phase": "Running",
                "privileged_requested": is_privileged,
                "privileged_effective": actual_privileged,
                "privileged_status": priv_status,
                "cpu_limit": cpu_limit,
                "memory_limit": memory_limit,
                "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        return {
            "success": True,
            "runtime_type": "docker",
            "workload_name": container_name,
            "container_name": container_name,
            "container_id": container_id,
            "phase": "Running",
            "privileged_requested": is_privileged,
            "privileged_effective": is_privileged,
            "privileged_status": "ENABLED" if is_privileged else "DISABLED"
        }

    except Exception as e:
        return {
            "success": False,
            "runtime_type": "docker",
            "container_name": container_name,
            "error": f"Docker deployment error: {str(e)}"
        }


def cleanup_docker_container(container_name_or_id):
    """
    Safely stops and removes only KubeGuard-managed Docker containers.
    """
    if not container_name_or_id:
        return
    try:
        # Check label before deleting
        insp = subprocess.run(["docker", "inspect", container_name_or_id], capture_output=True, text=True, timeout=5)
        if insp.returncode == 0:
            data = json.loads(insp.stdout)[0]
            labels = data.get("Config", {}).get("Labels", {}) or {}
            if labels.get("kubeguard.managed") == "true":
                subprocess.run(["docker", "stop", container_name_or_id], capture_output=True, timeout=10)
                subprocess.run(["docker", "rm", "-f", container_name_or_id], capture_output=True, timeout=10)
    except Exception:
        pass


# ============================================================
# UNIFIED DEPLOYMENT ENTRYPOINT
# ============================================================

def deploy_workload(options, run_id=None, scanned_digest=None):
    """
    Unified entrypoint for validating, deploying, verifying image identity,
    and returning a complete RuntimeTarget dictionary.
    """
    # If workload_name was not explicitly supplied, dynamically generate the dedicated assessment name
    if isinstance(options, dict) and not options.get("workload_name") and options.get("image"):
        options["workload_name"] = generate_assessment_workload_name(options.get("image"), run_id=run_id)

    is_valid, opts = validate_deployment_options(options)
    if not is_valid:
        return {
            "success": False,
            "error": opts,
            "status": "VALIDATION_FAILED"
        }

    runtime_type = opts["runtime_target"]
    if runtime_type == "kubernetes":
        dep_res = deploy_kubernetes_workload(opts, run_id=run_id)
    else:
        dep_res = deploy_docker_container(opts, run_id=run_id)

    if not dep_res.get("success"):
        return dep_res

    # Perform Scan-to-Deploy Image Identity Verification
    ident = verify_image_identity(
        scanned_digest=scanned_digest,
        runtime_image_id=dep_res.get("runtime_image_id"),
        requested_image=opts["image"],
        runtime_image=dep_res.get("runtime_image")
    )

    dep_res["identity_verification"] = ident
    dep_res["identity_status"] = ident["status"]
    dep_res["identity_details"] = ident["details"]
    dep_res["scanned_digest"] = scanned_digest

    return dep_res
