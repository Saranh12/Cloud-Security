import subprocess
import time
import os
import json
import threading
from datetime import datetime

STATE_FILE = os.path.join("reports", "dashboard_state.json")
_STATE_LOCK = threading.Lock()


def parse_cpu_to_millicores(cpu_val):
    """
    Parses a Kubernetes CPU metric string into an integer number of millicores.
    Examples:
      '4m' -> 4
      '0m' -> 0
      '5000000n' -> 5
      '1' -> 1000
    """
    if not cpu_val:
        return 0
    try:
        s = str(cpu_val).strip()
        if s.endswith("m"):
            return int(float(s[:-1]))
        elif s.endswith("n"):
            return int(round(float(s[:-1]) / 1000000.0))
        elif s.endswith("u"):
            return int(round(float(s[:-1]) / 1000.0))
        else:
            return int(round(float(s) * 1000.0))
    except (ValueError, TypeError):
        return 0


def parse_memory_to_mib(mem_val):
    """
    Parses a Kubernetes Memory metric string into an integer number of MiB.
    Examples:
      '24Mi' -> 24
      '1Gi' -> 1024
      '10240Ki' -> 10
    """
    if not mem_val:
        return 0
    try:
        s = str(mem_val).strip()
        if s.endswith("Mi"):
            return int(round(float(s[:-2])))
        elif s.endswith("Gi"):
            return int(round(float(s[:-2]) * 1024.0))
        elif s.endswith("Ki"):
            return int(round(float(s[:-2]) / 1024.0))
        elif s.endswith("M"):
            return int(round(float(s[:-1]) * 1000000.0 / 1048576.0))
        elif s.endswith("G"):
            return int(round(float(s[:-1]) * 1000000000.0 / 1048576.0))
        else:
            return int(round(float(s) / 1048576.0))
    except (ValueError, TypeError):
        return 0


def update_dashboard_metrics(metrics):
    """
    Thread-safely and atomically updates reports/dashboard_state.json
    with genuine live Kubernetes metrics.
    """
    if not os.path.exists("reports"):
        os.makedirs("reports", exist_ok=True)

    with _STATE_LOCK:
        data = {}
        if os.path.exists(STATE_FILE):
            for read_attempt in range(10):
                try:
                    with open(STATE_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict) and data:
                        break
                except Exception:
                    time.sleep(0.05)
            if os.path.exists(STATE_FILE) and os.path.getsize(STATE_FILE) > 50 and not data:
                # Do not overwrite STATE_FILE if reading failed due to a transient lock
                return

        if "modules" not in data or not isinstance(data["modules"], dict):
            data["modules"] = {}

        existing_m2 = data["modules"].get("M2", {})
        existing_details = existing_m2.get("details", {}) if isinstance(existing_m2, dict) else {}

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        time_short = datetime.now().strftime("%H:%M:%S")

        if "error" not in metrics:
            pod_name = metrics.get("pod_name", "")
            cpu_str = metrics.get("cpu", "0m")
            mem_str = metrics.get("memory", "0Mi")
            cpu_m = metrics.get("cpu_millicores", parse_cpu_to_millicores(cpu_str))
            mem_mib = metrics.get("memory_mib", parse_memory_to_mib(mem_str))

            history = existing_details.get("metrics_history", [])
            history.append({
                "time": time_short,
                "cpu_m": cpu_m,
                "cpu": cpu_str,
                "mem_mib": mem_mib,
                "mem": mem_str
            })
            if len(history) > 20:
                history = history[-20:]

            details = {
                "pod_name": pod_name,
                "cpu": cpu_str,
                "memory": mem_str,
                "cpu_millicores": cpu_m,
                "memory_mib": mem_mib,
                "metrics_available": True,
                "monitoring_status": "CONTINUOUS",
                "monitoring_interval": "5 seconds",
                "last_updated": now_str,
                "metrics_history": history,
                "pods": [
                    {
                        "name": pod_name,
                        "namespace": "default",
                        "status": "Running",
                        "cpu": cpu_str,
                        "memory": mem_str,
                        "restarts": 0,
                        "health": "Healthy"
                    }
                ]
            }
            existing_details.update(details)

            entry = {
                "status": "RUNNING",
                "severity": "None",
                "message": f"Pod={pod_name} | CPU={cpu_str} | Memory={mem_str}",
                "details": existing_details
            }
        else:
            existing_details.update({
                "metrics_available": False,
                "error": metrics["error"],
                "monitoring_status": "WAITING_FOR_WORKLOAD" if metrics.get("pod_terminated") else "CONTINUOUS",
                "monitoring_interval": "5 seconds",
                "last_updated": now_str
            })
            entry = {
                "status": "RUNNING",
                "severity": "None",
                "message": f"Metrics Unavailable: {metrics['error']}",
                "details": existing_details
            }

        data["modules"]["M2"] = entry
        data["modules"]["m2"] = entry
        data["M2"] = entry
        data["m2"] = entry
        data["execution_time"] = now_str

        try:
            tmp_file = STATE_FILE + ".tmp"
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            os.replace(tmp_file, STATE_FILE)
        except Exception:
            pass


def normalize_image_name(img):
    """
    Normalizes image string for comparison across registries, libraries, and tags.
    e.g., 'docker.io/library/python:3.12-slim' -> 'python:3.12-slim'
          'index.docker.io/library/nginx:latest' -> 'nginx:latest'
          'library/nginx:latest' -> 'nginx:latest'
          'nginx' -> 'nginx'
    """
    if not img:
        return ""
    img = img.strip()
    prefixes = [
        "index.docker.io/library/",
        "index.docker.io/",
        "docker.io/library/",
        "docker.io/",
        "library/"
    ]
    for p in prefixes:
        if img.startswith(p):
            img = img[len(p):]
            break
    return img


def matches_image_name(container_img, target_img):
    """
    Checks if container image matches target image.
    Supports tagged vs untagged matching (e.g. 'nginx' matches 'nginx:latest')
    and handles digests (e.g. 'python:3.12-slim@sha256:...').
    """
    if not container_img or not target_img:
        return False
    norm_c = normalize_image_name(container_img)
    norm_t = normalize_image_name(target_img)
    if norm_c == norm_t:
        return True

    # Strip digest for name/tag comparison if present
    img_c_nodigest = norm_c.split("@")[0]
    img_t_nodigest = norm_t.split("@")[0]
    if img_c_nodigest == img_t_nodigest:
        return True

    base_c = img_c_nodigest.split(":")[0]
    base_t = img_t_nodigest.split(":")[0]
    if base_c == base_t:
        tag_c = img_c_nodigest.split(":")[1] if ":" in img_c_nodigest else "latest"
        tag_t = img_t_nodigest.split(":")[1] if ":" in img_t_nodigest else "latest"
        return tag_c == tag_t
    return False


def resolve_owner_workload(pod_metadata, namespace="default"):
    """
    Resolves the owning controller of a pod (Deployment, ReplicaSet, StatefulSet, DaemonSet, Job).
    If a pod is owned by a ReplicaSet, determines whether the ReplicaSet is owned by a Deployment.
    """
    owner_refs = pod_metadata.get("ownerReferences", [])
    if not owner_refs:
        return {"kind": "Pod", "name": pod_metadata.get("name", "unknown")}

    direct_owner = owner_refs[0]
    kind = direct_owner.get("kind", "Unknown")
    name = direct_owner.get("name", "unknown")

    if kind == "ReplicaSet":
        try:
            cmd = ["kubectl", "get", "replicaset", name, "-n", namespace, "-o", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                rs_data = json.loads(res.stdout)
                rs_owners = rs_data.get("metadata", {}).get("ownerReferences", [])
                if rs_owners and rs_owners[0].get("kind") == "Deployment":
                    return {
                        "kind": "Deployment",
                        "name": rs_owners[0].get("name"),
                        "replicaset": name
                    }
        except Exception:
            pass
        return {"kind": "ReplicaSet", "name": name}

    return {"kind": kind, "name": name}


def discover_workload(target_image=None, target_pod=None, namespace=None, preferred_workload=None, manual_select=False):
    """
    Discovers the active Kubernetes workload pod matching target_image or target_pod.
    Inspects running pods across target namespace (and cluster-wide if needed).
    Resolves the owning workload (Deployment, ReplicaSet, StatefulSet, DaemonSet).
    Identifies exact container and handles ambiguity gracefully.
    Never returns an unrelated pod.
    """
    try:
        # Determine namespaces to query
        search_all = (namespace is None)
        cmd = ["kubectl", "get", "pods", "-A", "-o", "json"] if search_all else ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if res.returncode != 0:
            return {
                "found": False,
                "running": False,
                "error": f"Failed to query Kubernetes pods: {res.stderr.strip()}"
            }

        data = json.loads(res.stdout)
        items = data.get("items", [])

        # If not found in specified namespace (e.g. 'default'), try cluster-wide if not already done
        if not items and not search_all:
            cmd_all = ["kubectl", "get", "pods", "-A", "-o", "json"]
            res_all = subprocess.run(cmd_all, capture_output=True, text=True, timeout=12)
            if res_all.returncode == 0:
                data = json.loads(res_all.stdout)
                items = data.get("items", [])

        if not items:
            return {
                "found": False,
                "running": False,
                "message": "Image scan completed. No matching running Kubernetes workload was found.",
                "error": "No pods found in cluster"
            }

        matched_pods = []

        for pod in items:
            p_name = pod.get("metadata", {}).get("name", "")
            p_ns = pod.get("metadata", {}).get("namespace", "default")
            p_labels = pod.get("metadata", {}).get("labels", {})
            p_phase = pod.get("status", {}).get("phase", "Unknown")
            spec = pod.get("spec", {})
            containers = spec.get("containers", [])

            # Skip system pods unless specifically requested
            if p_ns in ["kube-system", "kube-node-lease", "kube-public"] and not (target_pod and p_name == target_pod):
                if not (target_image and ("kube-" in target_image or "coredns" in target_image or "etcd" in target_image)):
                    continue

            match = False
            matched_img = None
            matched_cname = None

            if target_pod:
                if p_name == target_pod and (not namespace or p_ns == namespace):
                    match = True
                    matched_c = None
                    if target_image and containers:
                        for c in containers:
                            if matches_image_name(c.get("image", ""), target_image):
                                matched_c = c
                                break
                    if not matched_c and containers:
                        matched_c = containers[0]
                    if matched_c:
                        matched_img = matched_c.get("image", "")
                        matched_cname = matched_c.get("name", "")
            elif target_image:
                for c in containers:
                    c_img = c.get("image", "")
                    if matches_image_name(c_img, target_image):
                        match = True
                        matched_img = c_img
                        matched_cname = c.get("name", "")
                        break
            else:
                if containers:
                    match = True
                    matched_img = containers[0].get("image", "")
                    matched_cname = containers[0].get("name", "")

            if match:
                cs_list = pod.get("status", {}).get("containerStatuses", [])
                sub_reason = None
                for cs in cs_list:
                    st = cs.get("state", {})
                    if "waiting" in st:
                        sub_reason = st["waiting"].get("reason", "Waiting")
                    elif "terminated" in st:
                        sub_reason = st["terminated"].get("reason", "Terminated")

                is_running = (p_phase == "Running")
                owner_info = resolve_owner_workload(pod.get("metadata", {}), namespace=p_ns)

                matched_pods.append({
                    "pod_name": p_name,
                    "namespace": p_ns,
                    "phase": p_phase,
                    "reason": sub_reason or p_phase,
                    "running": is_running,
                    "image": matched_img,
                    "container_name": matched_cname,
                    "owner_kind": owner_info.get("kind"),
                    "owner_name": owner_info.get("name"),
                    "labels": p_labels,
                    "creation_timestamp": pod.get("metadata", {}).get("creationTimestamp", "")
                })

        if not matched_pods:
            criteria = f"pod='{target_pod}'" if target_pod else f"image='{target_image}'"
            return {
                "found": False,
                "running": False,
                "message": "Image scan completed. No matching running Kubernetes workload was found.",
                "error": f"No running workload found matching {criteria} in cluster."
            }

        running_pods = [p for p in matched_pods if p["running"]]

        # Handle Ambiguity if multiple distinct running workloads exist
        selected = None
        if running_pods:
            # Group by distinct workload (namespace, owner_kind, owner_name)
            distinct_workloads = {}
            for p in running_pods:
                key = (p["namespace"], p["owner_kind"], p["owner_name"])
                if key not in distinct_workloads:
                    distinct_workloads[key] = p

            if len(distinct_workloads) > 1:
                workload_list = list(distinct_workloads.values())

                # Check if preferred_workload or active assessment workload is specified
                pref = (preferred_workload or os.environ.get("DEPLOYMENT_NAME") or os.environ.get("WORKLOAD_NAME") or "").strip().lower()
                matched_pref = None
                if pref:
                    for w in workload_list:
                        w_o = str(w.get("owner_name", "")).lower()
                        w_k = str(w.get("owner_kind", "")).lower()
                        if pref == w_o or pref == f"{w_k}/{w_o}":
                            matched_pref = w
                            break

                if matched_pref:
                    selected = matched_pref
                elif manual_select:
                    # ONLY prompt when manual_select is explicitly True (manual-assessment mode)
                    import sys
                    if sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                        print(f"\n[?] Ambiguous workload match: Found {len(workload_list)} running workloads for image '{target_image}':")
                        for idx, w in enumerate(workload_list, 1):
                            print(f"  [{idx}] Namespace: {w['namespace']:<12} | Workload: {w['owner_kind']}/{w['owner_name']:<16} | Pod: {w['pod_name']}")
                        try:
                            choice = input(f"Select workload to assess [1-{len(workload_list)}] (default 1): ").strip()
                            choice_idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(workload_list) else 0
                            selected = workload_list[choice_idx]
                        except (EOFError, KeyboardInterrupt):
                            selected = workload_list[0]
                    else:
                        selected = workload_list[0]
                else:
                    # In automatic image-assessment mode, NEVER prompt interactive input!
                    # Deterministically prefer KubeGuard-managed assessment workload if present
                    kg_workload = None
                    for w in workload_list:
                        labels = w.get("labels", {}) or {}
                        w_name = w.get("owner_name", "")
                        if labels.get("app.kubernetes.io/managed-by") == "kubeguard" or w_name.startswith("kubeguard-test-"):
                            kg_workload = w
                            break
                    selected = kg_workload or workload_list[0]
            else:
                selected = running_pods[0]
        else:
            selected = matched_pods[-1]

        err_msg = None
        if not selected["running"]:
            err_msg = f"Pod '{selected['pod_name']}' is in state '{selected['phase']}' (reason: {selected['reason']})"

        return {
            "found": True,
            "running": selected["running"],
            "pod_name": selected["pod_name"],
            "namespace": selected["namespace"],
            "phase": selected["phase"],
            "reason": selected["reason"],
            "image": selected["image"],
            "container_name": selected["container_name"],
            "owner_kind": selected.get("owner_kind"),
            "owner_name": selected.get("owner_name"),
            "labels": selected["labels"],
            "message": f"Discovered running workload: {selected.get('owner_kind')}/{selected.get('owner_name')} (Pod: {selected['pod_name']}, Namespace: {selected['namespace']})",
            "error": err_msg
        }

    except Exception as e:
        return {
            "found": False,
            "running": False,
            "message": "Image scan completed. No matching running Kubernetes workload was found.",
            "error": f"Workload discovery error: {str(e)}"
        }


def cleanup_temporary_workload(namespace="default"):
    """
    Safely deletes the temporary 'kubeguard-target' deployment and its pods
    if one was created, without touching any unrelated workloads.
    """
    try:
        subprocess.run(
            ["kubectl", "delete", "deployment", "kubeguard-target", "-n", namespace, "--ignore-not-found=true"],
            capture_output=True,
            text=True,
            timeout=15
        )
    except Exception:
        pass


def get_keepalive_command_for_image(image_name):
    """
    Returns an appropriate non-intrusive keep-alive command for CLI/interpreter
    base images (e.g., python, node, ubuntu, alpine, busybox) so they do not exit
    immediately when dynamically launched for monitoring.
    For server/daemon images (nginx, httpd, redis, etc.), returns None to use default CMD.
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


def ensure_workload(target_image=None, target_pod=None, namespace="default", timeout=25, allow_deploy=True, privileged=False):
    """
    Discovers or provisions an active Kubernetes workload for target_image.
    1. First checks if an existing pod is already running for target_image.
    2. If not, safely deploys a minimal managed deployment 'kubeguard-target' (if allow_deploy=True).
    3. Monitors pod readiness with bounded timeout.
    4. Accurately reports pull failures (ImagePullBackOff/ErrImagePull) or crashes.
    Never fabricates metrics or successful status for un-started workloads.
    """
    if not target_image and not target_pod:
        return {
            "found": False,
            "running": False,
            "error": "No target image or pod specified."
        }

    # 1. First check if a matching running pod already exists in namespace
    disc = discover_workload(target_image=target_image, target_pod=target_pod, namespace=namespace)
    if disc.get("found") and disc.get("running"):
        return disc

    # If target_pod was explicitly requested and failed, return its honest status
    if target_pod and not target_image:
        return disc

    # 2. Check target_image reference validity before deploying
    if target_image:
        try:
            from vuln_scan import validate_image_reference
            is_valid, validation_msg = validate_image_reference(target_image)
            if not is_valid:
                return {
                    "found": False,
                    "running": False,
                    "error": f"Invalid image reference: {validation_msg}"
                }
            target_image = validation_msg
        except Exception:
            pass

    if not allow_deploy:
        reason = (
            f"Automated deployment blocked by M1 security policy: Critical vulnerabilities detected in '{target_image}'. Automated deployment prevented without security exception."
            if target_image and "policy_blocked" in str(allow_deploy)
            else f"No running workload found in cluster for image '{target_image}'. Live container monitoring requires a running workload."
        )
        return {
            "found": False,
            "running": False,
            "not_applicable": True,
            "policy_blocked": ("policy" in str(allow_deploy).lower()),
            "error": reason
        }

    # 3. Create or update minimal managed deployment for the selected image
    keepalive_cmd = get_keepalive_command_for_image(target_image)
    command_yaml = ""
    if keepalive_cmd:
        command_yaml = f"        command: {json.dumps(keepalive_cmd)}\n"

    priv_yaml = "        securityContext:\n          privileged: true\n" if privileged else ""

    manifest = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubeguard-target
  namespace: {namespace}
  labels:
    app: kubeguard-target
    managed-by: kubeguard
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kubeguard-target
  template:
    metadata:
      labels:
        app: kubeguard-target
        managed-by: kubeguard
    spec:
      containers:
      - name: target-container
        image: {target_image}
{command_yaml}{priv_yaml}        imagePullPolicy: IfNotPresent
        resources:
          requests:
            cpu: 10m
            memory: 32Mi
          limits:
            cpu: 200m
            memory: 128Mi
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
            return {
                "found": False,
                "running": False,
                "error": f"Failed to apply deployment manifest: {apply_proc.stderr.strip()}"
            }
    except Exception as e:
        return {
            "found": False,
            "running": False,
            "error": f"Kubernetes apply error: {str(e)}"
        }

    # 4. Wait for pod to become ready or detect pull/startup failure
    start_time = time.time()
    last_phase = "Unknown"
    last_reason = "Pending"
    last_pod_name = None

    while (time.time() - start_time) < timeout:
        time.sleep(2)
        try:
            get_res = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "-l", "app=kubeguard-target", "-o", "json"],
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

            # Ensure we evaluate pods matching the requested target_image
            matching_pods = [
                p for p in items
                if any(matches_image_name(c.get("image", ""), target_image) for c in p.get("spec", {}).get("containers", []))
            ]
            eval_items = matching_pods if matching_pods else items
            pod = eval_items[-1]
            last_pod_name = pod.get("metadata", {}).get("name")
            status = pod.get("status", {})
            last_phase = status.get("phase", "Unknown")

            # Check container statuses for waiting/terminated reasons
            container_statuses = status.get("containerStatuses", [])
            for cs in container_statuses:
                state = cs.get("state", {})
                if "waiting" in state:
                    last_reason = state["waiting"].get("reason", last_reason)
                    msg = state["waiting"].get("message", "")
                    if last_reason in ["ImagePullBackOff", "ErrImagePull", "InvalidImageName"]:
                        cleanup_temporary_workload(namespace=namespace)
                        return {
                            "found": True,
                            "running": False,
                            "pod_name": last_pod_name,
                            "phase": last_phase,
                            "reason": last_reason,
                            "error": f"Image pull failed: {last_reason} ({msg.strip()})" if msg else f"Image pull failed: {last_reason}"
                        }
                elif "terminated" in state:
                    last_reason = state["terminated"].get("reason", last_reason)
                    exit_code = state["terminated"].get("exitCode", 0)
                    cleanup_temporary_workload(namespace=namespace)
                    return {
                        "found": True,
                        "running": False,
                        "pod_name": last_pod_name,
                        "phase": "CrashLoopBackOff" if exit_code != 0 else "Completed",
                        "reason": last_reason,
                        "error": f"Container terminated: {last_reason} (exit code {exit_code}). Workload requires an active foreground process."
                    }

            spec_containers = pod.get("spec", {}).get("containers", [])
            pod_matches = any(matches_image_name(c.get("image", ""), target_image) for c in spec_containers)

            if last_phase == "Running" and pod_matches:
                return {
                    "found": True,
                    "running": True,
                    "pod_name": last_pod_name,
                    "namespace": namespace,
                    "phase": "Running",
                    "reason": "Running",
                    "image": target_image,
                    "container_name": "target-container",
                    "labels": {"app": "kubeguard-target"},
                    "owner_kind": "Deployment",
                    "owner_name": "kubeguard-target",
                    "deployment_name": "kubeguard-target",
                    "error": None
                }

        except Exception:
            pass

    if last_pod_name:
        cleanup_temporary_workload(namespace=namespace)

    return {
        "found": True if last_pod_name else False,
        "running": False,
        "pod_name": last_pod_name,
        "phase": last_phase,
        "reason": last_reason,
        "error": f"Workload '{last_pod_name or target_image}' did not become ready within {timeout}s (state: {last_phase}/{last_reason})"
    }


def get_docker_metrics(container_name_or_id):
    """
    Collects live CPU and memory metrics from Docker daemon.
    Returns honest errors when Docker or metrics are unavailable.
    """
    if not container_name_or_id:
        return {"error": "No Docker container specified. Metrics unavailable.", "metrics_available": False, "cpu": None, "memory": None}

    import shutil
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return {"error": "Docker CLI not found in system PATH. Docker metrics unavailable.", "metrics_available": False, "cpu": None, "memory": None}

    try:
        cmd = ["docker", "stats", "--no-stream", "--format", "{{json .}}", container_name_or_id]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if res.returncode != 0:
            return {"error": f"docker stats failed: {res.stderr.strip()}", "metrics_available": False, "cpu": None, "memory": None}

        raw = res.stdout.strip()
        if not raw:
            return {"error": f"No stats returned for container '{container_name_or_id}'.", "metrics_available": False, "cpu": None, "memory": None}

        stat = json.loads(raw.splitlines()[0])
        cpu_str = stat.get("CPUPerc", "0%").replace("%", "").strip()
        try:
            cpu_pct = float(cpu_str)
            cpu_m = int(round(cpu_pct * 10))
        except Exception:
            cpu_m = 0

        mem_raw = stat.get("MemUsage", "0MiB / 0MiB").split("/")[0].strip()
        mem_mib = parse_memory_to_mib(mem_raw)

        return {
            "pod_name": container_name_or_id,
            "container_name": container_name_or_id,
            "cpu": f"{cpu_m}m",
            "memory": f"{mem_mib}Mi",
            "cpu_millicores": cpu_m,
            "memory_mib": mem_mib,
            "metrics_available": True,
            "runtime_type": "docker"
        }
    except Exception as e:
        return {"error": f"Failed to get Docker metrics: {str(e)}", "metrics_available": False, "cpu": None, "memory": None}


def get_pod_metrics(target_pod=None, target_image=None, container_name=None, namespace="default", runtime_type=None, workload_name=None, run_id=None):
    """
    Retrieves live CPU and memory metrics for the target pod and container.
    Supports Kubernetes (kubectl top) and Docker (docker stats) runtimes.
    Returns honest errors when metrics are unavailable or pod is not running.
    Never fabricates metrics.
    """
    if runtime_type is None:
        runtime_type = os.environ.get("RUNTIME_TARGET", "kubernetes").lower()

    if runtime_type == "docker":
        return get_docker_metrics(target_pod or container_name)
    # Resolve target_pod if not directly passed
    if not target_pod:
        target_pod = os.environ.get("TARGET_POD")
    if not target_image:
        target_image = os.environ.get("TARGET_IMAGE") or os.environ.get("CONTAINER_IMAGE")
    if not workload_name:
        workload_name = os.environ.get("DEPLOYMENT_NAME") or os.environ.get("WORKLOAD_NAME")

    # If target_pod still not resolved:
    if not target_pod:
        if workload_name:
            from runtime_target import find_workload_pods
            w_pods = find_workload_pods(workload_name=workload_name, namespace=namespace)
            if w_pods:
                target_pod = w_pods[0].get("metadata", {}).get("name")
                if not container_name:
                    c_list = w_pods[0].get("spec", {}).get("containers", [])
                    if c_list:
                        container_name = c_list[0].get("name")
        elif target_image:
            disc = discover_workload(target_image=target_image, namespace=namespace, manual_select=False)
            if disc.get("found"):
                if not disc.get("running"):
                    return {
                        "error": disc.get("error") or f"Pod '{disc.get('pod_name')}' is in state '{disc.get('phase')}'",
                        "metrics_available": False,
                        "pod_name": disc.get("pod_name"),
                        "phase": disc.get("phase"),
                        "cpu": None,
                        "memory": None
                    }
                target_pod = disc.get("pod_name")
                if not container_name:
                    container_name = disc.get("container_name")
            else:
                return {
                    "error": disc.get("error") or f"Workload for image '{target_image}' not found in namespace '{namespace}'",
                    "metrics_available": False,
                    "pod_name": None,
                    "cpu": None,
                    "memory": None
                }

    if not target_pod:
        return {
            "error": "No target pod or image specified. Metrics unavailable.",
            "metrics_available": False,
            "pod_name": None,
            "cpu": None,
            "memory": None
        }

    # 1. Try container-level metrics if container_name is specified
    if target_pod and container_name:
        cmd_c = ["kubectl", "top", "pod", target_pod, "-n", namespace, "--containers", "--no-headers"]
        try:
            res_c = subprocess.run(cmd_c, capture_output=True, text=True, timeout=5)
            if res_c.returncode == 0:
                lines_c = [l.strip() for l in res_c.stdout.strip().split("\n") if l.strip()]
                for line in lines_c:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == target_pod and parts[1] == container_name:
                        raw_cpu = parts[2]
                        raw_mem = parts[3]
                        cpu_m = parse_cpu_to_millicores(raw_cpu)
                        mem_mib = parse_memory_to_mib(raw_mem)
                        return {
                            "pod_name": target_pod,
                            "container_name": container_name,
                            "cpu": f"{cpu_m}m",
                            "memory": f"{mem_mib}Mi",
                            "cpu_millicores": cpu_m,
                            "memory_mib": mem_mib,
                            "metrics_available": True
                        }
        except Exception:
            pass

    # 2. Pod-level metrics query
    cmd = ["kubectl", "top", "pod", target_pod, "-n", namespace, "--no-headers"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        return {
            "error": f"Metrics query timed out for pod '{target_pod}'. Workload metrics unreachable.",
            "pod_terminated": False,
            "metrics_available": False,
            "pod_name": target_pod,
            "cpu": None,
            "memory": None
        }
    except Exception as exc:
        return {
            "error": f"Failed to query metrics for pod '{target_pod}': {exc}",
            "pod_terminated": False,
            "metrics_available": False,
            "pod_name": target_pod,
            "cpu": None,
            "memory": None
        }

    # Check for errors
    if result.returncode != 0:
        err = result.stderr.strip()
        # If target_pod was deleted/replaced and workload_name is known, resolve pod strictly for that workload
        if workload_name and ("not found" in err.lower() or "notfound" in err.lower()):
            from runtime_target import find_workload_pods
            w_pods = find_workload_pods(workload_name=workload_name, namespace=namespace)
            if w_pods:
                new_p = w_pods[0].get("metadata", {}).get("name")
                if new_p and new_p != target_pod:
                    target_pod = new_p
                    os.environ["TARGET_POD"] = target_pod
                    try:
                        retry_res = subprocess.run(
                            ["kubectl", "top", "pod", target_pod, "-n", namespace, "--no-headers"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if retry_res.returncode == 0:
                            result = retry_res
                            err = None
                    except Exception:
                        pass
        elif not workload_name and target_image and ("not found" in err.lower() or "notfound" in err.lower()):
            disc = discover_workload(target_image=target_image, namespace=namespace, manual_select=False)
            if disc.get("found") and disc.get("running"):
                target_pod = disc.get("pod_name")
                os.environ["TARGET_POD"] = target_pod
                try:
                    retry_res = subprocess.run(
                        ["kubectl", "top", "pod", target_pod, "-n", namespace, "--no-headers"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if retry_res.returncode == 0:
                        result = retry_res
                        err = None
                except Exception:
                    pass
        if err:
            is_not_found = "not found" in err.lower() or "notfound" in err.lower()
            return {
                "error": f"Pod '{target_pod}' not found. Workload terminated or awaiting replacement." if is_not_found else err,
                "pod_terminated": is_not_found,
                "metrics_available": False,
                "pod_name": target_pod,
                "cpu": None,
                "memory": None
            }

    # Split output into lines
    lines = [l for l in result.stdout.strip().split("\n") if l.strip()]

    # If no pods exist or output is empty
    if not lines:
        return {
            "error": f"Pod '{target_pod}' metrics not available yet",
            "metrics_available": False,
            "pod_name": target_pod,
            "cpu": None,
            "memory": None
        }

    # Lines[0] has our pod metrics
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[0] == target_pod:
            raw_cpu = parts[1]
            raw_mem = parts[2]
            cpu_m = parse_cpu_to_millicores(raw_cpu)
            mem_mib = parse_memory_to_mib(raw_mem)

            return {
                "pod_name": parts[0],
                "container_name": container_name,
                "cpu": f"{cpu_m}m",
                "memory": f"{mem_mib}Mi",
                "cpu_millicores": cpu_m,
                "memory_mib": mem_mib,
                "metrics_available": True
            }

    workload_desc = target_pod or target_image or "workload"
    return {
        "error": f"Running {workload_desc} pod metrics not found",
        "metrics_available": False,
        "pod_name": target_pod,
        "cpu": None,
        "memory": None
    }


# ==========================================
# CONTINUOUS MONITORING
# ==========================================

def continuous_monitoring(target_pod=None, target_image=None):

    print(
        "\n========== MODULE 2 : CONTINUOUS MONITORING ==========\n"
    )

    while True:

        metrics = get_pod_metrics(target_pod=target_pod, target_image=target_image)

        # Update dashboard state thread-safely
        update_dashboard_metrics(metrics)

        if "error" in metrics:

            print(
                "Error :",
                metrics["error"]
            )

        else:

            print(
                "Pod      :",
                metrics["pod_name"]
            )

            print(
                "CPU      :",
                metrics["cpu"]
            )

            print(
                "Memory   :",
                metrics["memory"]
            )

            print(
                "------------------------------------------"
            )

        # Check every 5 seconds
        time.sleep(5)


# ==========================================
# TEST MODULE 2 DIRECTLY
# ==========================================

if __name__ == "__main__":

    continuous_monitoring()