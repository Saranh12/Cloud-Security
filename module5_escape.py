import subprocess
import json
import os
from datetime import datetime


def get_pods(target_pod=None, target_image=None, namespace="default", workload_kind=None, workload_name=None):
    """
    Retrieves pod specifications from Kubernetes.
    Supports targeting a specific pod, an image, or querying all pods in a namespace.
    If target_pod is stale or replaced during rollout, discovers the live replacement pod.
    """
    try:
        if not workload_name:
            workload_name = os.environ.get("DEPLOYMENT_NAME") or os.environ.get("WORKLOAD_NAME")

        if target_pod:
            cmd = ["kubectl", "get", "pod", target_pod, "-n", namespace, "-o", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                # If target_pod returned not found, attempt to find live replacement pod for the workload
                if workload_name or target_image:
                    try:
                        from runtime_target import find_workload_pods
                        rep_pods = find_workload_pods(
                            workload_kind=workload_kind,
                            workload_name=workload_name,
                            target_image=target_image,
                            namespace=namespace
                        )
                        if rep_pods:
                            return [rep_pods[0]]
                    except Exception:
                        pass
                return {"error": result.stderr.strip() or f"Pod '{target_pod}' not found"}
            data = json.loads(result.stdout)
            return [data]

        if workload_name:
            from runtime_target import find_workload_pods
            rep_pods = find_workload_pods(
                workload_kind=workload_kind,
                workload_name=workload_name,
                target_image=target_image,
                namespace=namespace
            )
            if rep_pods:
                return rep_pods
            return {"error": f"No running pod found for workload '{workload_name}' in namespace '{namespace}'"}

        cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Failed to query pods"
            }

        data = json.loads(result.stdout)
        items = data.get("items", [])

        if not items:
            return {
                "error": f"No Pods found in namespace '{namespace}'"
            }

        if target_image:
            from monitoring import matches_image_name
            matched = []
            for pod in items:
                spec = pod.get("spec", {})
                all_containers = spec.get("containers", []) + spec.get("initContainers", [])
                for container in all_containers:
                    if matches_image_name(container.get("image", ""), target_image):
                        matched.append(pod)
                        break
            if not matched:
                return {
                    "error": f"No running pod found for image '{target_image}' in namespace '{namespace}'",
                    "not_applicable": True
                }
            return matched

        return items

    except Exception as e:
        return {
            "error": str(e)
        }


def detect_escape_indicators(pods, run_id=None, target_container=None):
    """
    Comprehensive container escape detection and security configuration inspection.
    Inspects all relevant containers:
      - Application containers
      - Init containers
      - Ephemeral containers (if present)

    Identifies:
      - Privileged mode (securityContext.privileged == True)
      - Dangerous Linux capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, ALL)
      - Host PID namespace (hostPID: True)
      - Host Network namespace (hostNetwork: True)
      - Host IPC namespace (hostIPC: True)
      - Host filesystem mounts (hostPath volumes)

    Correctly distinguishes:
      - CASE A: Privileged container (privileged == True) -> Critical risk, incident triggered
      - CASE B: Non-privileged container (privileged == False/omitted) -> Normal, check passed
      - CASE C: Non-privileged with independent risk (e.g. hostPID) -> Detected separately
    """
    if isinstance(pods, dict) and "error" in pods:
        return pods

    results = []
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    dangerous_caps = [
        "SYS_ADMIN",
        "SYS_PTRACE",
        "NET_ADMIN",
        "ALL"
    ]

    for pod in pods:
        metadata = pod.get("metadata", {})
        pod_name = metadata.get("name", "unknown-pod")
        namespace = metadata.get("namespace", "default")

        # Determine owning workload
        owner_refs = metadata.get("ownerReferences", [])
        if owner_refs:
            owning_workload = f"{owner_refs[0].get('kind', 'Workload')}/{owner_refs[0].get('name', 'unknown')}"
        else:
            owning_workload = f"Pod/{pod_name}"

        spec = pod.get("spec", {})

        pod_findings = []
        structured_findings = []
        container_results = []
        pod_severity = "None"
        pod_has_privileged = False

        # Gather all container categories
        app_containers = [("app", c) for c in spec.get("containers", [])]
        init_containers = [("init", c) for c in spec.get("initContainers", [])]
        ephemeral_containers = [("ephemeral", c) for c in spec.get("ephemeralContainers", [])]
        all_containers = app_containers + init_containers + ephemeral_containers

        # Map runtime container statuses for container ID, state, and restart tracking
        status_data = pod.get("status", {}) if isinstance(pod.get("status"), dict) else {}
        raw_cs_list = (
            (status_data.get("containerStatuses") or []) +
            (status_data.get("initContainerStatuses") or []) +
            (status_data.get("ephemeralContainerStatuses") or [])
        )
        container_statuses = {}
        for cs in raw_cs_list:
            if isinstance(cs, dict) and cs.get("name"):
                container_statuses[cs.get("name")] = cs

        # If target_container was requested and exists in pod, focus container checks on it
        target_container_matched = (
            any(c.get("name") == target_container for _, c in all_containers)
            if target_container else False
        )

        for c_type, container in all_containers:
            c_name = container.get("name", "unknown")
            if target_container_matched and c_name != target_container:
                continue
            c_image = container.get("image", "unknown")
            security = container.get("securityContext", {}) or {}

            # Query runtime container status
            cs = container_statuses.get(c_name, {})
            c_id = cs.get("containerID", "")
            state_dict = cs.get("state", {}) if isinstance(cs.get("state"), dict) else {}
            if "running" in state_dict:
                c_state = "Running"
            elif "waiting" in state_dict:
                c_state = f"Waiting ({state_dict['waiting'].get('reason', 'Pending')})"
            elif "terminated" in state_dict:
                c_state = f"Terminated ({state_dict['terminated'].get('reason', 'Exited')})"
            else:
                c_state = "Unknown"
            c_restart_count = cs.get("restartCount", 0)

            # 1. Check privileged mode explicitly
            # In Kubernetes, omitting privileged defaults to False.
            is_privileged = (security.get("privileged") is True)
            c_findings = []
            c_severity = "None"

            if is_privileged:
                pod_has_privileged = True
                c_findings.append("Privileged container configuration detected.")
                if c_name == "target-container":
                    pod_findings.append("Privileged container configuration detected.")
                else:
                    pod_findings.append(f"Container '{c_name}' runs in privileged mode.")
                c_severity = "Critical"
                if pod_severity != "Critical":
                    pod_severity = "Critical"

                structured_findings.append({
                    "run_id": run_id,
                    "pod": pod_name,
                    "namespace": namespace,
                    "container": c_name,
                    "container_id": c_id,
                    "container_type": c_type,
                    "container_state": c_state,
                    "restart_count": c_restart_count,
                    "image": c_image,
                    "owning_workload": owning_workload,
                    "finding_type": "PRIVILEGED_CONTAINER",
                    "severity": "Critical",
                    "privileged": True,
                    "finding": "Privileged container configuration detected.",
                    "evidence": "securityContext.privileged == true in container specification",
                    "timestamp": timestamp_str
                })

            # 2. Check dangerous capabilities
            capabilities = security.get("capabilities", {}) or {}
            add_caps = capabilities.get("add", []) or []
            for cap in add_caps:
                cap_upper = str(cap).upper()
                if cap_upper in dangerous_caps:
                    c_findings.append(f"Dangerous capability detected: {cap_upper}")
                    pod_findings.append(f"Container '{c_name}' added dangerous capability: {cap_upper}")
                    if c_severity != "Critical":
                        c_severity = "High"
                    if pod_severity != "Critical":
                        pod_severity = "High"

                    structured_findings.append({
                        "run_id": run_id,
                        "pod": pod_name,
                        "namespace": namespace,
                        "container": c_name,
                        "container_id": c_id,
                        "container_type": c_type,
                        "container_state": c_state,
                        "restart_count": c_restart_count,
                        "image": c_image,
                        "owning_workload": owning_workload,
                        "finding_type": "DANGEROUS_CAPABILITY",
                        "severity": "High",
                        "privileged": is_privileged,
                        "finding": f"Dangerous capability detected: {cap_upper}",
                        "evidence": f"securityContext.capabilities.add contains '{cap_upper}'",
                        "recommendation": f"Drop capability {cap_upper} and adhere to least-privilege principles.",
                        "timestamp": timestamp_str
                    })

            # 3. Check Root Execution / Security Context Weaknesses
            if security.get("runAsUser") == 0:
                c_findings.append("Container configured with explicit root user (runAsUser: 0).")
                pod_findings.append(f"Container '{c_name}' configured to execute as root user.")
                if pod_severity not in ["Critical", "High"]:
                    pod_severity = "Medium"
                if c_severity not in ["Critical", "High"]:
                    c_severity = "Medium"

                structured_findings.append({
                    "run_id": run_id,
                    "pod": pod_name,
                    "namespace": namespace,
                    "container": c_name,
                    "container_id": c_id,
                    "container_type": c_type,
                    "container_state": c_state,
                    "image": c_image,
                    "finding_type": "ROOT_EXECUTION",
                    "severity": "Medium",
                    "privileged": is_privileged,
                    "finding": "Container configured with explicit root user (runAsUser: 0).",
                    "evidence": "securityContext.runAsUser == 0",
                    "recommendation": "Configure container with non-root user (e.g. runAsUser >= 1000).",
                    "timestamp": timestamp_str
                })

            container_results.append({
                "container": c_name,
                "container_id": c_id,
                "type": c_type,
                "image": c_image,
                "state": c_state,
                "restart_count": c_restart_count,
                "privileged": is_privileged,
                "findings": c_findings,
                "severity": c_severity,
                "status": "SUSPICIOUS CONFIGURATION DETECTED" if c_findings else "NORMAL"
            })

        # ---------------------------------
        # Check Pod-Level Escape Indicators
        # ---------------------------------

        # 3. Host PID namespace
        if spec.get("hostPID") is True:
            pod_findings.append("Host PID namespace enabled.")
            if pod_severity != "Critical":
                pod_severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": pod_name,
                "namespace": namespace,
                "container": "all",
                "image": "N/A",
                "owning_workload": owning_workload,
                "finding_type": "HOST_PID",
                "severity": "High",
                "privileged": pod_has_privileged,
                "finding": "Host PID namespace enabled.",
                "evidence": "spec.hostPID == true in pod specification",
                "timestamp": timestamp_str
            })

        # 4. Host Network namespace
        if spec.get("hostNetwork") is True:
            pod_findings.append("Host network namespace enabled.")
            if pod_severity != "Critical":
                pod_severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": pod_name,
                "namespace": namespace,
                "container": "all",
                "image": "N/A",
                "owning_workload": owning_workload,
                "finding_type": "HOST_NETWORK",
                "severity": "High",
                "privileged": pod_has_privileged,
                "finding": "Host network namespace enabled.",
                "evidence": "spec.hostNetwork == true in pod specification",
                "timestamp": timestamp_str
            })

        # 5. Host IPC namespace
        if spec.get("hostIPC") is True:
            pod_findings.append("Host IPC namespace enabled.")
            if pod_severity != "Critical":
                pod_severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": pod_name,
                "namespace": namespace,
                "container": "all",
                "image": "N/A",
                "owning_workload": owning_workload,
                "finding_type": "HOST_IPC",
                "severity": "High",
                "privileged": pod_has_privileged,
                "finding": "Host IPC namespace enabled.",
                "evidence": "spec.hostIPC == true in pod specification",
                "timestamp": timestamp_str
            })

        # 6. Host filesystem mounts
        for volume in spec.get("volumes", []):
            if "hostPath" in volume:
                path = volume["hostPath"].get("path", "/")
                pod_findings.append(f"Host filesystem mount detected: {path}")
                if pod_severity != "Critical":
                    pod_severity = "High"
                structured_findings.append({
                    "run_id": run_id,
                    "pod": pod_name,
                    "namespace": namespace,
                    "container": "volume",
                    "image": "N/A",
                    "owning_workload": owning_workload,
                    "finding_type": "HOST_PATH_MOUNT",
                    "severity": "High",
                    "privileged": pod_has_privileged,
                    "finding": f"Host filesystem mount detected: {path}",
                    "evidence": f"spec.volumes hostPath mount target: '{path}'",
                    "timestamp": timestamp_str
                })

        # Final status & incident response gating
        if len(pod_findings) == 0:
            status = "NORMAL"
            incident_triggered = False
        else:
            status = "SUSPICIOUS CONFIGURATION DETECTED"
            # Incident response triggered if Critical finding (e.g. Privileged container)
            incident_triggered = (pod_severity == "Critical")

        # Pick primary container details for display (prefer targeted container or container with findings)
        target_c_list = [c for c in container_results if c.get("container") == target_container] if target_container else []
        priv_c = [c for c in container_results if c.get("privileged")]
        finding_c = [c for c in container_results if c.get("findings")]
        if target_c_list:
            primary_c = target_c_list[0]
        elif priv_c:
            primary_c = priv_c[0]
        elif finding_c:
            primary_c = finding_c[0]
        elif container_results:
            primary_c = container_results[0]
        else:
            primary_c = {}

        primary_c_name = primary_c.get("container", "main")
        primary_c_image = primary_c.get("image", "unknown")
        primary_c_id = primary_c.get("container_id", "")

        results.append({
            "pod": pod_name,
            "pod_uid": metadata.get("uid", ""),
            "namespace": namespace,
            "owning_workload": owning_workload,
            "container": primary_c_name,
            "container_id": primary_c_id,
            "image": primary_c_image,
            "privileged": pod_has_privileged,
            "containers": container_results,
            "findings": pod_findings,
            "structured_findings": structured_findings,
            "severity": pod_severity,
            "status": status,
            "incident_triggered": incident_triggered
        })

    return results


def inspect_docker_container(container_name_or_id, run_id=None):
    """
    Inspects a runtime Docker container for security risks:
      - Privileged mode (HostConfig.Privileged == True)
      - Dangerous capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, ALL)
      - Host PID / Network / IPC namespaces
      - HostPath volume mounts
      - Root execution
    Returns a standardized list of escape result dictionaries compatible with detect_escape_indicators.
    """
    import shutil
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return {"error": "Docker CLI not found on system PATH."}

    try:
        proc = subprocess.run(
            ["docker", "inspect", container_name_or_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode != 0:
            return {"error": f"Failed to inspect Docker container '{container_name_or_id}': {proc.stderr.strip()}"}

        data = json.loads(proc.stdout)
        if not data:
            return {"error": f"Empty inspection data for Docker container '{container_name_or_id}'"}

        c_info = data[0]
        c_id = c_info.get("Id", "")[:12]
        c_name = c_info.get("Name", "").lstrip("/")
        c_image = c_info.get("Config", {}).get("Image", "")
        host_config = c_info.get("HostConfig", {}) or {}
        config = c_info.get("Config", {}) or {}
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        findings = []
        structured_findings = []
        severity = "None"
        is_privileged = (host_config.get("Privileged") is True)

        # 1. Privileged mode
        if is_privileged:
            findings.append("Privileged container configuration detected.")
            severity = "Critical"
            structured_findings.append({
                "run_id": run_id,
                "pod": c_name,
                "container": c_name,
                "container_id": c_id,
                "image": c_image,
                "finding_type": "PRIVILEGED_CONTAINER",
                "severity": "Critical",
                "privileged": True,
                "finding": "Privileged container configuration detected.",
                "evidence": "HostConfig.Privileged == true in container configuration",
                "recommendation": "Disable privileged mode unless specifically required.",
                "timestamp": timestamp_str
            })

        # 2. Dangerous capabilities
        cap_add = host_config.get("CapAdd") or []
        dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "ALL"]
        for cap in cap_add:
            cap_upper = str(cap).upper()
            if cap_upper in dangerous_caps:
                findings.append(f"Dangerous capability detected: {cap_upper}")
                if severity != "Critical":
                    severity = "High"
                structured_findings.append({
                    "run_id": run_id,
                    "pod": c_name,
                    "container": c_name,
                    "container_id": c_id,
                    "image": c_image,
                    "finding_type": "DANGEROUS_CAPABILITY",
                    "severity": "High",
                    "privileged": is_privileged,
                    "finding": f"Dangerous capability detected: {cap_upper}",
                    "evidence": f"HostConfig.CapAdd contains '{cap_upper}'",
                    "recommendation": f"Drop capability {cap_upper}.",
                    "timestamp": timestamp_str
                })

        # 3. Host PID
        if host_config.get("PidMode") == "host":
            findings.append("Host PID namespace enabled.")
            if severity != "Critical":
                severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": c_name,
                "container": c_name,
                "finding_type": "HOST_PID",
                "severity": "High",
                "privileged": is_privileged,
                "finding": "Host PID namespace enabled.",
                "evidence": "HostConfig.PidMode == 'host'",
                "timestamp": timestamp_str
            })

        # 4. Host Network
        if host_config.get("NetworkMode") == "host":
            findings.append("Host network namespace enabled.")
            if severity != "Critical":
                severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": c_name,
                "container": c_name,
                "finding_type": "HOST_NETWORK",
                "severity": "High",
                "privileged": is_privileged,
                "finding": "Host network namespace enabled.",
                "evidence": "HostConfig.NetworkMode == 'host'",
                "timestamp": timestamp_str
            })

        # 5. Host IPC
        if host_config.get("IpcMode") == "host":
            findings.append("Host IPC namespace enabled.")
            if severity != "Critical":
                severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": c_name,
                "container": c_name,
                "finding_type": "HOST_IPC",
                "severity": "High",
                "privileged": is_privileged,
                "finding": "Host IPC namespace enabled.",
                "evidence": "HostConfig.IpcMode == 'host'",
                "timestamp": timestamp_str
            })

        # 6. Host filesystem mounts
        binds = host_config.get("Binds") or []
        for bind in binds:
            findings.append(f"Host filesystem mount detected: {bind}")
            if severity != "Critical":
                severity = "High"
            structured_findings.append({
                "run_id": run_id,
                "pod": c_name,
                "container": c_name,
                "finding_type": "HOST_PATH_MOUNT",
                "severity": "High",
                "privileged": is_privileged,
                "finding": f"Host filesystem mount detected: {bind}",
                "evidence": f"HostConfig.Binds contains '{bind}'",
                "timestamp": timestamp_str
            })

        # 7. Root execution
        user_str = str(config.get("User", "")).strip()
        if user_str in ["0", "root", ""]:
            findings.append("Container running as root user.")
            if severity == "None":
                severity = "Medium"

        status = "SUSPICIOUS CONFIGURATION DETECTED" if findings else "NORMAL"
        incident_triggered = (severity == "Critical")

        return [{
            "pod": c_name,
            "namespace": "docker",
            "owning_workload": f"DockerContainer/{c_name}",
            "container": c_name,
            "container_id": c_id,
            "image": c_image,
            "privileged": is_privileged,
            "findings": findings,
            "structured_findings": structured_findings,
            "severity": severity,
            "status": status,
            "incident_triggered": incident_triggered
        }]

    except Exception as e:
        return {"error": f"Failed to inspect Docker container: {str(e)}"}


def main(target_pod=None, target_image=None, namespace="default"):
    print("\n========== MODULE 5 : CONTAINER ESCAPE DETECTION ==========\n")
    if not target_pod:
        target_pod = os.environ.get("TARGET_POD")
    if not target_image:
        target_image = os.environ.get("TARGET_IMAGE")

    pods = get_pods(target_pod=target_pod, target_image=target_image, namespace=namespace)

    results = detect_escape_indicators(pods)

    if isinstance(results, dict) and "error" in results:
        print("Error :", results["error"])
        return

    suspicious_found = False

    for result in results:
        print("Pod        :", result["pod"])
        print("Namespace  :", result.get("namespace", "default"))
        print("Container  :", result.get("container", "main"))
        if result.get("container_id"):
            print("ContainerID:", result.get("container_id"))
        print("Image      :", result.get("image", "unknown"))
        print("Privileged :", "true" if result.get("privileged") else "false")
        print("Status     :", result["status"])
        print("Severity   :", result["severity"])

        if len(result["findings"]) == 0:
            print("Finding    : No privileged-container security risk detected.")
            print("Incident Response: Not triggered")
        else:
            suspicious_found = True
            for finding in result["findings"]:
                print("Finding    :", finding)
            if result.get("incident_triggered"):
                print("Incident Response: Triggered")
            else:
                print("Incident Response: Not triggered (Non-critical configuration)")

        print("-" * 50)

    if suspicious_found:
        print("Container escape risk or privileged configuration detected in one or more Pods.")
    else:
        print("No container escape indicators or privileged configurations detected.")


if __name__ == "__main__":
    import sys
    arg_pod = sys.argv[1] if len(sys.argv) > 1 else None
    arg_img = sys.argv[2] if len(sys.argv) > 2 else None
    main(target_pod=arg_pod, target_image=arg_img)
