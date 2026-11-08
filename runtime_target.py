"""
Runtime Target Representation and Workload Discovery / Revalidation Engine.

Provides:
- Shared RuntimeTarget representation across M2, M4, M5, M6, M7-M11.
- Upfront workload discovery and interactive selection prompt.
- Dynamic pod revalidation (handling stale pod names during Deployment rollouts).
- ReplicaSet -> Deployment ownerReferences resolution.
- Specific container targeting (without assuming container name equals image name).
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any


class RuntimeTarget:
    """
    Shared runtime target representation capturing complete workload and pod identity.
    """
    def __init__(
        self,
        namespace: str = "default",
        workload_kind: str = "Deployment",
        workload_name: str = "unknown",
        workload_uid: Optional[str] = None,
        owner_references: Optional[List[Dict[str, Any]]] = None,
        pod_name: str = "",
        pod_uid: Optional[str] = None,
        container_name: str = "",
        container_id: Optional[str] = None,
        requested_image: str = "",
        runtime_image: str = "",
        image_id: Optional[str] = None,
        privileged: bool = False,
        discovery_timestamp: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        status: str = "Running"
    ):
        self.namespace = namespace
        self.workload_kind = workload_kind
        self.workload_name = workload_name
        self.workload_uid = workload_uid
        self.owner_references = owner_references or []
        self.pod_name = pod_name
        self.pod_uid = pod_uid
        self.container_name = container_name
        self.container_id = container_id
        self.requested_image = requested_image
        self.runtime_image = runtime_image or requested_image
        self.image_id = image_id
        self.privileged = bool(privileged)
        self.discovery_timestamp = discovery_timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.labels = labels or {}
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "namespace": self.namespace,
            "workload_kind": self.workload_kind,
            "workload_name": self.workload_name,
            "workload_uid": self.workload_uid,
            "owner_references": self.owner_references,
            "pod_name": self.pod_name,
            "pod_uid": self.pod_uid,
            "container_name": self.container_name,
            "container_id": self.container_id,
            "requested_image": self.requested_image,
            "runtime_image": self.runtime_image,
            "image_id": self.image_id,
            "privileged": self.privileged,
            "discovery_timestamp": self.discovery_timestamp,
            "labels": self.labels,
            "status": self.status
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeTarget":
        if not data:
            return cls()
        return cls(
            namespace=data.get("namespace", "default"),
            workload_kind=data.get("workload_kind", "Deployment"),
            workload_name=data.get("workload_name", "unknown"),
            workload_uid=data.get("workload_uid"),
            owner_references=data.get("owner_references"),
            pod_name=data.get("pod_name", ""),
            pod_uid=data.get("pod_uid"),
            container_name=data.get("container_name", ""),
            container_id=data.get("container_id"),
            requested_image=data.get("requested_image", ""),
            runtime_image=data.get("runtime_image", ""),
            image_id=data.get("image_id"),
            privileged=data.get("privileged", False),
            discovery_timestamp=data.get("discovery_timestamp"),
            labels=data.get("labels"),
            status=data.get("status", "Running")
        )

    def __repr__(self) -> str:
        return (
            f"<RuntimeTarget {self.workload_kind}/{self.workload_name} "
            f"namespace={self.namespace} pod={self.pod_name} container={self.container_name} "
            f"image={self.runtime_image} privileged={self.privileged}>"
        )


def normalize_image_name(img: str) -> str:
    """
    Normalizes image string for comparison across registries, libraries, and tags.
    e.g., 'docker.io/library/python:3.12-slim' -> 'python:3.12-slim'
          'library/python:3.12-slim' -> 'python:3.12-slim'
          'python:3.12-slim' -> 'python:3.12-slim'
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


def matches_image_name(container_img: str, target_img: str) -> bool:
    """
    Checks if container image matches target image.
    Supports tagged vs untagged matching, private registries, and handles digest references.
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

    # Check repository match if one has registry prefix and other does not
    c_parts = img_c_nodigest.split("/")
    t_parts = img_t_nodigest.split("/")
    if len(t_parts) == 1 and len(c_parts) > 1 and c_parts[-1] == t_parts[0]:
        return True
    if len(c_parts) == 1 and len(t_parts) > 1 and t_parts[-1] == c_parts[0]:
        return True

    base_c = img_c_nodigest.split(":")[0]
    base_t = img_t_nodigest.split(":")[0]
    if base_c == base_t:
        tag_c = img_c_nodigest.split(":")[1] if ":" in img_c_nodigest else "latest"
        tag_t = img_t_nodigest.split(":")[1] if ":" in img_t_nodigest else "latest"
        return tag_c == tag_t
    return False


def resolve_owning_workload_from_metadata(metadata: Dict[str, Any], namespace: str = "default") -> Dict[str, Any]:
    """
    Resolves the owning workload from pod metadata.
    Follows:
      - Pod -> ReplicaSet -> Deployment
      - Pod -> Job -> CronJob
      - Pod -> StatefulSet
      - Pod -> DaemonSet
      - Standalone Pod
    """
    owner_refs = metadata.get("ownerReferences", [])
    if not owner_refs:
        pod_name = metadata.get("name", "unknown")
        return {"kind": "Pod", "name": pod_name, "uid": metadata.get("uid"), "owner_refs": []}

    direct_owner = owner_refs[0]
    kind = direct_owner.get("kind", "Unknown")
    name = direct_owner.get("name", "unknown")
    uid = direct_owner.get("uid")

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
                        "uid": rs_owners[0].get("uid"),
                        "replicaset": name,
                        "owner_refs": owner_refs
                    }
        except Exception:
            pass
        return {"kind": "ReplicaSet", "name": name, "uid": uid, "owner_refs": owner_refs}

    if kind == "Job":
        try:
            cmd = ["kubectl", "get", "job", name, "-n", namespace, "-o", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                job_data = json.loads(res.stdout)
                job_owners = job_data.get("metadata", {}).get("ownerReferences", [])
                if job_owners and job_owners[0].get("kind") == "CronJob":
                    return {
                        "kind": "CronJob",
                        "name": job_owners[0].get("name"),
                        "uid": job_owners[0].get("uid"),
                        "job": name,
                        "owner_refs": owner_refs
                    }
        except Exception:
            pass
        return {"kind": "Job", "name": name, "uid": uid, "owner_refs": owner_refs}

    return {"kind": kind, "name": name, "uid": uid, "owner_refs": owner_refs}


def discover_docker_workloads(
    target_image: Optional[str] = None,
    target_container: Optional[str] = None
) -> List[RuntimeTarget]:
    """
    Discovers running Docker containers matching target_image or target_container.
    Extracts container ID, name, runtime image, image ID, labels, and privileged status.
    """
    targets: List[RuntimeTarget] = []
    import shutil
    if not shutil.which("docker"):
        return []

    try:
        cmd = ["docker", "ps", "--format", "{{json .}}"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if res.returncode != 0:
            return []

        lines = [l.strip() for l in res.stdout.strip().split("\n") if l.strip()]
        for line in lines:
            try:
                c_summary = json.loads(line)
            except Exception:
                continue

            c_id = c_summary.get("ID", "")
            c_name = c_summary.get("Names", "").lstrip("/")
            c_img = c_summary.get("Image", "")

            # Match criteria
            matched = False
            if target_container:
                if target_container in [c_name, c_id] or c_name == target_container.lstrip("/"):
                    matched = True
            elif target_image:
                if matches_image_name(c_img, target_image):
                    matched = True
            else:
                matched = True

            if not matched:
                continue

            # Detailed inspect
            is_priv = False
            full_img_id = None
            labels_dict = {}
            status_str = "Running"

            try:
                insp_cmd = ["docker", "inspect", c_id]
                insp_res = subprocess.run(insp_cmd, capture_output=True, text=True, timeout=5)
                if insp_res.returncode == 0:
                    insp_data = json.loads(insp_res.stdout)
                    if insp_data:
                        details = insp_data[0]
                        host_cfg = details.get("HostConfig", {}) or {}
                        is_priv = (host_cfg.get("Privileged") is True)
                        full_img_id = details.get("Image")
                        cfg = details.get("Config", {}) or {}
                        labels_dict = cfg.get("Labels", {}) or {}
                        status_str = details.get("State", {}).get("Status", "Running")
            except Exception:
                pass

            targets.append(RuntimeTarget(
                namespace="docker",
                workload_kind="DockerContainer",
                workload_name=c_name or c_id,
                workload_uid=c_id,
                owner_references=[],
                pod_name=c_name or c_id,
                pod_uid=c_id,
                container_name=c_name or c_id,
                container_id=c_id,
                requested_image=target_image or c_img,
                runtime_image=c_img,
                image_id=full_img_id,
                privileged=is_priv,
                labels=labels_dict,
                status=status_str
            ))
    except Exception:
        pass

    return targets


def discover_runtime_workloads(
    target_image: Optional[str] = None,
    target_pod: Optional[str] = None,
    namespace: Optional[str] = "default",
    runtime: Optional[str] = None
) -> List[RuntimeTarget]:
    """
    Discovers all active Kubernetes or Docker workloads matching target_image or target_pod.
    Returns a deduplicated list of RuntimeTarget instances representing distinct workloads.
    """
    if runtime is None:
        runtime = os.environ.get("RUNTIME_TARGET", "kubernetes").lower()

    if runtime == "docker":
        return discover_docker_workloads(target_image=target_image, target_container=target_pod)

    targets: List[RuntimeTarget] = []
    try:
        search_all = (namespace is None or namespace == "")
        cmd = ["kubectl", "get", "pods", "-A", "-o", "json"] if search_all else ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if res.returncode != 0:
            return []

        data = json.loads(res.stdout)
        items = data.get("items", [])
        if not items and not search_all:
            # Fallback cluster-wide query if namespace returned 0 pods
            cmd_all = ["kubectl", "get", "pods", "-A", "-o", "json"]
            res_all = subprocess.run(cmd_all, capture_output=True, text=True, timeout=12)
            if res_all.returncode == 0:
                data = json.loads(res_all.stdout)
                items = data.get("items", [])

        if not items:
            return []

        # Map to track distinct workloads: (namespace, workload_kind, workload_name) -> RuntimeTarget
        workload_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        for pod in items:
            metadata = pod.get("metadata", {})
            p_name = metadata.get("name", "")
            p_ns = metadata.get("namespace", "default")
            p_uid = metadata.get("uid")
            p_labels = metadata.get("labels", {})
            creation_ts = metadata.get("creationTimestamp", "")
            status_data = pod.get("status", {})
            p_phase = status_data.get("phase", "Unknown")
            spec = pod.get("spec", {})
            containers = (
                spec.get("containers", []) +
                spec.get("initContainers", []) +
                spec.get("ephemeralContainers", [])
            )

            # Skip system namespaces unless explicitly targeted
            if p_ns in ["kube-system", "kube-node-lease", "kube-public"] and not (target_pod and p_name == target_pod):
                if not (target_image and ("kube-" in target_image or "coredns" in target_image or "etcd" in target_image)):
                    continue

            # Only inspect Running pods
            if p_phase != "Running":
                continue

            # Check container match
            matched_container = None
            if target_pod:
                if p_name == target_pod:
                    if target_image:
                        for c in containers:
                            if matches_image_name(c.get("image", ""), target_image):
                                matched_container = c
                                break
                    if not matched_container and containers:
                        matched_container = containers[0]
            elif target_image:
                for c in containers:
                    if matches_image_name(c.get("image", ""), target_image):
                        matched_container = c
                        break
            else:
                if containers:
                    matched_container = containers[0]

            if not matched_container:
                continue

            # Container details
            c_name = matched_container.get("name", "")
            c_img = matched_container.get("image", "")
            sec_ctx = matched_container.get("securityContext", {}) or {}
            is_priv = (sec_ctx.get("privileged") is True)

            # Container status details across regular, init, and ephemeral containers
            c_statuses = (
                status_data.get("containerStatuses", []) +
                status_data.get("initContainerStatuses", []) +
                status_data.get("ephemeralContainerStatuses", [])
            )
            c_id = None
            img_id = None
            for cs in c_statuses:
                if cs.get("name") == c_name:
                    c_id = cs.get("containerID")
                    img_id = cs.get("imageID")
                    break

            owner_info = resolve_owning_workload_from_metadata(metadata, namespace=p_ns)
            w_kind = owner_info.get("kind", "Deployment")
            w_name = owner_info.get("name", p_name)
            w_uid = owner_info.get("uid")
            owner_refs = owner_info.get("owner_refs", metadata.get("ownerReferences", []))

            key = (p_ns, w_kind, w_name)

            candidate = {
                "namespace": p_ns,
                "workload_kind": w_kind,
                "workload_name": w_name,
                "workload_uid": w_uid,
                "owner_references": owner_refs,
                "pod_name": p_name,
                "pod_uid": p_uid,
                "container_name": c_name,
                "container_id": c_id,
                "requested_image": target_image or c_img,
                "runtime_image": c_img,
                "image_id": img_id,
                "privileged": is_priv,
                "labels": p_labels,
                "creation_ts": creation_ts,
                "status": p_phase
            }

            # If workload already seen, prefer newer pod
            if key not in workload_map or creation_ts > workload_map[key]["creation_ts"]:
                workload_map[key] = candidate

        for data_dict in workload_map.values():
            targets.append(RuntimeTarget(
                namespace=data_dict["namespace"],
                workload_kind=data_dict["workload_kind"],
                workload_name=data_dict["workload_name"],
                workload_uid=data_dict["workload_uid"],
                owner_references=data_dict["owner_references"],
                pod_name=data_dict["pod_name"],
                pod_uid=data_dict["pod_uid"],
                container_name=data_dict["container_name"],
                container_id=data_dict["container_id"],
                requested_image=data_dict["requested_image"],
                runtime_image=data_dict["runtime_image"],
                image_id=data_dict["image_id"],
                privileged=data_dict["privileged"],
                labels=data_dict["labels"],
                status=data_dict["status"]
            ))

    except Exception:
        pass

    return targets


def prompt_or_select_runtime_target(
    workloads: List[RuntimeTarget],
    preferred_workload: Optional[str] = None,
    is_cli: bool = True
) -> Optional[RuntimeTarget]:
    """
    Selects the active runtime target.
    If multiple workloads match:
      - Checks if preferred_workload matches.
      - In interactive CLI mode, displays the exact prompt format required by Section 6:
          Available workloads:

          [1] Deployment/python-app
          Namespace: default
          Pod: python-app-xxxxx
          Container: python
          Image: python:3.12-slim
          Privileged: true

          [2] Deployment/kubeguard-python
          Namespace: default
          Pod: kubeguard-python-xxxxx
          Container: target-container
          Image: python:3.12-slim
          Privileged: false

          Select workload:
      - In non-interactive mode, deterministically selects the first workload and logs notice.
    """
    if not workloads:
        return None

    if len(workloads) == 1:
        return workloads[0]

    # Check for active assessment workload or explicit preferred workload match (name or kind/name)
    active_workload = preferred_workload or os.environ.get("DEPLOYMENT_NAME") or os.environ.get("WORKLOAD_NAME")
    if active_workload:
        pref = str(active_workload).strip().lower()
        for w in workloads:
            if (
                pref == w.workload_name.lower() or
                pref == f"{w.workload_kind}/{w.workload_name}".lower() or
                pref == w.pod_name.lower()
            ):
                return w

    # In automatic mode, if a KubeGuard assessment workload is in the list, automatically select it
    for w in workloads:
        if w.workload_name.startswith("kubeguard-test-"):
            return w

    # Multiple workloads match: Prompt user if CLI or stdin is interactive
    is_interactive = is_cli and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()

    if is_interactive:
        print("\nAvailable workloads:\n")
        for idx, w in enumerate(workloads, 1):
            priv_str = "true" if w.privileged else "false"
            print(f"[{idx}] {w.workload_kind}/{w.workload_name}")
            print(f"Namespace: {w.namespace}")
            print(f"Pod: {w.pod_name}")
            print(f"Container: {w.container_name}")
            print(f"Image: {w.runtime_image}")
            print(f"Privileged: {priv_str}\n")

        try:
            choice = input("Select workload: ").strip()
            if choice.isdigit():
                c_int = int(choice)
                if 1 <= c_int <= len(workloads):
                    return workloads[c_int - 1]
            elif choice:
                # Match by string name
                c_lower = choice.lower()
                for w in workloads:
                    if (
                        c_lower == w.workload_name.lower() or
                        c_lower == f"{w.workload_kind}/{w.workload_name}".lower() or
                        c_lower in w.workload_name.lower()
                    ):
                        return w
            # Default to first option
            return workloads[0]
        except (EOFError, KeyboardInterrupt):
            return workloads[0]
    else:
        selected = workloads[0]
        print(
            f"[!] Ambiguity Notice: Multiple workloads found for image '{selected.requested_image}'. "
            f"Selected primary: {selected.namespace}/{selected.workload_kind}/{selected.workload_name} "
            f"(Pod: {selected.pod_name}, Privileged: {str(selected.privileged).lower()})"
        )
        return selected


def find_workload_pods(
    workload_kind: Optional[str] = None,
    workload_name: Optional[str] = None,
    target_image: Optional[str] = None,
    namespace: str = "default"
) -> List[Dict[str, Any]]:
    """
    Finds live pod specifications in a namespace belonging to a specific owning workload.
    """
    matched: List[Dict[str, Any]] = []
    try:
        cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            return []

        data = json.loads(res.stdout)
        items = data.get("items", [])

        for pod in items:
            p_status = pod.get("status", {})
            if p_status.get("phase") != "Running":
                continue

            metadata = pod.get("metadata", {})
            owner_info = resolve_owning_workload_from_metadata(metadata, namespace=namespace)

            owner_match = True
            if workload_name:
                w_owner = owner_info.get("name", "")
                if workload_kind:
                    owner_match = (
                        owner_info.get("kind", "").lower() == workload_kind.lower() and
                        w_owner.lower() == workload_name.lower()
                    )
                else:
                    owner_match = (w_owner.lower() == workload_name.lower())

            img_match = True
            if target_image:
                img_match = False
                for c in pod.get("spec", {}).get("containers", []):
                    if matches_image_name(c.get("image", ""), target_image):
                        img_match = True
                        break

            if owner_match and img_match:
                matched.append(pod)

        # Sort newest first
        matched.sort(
            key=lambda p: p.get("metadata", {}).get("creationTimestamp", ""),
            reverse=True
        )
    except Exception:
        pass

    return matched


def revalidate_runtime_target(
    target: RuntimeTarget,
    timeout: int = 10
) -> Tuple[bool, Optional[str]]:
    """
    Revalidates the selected workload immediately before inspection modules (e.g. M5).
    - Checks if target.pod_name is still valid and running.
    - If stale/terminated, resolves the replacement pod via owning workload and ownerReferences.
    - Updates target.pod_name, target.pod_uid, target.container_id without switching workloads.
    - Returns (True, None) if live ready pod confirmed, or (False, error_message).
    """
    if not target:
        return False, "Runtime target is None"

    # 0. Docker runtime revalidation
    if target.namespace == "docker" or target.workload_kind == "DockerContainer":
        c_id = target.container_id or target.pod_name or target.workload_name
        import shutil
        if not shutil.which("docker"):
            return False, "Docker CLI is not available in PATH"
        try:
            insp_cmd = ["docker", "inspect", c_id]
            insp_res = subprocess.run(insp_cmd, capture_output=True, text=True, timeout=timeout)
            if insp_res.returncode == 0:
                insp_data = json.loads(insp_res.stdout)
                if insp_data:
                    details = insp_data[0]
                    state = details.get("State", {})
                    if state.get("Running", False) or state.get("Status") == "running":
                        host_cfg = details.get("HostConfig", {}) or {}
                        target.privileged = (host_cfg.get("Privileged") is True)
                        target.status = state.get("Status", "running")
                        cfg = details.get("Config", {}) or {}
                        target.runtime_image = cfg.get("Image", target.runtime_image)
                        target.image_id = details.get("Image", target.image_id)
                        target.labels = cfg.get("Labels", target.labels)
                        return True, None
                    else:
                        return False, f"Docker container '{c_id}' is not running (status: {state.get('Status')})"
            return False, f"Docker container '{c_id}' not found"
        except Exception as e:
            return False, f"Docker inspect failed: {e}"

    # 1. First probe existing pod_name
    if target.pod_name:
        cmd = ["kubectl", "get", "pod", target.pod_name, "-n", target.namespace, "-o", "json"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                pod_json = json.loads(res.stdout)
                phase = pod_json.get("status", {}).get("phase", "")
                if phase == "Running":
                    # Pod is alive and running; verify ownership
                    owner_info = resolve_owning_workload_from_metadata(pod_json.get("metadata", {}), namespace=target.namespace)
                    if (
                        not target.workload_name or
                        owner_info.get("name", "").lower() == target.workload_name.lower()
                    ):
                        # Update container ID if available
                        for cs in pod_json.get("status", {}).get("containerStatuses", []):
                            if cs.get("name") == target.container_name:
                                target.container_id = cs.get("containerID", target.container_id)
                                target.image_id = cs.get("imageID", target.image_id)
                                break
                        return True, None
        except Exception:
            pass

    # 2. Pod is stale, terminating, or deleted: Rediscover replacement pod for the SAME workload
    replacement_pods = find_workload_pods(
        workload_kind=target.workload_kind,
        workload_name=target.workload_name,
        target_image=target.requested_image,
        namespace=target.namespace
    )

    if replacement_pods:
        new_pod = replacement_pods[0]
        new_meta = new_pod.get("metadata", {})
        old_pod_name = target.pod_name
        target.pod_name = new_meta.get("name", "")
        target.pod_uid = new_meta.get("uid")
        target.discovery_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Resolve container name and ID
        containers = new_pod.get("spec", {}).get("containers", [])
        matched_c = None
        if target.container_name:
            for c in containers:
                if c.get("name") == target.container_name:
                    matched_c = c
                    break
        if not matched_c and target.requested_image:
            for c in containers:
                if matches_image_name(c.get("image", ""), target.requested_image):
                    matched_c = c
                    target.container_name = c.get("name", target.container_name)
                    break
        if not matched_c and containers:
            matched_c = containers[0]
            target.container_name = matched_c.get("name", target.container_name)

        if matched_c:
            sec_ctx = matched_c.get("securityContext", {}) or {}
            target.privileged = (sec_ctx.get("privileged") is True)
            target.runtime_image = matched_c.get("image", target.runtime_image)

        for cs in new_pod.get("status", {}).get("containerStatuses", []):
            if cs.get("name") == target.container_name:
                target.container_id = cs.get("containerID")
                target.image_id = cs.get("imageID")
                break

        print(
            f"[+] Workload pod updated: '{old_pod_name}' -> replacement pod '{target.pod_name}' "
            f"(owning workload: {target.workload_kind}/{target.workload_name})"
        )
        return True, None

    return False, f"No ready pods found for workload {target.workload_kind}/{target.workload_name} in namespace '{target.namespace}'"


TARGET_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "target_config.json")


def get_persisted_target_config() -> Optional[Dict[str, Any]]:
    """Reads persisted target workload configuration from config/target_config.json."""
    if os.path.exists(TARGET_CONFIG_PATH):
        try:
            with open(TARGET_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and data.get("workload_name"):
                    return data
        except Exception:
            pass
    return None


def persist_target_config(
    workload_name: str,
    namespace: str = "default",
    container_name: Optional[str] = None,
    image: Optional[str] = None,
    workload_kind: str = "Deployment"
) -> Dict[str, Any]:
    """Saves the target workload configuration so subsequent runs use it deterministically."""
    os.makedirs(os.path.dirname(TARGET_CONFIG_PATH), exist_ok=True)
    cfg = {
        "workload_kind": workload_kind,
        "workload_name": workload_name,
        "namespace": namespace,
        "container_name": container_name,
        "image": image,
        "configured_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(TARGET_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4)
    return cfg


def list_available_deployments(namespace: str = "default") -> List[Dict[str, Any]]:
    """
    Queries active Kubernetes Deployments in the namespace.
    Filters out system and obsolete test workloads.
    Discovers primary container and security context dynamically.
    """
    deployments = []
    try:
        cmd = ["kubectl", "get", "deployments", "-n", namespace, "-o", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if res.returncode != 0:
            return []

        data = json.loads(res.stdout)
        for item in data.get("items", []):
            name = item.get("metadata", {}).get("name", "")
            labels = item.get("metadata", {}).get("labels", {}) or {}

            # Skip obsolete test workloads
            if name.startswith("kubeguard-test-") or labels.get("kubeguard.io/assessment") == "true":
                continue

            containers = item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            primary_c = containers[0] if containers else {}
            c_name = primary_c.get("name", "")
            img = primary_c.get("image", "")
            sec = primary_c.get("securityContext", {}) or {}
            is_priv = (sec.get("privileged") is True)

            status = item.get("status", {})
            ready = f"{status.get('readyReplicas', 0)}/{status.get('replicas', 0)}"

            deployments.append({
                "workload_kind": "Deployment",
                "workload_name": name,
                "namespace": namespace,
                "container_name": c_name,
                "image": img,
                "privileged": is_priv,
                "ready": ready,
                "labels": labels
            })
    except Exception:
        pass

    return deployments


def resolve_existing_deployment_target(
    workload_name: str,
    namespace: str = "default",
    container_name: Optional[str] = None,
    timeout: int = 15
) -> Tuple[bool, Optional[RuntimeTarget], Optional[str]]:
    """
    Resolves the exact identity of an existing Kubernetes Deployment and its live active pod.
    - Inspects Deployment manifest to discover exact container name, image, and spec privileged status.
    - Resolves active replacement pod matching deployment selector.
    - Captures pod name, UID, container ID, runtime image ID, and effective privileged status.
    - Returns (success, RuntimeTarget, error_message).
    """
    try:
        # 1. Fetch Deployment specification
        cmd = ["kubectl", "get", "deployment", workload_name, "-n", namespace, "-o", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            return False, None, f"Deployment '{workload_name}' not found in namespace '{namespace}': {res.stderr.strip()}"

        dep_data = json.loads(res.stdout)
        containers = dep_data.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if not containers:
            return False, None, f"Deployment '{workload_name}' has no containers defined in template spec."

        # Discover container
        matched_c = None
        if container_name:
            for c in containers:
                if c.get("name") == container_name:
                    matched_c = c
                    break
        if not matched_c:
            # Pick first container dynamically
            matched_c = containers[0]

        actual_container_name = matched_c.get("name")
        deployment_image = matched_c.get("image")
        sec_ctx = matched_c.get("securityContext", {}) or {}
        privileged_in_spec = (sec_ctx.get("privileged") is True)
        selector_labels = dep_data.get("spec", {}).get("selector", {}).get("matchLabels", {})

        # 2. Query active pods for this deployment
        selector_str = ",".join([f"{k}={v}" for k, v in selector_labels.items()]) if selector_labels else f"app={workload_name}"
        active_pod = None
        start_time = datetime.now()

        # Wait bounded time if rollout is in progress
        while (datetime.now() - start_time).total_seconds() < timeout:
            cmd_pod = ["kubectl", "get", "pods", "-n", namespace, "-l", selector_str, "-o", "json"]
            res_pod = subprocess.run(cmd_pod, capture_output=True, text=True, timeout=8)
            if res_pod.returncode == 0:
                pod_data = json.loads(res_pod.stdout)
                items = pod_data.get("items", [])
                # Filter out terminating pods
                running_items = [p for p in items if not p.get("metadata", {}).get("deletionTimestamp")]
                if not running_items:
                    running_items = items
                # Sort newest first
                running_items.sort(key=lambda p: p.get("metadata", {}).get("creationTimestamp", ""), reverse=True)
                for p in running_items:
                    phase = p.get("status", {}).get("phase")
                    if phase in ["Running", "Pending"]:
                        active_pod = p
                        if phase == "Running":
                            break
                if active_pod and active_pod.get("status", {}).get("phase") == "Running":
                    break

            import time
            time.sleep(1.5)

        if not active_pod:
            return False, None, f"No active pods found for Deployment '{workload_name}' in namespace '{namespace}' (selector: {selector_str})."

        pod_meta = active_pod.get("metadata", {})
        pod_name = pod_meta.get("name")
        pod_uid = pod_meta.get("uid")

        # Container status details
        container_id = None
        runtime_image_id = None
        for cs in active_pod.get("status", {}).get("containerStatuses", []):
            if cs.get("name") == actual_container_name:
                container_id = cs.get("containerID")
                runtime_image_id = cs.get("imageID")
                break

        # Actual pod spec privileged verification
        actual_privileged = False
        for c in active_pod.get("spec", {}).get("containers", []):
            if c.get("name") == actual_container_name:
                c_sec = c.get("securityContext", {}) or {}
                actual_privileged = (c_sec.get("privileged") is True)
                break

        target = RuntimeTarget(
            namespace=namespace,
            workload_kind="Deployment",
            workload_name=workload_name,
            workload_uid=dep_data.get("metadata", {}).get("uid"),
            pod_name=pod_name,
            pod_uid=pod_uid,
            container_name=actual_container_name,
            container_id=container_id,
            requested_image=deployment_image,
            runtime_image=deployment_image,
            image_id=runtime_image_id,
            privileged=actual_privileged,
            labels=pod_meta.get("labels", {}),
            status=active_pod.get("status", {}).get("phase", "Running")
        )

        return True, target, None

    except Exception as e:
        return False, None, f"Failed to resolve deployment target '{workload_name}': {str(e)}"


def cleanup_obsolete_kubeguard_workloads(namespace: str = "default", preserve_target: Optional[str] = None) -> List[str]:
    """
    Safely deletes obsolete KubeGuard-owned test deployments (e.g. kubeguard-test-*).
    Strictly verifies ownership labels and refuses to touch user workloads (python-app, node-app, nginx).
    """
    deleted = []
    try:
        cmd = ["kubectl", "get", "deployments", "-n", namespace, "-o", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            return []

        data = json.loads(res.stdout)
        for item in data.get("items", []):
            w_name = item.get("metadata", {}).get("name", "")
            labels = item.get("metadata", {}).get("labels", {}) or {}

            if preserve_target and w_name.lower() == preserve_target.lower():
                continue

            is_obsolete_test = (
                w_name.startswith("kubeguard-test-") or
                labels.get("kubeguard.io/assessment") == "true" or
                (w_name in ["kubeguard-target", "kubeguard-priv"])
            )

            # Extra safety: NEVER delete user deployments
            if w_name in ["python-app", "node-app", "nginx", "redis-app", "mysql", "postgres"]:
                continue

            if is_obsolete_test:
                del_cmd = ["kubectl", "delete", "deployment", w_name, "-n", namespace, "--ignore-not-found=true"]
                del_res = subprocess.run(del_cmd, capture_output=True, text=True, timeout=12)
                if del_res.returncode == 0:
                    deleted.append(w_name)
    except Exception:
        pass

    return deleted


def parse_alert_status(success, error, was_attempted=True):
    """Normalizes notification results into SENT / FAILED / NOT CONFIGURED / NOT REQUIRED."""
    if not was_attempted:
        return "NOT REQUIRED"
    if success is True:
        return "SENT"
    err_str = str(error or "").lower()
    if "not configured" in err_str or "missing" in err_str or "none configured" in err_str:
        return "NOT CONFIGURED"
    if "not attempted" in err_str or "skipped" in err_str:
        return "NOT REQUIRED"
    return "FAILED"


def get_live_assessment_telemetry(workload_name: Optional[str] = None, namespace: str = "default") -> Dict[str, Any]:
    """
    Collects live real-time telemetry and security assessment state for M4 and M5
    against the actual admitted Kubernetes workload and current replacement pod.
    Strictly queries real cluster metrics and pod manifests. Never fabricates values.
    """
    # 1. Resolve active workload target
    if not workload_name:
        persisted = get_persisted_target_config()
        if persisted and persisted.get("workload_name"):
            workload_name = persisted.get("workload_name")
            namespace = persisted.get("namespace", namespace)

    if not workload_name:
        avail = list_available_deployments(namespace=namespace)
        if avail:
            workload_name = avail[0]["name"]

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Fallback structure if workload cannot be resolved
    if not workload_name:
        return {
            "success": False,
            "error": "No target workload configured or available in namespace.",
            "timestamp": now_str,
            "workload_name": "None",
            "pod_name": "None",
            "m4": {
                "pod": "None",
                "container": "None",
                "deployment_name": "None",
                "namespace": namespace,
                "image": "None",
                "cpu": "UNAVAILABLE",
                "memory": "UNAVAILABLE",
                "status": "UNAVAILABLE",
                "severity": "None",
                "reason": "No target workload configured.",
                "container_status": "Unavailable",
                "metrics_available": False,
                "assessment_timestamp": now_str,
                "metric_timestamp": now_str,
                "telegram_status": "NOT REQUIRED",
                "email_status": "NOT REQUIRED"
            },
            "m5": {
                "pod": "None",
                "container": "None",
                "deployment_name": "None",
                "namespace": namespace,
                "image": "None",
                "image_digest": "None",
                "status": "UNAVAILABLE",
                "severity": "None",
                "reason": "No target workload configured.",
                "findings": [],
                "finding_counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "privileged": False,
                "remediation": "Configure or deploy a target workload to assess security configurations.",
                "assessment_timestamp": now_str
            }
        }

    # 2. Resolve deployment and live active pod
    ok, target, err = resolve_existing_deployment_target(workload_name, namespace=namespace, timeout=5)
    if not ok or not target:
        err_msg = err or f"Could not resolve live target for '{workload_name}'"
        return {
            "success": False,
            "error": err_msg,
            "timestamp": now_str,
            "workload_name": workload_name,
            "pod_name": "None",
            "m4": {
                "pod": "None",
                "container": "None",
                "deployment_name": workload_name,
                "namespace": namespace,
                "image": "None",
                "cpu": "UNAVAILABLE",
                "memory": "UNAVAILABLE",
                "status": "UNAVAILABLE",
                "severity": "None",
                "reason": err_msg,
                "container_status": "Unavailable",
                "metrics_available": False,
                "assessment_timestamp": now_str,
                "metric_timestamp": now_str,
                "telegram_status": "NOT REQUIRED",
                "email_status": "NOT REQUIRED"
            },
            "m5": {
                "pod": "None",
                "container": "None",
                "deployment_name": workload_name,
                "namespace": namespace,
                "image": "None",
                "image_digest": "None",
                "status": "UNAVAILABLE",
                "severity": "None",
                "reason": err_msg,
                "findings": [],
                "finding_counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "privileged": False,
                "remediation": "Ensure the deployment has running pods in the cluster.",
                "assessment_timestamp": now_str
            }
        }

    # 3. Query admitted pod JSON directly from Kubernetes
    pod_json = None
    container_status_str = "Running"
    image_digest = target.image_id or "Not available"
    admitted_sec_ctx = {}
    try:
        cmd_p = ["kubectl", "get", "pod", target.pod_name, "-n", target.namespace, "-o", "json"]
        res_p = subprocess.run(cmd_p, capture_output=True, text=True, timeout=8)
        if res_p.returncode == 0:
            pod_json = json.loads(res_p.stdout)
            # Find matching container in spec
            for c in pod_json.get("spec", {}).get("containers", []):
                if c.get("name") == target.container_name:
                    admitted_sec_ctx = c.get("securityContext", {}) or {}
                    break
            # Find matching container status
            for cs in pod_json.get("status", {}).get("containerStatuses", []):
                if cs.get("name") == target.container_name:
                    if cs.get("imageID"):
                        image_digest = cs.get("imageID")
                    st = cs.get("state", {})
                    if "running" in st:
                        container_status_str = "Running"
                    elif "waiting" in st:
                        container_status_str = f"Waiting ({st['waiting'].get('reason', 'Pending')})"
                    elif "terminated" in st:
                        container_status_str = f"Terminated ({st['terminated'].get('reason', 'Exited')})"
                    break
    except Exception:
        pass

    # 4. Query live metrics from Kubernetes metrics-server
    cpu_val = "UNAVAILABLE"
    mem_val = "UNAVAILABLE"
    metrics_available = False
    metric_time_str = now_str
    m4_status = "NORMAL"
    m4_severity = "None"
    m4_reason = "No suspicious activity detected."

    try:
        cmd_top = ["kubectl", "top", "pod", target.pod_name, "-n", target.namespace, "--no-headers"]
        res_top = subprocess.run(cmd_top, capture_output=True, text=True, timeout=8)
        if res_top.returncode == 0 and res_top.stdout.strip():
            parts = res_top.stdout.strip().split()
            if len(parts) >= 3:
                cpu_val = parts[1]
                mem_val = parts[2]
                metrics_available = True
                metric_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                from module4_detection import detect_threat
                t_res = detect_threat({"cpu": cpu_val, "memory": mem_val, "pod": target.pod_name})
                m4_status = t_res.get("status", "NORMAL")
                m4_severity = t_res.get("severity", "None")
                m4_reason = t_res.get("reason", "No suspicious activity detected.")
        else:
            err_out = (res_top.stderr or res_top.stdout or "").strip()
            if "not available" in err_out.lower() or "not found" in err_out.lower():
                m4_status = "UNAVAILABLE"
                m4_reason = f"Metrics not available yet for pod '{target.pod_name}'. Metrics server is still aggregating data."
            else:
                m4_status = "FAILED"
                m4_reason = err_out or "Metrics server query returned non-zero code."
    except subprocess.TimeoutExpired:
        m4_status = "FAILED"
        m4_reason = f"Metrics query timed out after 8s for pod '{target.pod_name}'. Metrics server is unresponsive."
    except Exception as e:
        m4_status = "FAILED"
        m4_reason = f"Metrics query failed: {str(e)}"

    # 5. Execute M5 Container Escape and Security Inspection on admitted Pod
    from module5_escape import detect_escape_indicators
    m5_findings = []
    m5_status = "NORMAL"
    m5_severity = "None"
    m5_reason = "No container escape indicators detected."
    m5_remediation = "Maintain secure baseline policies and prevent admission of privileged containers."
    finding_counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    is_priv = target.privileged

    raw_inspect_lines = [
        f"KUBERNETES ADMITTED CONTAINER SECURITY INSPECTION",
        f"Workload   : {target.workload_kind}/{target.workload_name}",
        f"Pod        : {target.pod_name} (UID: {target.pod_uid})",
        f"Namespace  : {target.namespace}",
        f"Container  : {target.container_name}",
        f"Image      : {target.runtime_image}",
        f"Image ID   : {image_digest}",
        f"Container ID: {target.container_id or 'N/A'}",
        f"Admitted SecurityContext: {json.dumps(admitted_sec_ctx, indent=2)}",
        f"--------------------------------------------------"
    ]

    if pod_json:
        try:
            esc_res = detect_escape_indicators([pod_json], target_container=target.container_name)
            if isinstance(esc_res, list) and esc_res:
                primary = esc_res[0]
                m5_findings = primary.get("findings", [])
                is_priv = primary.get("privileged", is_priv)
                if m5_findings:
                    m5_status = "SUSPICIOUS ACTIVITY DETECTED"
                    m5_severity = primary.get("severity", "Critical" if is_priv else "High")
                    m5_reason = "• " + "\n• ".join(m5_findings)
                    if is_priv:
                        m5_remediation = "Remove securityContext.privileged from the container specification. Restrict container capabilities to least privilege."
                    else:
                        m5_remediation = "Remediate container security context settings to enforce least privilege access."

                    for f in m5_findings:
                        raw_inspect_lines.append(f"[FINDING] {f}")
                        finding_counts["total"] += 1
                        if "privileged" in f.lower():
                            finding_counts["critical"] += 1
                        else:
                            finding_counts["high"] += 1
                else:
                    m5_status = "NORMAL"
                    m5_severity = "None"
                    m5_reason = "No container escape indicators detected."
                    raw_inspect_lines.append("[CHECK] No container escape indicators detected.")
        except Exception as ee:
            raw_inspect_lines.append(f"[ERROR] Escape detection failed: {ee}")

    # 6. Read alert delivery status from persisted state / environment
    state_file = os.path.join(os.path.dirname(__file__), "reports", "dashboard_state.json")
    m4_tg_stat = "NOT CONFIGURED"
    m4_tg_err = None
    m4_em_stat = "NOT CONFIGURED"
    m4_em_err = None

    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as sf:
                s_data = json.load(sf)
                m4_dt = s_data.get("modules", {}).get("M4", {}).get("details", {}) or {}
                m6_dt = s_data.get("modules", {}).get("M6", {}).get("details", {}) or {}
                m4_alert = m6_dt.get("m4_alert", {})

                tg_succ = (m4_alert.get("telegram_status") == "SENT" or m4_dt.get("telegram_status") == "SENT")
                m4_tg_err = m4_alert.get("telegram_error") or m4_dt.get("telegram_error")
                m4_tg_stat = parse_alert_status(tg_succ, m4_tg_err, was_attempted=True)

                em_succ = (m4_alert.get("email_status") == "SENT" or m4_dt.get("email_status") == "SENT")
                m4_em_err = m4_alert.get("email_error") or m4_dt.get("email_error")
                m4_em_stat = parse_alert_status(em_succ, m4_em_err, was_attempted=True)
        except Exception:
            pass

    # 7. Pod Activity Analysis summary text
    if m4_status == "NORMAL":
        analysis_title = "No suspicious activity detected"
        analysis_body = "The container is running normally. No abnormal behavior found based on the current monitoring rules."
        analysis_type = "normal"
    elif m4_status in ["SUSPICIOUS ACTIVITY DETECTED", "THREAT DETECTED"]:
        analysis_title = "Suspicious activity detected"
        analysis_body = f"Abnormal resource threshold behavior detected in container: {m4_reason}"
        analysis_type = "threat"
    else:
        analysis_title = "Monitoring Signal Unavailable"
        analysis_body = f"Kubernetes metrics could not be collected for this pod ({m4_reason}). Cannot verify whether behavior is normal."
        analysis_type = "unavailable"

    telemetry = {
        "success": True,
        "timestamp": now_str,
        "workload_name": target.workload_name,
        "pod_name": target.pod_name,
        "runtime_target": target.to_dict(),
        "m4": {
            "pod": target.pod_name,
            "container": target.container_name,
            "deployment_name": target.workload_name,
            "namespace": target.namespace,
            "image": target.runtime_image,
            "cpu": cpu_val,
            "memory": mem_val,
            "status": m4_status,
            "severity": m4_severity,
            "reason": m4_reason,
            "container_status": container_status_str,
            "metrics_available": metrics_available,
            "assessment_timestamp": now_str,
            "metric_timestamp": metric_time_str,
            "analysis_title": analysis_title,
            "analysis_body": analysis_body,
            "analysis_type": analysis_type,
            "telegram_status": m4_tg_stat,
            "telegram_error": m4_tg_err,
            "email_status": m4_em_stat,
            "email_error": m4_em_err
        },
        "m5": {
            "pod": target.pod_name,
            "container": target.container_name,
            "deployment_name": target.workload_name,
            "namespace": target.namespace,
            "image": target.runtime_image,
            "image_digest": image_digest,
            "cpu": cpu_val,
            "memory": mem_val,
            "status": m5_status,
            "severity": m5_severity,
            "reason": m5_reason,
            "findings": m5_findings,
            "finding_counts": finding_counts,
            "privileged": is_priv,
            "admitted_security_context": admitted_sec_ctx,
            "remediation": m5_remediation,
            "assessment_timestamp": now_str,
            "raw_output": "\n".join(raw_inspect_lines)
        }
    }

    return telemetry
