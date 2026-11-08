import subprocess
import json
import time
import yaml
import re


# ==========================================
# GET POD INFORMATION
# ==========================================

def get_pod(pod_name, namespace=None):

    try:
        cmd = ["kubectl", "get", "pod", pod_name]
        if namespace:
            cmd.extend(["-n", namespace])
        cmd.extend(["-o", "json"])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:

            return {
                "error": result.stderr.strip()
            }

        return json.loads(
            result.stdout
        )

    except Exception as e:

        return {
            "error": str(e)
        }


# ==========================================
# CHECK POD OWNER
# ==========================================

def check_pod_controller(pod_data):
    owners = pod_data.get(
        "metadata",
        {}
    ).get(
        "ownerReferences",
        []
    )

    supported_controllers = [
        "ReplicaSet",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Job",
        "CronJob"
    ]

    for owner in owners:
        kind = owner.get("kind")
        if kind in supported_controllers:
            return {
                "managed": True,
                "owner": owner.get("name"),
                "kind": kind
            }

    return {
        "managed": False,
        "owner": None
    }


# ==========================================
# CHECK POD STATUS
# ==========================================

def is_running_pod(pod_data):

    phase = pod_data.get(
        "status",
        {}
    ).get(
        "phase"
    )

    return phase == "Running"


# ==========================================
# CHECK IF POD IS APPLICATION POD
# ==========================================

def is_application_pod(pod_data):

    labels = pod_data.get(
        "metadata",
        {}
    ).get(
        "labels",
        {}
    )

    return "app" in labels or "app.kubernetes.io/name" in labels or bool(labels)


# ==========================================
# DELETE SUSPICIOUS POD
# ==========================================

def delete_pod(
    pod_name,
    namespace
):

    try:

        result = subprocess.run(
            [
                "kubectl",
                "delete",
                "pod",
                pod_name,
                "-n",
                namespace
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:

            return {
                "success": False,
                "error": result.stderr.strip()
            }

        return {
            "success": True,
            "message": result.stdout.strip()
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }


# ==========================================
# FIND CORRECT REPLACEMENT POD
# ==========================================

def find_replacement_pod(
    old_pod,
    namespace,
    old_labels
):

    for _ in range(15):

        result = subprocess.run(
            [
                "kubectl",
                "get",
                "pods",
                "-n",
                namespace,
                "-o",
                "json"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:

            try:

                data = json.loads(
                    result.stdout
                )

                for pod in data.get(
                    "items",
                    []
                ):

                    name = pod[
                        "metadata"
                    ]["name"]

                    if name == old_pod:
                        continue

                    labels = pod.get("metadata", {}).get("labels", {})

                    # Determine application identity match
                    app_key = None
                    for candidate in ["app", "app.kubernetes.io/name", "name"]:
                        if candidate in old_labels and candidate in labels:
                            app_key = candidate
                            break
                    if app_key:
                        if labels.get(app_key) != old_labels.get(app_key):
                            continue
                    else:
                        # Fallback: check match against non-hash labels
                        mismatch = False
                        for k, v in old_labels.items():
                            if k not in ["pod-template-hash", "controller-revision-hash"]:
                                if labels.get(k) != v:
                                    mismatch = True
                                    break
                        if mismatch:
                            continue

                    phase = pod.get(
                        "status",
                        {}
                    ).get(
                        "phase"
                    )

                    if phase != "Running":
                        continue

                    # Reinspect security configuration of replacement pod
                    rep_spec = pod.get("spec", {})
                    rep_priv = any(
                        c.get("securityContext", {}).get("privileged") is True
                        for c in (rep_spec.get("containers", []) + rep_spec.get("initContainers", []))
                    )

                    return {
                        "found": True,
                        "pod": name,
                        "status": phase,
                        "privileged": rep_priv,
                        "security_reinspected": True,
                        "original_pod": old_pod,
                        "replacement_pod": name,
                        "security_note": (
                            "Warning: Replacement pod recreated with privileged=true from controller template"
                            if rep_priv else
                            "Replacement pod reinspected: runs with privileged=false"
                        )
                    }

            except Exception:
                pass

        time.sleep(2)

    return {
        "found": False
    }


# ==========================================
# GENERATE NETWORK POLICY
# ==========================================

def generate_network_policy(
    pod_name,
    namespace
):

    pod_data = get_pod(
        pod_name
    )

    if "error" in pod_data:

        return pod_data

    labels = pod_data.get(
        "metadata",
        {}
    ).get(
        "labels",
        {}
    )

    if not labels:

        return {
            "success": False,
            "error": "No labels found for Pod."
        }

    app_label = labels.get("app") or labels.get("app.kubernetes.io/name") or (list(labels.values())[0] if labels else None)
    app_key = "app" if "app" in labels else ("app.kubernetes.io/name" if "app.kubernetes.io/name" in labels else (list(labels.keys())[0] if labels else "app"))

    if not app_label:
        return {
            "success": False,
            "error": "Application label not found."
        }

    safe_label = re.sub(r'[^a-z0-9-]', '-', str(app_label).lower()).strip('-')[:50] or "target"

    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"isolate-{safe_label}",
            "namespace": namespace
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    app_key: app_label
                }
            },
            "policyTypes": [
                "Ingress",
                "Egress"
            ],
            "ingress": [],
            "egress": []
        }
    }

    filename = f"networkpolicy-{safe_label}.yaml"

    try:

        with open(
            filename,
            "w"
        ) as file:

            yaml.dump(
                policy,
                file,
                sort_keys=False
            )

        return {

            "success": True,

            "file":
                filename
        }

    except Exception as e:

        return {

            "success": False,

            "error":
                str(e)
        }


# ==========================================
# M9 RESPONSE
# ==========================================

def auto_isolate_pod(
    pod_name,
    namespace=None,
    authorized=False
):

    print(
        "\n[M9] Checking affected Pod..."
    )

    # --------------------------------------
    # Get Pod information
    # --------------------------------------

    pod_data = get_pod(
        pod_name,
        namespace=namespace
    )

    if "error" in pod_data:

        return pod_data

    # --------------------------------------
    # SAFETY CHECK 1
    # Namespace
    # --------------------------------------

    pod_ns = pod_data.get(
        "metadata",
        {}
    ).get(
        "namespace",
        namespace or "default"
    )
    namespace = pod_ns

    print(
        "[M9] Namespace:",
        namespace
    )

    if namespace == "kube-system":

        return {

            "success": False,

            "ignored": True,

            "error":
                "Pod belongs to kube-system. "
                "M9 action cancelled."
        }

    # --------------------------------------
    # SAFETY CHECK 2
    # Pod must be Running
    # --------------------------------------

    if not is_running_pod(
        pod_data
    ):

        phase = pod_data.get(
            "status",
            {}
        ).get(
            "phase",
            "Unknown"
        )

        return {

            "success": False,

            "ignored": True,

            "error":
                f"Pod is not Running "
                f"(status: {phase}). "
                f"M9 action skipped."
        }

    print(
        "[M9] Pod status: Running"
    )

    # --------------------------------------
    # SAFETY CHECK 3
    # Application Pod
    # --------------------------------------

    if not is_application_pod(
        pod_data
    ):

        return {

            "success": False,

            "ignored": True,

            "error":
                "Pod is not an application Pod. "
                "M9 action skipped."
        }

    print(
        "[M9] Application Pod confirmed."
    )

    # --------------------------------------
    # SAFETY CHECK 4
    # Controller
    # --------------------------------------

    controller = check_pod_controller(
        pod_data
    )

    if not controller["managed"]:

        return {

            "success": False,

            "error":
                "Pod is not managed by a ReplicaSet. "
                "Automatic deletion cancelled."
        }

    print(
        "[M9] Controller:",
        controller["owner"]
    )

    # --------------------------------------
    # Save old Pod labels
    # --------------------------------------

    old_labels = pod_data.get(
        "metadata",
        {}
    ).get(
        "labels",
        {}
    )

    # --------------------------------------
    # Generate NetworkPolicy
    # --------------------------------------

    print(
        "[M9] Generating NetworkPolicy recommendation..."
    )

    policy_result = generate_network_policy(
        pod_name,
        namespace
    )

    if policy_result.get(
        "success"
    ):

        print(
            "[M9] NetworkPolicy generated:",
            policy_result["file"]
        )

        print(
            "[M9] NetworkPolicy NOT automatically applied."
        )

    else:

        print(
            "[M9] Policy error:",
            policy_result.get(
                "error"
            )
        )

    # --------------------------------------
    # User Authorization Check for Pod Deletion
    # --------------------------------------
    if not authorized:
        print(
            "[M9] Pod isolation recommended. Action proposed: delete pod and apply NetworkPolicy."
        )
        print(
            "[M9] Pod NOT deleted (awaiting explicit user authorization)."
        )
        return {
            "success": True,
            "action_executed": False,
            "status": "RECOMMENDATION_GENERATED",
            "recommendation": f"Isolation recommended for pod '{pod_name}'. NetworkPolicy generated. Pod deletion and replacement held pending user authorization.",
            "old_pod": pod_name,
            "replacement": {
                "found": False,
                "status": "Held (User authorization required before deleting active workload)"
            },
            "policy": policy_result
        }

    # --------------------------------------
    # Delete suspicious Pod (Authorized)
    # --------------------------------------

    print(
        "[M9] Explicit user authorization confirmed. Deleting suspicious Pod..."
    )

    delete_result = delete_pod(
        pod_name,
        namespace
    )

    if not delete_result["success"]:

        return delete_result

    print(
        "[M9] Pod deletion successful."
    )

    # --------------------------------------
    # Wait for replacement
    # --------------------------------------

    print(
        "[M9] Waiting for Kubernetes "
        "to create replacement..."
    )

    replacement = find_replacement_pod(
        pod_name,
        namespace,
        old_labels
    )

    if replacement.get(
        "found"
    ):

        print(
            "[M9] Replacement Pod:",
            replacement["pod"]
        )

        print(
            "[M9] Replacement Status:",
            replacement["status"]
        )

        print(
            "[M9] Replacement Pod verified successfully."
        )

    else:

        print(
            "[M9] Replacement Pod not found."
        )

    return {

        "success": True,

        "action_executed": True,

        "old_pod":
            pod_name,

        "replacement":
            replacement,

        "policy":
            policy_result
    }


# ==========================================
# MAIN
# ==========================================

def main():

    print(
        "\n========== MODULE 9 : AUTO-ISOLATION ==========\n"
    )

    print(
        "M9 receives CRITICAL findings automatically from M5."
    )

    print(
        "M9 performs safety checks before taking action."
    )

    print(
        "\n================================================\n"
    )


if __name__ == "__main__":

    main()