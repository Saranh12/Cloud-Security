import subprocess
import json
import time
import yaml


# ==========================================
# GET POD INFORMATION
# ==========================================

def get_pod(pod_name):

    try:

        result = subprocess.run(
            [
                "kubectl",
                "get",
                "pod",
                pod_name,
                "-o",
                "json"
            ],
            capture_output=True,
            text=True
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

    for owner in owners:

        if owner.get("kind") == "ReplicaSet":

            return {
                "managed": True,
                "owner": owner.get("name")
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
            text=True
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
            text=True
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

                    labels = pod[
                        "metadata"
                    ].get(
                        "labels",
                        {}
                    )

                    if "app" not in labels:
                        continue

                    same_application = True

                    for key, value in old_labels.items():

                        if labels.get(key) != value:

                            same_application = False

                            break

                    if not same_application:
                        continue

                    phase = pod.get(
                        "status",
                        {}
                    ).get(
                        "phase"
                    )

                    if phase != "Running":
                        continue

                    return {
                        "found": True,
                        "pod": name,
                        "status": phase
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

    policy = {

        "apiVersion":
            "networking.k8s.io/v1",

        "kind":
            "NetworkPolicy",

        "metadata": {

            "name":
                f"isolate-{app_label}",

            "namespace":
                namespace
        },

        "spec": {

            "podSelector": {

                "matchLabels": {

                    app_key:
                        app_label
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

    filename = (
        f"networkpolicy-{app_label}.yaml"
    )

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
    pod_name
):

    print(
        "\n[M9] Checking affected Pod..."
    )

    # --------------------------------------
    # Get Pod information
    # --------------------------------------

    pod_data = get_pod(
        pod_name
    )

    if "error" in pod_data:

        return pod_data

    # --------------------------------------
    # SAFETY CHECK 1
    # Namespace
    # --------------------------------------

    namespace = pod_data.get(
        "metadata",
        {}
    ).get(
        "namespace",
        "default"
    )

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
    # Delete suspicious Pod
    # --------------------------------------

    print(
        "[M9] Deleting suspicious Pod..."
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