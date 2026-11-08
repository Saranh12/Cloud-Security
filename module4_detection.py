import subprocess

CPU_THRESHOLD = 200
MEMORY_THRESHOLD = 100


def get_workload_usage(target_pod=None, target_image=None, label_selector=None, namespace="default", cached_metrics=None, timeout=None, workload_name=None):
    """
    Retrieves live CPU and memory metrics for the target workload pod.
    Preserves backwards compatibility with get_nginx_usage callers.
    Never silently falls back to an unrelated Nginx pod.
    Supports configurable timeout via parameter or KUBECTL_TIMEOUT environment variable (default: 15s).
    Reuses cached live metrics from M2 when available to avoid unnecessary duplicate queries.
    Handles subprocess.TimeoutExpired explicitly with structured error messages.
    """
    import os

    # 1. Check if cached live metrics from M2 monitoring are provided and valid
    if cached_metrics and isinstance(cached_metrics, dict):
        c_pod = cached_metrics.get("pod") or cached_metrics.get("pod_name")
        c_cpu = cached_metrics.get("cpu")
        c_mem = cached_metrics.get("memory")
        if c_cpu and c_mem and (not target_pod or not c_pod or c_pod == target_pod):
            return {
                "pod": c_pod or target_pod or "workload",
                "cpu": c_cpu,
                "memory": c_mem,
                "source": "cached_telemetry"
            }

    # Resolve target_pod if not passed directly
    if not target_pod:
        target_pod = os.environ.get("TARGET_POD")

    if not workload_name:
        workload_name = os.environ.get("DEPLOYMENT_NAME") or os.environ.get("WORKLOAD_NAME")

    # If target_pod is not yet set but workload_name is known, resolve pod strictly for that workload
    if not target_pod and workload_name:
        try:
            from runtime_target import find_workload_pods
            w_pods = find_workload_pods(workload_name=workload_name, namespace=namespace)
            if w_pods:
                target_pod = w_pods[0].get("metadata", {}).get("name")
        except Exception:
            pass

    if not target_image:
        target_image = os.environ.get("TARGET_IMAGE") or os.environ.get("CONTAINER_IMAGE")

    # If target_pod is still not set and target_image is provided, discover non-interactively
    if not target_pod and target_image:
        try:
            from monitoring import discover_workload
            disc = discover_workload(target_image=target_image, namespace=namespace, manual_select=False)
            if disc.get("found"):
                if not disc.get("running"):
                    return {
                        "error": disc.get("error") or f"Pod '{disc.get('pod_name')}' is in state '{disc.get('phase')}'"
                    }
                target_pod = disc.get("pod_name")
            else:
                return {
                    "error": disc.get("error") or f"No workload found for image '{target_image}'"
                }
        except Exception as disc_err:
            return {"error": f"Workload discovery failed: {disc_err}"}

    if target_pod:
        cmd = ["kubectl", "top", "pod", target_pod, "-n", namespace, "--no-headers"]
    elif label_selector:
        cmd = ["kubectl", "top", "pod", "-l", label_selector, "-n", namespace, "--no-headers"]
    else:
        return {
            "error": "No target workload pod or image specified. Metrics unavailable."
        }

    # Resolve configurable timeout with reasonable default (15s)
    if timeout is None:
        try:
            timeout = int(os.environ.get("KUBECTL_TIMEOUT", "15"))
        except (ValueError, TypeError):
            timeout = 15

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired as te:
        target_desc = target_pod or label_selector or "target pod"
        stdout_snippet = f" (output: {te.stdout.strip()})" if getattr(te, "stdout", None) and str(te.stdout).strip() else ""
        stderr_snippet = f" (stderr: {te.stderr.strip()})" if getattr(te, "stderr", None) and str(te.stderr).strip() else ""
        return {
            "error": f"Metrics query timed out after {timeout}s for '{target_desc}'. Kubernetes metrics server is unresponsive or overloaded.{stdout_snippet}{stderr_snippet}",
            "timeout": True,
            "pod": target_pod or "unknown"
        }
    except Exception as e:
        return {
            "error": f"Failed to execute kubectl top: {str(e)}"
        }

    if result.returncode != 0:
        err = result.stderr.strip()
        err_lower = err.lower()
        if "not found" in err_lower or "notfound" in err_lower:
            return {
                "error": f"Pod '{target_pod}' not found in namespace '{namespace}'. Workload terminated or awaiting replacement.",
                "pod": target_pod
            }
        if "metrics not available" in err_lower or "not available yet" in err_lower:
            return {
                "error": f"Metrics not available yet for pod '{target_pod}'. Metrics server is still aggregating data.",
                "pod": target_pod
            }
        return {
            "error": err or f"Metrics unavailable for pod '{target_pod}' (kubectl top exited with code {result.returncode})",
            "pod": target_pod
        }

    output = result.stdout.strip()
    if not output:
        workload_desc = target_pod or label_selector or target_image or "Workload"
        return {
            "error": f"{workload_desc} Pod not found or metrics not available (empty output returned by kubectl top)"
        }

    lines = [l.strip() for l in output.splitlines() if l.strip()]
    if not lines:
        return {
            "error": f"No metric lines returned for pod '{target_pod}'."
        }

    parts = lines[0].split()
    if len(parts) < 3:
        return {
            "error": f"Malformed metrics output from kubectl top: '{lines[0]}'"
        }

    return {
        "pod": parts[0],
        "cpu": parts[1],
        "memory": parts[2]
    }


# Aliases for backwards compatibility
get_nginx_usage = get_workload_usage
get_pod_usage = get_workload_usage


def cpu_to_millicores(cpu):

    try:

        if cpu.endswith("m"):
            return float(cpu[:-1])

        if cpu.endswith("n"):
            return float(cpu[:-1]) / 1000000

        return float(cpu) * 1000

    except:

        return 0


def memory_to_mebibytes(memory):

    try:

        if memory.endswith("Mi"):
            return float(memory[:-2])

        if memory.endswith("Gi"):
            return float(memory[:-2]) * 1024

        if memory.endswith("Ki"):
            return float(memory[:-2]) / 1024

        return 0

    except:

        return 0


def detect_threat(data):

    if "error" in data:

        return {
            "status": "ERROR",
            "severity": "None",
            "reason": data["error"]
        }

    cpu = cpu_to_millicores(data["cpu"])
    memory = memory_to_mebibytes(data["memory"])

    # CPU suspicious
    if cpu > CPU_THRESHOLD:

        return {
            "status": "SUSPICIOUS ACTIVITY DETECTED",
            "severity": "High",
            "reason": "Abnormally high CPU usage detected."
        }

    # Memory suspicious
    if memory > MEMORY_THRESHOLD:

        return {
            "status": "SUSPICIOUS ACTIVITY DETECTED",
            "severity": "High",
            "reason": "Abnormally high memory usage detected."
        }

    # Normal
    return {
        "status": "NORMAL",
        "severity": "None",
        "reason": "No suspicious activity detected."
    }


def main():

    data = get_nginx_usage()

    if "error" in data:

        print("\n========== MODULE 4 : THREAT DETECTION ==========\n")

        print("Error :", data["error"])

        return

    result = detect_threat(data)

    print("\n========== MODULE 4 : THREAT DETECTION ==========\n")

    print("Pod      :", data["pod"])
    print("CPU      :", data["cpu"])
    print("Memory   :", data["memory"])
    print()
    print("Status   :", result["status"])
    print("Severity :", result["severity"])
    print("Reason   :", result["reason"])

    print("\n==================================================\n")


if __name__ == "__main__":
    main()