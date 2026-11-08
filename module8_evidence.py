import subprocess
import os
import re
from datetime import datetime


EVIDENCE_DIR = "evidence"


def run_kubectl(args):
    try:
        result = subprocess.run(
            ["kubectl"] + args,
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return None, result.stderr.strip()

        return result.stdout, None

    except Exception as e:
        return None, str(e)


def run_docker(args):
    try:
        result = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return None, result.stderr.strip()

        return result.stdout, None

    except Exception as e:
        return None, str(e)


def collect_evidence(pod_name, namespace="default", run_id=None, target=None):

    print("\n========== MODULE 8 : EVIDENCE COLLECTION ==========\n")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(pod_name))

    if run_id:
        incident_dir = os.path.join(
            EVIDENCE_DIR,
            f"incident_{run_id}_{timestamp}_{safe_target_name}"
        )
    else:
        incident_dir = os.path.join(
            EVIDENCE_DIR,
            f"incident_{timestamp}_{safe_target_name}"
        )

    os.makedirs(incident_dir, exist_ok=True)

    is_docker = (
        namespace == "docker" or
        (target and getattr(target, "namespace", None) == "docker") or
        (target and getattr(target, "workload_kind", None) == "DockerContainer")
    )

    print(f"[M8] Affected Target : {pod_name}")
    print(f"[M8] Namespace/Runtime: {'docker' if is_docker else namespace}")
    print(f"[M8] Evidence Directory : {incident_dir}")

    if is_docker:
        evidence = [
            ("docker_inspect.json", ["inspect", pod_name]),
            ("docker_logs.txt", ["logs", "--tail", "1000", pod_name]),
            ("docker_top.txt", ["top", pod_name]),
            ("docker_stats.txt", ["stats", "--no-stream", pod_name])
        ]
        runner = run_docker
    else:
        evidence = [
            (
                "pod.yaml",
                ["get", "pod", pod_name, "-n", namespace, "-o", "yaml"]
            ),
            (
                "pod_status.txt",
                ["get", "pod", pod_name, "-n", namespace]
            ),
            (
                "pod_describe.txt",
                ["describe", "pod", pod_name, "-n", namespace]
            ),
            (
                "pod_logs.txt",
                ["logs", pod_name, "-n", namespace, "--all-containers=true"]
            )
        ]
        runner = run_kubectl

    successful = 0

    for filename, command in evidence:

        print(f"[M8] Collecting {filename}...")

        output, error = runner(command)

        if error:
            print(f"[M8] Warning: {error}")

            output = (
                "Evidence collection failed.\n\n"
                + error
            )

        file_path = os.path.join(
            incident_dir,
            filename
        )

        with open(file_path, "w", encoding="utf-8", errors="replace") as file:
            file.write(output or "")

        print(f"[M8] Saved: {file_path}")

        if output:
            successful += 1

    print("\n[M8] Evidence Summary")
    print("-------------------------")
    print(f"[M8] Evidence files collected : {successful}")
    print(f"[M8] Evidence location        : {incident_dir}")

    if successful > 0:
        print("[M8] Evidence Collection : SUCCESS")
        print(f"[M8] EVIDENCE_DIRECTORY: {incident_dir}")
        if run_id:
            try:
                import shutil
                run_ev_dir = os.path.join("runs", run_id, "evidence", os.path.basename(incident_dir))
                shutil.copytree(incident_dir, run_ev_dir, dirs_exist_ok=True)
            except Exception:
                pass
        return incident_dir

    print("[M8] Evidence Collection : FAILED")
    return None


def main():
    import sys
    pod_name = ""
    args = sys.argv[1:]
    if args:
        pod_name = args[0].strip()
    elif os.environ.get("TARGET_POD"):
        pod_name = os.environ.get("TARGET_POD").strip()
    elif sys.stdin.isatty():
        try:
            pod_name = input("Enter Pod name: ").strip()
        except (EOFError, KeyboardInterrupt):
            pass

    if not pod_name:
        print("[M8] Error: Pod name is required.")
        return

    print("\n========== MODULE 8 : EVIDENCE COLLECTION ==========\n")
    collect_evidence(pod_name)


if __name__ == "__main__":
    main()
