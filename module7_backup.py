import subprocess
import os
import re
from datetime import datetime


BACKUP_DIR = "backups"


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


def create_backup(run_id=None, namespace="default", target=None):
    os.makedirs(BACKUP_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if run_id:
        backup_path = os.path.join(
            BACKUP_DIR,
            f"backup_{run_id}_{timestamp}"
        )
    else:
        backup_path = os.path.join(
            BACKUP_DIR,
            f"backup_{timestamp}"
        )

    os.makedirs(backup_path, exist_ok=True)

    is_docker = (
        namespace == "docker" or
        (target and getattr(target, "namespace", None) == "docker") or
        (target and getattr(target, "workload_kind", None) == "DockerContainer")
    )

    print(f"[M7] Backup directory: {backup_path}")
    print(f"[M7] Namespace/Runtime: {'docker' if is_docker else namespace}")

    successful = 0

    if is_docker:
        c_id = None
        if target:
            c_id = getattr(target, "container_id", None) or getattr(target, "pod_name", None) or getattr(target, "workload_name", None)

        docker_tasks = [
            ("docker_ps.json", ["ps", "--format", "{{json .}}"])
        ]
        if c_id:
            docker_tasks.append(("docker_inspect.json", ["inspect", c_id]))
            docker_tasks.append(("docker_logs.txt", ["logs", "--tail", "1000", c_id]))

        for filename, command in docker_tasks:
            print(f"[M7] Backing up docker {command[0]}...")
            output, error = run_docker(command)
            if error:
                print(f"[M7] Warning: {error}")
                continue

            file_path = os.path.join(backup_path, filename)
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(output or "")
            print(f"[M7] Saved: {file_path}")
            successful += 1

    else:
        resources = [
            ("pods.yaml", ["get", "pods", "-n", namespace, "-o", "yaml"]),
            ("deployments.yaml", ["get", "deployments", "-n", namespace, "-o", "yaml"]),
            ("statefulsets.yaml", ["get", "statefulsets", "-n", namespace, "-o", "yaml"]),
            ("daemonsets.yaml", ["get", "daemonsets", "-n", namespace, "-o", "yaml"]),
            ("jobs.yaml", ["get", "jobs", "-n", namespace, "-o", "yaml"]),
            ("cronjobs.yaml", ["get", "cronjobs", "-n", namespace, "-o", "yaml"]),
            ("services.yaml", ["get", "services", "-n", namespace, "-o", "yaml"]),
            ("configmaps.yaml", ["get", "configmaps", "-n", namespace, "-o", "yaml"]),
            ("secrets.yaml", ["get", "secrets", "-n", namespace, "-o", "yaml"]),
            ("networkpolicies.yaml", ["get", "networkpolicies", "-n", namespace, "-o", "yaml"])
        ]

        for filename, command in resources:
            print(f"[M7] Backing up {command[1]}...")
            output, error = run_kubectl(command)

            if error:
                print(f"[M7] Warning: {error}")
                continue

            # Redact credentials and private keys from secrets backup to preserve least-privilege security
            if filename == "secrets.yaml" and output:
                output = re.sub(r'(\s+data:\s*\n)((\s+[^:\n]+:\s*[^\n]+\n)+)', r'\1    # [REDACTED FOR SECURITY]\n', output)
                output = re.sub(r'(\s+stringData:\s*\n)((\s+[^:\n]+:\s*[^\n]+\n)+)', r'\1    # [REDACTED FOR SECURITY]\n', output)

            file_path = os.path.join(
                backup_path,
                filename
            )

            with open(file_path, "w", encoding="utf-8") as file:
                file.write(output or "")

            print(f"[M7] Saved: {file_path}")
            successful += 1

    print("\n[M7] Backup Summary")
    print("-------------------------")
    print(f"[M7] Resources backed up : {successful}")
    print(f"[M7] Backup location     : {backup_path}")

    if successful > 0:
        print("[M7] Backup Status      : SUCCESS")
        if run_id:
            try:
                import shutil
                run_bak_dir = os.path.join("runs", run_id, "backups", os.path.basename(backup_path))
                shutil.copytree(backup_path, run_bak_dir, dirs_exist_ok=True)
            except Exception:
                pass
        return backup_path

    print("[M7] Backup Status      : FAILED")
    return None


def main():
    create_backup()


if __name__ == "__main__":
    main()
