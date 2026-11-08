import subprocess
import json
import os
import re
import sys
import time
import shutil
from datetime import datetime


def validate_image_reference(image_name):
    """
    Validates container image reference syntax.
    Returns (True, sanitized_image_name) or (False, error_message).
    """
    if image_name is None:
        return False, "Image reference cannot be None."
    if not isinstance(image_name, str):
        return False, f"Image reference must be a string, got {type(image_name).__name__}."

    img = image_name.strip()
    if not img:
        return False, "Image reference cannot be empty or whitespace."

    # Disallow control characters, whitespace, quotes, and dangerous shell metacharacters
    disallowed = set(" \t\n\r\"'`;|&<>$()[]{}!#*^\\")
    if any(c in disallowed for c in img):
        return False, f"Image reference '{img}' contains invalid or disallowed characters."

    # Must start and end with an alphanumeric character
    if not img[0].isalnum():
        return False, f"Image reference '{img}' must start with an alphanumeric character."
    if not img[-1].isalnum():
        return False, f"Image reference '{img}' must end with an alphanumeric character."

    # Prohibit consecutive punctuation like :: or // or @@
    if "::" in img or "//" in img or "@@" in img:
        return False, f"Image reference '{img}' contains consecutive separator characters."

    # Validate characters: alphanumeric, '.', '_', '-', ':', '/', '@'
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._:@/-]*[a-zA-Z0-9]$'
    if not re.match(pattern, img):
        return False, f"Image reference '{img}' does not conform to container image reference syntax."

    # If digest '@' is present, it must be in format @algorithm:hex
    if "@" in img:
        parts = img.split("@")
        if len(parts) != 2:
            return False, f"Image reference '{img}' has multiple '@' digest separators."
        digest_part = parts[1]
        if ":" not in digest_part or not re.match(r'^[a-zA-Z0-9-_+.]+:[a-fA-F0-9]+$', digest_part):
            return False, f"Invalid digest format in image reference: '{img}'"

    return True, img


def sanitize_error_message(msg):
    """Redacts potential secrets, credentials, or tokens from error text."""
    if not isinstance(msg, str):
        return str(msg)
    # Redact user:password in URLs
    sanitized = re.sub(r'://([^:]+):([^@]+)@', r'://\1:***@', msg)
    # Redact authorization / bearer tokens
    sanitized = re.sub(r'(bearer\s+)[A-Za-z0-9._~+/-]+', r'\1***', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'(password[:=]\s*)[^\s,]+', r'\1***', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'(token[:=]\s*)[^\s,]+', r'\1***', sanitized, flags=re.IGNORECASE)
    return sanitized


def classify_trivy_error(returncode, stderr, stdout=""):
    """Classifies Trivy failure reasons based on return code and output."""
    combined = f"{stderr}\n{stdout}".lower()

    # 1. Authentication / Permission errors
    if any(k in combined for k in [
        "401 unauthorized", "authentication required", "denied: access forbidden",
        "unauthorized: authentication required", "no basic auth credentials",
        "docker_auth", "pull access denied", "unauthorized"
    ]):
        return "AUTH_FAILED", "Authentication failed for container registry. Verify registry credentials."

    # 2. Image Not Found
    if any(k in combined for k in [
        "manifest unknown", "repository does not exist", "not found",
        "image does not exist", "could not find image", "reference does not exist",
        "tag does not exist"
    ]):
        return "IMAGE_NOT_FOUND", "Container image not found in registry. Verify image name and tag."

    # 3. Network or Database download errors
    if any(k in combined for k in [
        "no such host", "connection refused", "i/o timeout", "failed to download",
        "network error", "lookup ", "tls handshake timeout", "temporary failure in name resolution",
        "connection reset by peer"
    ]):
        return "NETWORK_ERROR", "Network failure or vulnerability database download failed."

    # 4. General Scanner failure
    clean_err = stderr.strip() if stderr.strip() else (stdout.strip() if stdout.strip() else f"Trivy exited with code {returncode}")
    return "SCAN_FAILED", clean_err


DEFAULT_TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", 300))


def scan_image(image_name, timeout=None, output_path="reports/trivy_scan.json"):
    """
    Image-agnostic container vulnerability scanner using Trivy.

    Supports scanning any container image reference supported by Trivy
    (e.g., nginx:latest, python:3.12-slim, node:22, alpine:3.21, etc.).

    Collects vulnerability IDs, package names, installed and fixed versions,
    severity levels, vulnerability titles, primary references, OS info,
    and image digests.

    Preserves exact backward-compatible return format:
      - 'image': image name
      - 'severity_counts': dict of LOW, MEDIUM, HIGH, CRITICAL counts (or None on failure)
      - 'critical_cve_ids': list of critical CVE ID strings
      - 'deployment_blocked': boolean (True if CRITICAL > 0 or unverified)
    Plus non-breaking enriched metadata.
    """
    if timeout is None:
        timeout = DEFAULT_TRIVY_TIMEOUT

    start_time = time.time()
    scan_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Validate image reference
    is_valid, validation_res = validate_image_reference(image_name)
    if not is_valid:
        return {
            "error": validation_res,
            "error_type": "INVALID_IMAGE_REFERENCE",
            "image": str(image_name) if image_name is not None else "",
            "status": "FAILED",
            "deployment_blocked": True,
            "severity_counts": None,
            "critical_cve_ids": [],
            "vulnerabilities_unverified": True
        }
    target_image = validation_res

    # 2. Verify Trivy executable exists in system PATH
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        return {
            "error": "Trivy executable not found in system PATH. Ensure Trivy is installed.",
            "error_type": "SCANNER_NOT_FOUND",
            "image": target_image,
            "status": "FAILED",
            "deployment_blocked": True,
            "severity_counts": None,
            "critical_cve_ids": [],
            "vulnerabilities_unverified": True
        }

    # 3. Remove existing report to prevent stale results from masquerading on failure
    if output_path and os.path.exists(output_path):
        try:
            os.remove(output_path)
        except Exception:
            pass

    # 4. Execute Trivy safely with shell=False and list arguments
    # First attempt: use local vulnerability DB (--skip-db-update) for fast execution
    cmd = [
        "trivy",
        "image",
        "--quiet",
        "--skip-db-update",
        "--format",
        "json",
        "--scanners",
        "vuln",
        target_image
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {
            "error": f"Trivy scan timed out after {timeout} seconds for image '{target_image}'.",
            "error_type": "TIMEOUT",
            "image": target_image,
            "status": "FAILED",
            "deployment_blocked": True,
            "severity_counts": None,
            "critical_cve_ids": [],
            "vulnerabilities_unverified": True
        }
    except Exception as e:
        return {
            "error": f"Failed to execute Trivy subprocess: {sanitize_error_message(str(e))}",
            "error_type": "SCANNER_EXEC_ERROR",
            "image": target_image,
            "status": "FAILED",
            "deployment_blocked": True,
            "severity_counts": None,
            "critical_cve_ids": [],
            "vulnerabilities_unverified": True
        }

    # 5. Fallback: if --skip-db-update failed, retry without it unless it's a known non-DB failure
    if result.returncode != 0:
        elapsed = time.time() - start_time
        remaining_timeout = max(30, int(timeout - elapsed))
        stderr_text = result.stderr or ""
        stdout_text = result.stdout or ""
        combined_err = f"{stderr_text}\n{stdout_text}".lower()

        # Don't retry if image is clearly not found or unauthorized
        is_terminal_err = any(k in combined_err for k in [
            "manifest unknown", "repository does not exist", "not found",
            "401 unauthorized", "authentication required", "pull access denied"
        ])

        if not is_terminal_err:
            fallback_cmd = [
                "trivy",
                "image",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln",
                target_image
            ]
            try:
                fallback_res = subprocess.run(
                    fallback_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=remaining_timeout
                )
                if fallback_res.returncode == 0:
                    result = fallback_res
            except subprocess.TimeoutExpired:
                return {
                    "error": f"Trivy fallback scan timed out for image '{target_image}'.",
                    "error_type": "TIMEOUT",
                    "image": target_image,
                    "status": "FAILED",
                    "deployment_blocked": True,
                    "severity_counts": None,
                    "critical_cve_ids": [],
                    "vulnerabilities_unverified": True
                }
            except Exception:
                pass

    # 6. Check if scan execution failed
    if result.returncode != 0:
        err_type, clean_msg = classify_trivy_error(result.returncode, result.stderr, result.stdout)
        sanitized_msg = sanitize_error_message(clean_msg)
        return {
            "error": sanitized_msg,
            "error_type": err_type,
            "image": target_image,
            "status": "FAILED",
            "deployment_blocked": True,
            "severity_counts": None,
            "critical_cve_ids": [],
            "vulnerabilities_unverified": True,
            "raw_error": sanitize_error_message(result.stderr.strip() or result.stdout.strip())
        }

    # 7. Parse JSON output defensively
    raw_output = result.stdout or ""
    if not raw_output.strip():
        return {
            "error": "Trivy produced empty output.",
            "error_type": "MALFORMED_OUTPUT",
            "image": target_image,
            "status": "FAILED"
        }
    try:
        data = json.loads(raw_output)
    except (json.JSONDecodeError, TypeError) as jde:
        return {
            "error": f"Failed to parse Trivy scan output as valid JSON: {jde}",
            "error_type": "MALFORMED_OUTPUT",
            "image": target_image,
            "status": "FAILED"
        }

    # 8. Atomically save the scan report JSON to output_path
    if output_path:
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            tmp_path = f"{output_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            os.replace(tmp_path, output_path)
        except Exception:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
            except Exception:
                pass

    # 9. Extract vulnerability counts and detailed findings
    counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }
    critical_cves = []
    all_vulnerabilities = []

    results = data.get("Results", [])
    if isinstance(results, list):
        for res in results:
            if not isinstance(res, dict):
                continue
            target_name = res.get("Target", "")
            target_class = res.get("Class", "")
            target_type = res.get("Type", "")
            vulnerabilities = res.get("Vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                cve_id = vuln.get("VulnerabilityID") or "UNKNOWN"
                severity = (vuln.get("Severity") or "UNKNOWN").upper()
                pkg_name = vuln.get("PkgName") or "Unknown"
                installed_ver = vuln.get("InstalledVersion") or "Unknown"
                fixed_ver = vuln.get("FixedVersion")
                title = vuln.get("Title") or vuln.get("Description") or ""
                if len(title) > 200:
                    title = title[:197] + "..."
                primary_url = vuln.get("PrimaryURL") or (vuln.get("References", [None])[0] if vuln.get("References") else None)

                if severity in counts:
                    counts[severity] += 1

                if severity == "CRITICAL":
                    if cve_id not in critical_cves and cve_id != "UNKNOWN":
                        critical_cves.append(cve_id)

                all_vulnerabilities.append({
                    "id": cve_id,
                    "package": pkg_name,
                    "installed_version": installed_ver,
                    "fixed_version": fixed_ver,
                    "severity": severity,
                    "title": title,
                    "primary_url": primary_url,
                    "target": target_name,
                    "class": target_class,
                    "type": target_type
                })

    # Policy: Block deployment if any CRITICAL vulnerabilities are detected
    deployment_blocked = counts["CRITICAL"] > 0
    scan_duration = round(time.time() - start_time, 2)

    # 10. Extract metadata (OS, digest, image ID)
    metadata = data.get("Metadata", {}) if isinstance(data.get("Metadata"), dict) else {}
    os_info = None
    if "OS" in metadata and isinstance(metadata["OS"], dict):
        fam = metadata["OS"].get("Family", "")
        name = metadata["OS"].get("Name", "")
        os_info = f"{fam} {name}".strip() if (fam or name) else None

    image_digest = None
    repo_digests = metadata.get("RepoDigests", [])
    if repo_digests and isinstance(repo_digests, list) and len(repo_digests) > 0:
        image_digest = repo_digests[0]
    elif metadata.get("ImageID"):
        image_digest = metadata.get("ImageID")
    elif data.get("ArtifactID"):
        image_digest = data.get("ArtifactID")

    # 11. Return full scan result
    return {
        "image": target_image,
        "severity_counts": counts,
        "critical_cve_ids": critical_cves,
        "deployment_blocked": deployment_blocked,
        "status": "COMPLETED",
        "scan_time": scan_time_str,
        "scan_duration": scan_duration,
        "total_vulnerabilities": sum(counts.values()),
        "image_digest": image_digest,
        "os": os_info,
        "vulnerabilities": all_vulnerabilities
    }


def scan_images(image_list, timeout=None, output_dir="reports"):
    """
    Scans multiple container images using Trivy.
    Accepts an iterable of image reference strings or a comma-separated string.
    Processes each image independently: a failure in one image does not halt
    scanning of the remaining images.

    Returns an aggregated dictionary:
      - 'images': list of individual scan results
      - 'total_scanned': total number of images processed
      - 'successful': number of successful scans
      - 'failed': number of failed scans
      - 'total_vulnerabilities': total vulnerabilities across all images
      - 'severity_counts': aggregated {"LOW": int, "MEDIUM": int, "HIGH": int, "CRITICAL": int}
      - 'critical_cve_ids': sorted unique list of critical CVE IDs
      - 'deployment_blocked': True if any image is blocked or unverified
    """
    if isinstance(image_list, str):
        if "," in image_list:
            images = [img.strip() for img in image_list.split(",") if img.strip()]
        else:
            images = [image_list.strip()] if image_list.strip() else []
    elif hasattr(image_list, "__iter__"):
        images = list(image_list)
    else:
        images = []

    if not images:
        return {
            "error": "No container images provided for scanning.",
            "error_type": "EMPTY_IMAGE_LIST",
            "images": [],
            "total_scanned": 0,
            "successful": 0,
            "failed": 0,
            "total_vulnerabilities": 0,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "critical_cve_ids": [],
            "deployment_blocked": True
        }

    results = []
    agg_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    all_critical_cves = set()
    successful = 0
    failed = 0
    any_blocked = False

    for img in images:
        # Sanitize image name for safe report filename
        sanitized_fn = re.sub(r'[^a-zA-Z0-9._-]', '_', str(img))
        out_path = os.path.join(output_dir, f"trivy_{sanitized_fn}.json") if output_dir else None

        res = scan_image(img, timeout=timeout, output_path=out_path)
        results.append(res)

        if res.get("status") == "COMPLETED":
            successful += 1
            counts = res.get("severity_counts") or {}
            for k in agg_counts:
                agg_counts[k] += counts.get(k, 0)
            for cve in res.get("critical_cve_ids", []):
                all_critical_cves.add(cve)
            if res.get("deployment_blocked", False):
                any_blocked = True
        else:
            failed += 1
            any_blocked = True

    return {
        "images": results,
        "total_scanned": len(images),
        "successful": successful,
        "failed": failed,
        "total_vulnerabilities": sum(agg_counts.values()),
        "severity_counts": agg_counts,
        "critical_cve_ids": sorted(list(all_critical_cves)),
        "deployment_blocked": any_blocked
    }


# Standalone CLI execution
if __name__ == "__main__":
    test_img = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET_IMAGE", "nginx:latest")
    scan_res = scan_image(test_img)
    print(json.dumps(scan_res, indent=4))