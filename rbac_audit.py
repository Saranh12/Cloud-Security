import subprocess
import json
import os
import re
from datetime import datetime


# ==========================================
# Check Kubernetes Cluster
# ==========================================

def check_cluster():
    """Checks if the Kubernetes cluster is reachable via kubectl cluster-info."""
    try:
        result = subprocess.run(
            ["kubectl", "cluster-info"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "status": False,
                "message": "Cluster Not Running"
            }

        # Try to extract context/cluster info from output
        first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "Cluster Connected"
        return {
            "status": True,
            "message": "Cluster Connected",
            "cluster_info": first_line
        }

    except Exception as e:
        return {
            "status": False,
            "message": str(e)
        }


def get_current_context():
    """Retrieves current Kubernetes context name, if available."""
    try:
        result = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "default-cluster"


# ==========================================
# Query RBAC Resources
# ==========================================

def get_roles():
    """Retrieves all namespace-scoped Roles across all namespaces."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "roles", "-A", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Failed to query Roles",
                "count": 0,
                "roles": []
            }

        data = json.loads(result.stdout)
        items = data.get("items", [])
        return {
            "count": len(items),
            "roles": items
        }

    except Exception as e:
        return {
            "error": str(e),
            "count": 0,
            "roles": []
        }


def get_cluster_roles():
    """Retrieves all cluster-scoped ClusterRoles."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "clusterroles", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Failed to query ClusterRoles",
                "count": 0,
                "cluster_roles": []
            }

        data = json.loads(result.stdout)
        items = data.get("items", [])
        return {
            "count": len(items),
            "cluster_roles": items
        }

    except Exception as e:
        return {
            "error": str(e),
            "count": 0,
            "cluster_roles": []
        }


def get_role_bindings():
    """Retrieves all namespace-scoped RoleBindings across all namespaces."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "rolebindings", "-A", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Failed to query RoleBindings",
                "count": 0,
                "bindings": []
            }

        data = json.loads(result.stdout)
        items = data.get("items", [])
        return {
            "count": len(items),
            "bindings": items
        }

    except Exception as e:
        return {
            "error": str(e),
            "count": 0,
            "bindings": []
        }


def get_cluster_role_bindings():
    """Retrieves all cluster-scoped ClusterRoleBindings."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "clusterrolebindings", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Failed to query ClusterRoleBindings",
                "count": 0,
                "bindings": []
            }

        data = json.loads(result.stdout)
        items = data.get("items", [])
        return {
            "count": len(items),
            "bindings": items
        }

    except Exception as e:
        return {
            "error": str(e),
            "count": 0,
            "bindings": []
        }


# ==========================================
# Analyze Roles and ClusterRoles
# ==========================================

def analyze_single_role(role_item, is_cluster_role=True):
    """
    Rule-based analysis of a single Role or ClusterRole.
    Evaluates:
      - cluster-admin privileges (Critical, score 100)
      - Wildcards '*' in verbs or resources (High, score 80)
      - Privilege escalation verbs: bind, escalate, impersonate (Critical/High, score 90-100)
      - Secret reading permissions: secrets + get/list/watch (High, score 75)
      - Pod execution: pods/exec, pods/attach (High, score 70)
      - Modification of critical resources: pods, deployments, configmaps, secrets (Medium, score 60)
    """
    metadata = role_item.get("metadata", {})
    role_name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "cluster-wide" if is_cluster_role else "default")
    rules = role_item.get("rules", [])

    severity = None
    score = 0
    reason = ""
    recommendation = ""
    evidence = []

    # 1. Cluster Administrator
    if role_name == "cluster-admin":
        severity = "Critical"
        score = 100
        reason = "Cluster Administrator privileges (full cluster control)"
        recommendation = "Avoid assigning cluster-admin. Follow the principle of least privilege."
        evidence.append("Role name is 'cluster-admin' with full administrative authority.")
        return {
            "role": role_name,
            "scope": "ClusterRole" if is_cluster_role else "Role",
            "namespace": namespace,
            "severity": severity,
            "score": score,
            "reason": reason,
            "recommendation": recommendation,
            "evidence": evidence,
            "rules_count": len(rules)
        }

    # 2. Rule-based inspection
    has_wildcard = False
    has_escalate = False
    has_secret_read = False
    has_pod_exec = False
    has_critical_modify = False

    for rule in rules:
        verbs = set(rule.get("verbs", []))
        resources = set(rule.get("resources", []))
        api_groups = set(rule.get("apiGroups", []))

        # Check for privilege escalation
        if any(v in verbs for v in ["bind", "escalate"]):
            has_escalate = True
            evidence.append(f"Privilege escalation verb(s) detected: {sorted(verbs.intersection({'bind', 'escalate'}))}")
        if "impersonate" in verbs:
            has_escalate = True
            evidence.append("Impersonation permissions detected.")

        # Check for wildcards
        if "*" in verbs or "*" in resources:
            has_wildcard = True
            evidence.append(f"Wildcard permission detected (verbs: {list(verbs)}, resources: {list(resources)})")

        # Check for secret access
        if "secrets" in resources or "*" in resources:
            if any(v in verbs for v in ["get", "list", "watch", "*"]):
                has_secret_read = True
                evidence.append("Secret read access detected (get/list/watch on secrets).")

        # Check for pod exec
        if any(r in resources for r in ["pods/exec", "pods/attach"]):
            if any(v in verbs for v in ["create", "get", "*"]):
                has_pod_exec = True
                evidence.append(f"Pod exec/attach execution permission detected on {list(resources)}.")

        # Check for modification of core resources
        if any(r in resources for r in ["pods", "deployments", "configmaps", "secrets"]):
            if any(v in verbs for v in ["create", "update", "patch", "delete", "*"]):
                has_critical_modify = True

    # Determine severity
    if has_escalate:
        severity = "Critical"
        score = 95
        reason = "Privilege escalation permissions (bind/escalate/impersonate)"
        recommendation = "Remove bind/escalate/impersonate permissions to prevent privilege escalation."
    elif has_wildcard:
        severity = "High"
        score = 80
        reason = "Wildcard permissions detected"
        recommendation = "Replace wildcard (*) permissions with specific, least-privilege permissions."
    elif has_secret_read:
        severity = "High"
        score = 75
        reason = "Direct read access to Kubernetes Secrets"
        recommendation = "Restrict access to sensitive Secrets. Use dedicated ServiceAccounts."
    elif has_pod_exec:
        severity = "High"
        score = 70
        reason = "Interactive container execution permissions (pods/exec)"
        recommendation = "Restrict pods/exec permissions to authorized debugging personnel."
    elif has_critical_modify:
        severity = "Medium"
        score = 60
        reason = "Can modify important Kubernetes resources"
        recommendation = "Restrict write permissions (create/patch/delete) if not strictly required."
        evidence.append("Write/modify permissions on core workload resources.")

    if severity:
        return {
            "role": role_name,
            "scope": "ClusterRole" if is_cluster_role else "Role",
            "namespace": namespace,
            "severity": severity,
            "score": score,
            "reason": reason,
            "recommendation": recommendation,
            "evidence": evidence,
            "rules_count": len(rules)
        }

    return None


def analyze_cluster_roles(cluster_roles):
    """
    Analyzes ClusterRoles for dangerous configurations.
    Maintains full backward compatibility with legacy caller signature.
    """
    findings = []
    if not cluster_roles or not isinstance(cluster_roles, list):
        return findings

    for role in cluster_roles:
        res = analyze_single_role(role, is_cluster_role=True)
        if res:
            findings.append(res)

    return findings


def analyze_namespace_roles(roles):
    """Analyzes namespace-scoped Roles for dangerous configurations."""
    findings = []
    if not roles or not isinstance(roles, list):
        return findings

    for role in roles:
        res = analyze_single_role(role, is_cluster_role=False)
        if res:
            findings.append(res)

    return findings


# ==========================================
# Analyze RoleBindings and ClusterRoleBindings
# ==========================================

def analyze_single_binding(binding, is_cluster_binding=True, dangerous_roles=None):
    """
    Analyzes a single RoleBinding or ClusterRoleBinding.
    Correctly accounts for:
      - RoleBinding referencing a ClusterRole (applies in that namespace only)
      - ClusterRoleBinding referencing a ClusterRole (applies cluster-wide)
      - Subjects: ServiceAccount, User, Group
      - Severity: Critical if binding cluster-admin, High if binding wildcard/escalating role
    """
    metadata = binding.get("metadata", {})
    binding_name = metadata.get("name", "unknown")
    binding_ns = metadata.get("namespace", "cluster-wide" if is_cluster_binding else "default")

    role_ref = binding.get("roleRef", {})
    ref_name = role_ref.get("name", "")
    ref_kind = role_ref.get("kind", "ClusterRole" if is_cluster_binding else "Role")

    subjects = binding.get("subjects", [])
    findings = []

    # Filter out standard system-level controllers if not bound to unmanaged service accounts
    is_cluster_admin = (ref_name == "cluster-admin")
    is_dangerous_role = dangerous_roles and ref_name in dangerous_roles

    if not is_cluster_admin and not is_dangerous_role:
        return findings

    for subject in subjects:
        sub_name = subject.get("name", "Unknown")
        sub_kind = subject.get("kind", "Unknown")
        sub_ns = subject.get("namespace", binding_ns if not is_cluster_binding else "-")

        # Determine severity and scope
        if is_cluster_admin:
            if is_cluster_binding:
                severity = "Critical"
                score = 100
                reason = "Cluster Administrator role assigned cluster-wide"
                recommendation = "Assign cluster-admin only to trusted cluster administrators. Prefer namespace-scoped roles."
            else:
                severity = "High"
                score = 80
                reason = f"Cluster Administrator permissions scoped to namespace '{binding_ns}' via RoleBinding"
                recommendation = "Replace cluster-admin RoleBinding with an administrative role scoped to least privilege."
        else:
            severity = "High"
            score = 75
            reason = f"High-privilege role '{ref_name}' assigned to {sub_kind} '{sub_name}'"
            recommendation = "Review binding permissions and enforce least privilege."

        findings.append({
            "binding": binding_name,
            "role": ref_name,
            "role_kind": ref_kind,
            "scope": "ClusterRoleBinding" if is_cluster_binding else "RoleBinding",
            "subject": sub_name,
            "type": sub_kind,
            "namespace": sub_ns,
            "binding_namespace": binding_ns,
            "severity": severity,
            "score": score,
            "reason": reason,
            "recommendation": recommendation,
            "evidence": f"{sub_kind} '{sub_name}' bound to {ref_kind} '{ref_name}' via {binding_name}"
        })

    return findings


def analyze_cluster_role_bindings(bindings, dangerous_roles=None):
    """
    Analyzes ClusterRoleBindings for dangerous assignments.
    Maintains full backward compatibility with legacy caller signature.
    """
    findings = []
    if not bindings or not isinstance(bindings, list):
        return findings

    for b in bindings:
        sub_findings = analyze_single_binding(b, is_cluster_binding=True, dangerous_roles=dangerous_roles)
        findings.extend(sub_findings)

    return findings


def analyze_role_bindings(bindings, dangerous_roles=None):
    """Analyzes namespace-scoped RoleBindings for dangerous assignments."""
    findings = []
    if not bindings or not isinstance(bindings, list):
        return findings

    for b in bindings:
        sub_findings = analyze_single_binding(b, is_cluster_binding=False, dangerous_roles=dangerous_roles)
        findings.extend(sub_findings)

    return findings


# ==========================================
# Comprehensive RBAC Audit Runner
# ==========================================

def perform_rbac_audit(run_id=None):
    """
    Executes a complete, rule-based RBAC audit across the cluster.
    Queries and analyzes:
      - Roles
      - ClusterRoles
      - RoleBindings
      - ClusterRoleBindings
    Generates reports/rbac_report.txt and reports/rbac_report.json.
    Returns structured audit results.
    """
    cluster = check_cluster()
    context_name = get_current_context() if cluster.get("status") else "Unavailable"

    if not cluster.get("status"):
        audit_result = {
            "status": "FAILED",
            "cluster_connected": False,
            "cluster_status": cluster.get("message", "Cluster Not Running"),
            "context": context_name,
            "roles_count": 0,
            "cluster_roles_count": 0,
            "role_bindings_count": 0,
            "cluster_role_bindings_count": 0,
            "dangerous_roles": [],
            "dangerous_bindings": [],
            "warnings": [f"Kubernetes cluster unreachable: {cluster.get('message')}"],
            "severity": "None",
            "report_path": "reports/rbac_report.txt",
            "json_report_path": "reports/rbac_report.json"
        }
        save_report(audit_result.get("dangerous_roles", []), metadata=audit_result, run_id=run_id)
        save_json_report(audit_result, run_id=run_id)
        return audit_result

    # 1. Query resources
    roles_res = get_roles()
    cluster_roles_res = get_cluster_roles()
    role_bindings_res = get_role_bindings()
    cluster_role_bindings_res = get_cluster_role_bindings()

    warnings = []
    if "error" in roles_res:
        warnings.append(f"Roles query warning: {roles_res['error']}")
    if "error" in cluster_roles_res:
        warnings.append(f"ClusterRoles query warning: {cluster_roles_res['error']}")
    if "error" in role_bindings_res:
        warnings.append(f"RoleBindings query warning: {role_bindings_res['error']}")
    if "error" in cluster_role_bindings_res:
        warnings.append(f"ClusterRoleBindings query warning: {cluster_role_bindings_res['error']}")

    # 2. Analyze Roles & ClusterRoles
    cr_findings = analyze_cluster_roles(cluster_roles_res.get("cluster_roles", []))
    r_findings = analyze_namespace_roles(roles_res.get("roles", []))
    all_role_findings = cr_findings + r_findings

    dangerous_role_names = {f["role"] for f in all_role_findings if f.get("severity") in ["Critical", "High"]}

    # 3. Analyze RoleBindings & ClusterRoleBindings
    crb_findings = analyze_cluster_role_bindings(cluster_role_bindings_res.get("bindings", []), dangerous_roles=dangerous_role_names)
    rb_findings = analyze_role_bindings(role_bindings_res.get("bindings", []), dangerous_roles=dangerous_role_names)
    all_binding_findings = crb_findings + rb_findings

    # 4. Determine overall severity
    levels = {"None": 0, "Medium": 1, "High": 2, "Critical": 3}
    highest_sev = "None"
    for item in (all_role_findings + all_binding_findings):
        sev = item.get("severity", "None")
        if levels.get(sev, 0) > levels.get(highest_sev, 0):
            highest_sev = sev

    audit_result = {
        "status": "COMPLETED",
        "cluster_connected": True,
        "cluster_status": cluster.get("message", "Cluster Connected"),
        "context": context_name,
        "roles_count": roles_res.get("count", 0),
        "cluster_roles_count": cluster_roles_res.get("count", 0),
        "role_bindings_count": role_bindings_res.get("count", 0),
        "cluster_role_bindings_count": cluster_role_bindings_res.get("count", 0),
        "dangerous_roles": all_role_findings,
        "dangerous_bindings": all_binding_findings,
        "severity": highest_sev,
        "warnings": warnings,
        "report_path": "reports/rbac_report.txt",
        "json_report_path": "reports/rbac_report.json"
    }

    # Save reports
    save_report(all_role_findings, binding_findings=all_binding_findings, metadata=audit_result, run_id=run_id)
    save_json_report(audit_result, run_id=run_id)

    return audit_result


# ==========================================
# Save Reports
# ==========================================

def save_report(findings, binding_findings=None, metadata=None, run_id=None):
    """
    Generates a detailed human-readable reports/rbac_report.txt.
    Supports all 18 required audit fields:
      1. Audit timestamp
      2. Pipeline Run ID
      3. Cluster connectivity status
      4. Kubernetes context
      5. Namespace scope
      6. Total Roles
      7. Total ClusterRoles
      8. Total RoleBindings
      9. Total ClusterRoleBindings
      10. Dangerous role findings
      11. Dangerous binding findings
      12. Subject details
      13. Permission rules evidence
      14. Severity
      15. Risk score
      16. Evidence and reasoning
      17. API errors / warnings
      18. Summary and remediation recommendations
    Maintains backward compatibility if called with only findings list.
    """
    os.makedirs("reports", exist_ok=True)
    meta = metadata or {}
    b_findings = binding_findings if binding_findings is not None else meta.get("dangerous_bindings", [])
    r_findings = findings if isinstance(findings, list) else meta.get("dangerous_roles", [])

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_run_id = run_id or meta.get("run_id") or "N/A"
    cluster_st = meta.get("cluster_status", "Connected")
    context_str = meta.get("context", "kubernetes-admin@kubernetes")
    roles_cnt = meta.get("roles_count", len(r_findings))
    cr_cnt = meta.get("cluster_roles_count", len(r_findings))
    rb_cnt = meta.get("role_bindings_count", len(b_findings))
    crb_cnt = meta.get("cluster_role_bindings_count", len(b_findings))

    with open("reports/rbac_report.txt", "w", encoding="utf-8") as file:
        file.write("======================================================================\n")
        file.write("                   KUBEGUARD RBAC SECURITY AUDIT REPORT               \n")
        file.write("======================================================================\n\n")

        file.write(f"Audit Timestamp        : {timestamp_str}\n")
        file.write(f"Pipeline Run ID        : {active_run_id}\n")
        file.write(f"Cluster Status         : {cluster_st}\n")
        file.write(f"Kubernetes Context     : {context_str}\n")
        file.write(f"Namespace Scope        : All Namespaces (-A) & Cluster-Scoped\n")
        file.write(f"Total Roles            : {roles_cnt}\n")
        file.write(f"Total ClusterRoles     : {cr_cnt}\n")
        file.write(f"Total RoleBindings     : {rb_cnt}\n")
        file.write(f"Total ClusterRoleBinds : {crb_cnt}\n")
        file.write(f"Dangerous Roles Found  : {len(r_findings)}\n")
        file.write(f"Dangerous Bindings     : {len(b_findings)}\n")
        file.write("----------------------------------------------------------------------\n\n")

        # Warnings / Incomplete-scan warnings
        warnings = meta.get("warnings", [])
        if warnings:
            file.write("API WARNINGS / INCOMPLETE SCAN NOTES:\n")
            for w in warnings:
                file.write(f"  [!] {w}\n")
            file.write("\n----------------------------------------------------------------------\n\n")

        # Section 1: Dangerous Roles
        file.write("======================================================================\n")
        file.write("SECTION 1: DANGEROUS ROLES & CLUSTERROLES\n")
        file.write("======================================================================\n")

        if not r_findings:
            file.write("No dangerous RBAC roles or clusterroles detected.\n\n")
        else:
            for i, item in enumerate(r_findings, start=1):
                file.write(f"[{i}] Role Name      : {item.get('role')}\n")
                file.write(f"    Scope          : {item.get('scope', 'ClusterRole')}\n")
                file.write(f"    Namespace      : {item.get('namespace', '-')}\n")
                file.write(f"    Severity       : {item.get('severity')}\n")
                file.write(f"    Risk Score     : {item.get('score', 0)}/100\n")
                file.write(f"    Reason         : {item.get('reason')}\n")
                file.write(f"    Recommendation : {item.get('recommendation')}\n")
                evidence_items = item.get("evidence", [])
                if evidence_items:
                    file.write("    Evidence / Permission Rules:\n")
                    for ev in evidence_items:
                        file.write(f"      - {ev}\n")
                file.write("----------------------------------------------------------------------\n")
            file.write("\n")

        # Section 2: Dangerous Role Bindings
        file.write("======================================================================\n")
        file.write("SECTION 2: DANGEROUS ROLE BINDINGS & CLUSTERROLE BINDINGS\n")
        file.write("======================================================================\n")

        if not b_findings:
            file.write("No dangerous role bindings detected.\n\n")
        else:
            for i, b in enumerate(b_findings, start=1):
                file.write(f"[{i}] Binding Name   : {b.get('binding', b.get('role', 'Unknown'))}\n")
                file.write(f"    Role Assigned  : {b.get('role')}\n")
                file.write(f"    Role Kind      : {b.get('role_kind', 'ClusterRole')}\n")
                file.write(f"    Binding Scope  : {b.get('scope', 'ClusterRoleBinding')}\n")
                file.write(f"    Subject Name   : {b.get('subject')}\n")
                file.write(f"    Subject Type   : {b.get('type')}\n")
                file.write(f"    Subject NS     : {b.get('namespace', '-')}\n")
                file.write(f"    Binding NS     : {b.get('binding_namespace', '-')}\n")
                file.write(f"    Severity       : {b.get('severity')}\n")
                file.write(f"    Risk Score     : {b.get('score', 0)}/100\n")
                file.write(f"    Reason         : {b.get('reason')}\n")
                file.write(f"    Recommendation : {b.get('recommendation')}\n")
                if b.get("evidence"):
                    file.write(f"    Evidence       : {b.get('evidence')}\n")
                file.write("----------------------------------------------------------------------\n")
            file.write("\n")

        # Section 3: Summary and Remediation Guidance
        file.write("======================================================================\n")
        file.write("SECTION 3: REMEDIATION GUIDANCE & LEAST PRIVILEGE SUMMARY\n")
        file.write("======================================================================\n")
        file.write("1. Avoid binding 'cluster-admin' to broad ServiceAccounts or external Users.\n")
        file.write("2. Replace wildcard (*) verbs and resources with explicit resource actions.\n")
        file.write("3. Prefer namespace-scoped RoleBindings over cluster-wide ClusterRoleBindings.\n")
        file.write("4. Audit privilege escalation verbs ('bind', 'escalate', 'impersonate') regularly.\n")
        file.write("5. Ensure automated workloads run with dedicated, least-privilege ServiceAccounts.\n")
        file.write("======================================================================\n")


def save_json_report(findings, run_id=None):
    """
    Saves structured RBAC findings to reports/rbac_report.json.
    Supports either dictionary (full audit result) or list of findings.
    """
    os.makedirs("reports", exist_ok=True)
    out_dict = {}

    if isinstance(findings, dict):
        out_dict = dict(findings)
        out_dict["audit_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if run_id:
            out_dict["run_id"] = run_id
    else:
        out_dict = {
            "audit_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "run_id": run_id or "N/A",
            "findings": findings
        }

    with open("reports/rbac_report.json", "w", encoding="utf-8") as file:
        json.dump(out_dict, file, indent=4)


# ==========================================
# CLI Execution
# ==========================================

def main():
    print("==================================================")
    print("           KubeGuard RBAC Audit")
    print("==================================================")

    res = perform_rbac_audit()
    print(f"Cluster Status         : {res['cluster_status']}")
    print(f"Total Roles            : {res['roles_count']}")
    print(f"Total Cluster Roles    : {res['cluster_roles_count']}")
    print(f"Total Role Bindings    : {res['role_bindings_count']}")
    print(f"Total Cluster Role Bnd : {res['cluster_role_bindings_count']}")
    print(f"Dangerous Roles        : {len(res['dangerous_roles'])}")
    print(f"Dangerous Bindings     : {len(res['dangerous_bindings'])}")
    print(f"Severity Level         : {res['severity']}")
    print("==================================================")
    print("Detailed Text Report   : reports/rbac_report.txt")
    print("Detailed JSON Report   : reports/rbac_report.json")
    print("==================================================")


if __name__ == "__main__":
    main()
