from rbac_audit import (
    check_cluster,
    get_roles,
    get_cluster_roles,
    analyze_cluster_roles,
    save_report,
    get_cluster_role_bindings,
    analyze_cluster_role_bindings
)

def run_rbac_test():
    print("==================================================")
    print("           KubeGuard RBAC Audit")
    print("==================================================")

    # Step 1 - Check Cluster
    cluster = check_cluster()

    if not cluster["status"]:
        print("Cluster Status :", cluster["message"])
        return

    print("Cluster Status :", cluster["message"])

    # Step 2 - Get Roles
    roles = get_roles()

    if "error" in roles:
        print(roles["error"])
        return

    print("Total Roles :", roles["count"])

    # Step 3 - Get Cluster Roles
    cluster_roles = get_cluster_roles()

    if "error" in cluster_roles:
        print(cluster_roles["error"])
        return

    print("Total Cluster Roles :", cluster_roles["count"])

    # Step 4 - Analyze Cluster Roles
    findings = analyze_cluster_roles(cluster_roles["cluster_roles"])

    # Step 5 - Save Report
    save_report(findings)

    # Step 6 - Get Cluster Role Bindings
    bindings = get_cluster_role_bindings()

    if "error" in bindings:
        print(bindings["error"])
        return

    print("Cluster Role Bindings :", bindings["count"])

    # Step 7 - Analyze Dangerous Bindings
    binding_findings = analyze_cluster_role_bindings(bindings["bindings"])

    print("\n==================================================")
    print("             RBAC SECURITY REPORT")
    print("==================================================")

    if len(findings) == 0:
        print("\nNo dangerous RBAC roles found.\n")
    else:
        for i, item in enumerate(findings, start=1):
            print("----------------------------------------")
            print("Finding        :", i)
            print("Role           :", item["role"])
            print("Severity       :", item["severity"])

            if item["severity"] == "Critical":
                score = 100
                recommendation = "Avoid assigning cluster-admin. Use least privilege."
            else:
                score = 80
                recommendation = "Replace wildcard (*) permissions with specific permissions."

            print("Risk Score     :", str(score) + "/100")
            print("Reason         :", item["reason"])
            print("Recommendation :", recommendation)

    print("\n==================================================")
    print("      DANGEROUS CLUSTER ROLE BINDINGS")
    print("==================================================")

    if len(binding_findings) == 0:
        print("No dangerous bindings found.")
    else:
        for i, item in enumerate(binding_findings, start=1):
            print("----------------------------------------")
            print("Finding        :", i)
            print("Role           :", item["role"])
            print("Assigned To    :", item["subject"])
            print("Type           :", item["type"])
            print("Namespace      :", item["namespace"])
            print("Severity       :", item["severity"])

    print("\n==================================================")
    print("Report Saved : reports/rbac_report.txt")
    print("RBAC Audit Completed Successfully")
    print("==================================================")


if __name__ == "__main__":
    run_rbac_test()