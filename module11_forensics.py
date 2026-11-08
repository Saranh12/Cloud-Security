import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# ============================================================
# MODULE 11 - FORENSIC ANALYSIS + FORENSIC REPORT
# ============================================================

def generate_forensic_report(
    scan_result=None,
    monitor_result=None,
    cluster=None,
    roles=None,
    cluster_roles=None,
    bindings=None,
    findings=None,
    binding_findings=None,
    threat_data=None,
    threat_result=None,
    escape_results=None,
    m7_backup_result=None,
    m8_results=None,
    m9_results=None,
    m10_results=None,
    run_id=None,
    incident_id=None,
    alert_results=None,
    module_statuses=None
):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if run_id:
        report_filename = f"KubeGuard_Forensic_Incident_Report_{run_id}.pdf"
    else:
        report_filename = f"KubeGuard_Forensic_Incident_Report_{timestamp}.pdf"

    report_path = os.path.join(
        "reports",
        report_filename
    )

    # ========================================================
    # SAFE DEFAULTS
    # ========================================================

    scan_result = scan_result or {}
    monitor_result = monitor_result or {}
    cluster = cluster or {}
    roles = roles or {}
    cluster_roles = cluster_roles or {}
    bindings = bindings or {}
    findings = findings or []
    binding_findings = binding_findings or []
    threat_data = threat_data or {}
    threat_result = threat_result or {}
    escape_results = escape_results or []
    m8_results = m8_results or []
    m9_results = m9_results or []
    m10_results = m10_results or []

    # ========================================================
    # BASIC INFORMATION
    # ========================================================

    pod_name = (
        threat_data.get("pod")
        or monitor_result.get("pod_name")
        or "Unknown"
    )

    namespace = (
        threat_data.get("namespace")
        or "default"
    )

    image_name = (
        scan_result.get("image")
        or "Unknown"
    )

    # ========================================================
    # RISK CALCULATION
    # ========================================================

    severity_order = {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    overall_risk = "LOW"

    def add_severity(value):
        nonlocal overall_risk

        if value is None:
            return

        value = str(value).upper().strip()

        if value == "NONE":
            return

        if value in severity_order:
            if severity_order[value] > severity_order[overall_risk]:
                overall_risk = value

    # M1 vulnerability information
    counts = scan_result.get("severity_counts", {})

    add_severity(
        "CRITICAL"
        if counts.get("CRITICAL", 0) > 0
        else None
    )

    add_severity(
        "HIGH"
        if counts.get("HIGH", 0) > 0
        else None
    )

    add_severity(
        "MEDIUM"
        if counts.get("MEDIUM", 0) > 0
        else None
    )

    # M3 RBAC
    for item in findings:
        add_severity(item.get("severity"))

    for item in binding_findings:
        add_severity(item.get("severity"))

    # M4 threat detection
    add_severity(
        threat_result.get("severity")
    )

    # M5 container escape (scoped to target pod when known)
    if isinstance(escape_results, list):
        for result in escape_results:
            if isinstance(result, dict):
                if pod_name and pod_name != "Unknown" and result.get("pod") and result.get("pod") != pod_name:
                    continue
                add_severity(result.get("severity"))

    # ========================================================
    # EVIDENCE INTEGRITY
    # ========================================================

    integrity_status = "NOT AVAILABLE"

    if m10_results:

        integrity_values = []

        for result in m10_results:

            if isinstance(result, dict):
                integrity_values.append(
                    bool(result.get("success"))
                )

        if integrity_values:
            if all(integrity_values):
                integrity_status = "VERIFIED"
            else:
                any_tampered = any("TAMPERED" in str(r.get("error", "")).upper() for r in m10_results if isinstance(r, dict))
                integrity_status = "TAMPERED" if any_tampered else "FAILED"
                add_severity("CRITICAL")

    # ========================================================
    # FORENSIC FINDINGS
    # ========================================================

    forensic_findings = []

    # M1
    critical_count = counts.get("CRITICAL", 0)
    high_count = counts.get("HIGH", 0)
    medium_count = counts.get("MEDIUM", 0)
    low_count = counts.get("LOW", 0)

    if critical_count > 0:

        forensic_findings.append(
            (
                "CRITICAL",
                f"Container image contains {critical_count} "
                f"critical vulnerabilities."
            )
        )

    elif high_count > 0:

        forensic_findings.append(
            (
                "HIGH",
                f"Container image contains {high_count} "
                f"high-severity vulnerabilities."
            )
        )

    # M3
    critical_rbac = [
        item for item in findings
        if str(item.get("severity", "")).upper() == "CRITICAL"
    ]

    if critical_rbac:

        forensic_findings.append(
            (
                "CRITICAL",
                "Critical Kubernetes RBAC privilege detected."
            )
        )

    elif findings:

        forensic_findings.append(
            (
                "HIGH",
                f"{len(findings)} potentially dangerous RBAC "
                f"role finding(s) were identified."
            )
        )

    # M4
    threat_severity = str(
        threat_result.get("severity", "NONE")
    ).upper()

    if threat_severity not in ("NONE", "LOW", ""):

        forensic_findings.append(
            (
                threat_severity,
                threat_result.get(
                    "reason",
                    "Threat detection identified suspicious activity."
                )
            )
        )

    # M5
    if isinstance(escape_results, list):
        for result in escape_results:
            if isinstance(result, dict):
                escape_severity = str(
                    result.get("severity", "NONE")
                ).upper()

                if escape_severity not in ("NONE", "LOW", ""):
                    findings_text = "; ".join(result.get("findings", [])) if result.get("findings") else "Container escape indicators were identified."
                    forensic_findings.append(
                        (
                            escape_severity,
                            findings_text
                        )
                    )

    if not forensic_findings:

        forensic_findings.append(
            (
                "LOW",
                "No active critical threat or container escape "
                "indicator was detected during this execution."
            )
        )

    # ========================================================
    # INCIDENT TIMELINE
    # ========================================================

    timeline = [
        (
            "M1",
            "Image Vulnerability Scan",
            "Container image security assessment completed."
        ),
        (
            "M2",
            "Container Monitoring",
            "Pod resource monitoring completed."
        ),
        (
            "M3",
            "RBAC Audit",
            "Kubernetes role and binding security analysis completed."
        ),
        (
            "M4",
            "Threat Detection",
            "Runtime threat analysis completed."
        ),
        (
            "M5",
            "Container Escape Detection",
            "Container escape indicator analysis completed."
        ),
        (
            "M6",
            "Alerting",
            "Security alert processing completed."
        ),
        (
            "M7",
            "Backup",
            "Incident backup response evaluated."
        ),
        (
            "M8",
            "Evidence Collection",
            "Forensic evidence collection evaluated."
        ),
        (
            "M9",
            "Auto-Isolation",
            "Automatic isolation response evaluated."
        ),
        (
            "M10",
            "Evidence Integrity",
            "Evidence integrity verification evaluated."
        ),
        (
            "M11",
            "Forensic Analysis",
            "Results from M1-M10 correlated into a forensic assessment."
        )
    ]

    # ========================================================
    # ROOT CAUSE ASSESSMENT
    # ========================================================

    root_cause = "No confirmed malicious root cause was established."

    if critical_count > 0:

        root_cause = (
            "The primary risk originates from critical vulnerabilities "
            "present in the deployed container image. Further analysis "
            "is required to determine exploitability and whether the "
            "vulnerabilities were involved in an actual compromise."
        )

    elif critical_rbac:

        root_cause = (
            "The investigation identified excessive or highly privileged "
            "Kubernetes RBAC access. This represents a significant "
            "potential attack-path and should be reviewed against the "
            "principle of least privilege."
        )

    elif threat_severity in ("HIGH", "CRITICAL"):

        root_cause = (
            "Runtime threat detection produced a significant finding. "
            "The available M1-M10 results should be correlated with "
            "application and Kubernetes audit logs for confirmation."
        )

    # ========================================================
    # IMPACT ASSESSMENT
    # ========================================================

    if overall_risk == "CRITICAL":

        impact = (
            "Potentially significant impact. The environment contains "
            "critical security findings that could affect confidentiality, "
            "integrity, or availability if successfully exploited."
        )

    elif overall_risk == "HIGH":

        impact = (
            "Elevated security impact. High-severity findings may provide "
            "meaningful attack paths and require remediation and validation."
        )

    elif overall_risk == "MEDIUM":

        impact = (
            "Moderate security impact. Findings should be remediated and "
            "reviewed to prevent escalation."
        )

    else:

        impact = (
            "No immediate critical runtime impact was identified during "
            "this execution. Security hardening and vulnerability "
            "remediation are still recommended."
        )

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    recommendations = []

    if critical_count > 0 or high_count > 0:

        recommendations.append(
            "Replace or rebuild vulnerable container images and "
            "rescan before deployment."
        )

    if findings or binding_findings:

        recommendations.append(
            "Review Kubernetes RBAC permissions and apply least privilege."
        )

    if threat_severity not in ("NONE", "LOW", ""):

        recommendations.append(
            "Review Kubernetes audit logs, application logs, and "
            "runtime activity around the detection timestamp."
        )

    has_escape_risk = (isinstance(escape_results, list) and any(len(r.get("findings", [])) > 0 for r in escape_results if isinstance(r, dict)))
    if has_escape_risk:

        recommendations.append(
            "Review container security context, Linux capabilities, "
            "host mounts, and privileged configuration."
        )

    if m8_results:

        recommendations.append(
            "Preserve collected evidence and restrict modification "
            "of original forensic artifacts."
        )

    if integrity_status in ["FAILED", "TAMPERED"]:

        recommendations.append(
            "Investigate evidence integrity failure or tampering and preserve "
            "the original evidence set."
        )

    recommendations.extend([
        "Maintain a documented incident timeline.",
        "Apply security updates and rebuild affected workloads.",
        "Continue monitoring the affected Kubernetes workload.",
        "Retain this report together with the associated evidence."
    ])

    # Remove duplicate recommendations
    recommendations = list(dict.fromkeys(recommendations))

    # ========================================================
    # REPORT STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="KGTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#17365D"),
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="KGSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#555555"),
            spaceAfter=5
        )
    )

    styles.add(
        ParagraphStyle(
            name="KGSection",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#17365D"),
            spaceBefore=6,
            spaceAfter=10
        )
    )

    styles.add(
        ParagraphStyle(
            name="KGBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            spaceAfter=6
        )
    )

    styles.add(
        ParagraphStyle(
            name="KGSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#555555")
        )
    )

    def P(text, style="KGBody"):
        return Paragraph(str(text), styles[style])

    # ========================================================
    # FOOTER
    # ========================================================

    def footer(canvas, doc):

        canvas.saveState()

        canvas.setStrokeColor(
            colors.HexColor("#C8D2E0")
        )

        canvas.line(
            18 * mm,
            13 * mm,
            192 * mm,
            13 * mm
        )

        canvas.setFont(
            "Helvetica",
            7.5
        )

        canvas.setFillColor(
            colors.HexColor("#666666")
        )

        canvas.drawString(
            18 * mm,
            8 * mm,
            "KubeGuard • Security Incident & Forensic Report"
        )

        canvas.drawRightString(
            192 * mm,
            8 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    # ========================================================
    # DOCUMENT
    # ========================================================

    document = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="KubeGuard Security Incident & Forensic Report",
        author="KubeGuard"
    )

    story = []

    # ========================================================
    # COVER
    # ========================================================

    story.append(
        Spacer(1, 24 * mm)
    )

    story.append(
        P(
            "KUBEGUARD",
            "KGTitle"
        )
    )

    story.append(
        P(
            "SECURITY INCIDENT & FORENSIC REPORT",
            "KGSubtitle"
        )
    )

    story.append(
        P(
            "Module 11 — Forensic Analysis & Overall Incident Report",
            "KGSubtitle"
        )
    )

    story.append(
        Spacer(1, 16 * mm)
    )

    is_image_only = (pod_name in ["Unknown", "None", None] or monitor_result.get("not_applicable", False))
    operating_mode_str = "IMAGE-ONLY ANALYSIS" if is_image_only else f"RUNNING WORKLOAD ({pod_name})"
    image_digest_str = scan_result.get("digest") or scan_result.get("repo_digest") or "Omitted (Tag Reference)"

    is_incident = bool(incident_id or any(r.get("incident_triggered") or r.get("severity") == "Critical" for r in escape_results if isinstance(r, dict)))
    incident_display = incident_id or (f"inc_{run_id}" if is_incident and run_id else ("INCIDENT-DETECTED" if is_incident else "N/A (No Incident Triggered)"))

    cover_data = [
        [
            P("<b>Run ID</b>"),
            P(run_id or "N/A")
        ],
        [
            P("<b>Incident ID</b>"),
            P(f"<b>{incident_display}</b>")
        ],
        [
            P("<b>Incident Time</b>"),
            P(datetime.now().strftime(
                "%d %B %Y, %H:%M:%S"
            ))
        ],
        [
            P("<b>Operating Mode</b>"),
            P(f"<b>{operating_mode_str}</b>")
        ],
        [
            P("<b>Container Image</b>"),
            P(image_name)
        ],
        [
            P("<b>Image Digest</b>"),
            P(f"<font size=7>{image_digest_str}</font>")
        ],
        [
            P("<b>Deployment Target</b>"),
            P(str(monitor_result.get("runtime_type", "kubernetes")).title() if not is_image_only else "N/A (Not Deployed)")
        ],
        [
            P("<b>Deployment</b>"),
            P((monitor_result.get("deployment_name") or monitor_result.get("owner_name") or "None") if not is_image_only else "N/A (Not Deployed)")
        ],
        [
            P("<b>Target Workload Pod</b>"),
            P(pod_name if not is_image_only else "N/A (Image-Only Mode)")
        ],
        [
            P("<b>Scan-to-Deploy Identity</b>"),
            P(f"<b>{monitor_result.get('identity_status', 'UNVERIFIED')}</b>")
        ],
        [
            P("<b>Privileged Mode</b>"),
            P(f"<b>{monitor_result.get('privileged_status') or ('ENABLED' if any(r.get('privileged') for r in escape_results if isinstance(r, dict)) else 'DISABLED')}</b>")
        ],
        [
            P("<b>Namespace</b>"),
            P(namespace)
        ],
        [
            P("<b>Overall Risk</b>"),
            P(f"<b>{overall_risk}</b>")
        ],
        [
            P("<b>Evidence Integrity</b>"),
            P(f"<b>{integrity_status}</b>")
        ],
        [
            P("<b>Evidence Sets</b>"),
            P(str(len(m8_results)))
        ],
        [
            P("<b>Report Status</b>"),
            P("<b>GENERATED</b>")
        ]
    ]

    cover_table = Table(
        cover_data,
        colWidths=[
            55 * mm,
            105 * mm
        ],
        hAlign="CENTER"
    )

    cover_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#EEF3F8")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#C8D2E0")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(cover_table)

    story.append(
        Spacer(1, 15 * mm)
    )

    story.append(
        P(
            "This report consolidates the results of KubeGuard "
            "Modules 1 through 10 and records the forensic "
            "assessment performed by Module 11.",
            "KGSmall"
        )
    )

    story.append(PageBreak())

    # ========================================================
    # 1 EXECUTIVE SUMMARY
    # ========================================================

    story.append(
        P(
            "1. Executive Summary",
            "KGSection"
        )
    )

    if is_image_only:
        story.append(
            P(
                f"KubeGuard completed an <b>Image-Only Security Assessment</b> for container image "
                f"<b>{image_name}</b>. No active workload running this image was detected in the cluster. "
                f"Image vulnerability analysis and cluster-wide RBAC audits were completed. "
                f"Runtime-dependent container checks (M2 live monitoring, M4 runtime threat detection, "
                f"and M5 pod configuration escape audit) were evaluated as <b>NOT APPLICABLE</b>. "
                f"The highest risk identified is <b>{overall_risk}</b>."
            )
        )
    else:
        story.append(
            P(
                f"KubeGuard completed its automated Kubernetes security "
                f"workflow for active target workload pod <b>{pod_name}</b> (image: <b>{image_name}</b>). "
                f"The highest risk identified across the available security findings is "
                f"<b>{overall_risk}</b>."
            )
        )

    story.append(
        P(
            "Module 11 correlated vulnerability scanning, runtime "
            "monitoring, RBAC analysis, threat detection, container "
            "escape detection, alerting, backup, evidence collection, "
            "isolation, and evidence integrity results."
        )
    )

    risk_color = colors.HexColor("#176B3A")

    if overall_risk == "CRITICAL":
        risk_color = colors.HexColor("#B00020")
    elif overall_risk == "HIGH":
        risk_color = colors.HexColor("#C45A00")
    elif overall_risk == "MEDIUM":
        risk_color = colors.HexColor("#9A6700")

    risk_table = Table(
        [[
            P("<b>OVERALL INCIDENT RISK</b>"),
            P(f"<b>{overall_risk}</b>")
        ]],
        colWidths=[
            75 * mm,
            40 * mm
        ]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, 0),
                colors.HexColor("#EEF3F8")
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, 0),
                risk_color
            ),
            (
                "TEXTCOLOR",
                (1, 0),
                (1, 0),
                colors.white
            ),
            (
                "ALIGN",
                (1, 0),
                (1, 0),
                "CENTER"
            ),
            (
                "FONTNAME",
                (1, 0),
                (1, 0),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                colors.HexColor("#C8D2E0")
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                9
            )
        ])
    )

    story.append(risk_table)

    # ========================================================
    # 2 MODULE STATUS
    # ========================================================

    story.append(
        P(
            "2. Module Status — M1 to M11",
            "KGSection"
        )
    )

    m1_st = "FAILED" if "error" in scan_result else "COMPLETED"
    if is_image_only:
        m2_st = "NOT APPLICABLE (Image-Only Mode)"
        m4_st = "NOT APPLICABLE (No Active Workload)"
        m5_st = "NOT APPLICABLE (Image Not Deployed)"
        m7_st = "NOT APPLICABLE (Image-Only Mode)"
        m8_st = "NOT APPLICABLE (Image-Only Mode)"
        m9_st = "NOT APPLICABLE (Image-Only Mode)"
        m10_st = "NOT APPLICABLE (Image-Only Mode)"
    else:
        m2_st = "FAILED / UNAVAILABLE" if "error" in monitor_result else "COMPLETED"
        m4_st = "FAILED" if "error" in threat_data else ("NOT AVAILABLE" if threat_result.get("status") in ["NOT AVAILABLE", "ERROR"] else "COMPLETED")
        if isinstance(escape_results, dict) and "error" in escape_results:
            m5_st = "FAILED"
        elif any(len(r.get("findings", [])) > 0 for r in escape_results):
            m5_st = "SUSPICIOUS ACTIVITY"
        else:
            m5_st = "COMPLETED"
        m7_st = "EXECUTED" if m7_backup_result else "SKIPPED (No Critical Finding)"
        m8_st = "EXECUTED" if m8_results else "SKIPPED (No Critical Finding)"
        if m9_results:
            m9_st = "EXECUTED" if any(r.get("action_executed") for r in m9_results) else "RECOMMENDATION GENERATED"
        else:
            m9_st = "SKIPPED (No Critical Finding)"
        m10_st = integrity_status if integrity_status != "NOT AVAILABLE" else "SKIPPED (No Evidence Collected)"

    m3_st = "COMPLETED" if cluster.get("status") else "FAILED"
    m6_st = "COMPLETED"

    module_rows = [
        ["M1", "Image Vulnerability Scan", m1_st],
        ["M2", "Container Monitoring", m2_st],
        ["M3", "RBAC Audit", m3_st],
        ["M4", "Threat Detection", m4_st],
        ["M5", "Container Escape Detection", m5_st],
        ["M6", "Security Alerting", m6_st],
        ["M7", "Backup", m7_st],
        ["M8", "Evidence Collection", m8_st],
        ["M9", "Isolation / Replacement", m9_st],
        ["M10", "Evidence Integrity", m10_st],
        ["M11", "Forensic Analysis & Report", "GENERATED"]
    ]

    module_data = [[
        P("<b>Module</b>"),
        P("<b>Function</b>"),
        P("<b>Status</b>")
    ]]

    for row in module_rows:

        module_data.append([
            P(row[0]),
            P(row[1]),
            P(row[2])
        ])

    module_table = Table(
        module_data,
        colWidths=[
            22 * mm,
            88 * mm,
            60 * mm
        ],
        repeatRows=1
    )

    module_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#17365D")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.45,
                colors.HexColor("#C8D2E0")
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#F5F7FA")
                ]
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                5
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                5
            )
        ])
    )

    story.append(module_table)

    story.append(PageBreak())

    # ========================================================
    # 3 M1
    # ========================================================

    story.append(
        P(
            "3. Module 1 — Image Vulnerability Analysis",
            "KGSection"
        )
    )

    story.append(
        P(
            f"<b>Image:</b> {image_name}"
        )
    )

    vulnerability_table = Table(
        [
            [
                P("<b>Severity</b>"),
                P("<b>Count</b>")
            ],
            [
                P("Critical"),
                P(critical_count)
            ],
            [
                P("High"),
                P(high_count)
            ],
            [
                P("Medium"),
                P(medium_count)
            ],
            [
                P("Low"),
                P(low_count)
            ]
        ],
        colWidths=[
            90 * mm,
            50 * mm
        ],
        repeatRows=1
    )

    vulnerability_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#17365D")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.45,
                colors.HexColor("#C8D2E0")
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#F5F7FA")
                ]
            )
        ])
    )

    story.append(vulnerability_table)

    story.append(
        Spacer(1, 5 * mm)
    )

    story.append(
        P(
            "<b>Deployment Blocked:</b> "
            + (
                "YES"
                if scan_result.get("deployment_blocked")
                else "NO"
            )
        )
    )

    critical_cves = scan_result.get(
        "critical_cve_ids",
        []
    )

    story.append(
        P(
            "<b>Critical CVEs:</b> "
            + (
                ", ".join(
                    map(str, critical_cves)
                )
                if critical_cves
                else "None"
            )
        )
    )

    # ========================================================
    # 4 M2
    # ========================================================

    story.append(
        P(
            "4. Module 2 — Container Monitoring",
            "KGSection"
        )
    )

    story.append(
        P(
            f"<b>Pod:</b> "
            f"{monitor_result.get('pod_name', pod_name)}"
        )
    )

    story.append(
        P(
            f"<b>CPU:</b> "
            f"{monitor_result.get('cpu', 'Unknown')}"
        )
    )

    story.append(
        P(
            f"<b>Memory:</b> "
            f"{monitor_result.get('memory', 'Unknown')}"
        )
    )

    story.append(
        P(
            "<b>Monitoring:</b> Continuous monitoring"
        )
    )

    # ========================================================
    # 5 M3
    # ========================================================

    story.append(
        P(
            "5. Module 3 — Kubernetes RBAC Audit",
            "KGSection"
        )
    )

    story.append(
        P(
            f"<b>Cluster Status:</b> "
            f"{cluster.get('message', 'Unknown')}"
        )
    )

    story.append(
        P(
            f"<b>Roles:</b> {roles.get('count', 0)} &nbsp;&nbsp; "
            f"<b>Cluster Roles:</b> "
            f"{cluster_roles.get('count', 0)} &nbsp;&nbsp; "
            f"<b>Bindings:</b> "
            f"{bindings.get('count', 0)}"
        )
    )

    if findings:

        story.append(
            P(
                "<b>Dangerous Roles</b>"
            )
        )

        for item in findings:

            story.append(
                P(
                    f"Role: <b>{item.get('role', 'Unknown')}</b> | "
                    f"Severity: {item.get('severity', 'Unknown')} | "
                    f"Risk Score: {item.get('score', 'N/A')} | "
                    f"Reason: {item.get('reason', 'Unknown')}"
                )
            )

    else:

        story.append(
            P(
                "No dangerous RBAC roles were reported."
            )
        )

    if binding_findings:

        story.append(
            P(
                "<b>Dangerous Bindings</b>"
            )
        )

        for item in binding_findings:

            story.append(
                P(
                    f"Role: {item.get('role', 'Unknown')} | "
                    f"Assigned: {item.get('assigned', 'Unknown')} | "
                    f"Type: {item.get('type', 'Unknown')} | "
                    f"Namespace: {item.get('namespace', '-')}"
                )
            )

    # ========================================================
    # 6 M4 / M5
    # ========================================================

    story.append(
        P(
            "6. Module 4 & 5 — Threat and Escape Analysis",
            "KGSection"
        )
    )

    story.append(
        P(
            f"<b>Threat Status:</b> "
            f"{threat_result.get('status', 'Unknown')}"
        )
    )

    story.append(
        P(
            f"<b>Threat Severity:</b> "
            f"{threat_result.get('severity', 'None')}"
        )
    )

    story.append(
        P(
            f"<b>Threat Reason:</b> "
            f"{threat_result.get('reason', 'No information available.')}"
        )
    )

    story.append(Spacer(1, 4 * mm))
    story.append(P("<b>Container Escape Detection (M5)</b>", "KGBody"))

    if isinstance(escape_results, dict) and "error" in escape_results:
        story.append(P("<b>Assessment Status:</b> FAILED"))
        story.append(P(f"<b>Error:</b> {escape_results['error']}"))
    elif not escape_results:
        if is_image_only:
            story.append(P("<b>Assessment Status:</b> NOT APPLICABLE (Image-Only Mode — Workload not deployed)"))
        else:
            story.append(P("<b>Assessment Status:</b> NO TARGETS INSPECTED"))
    else:
        m5_findings_total = sum(len(r.get("findings", [])) for r in escape_results if isinstance(r, dict))
        if m5_findings_total == 0:
            story.append(P(f"<b>Assessment Status:</b> COMPLETED | <b>Status:</b> NORMAL | <b>Severity:</b> None"))
            story.append(P(f"<b>Summary:</b> Pods checked={len(escape_results)} | Escape indicators=0"))
            story.append(P("• No container escape indicators detected across inspected targets."))
        else:
            story.append(P(f"<b>Assessment Status:</b> COMPLETED | <b>Status:</b> SUSPICIOUS ACTIVITY DETECTED"))
            story.append(P(f"<b>Summary:</b> Pods checked={len(escape_results)} | Escape indicators={m5_findings_total}"))

        for result in escape_results:
            if not isinstance(result, dict):
                continue
            story.append(Spacer(1, 2 * mm))
            p_name = result.get("pod", pod_name)
            p_ns = result.get("namespace", namespace)
            c_name = result.get("container", "main")
            c_img = result.get("image", image_name)
            is_priv = result.get("privileged", False)
            priv_str = "true" if is_priv else "false"
            inc_trig = "Triggered" if result.get("incident_triggered") else "Not triggered"

            story.append(P(f"<b>Pod:</b> {p_name} | <b>Namespace:</b> {p_ns}"))
            story.append(P(f"<b>Container:</b> {c_name} | <b>Image:</b> {c_img}"))
            story.append(P(f"<b>Privileged Mode:</b> <b>{priv_str}</b>"))
            story.append(P(f"<b>Status:</b> {result.get('status', 'NORMAL')} | <b>Severity:</b> {result.get('severity', 'None')}"))
            story.append(P(f"<b>Incident Response:</b> <b>{inc_trig}</b>"))

            escape_findings = result.get("findings", [])
            if escape_findings:
                story.append(P("<b>Detected Security Findings:</b>"))
                for finding in escape_findings:
                    story.append(P(f"• {finding}"))
            else:
                story.append(P("• No container escape indicators detected."))

    # ========================================================
    # 7 M6-M10 RESPONSE
    # ========================================================

    story.append(PageBreak())

    story.append(
        P(
            "7. Modules 6–10 — Incident Response",
            "KGSection"
        )
    )

    response_rows = [
        [
            P("<b>Module</b>"),
            P("<b>Action</b>"),
            P("<b>Result</b>")
        ],
        [
            P("M6"),
            P("Security Alerting"),
            P("Completed")
        ],
        [
            P("M7"),
            P("Backup"),
            P(
                "Executed"
                if m7_backup_result
                else "Skipped"
            )
        ],
        [
            P("M8"),
            P("Evidence Collection"),
            P(
                "Executed"
                if m8_results
                else "Skipped"
            )
        ],
        [
            P("M9"),
            P("Automatic Isolation"),
            P(
                "Executed"
                if m9_results
                else "Skipped"
            )
        ],
        [
            P("M10"),
            P("Evidence Integrity"),
            P(integrity_status)
        ]
    ]

    response_table = Table(
        response_rows,
        colWidths=[
            25 * mm,
            85 * mm,
            55 * mm
        ],
        repeatRows=1
    )

    response_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#17365D")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.45,
                colors.HexColor("#C8D2E0")
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#F5F7FA")
                ]
            )
        ])
    )

    story.append(response_table)

    story.append(
        Spacer(1, 7 * mm)
    )

    story.append(
        P(
            f"<b>Evidence Integrity:</b> "
            f"{integrity_status}"
        )
    )

    if m8_results:

        story.append(
            P(
                "<b>Evidence Locations</b>"
            )
        )

        for result in m8_results:

            story.append(
                P(
                    result.get(
                        "evidence_dir",
                        "Unknown"
                    ),
                    "KGSmall"
                )
            )

    # ========================================================
    # 8 FORENSIC FINDINGS
    # ========================================================

    story.append(
        P(
            "8. Forensic Findings",
            "KGSection"
        )
    )

    finding_rows = [[
        P("<b>Risk</b>"),
        P("<b>Finding</b>")
    ]]

    for severity, finding in forensic_findings:

        finding_rows.append([
            P(f"<b>{severity}</b>"),
            P(finding)
        ])

    finding_table = Table(
        finding_rows,
        colWidths=[
            35 * mm,
            125 * mm
        ],
        repeatRows=1
    )

    finding_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#17365D")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.45,
                colors.HexColor("#C8D2E0")
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#F5F7FA")
                ]
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(finding_table)

    # ========================================================
    # 9 TIMELINE
    # ========================================================

    story.append(
        P(
            "9. Incident Timeline",
            "KGSection"
        )
    )

    timeline_rows = [[
        P("<b>Module</b>"),
        P("<b>Stage</b>"),
        P("<b>Forensic Event</b>")
    ]]

    for module, stage, event in timeline:

        timeline_rows.append([
            P(module),
            P(stage),
            P(event)
        ])

    timeline_table = Table(
        timeline_rows,
        colWidths=[
            22 * mm,
            55 * mm,
            83 * mm
        ],
        repeatRows=1
    )

    timeline_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#17365D")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.45,
                colors.HexColor("#C8D2E0")
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#F5F7FA")
                ]
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(timeline_table)

    story.append(PageBreak())

    # ========================================================
    # 10 ROOT CAUSE
    # ========================================================

    story.append(
        P(
            "10. Root Cause Assessment",
            "KGSection"
        )
    )

    story.append(
        P(
            root_cause
        )
    )

    # ========================================================
    # 11 IMPACT
    # ========================================================

    story.append(
        P(
            "11. Impact Assessment",
            "KGSection"
        )
    )

    story.append(
        P(
            impact
        )
    )

    # ========================================================
    # 12 RECOMMENDATIONS
    # ========================================================

    story.append(
        P(
            "12. Security Recommendations",
            "KGSection"
        )
    )

    for index, recommendation in enumerate(
        recommendations,
        start=1
    ):

        story.append(
            P(
                f"<b>{index}.</b> {recommendation}"
            )
        )

    # ========================================================
    # 13 FINAL ASSESSMENT
    # ========================================================

    story.append(
        P(
            "13. Final Forensic Assessment",
            "KGSection"
        )
    )

    final_table = Table(
        [
            [
                P("<b>Overall Risk</b>"),
                P(f"<b>{overall_risk}</b>")
            ],
            [
                P("<b>Evidence Integrity</b>"),
                P(f"<b>{integrity_status}</b>")
            ],
            [
                P("<b>Forensic Analysis</b>"),
                P("<b>COMPLETED</b>")
            ],
            [
                P("<b>Report</b>"),
                P("<b>GENERATED</b>")
            ]
        ],
        colWidths=[
            70 * mm,
            70 * mm
        ]
    )

    final_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#EEF3F8")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                colors.HexColor("#C8D2E0")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(final_table)

    story.append(
        Spacer(1, 8 * mm)
    )

    story.append(
        P(
            "This document is the consolidated KubeGuard forensic "
            "report generated from Modules 1 through 11."
        )
    )

    story.append(
        P(
            "Module 11 Status: <b>FORENSIC ANALYSIS COMPLETED</b>",
            "KGSmall"
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer
    )

    # ========================================================
    # CONSOLE OUTPUT
    # ========================================================

    print(
        "[M11] Forensic analysis completed successfully."
    )

    print(
        "[M11] Overall Risk :",
        overall_risk
    )

    print(
        "[M11] Evidence Integrity :",
        integrity_status
    )

    print(
        "[M11] Forensic Report generated successfully."
    )

    # Copy to runs/<run_id>/reports if run_id is provided
    if run_id:
        try:
            import shutil
            run_rep_dir = os.path.join("runs", run_id, "reports")
            os.makedirs(run_rep_dir, exist_ok=True)
            shutil.copy2(report_path, os.path.join(run_rep_dir, os.path.basename(report_path)))
        except Exception:
            pass

    return report_path