# Cloud Security – Kubernetes Threat Detection & Digital Forensics

A Python-based cloud and container security platform designed to monitor Kubernetes workloads, detect security threats, identify container vulnerabilities, and support incident investigation through evidence collection and digital forensics.

## Overview

Cloud Security provides an integrated security monitoring and analysis workflow for Kubernetes environments.

The platform combines vulnerability scanning, workload monitoring, RBAC auditing, threat detection, container escape detection, alerting, isolation, evidence integrity, and forensic reporting.

## Features

### 1. Vulnerability Scanning
- Container image vulnerability scanning using Trivy.
- Vulnerability identification and reporting.

### 2. Container Monitoring
- Kubernetes workload monitoring.
- Container resource and runtime monitoring.

### 3. RBAC Auditing
- Kubernetes Role-Based Access Control auditing.
- Identification of potentially risky permissions.

### 4. Threat Detection
- Runtime threat detection.
- Threat severity assessment.

### 5. Container Escape Detection
- Container security monitoring.
- Detection of potentially dangerous container configurations.

### 6. Alerting System
- Telegram notifications.
- Email notifications.
- Security alert logging.

### 7. Backup and Isolation
- Workload backup functionality.
- NetworkPolicy-based isolation support.

### 8. Evidence Collection
- Security evidence collection.
- Incident-related evidence management.

### 9. Isolation Management
- Workload isolation and security response support.

### 10. Evidence Integrity
- Evidence integrity verification.
- Tampering detection support.

### 11. Digital Forensics
- Incident analysis.
- Automated forensic PDF report generation.

### Dashboard
- Flask-based security dashboard.
- Security monitoring and report visualization.

## Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Backend | Flask |
| Container Orchestration | Kubernetes |
| Container Security | Trivy |
| Notifications | Telegram, Email |
| Data Format | JSON, YAML |
| Reporting | ReportLab |
| Frontend | HTML, CSS, JavaScript |
| Version Control | Git and GitHub |

## Project Structure

```text
Cloud-Security/
│
├── config/
│   └── target_config.example.json
│
├── dashboard/
│   ├── app.py
│   └── templates/
│       └── dashboard.html
│
├── reports/
│
├── main.py
├── monitoring.py
├── alerting.py
├── email_alerting.py
├── alert_logger.py
├── deployment_manager.py
├── runtime_target.py
├── run_manager.py
│
├── module4_detection.py
├── module5_escape.py
├── module7_backup.py
├── module7_isolation.py
├── module8_evidence.py
├── module9_isolation.py
├── module10_integrity.py
├── module11_forensics.py
│
├── rbac_audit.py
├── vuln_scan.py
│
├── networkpolicy-nginx.yaml
├── networkpolicy-node-app.yaml
├── networkpolicy-python-app.yaml
├── node-workload.yaml
├── python-workload.yaml
│
├── test_*.py
├── requirements.txt
├── .gitignore
└── README.md
