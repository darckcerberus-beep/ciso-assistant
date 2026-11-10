# CISO Assistant Automation & Orchestration Platform

An enterprise-grade automation and orchestration platform for **CISO Assistant**, bridging compliance audits, dynamic risk modeling, applied control remediation, audit findings, and third-party risk management (TPRM).

---

## 📌 Executive Features & Demonstration Guide

👉 **For a full executive presentation and feature breakdown for leadership and management, see [FEATURES_OVERVIEW.md](FEATURES_OVERVIEW.md).**

It includes:
- **Executive Summary & Business ROI**
- **Core Architecture & Flowchart**
- **Detailed Feature Breakdown**
- **12 Pre-Configured Reference Applications & Vendor Profiles**
- **Live 5-Step Demonstration Script for Leadership**
- **Command-Line & Interactive Menu Reference**
- **Architecture File Map**

---

## 🚀 Quick Start

### 1. Modern Web UI & Orchestration Dashboard
Launch the web interface (mirroring all CLI features with real-time SSE execution drawer):
```bash
python3 main.py --web
# or standalone:
python3 web_app.py
```
Visit **`http://127.0.0.1:5000`** in your browser.
Options: `--web-port 8080`, `--web-host 0.0.0.0`, `--web-open` (automatically opens browser).

### 2. Interactive Terminal Menu
Launch the interactive terminal manager (or select option `10` to start the Web UI):
```bash
python3 main.py
```
*(or via the alias `python3 manage_examples.py`)*

### 2. Check Deployment Status
```bash
python3 main.py --status
```

### 3. Provision Example Applications
```bash
# Provision all reference applications
python3 main.py --create all

# Or provision a specific application or vendor profile
python3 main.py --create app_secure_core
python3 main.py --create vendor_cloud_crm
```

### 4. Interactive Audit Demo (Unanswered Workflow)
```bash
python3 main.py --create-audit App-Demo-Auditor --user auditor@example.com
```

### 5. Generate Controls & Dynamic Risk Scenarios
```bash
python3 main.py --generate-risks App-Demo-Auditor
```

### 6. Backup & Disaster Recovery
```bash
# Create portable JSON workspace snapshot
python3 main.py --backup snapshot

# Create full server database dump
python3 main.py --backup dump

# List discovered backups & checksums
python3 main.py --list-backups
```

### 7. Framework Loading & Catalog Management (with Automated Pre-Operation Backup)
```bash
# List built-in stored library catalog (375+ frameworks available in CISO Assistant)
python3 main.py --list-stored-libraries
python3 main.py --list-stored-libraries --query "27001:2022"

# Load a framework from built-in library (with automated pre-load workspace backup)
python3 main.py --load-framework "ISO/IEC 27001:2022" --backup-before-load snapshot

# Load a custom local YAML or Excel framework definition
python3 main.py --load-framework YML/appsec.yml --backup-before-load snapshot

# Force reload an updated framework
python3 main.py --load-framework "Controlli-Minimi-AGID" --force-reload

# Unload an active framework safely (with automated pre-operation backup)
python3 main.py --unload-framework "Controlli-Minimi-AGID" --backup-before-load snapshot
```

---

## 🧪 Testing & Verification

Run the comprehensive automated test suite:
```bash
python3 -m unittest discover tests
```
*Comprehensive test coverage across API, web, orchestration, backup, framework loading, and risk simulation modules.*

