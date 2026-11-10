# CISO Assistant Framework Versioning & Answers Snapshot Guide

## 1. Overview & Problem Statement

When managing compliance assessments in CISO Assistant (e.g. `App-Audit-Demo-ThibaultR`, `Adobe Campaign`, `Ravelin`, `PIM`, `Stripe`), respondents provide extensive answers, compliance results, and observations.

Updating a framework library (e.g. updating `appsec` from version 35 to 36 via `/api/loaded-libraries/{id}/update/`):
- Modifies requirement nodes, question schemas, and choice URNs.
- May add, reorder, rephrase, or remove questions (e.g., transitioning `data_classification` from a single classification question to a 4-question sensitivity model and removing `Aggregation & Scope`).
- Risks orphaning or clearing answers submitted by respondents if question URNs change across framework versions.

To solve this, CISO Assistant includes an end-to-end **Framework Version & Questionnaire Answers Snapshot Solution** providing:
1. **Pre-Update Snapshots**: Complete export of framework metadata, library version, requirement nodes catalog, question schemas, and all compliance assessment answers enriched with human-readable text.
2. **Semantic Question & Choice Remapping**: Intelligent cross-version restoration that matches questions by URN, text, or semantic overlap, and choice values by text label, preserving answers across framework updates.
3. **Auditing & Diffing Engine**: Instant comparison between snapshots or against live CISO Assistant state to verify added, removed, or modified questions and identify application answer drift.
4. **Dry-Run Safety**: Full simulation of answers restoration before writing any updates to the live database.

---

## 2. Snapshot Data Schema

Snapshots are stored in JSON format under `backups/framework_snapshots/` with SHA-256 integrity verification:

```json
{
  "type": "framework_answers_snapshot",
  "version": "1.0",
  "created_at": "2026-11-10T15:01:15.968637+00:00",
  "source_url": "https://ciso-assistant.siege.red",
  "notes": "Pre-v36 update snapshot of appsec",
  "framework": {
    "id": "706563e2-b305-472c-b68d-76c1fc32198a",
    "name": "Application Security Assessment Framework (AppSec)",
    "ref_id": "appsec",
    "urn": "urn:intuitem:risk:framework:appsec",
    "library_id": "0bd6e998-2440-437c-a2df-b9fd3d2643ca",
    "library_name": "Application Security Assessment Framework (AppSec)",
    "library_version": 35,
    "library_urn": "urn:intuitem:risk:library:appsec",
    "requirements_count": 60,
    "requirements": {
      "stakeholder_identification": {
        "ref_id": "stakeholder_identification",
        "urn": "urn:intuitem:risk:req_node:appsec:stakeholder_identification",
        "name": "Stakeholder identification",
        "questions": {
          "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1": {
            "text": "Is there a designated business contact?",
            "type": "unique_choice",
            "choices": [
              {
                "urn": "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1:c1",
                "value": "Yes"
              },
              {
                "urn": "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1:c2",
                "value": "No"
              }
            ]
          }
        }
      }
    }
  },
  "counts": {
    "compliance_assessments_count": 5,
    "total_requirement_assessments": 300,
    "answered_requirement_assessments": 43,
    "total_answers": 80
  },
  "compliance_assessments": [
    {
      "id": "e4da41f2-608c-4bec-a445-b4cdecfbdde2",
      "name": "Assessment of Application Security Assessment Framework (AppSec) in App-Audit-Demo-ThibaultR",
      "perimeter_id": "d0d02c0f-111e-4bb4-9c22-e9b4d752a31b",
      "perimeter_name": "App-Audit-Demo-ThibaultR",
      "status": "in_progress",
      "total_requirements": 60,
      "answered_requirements": 19,
      "assessments": [
        {
          "requirement_assessment_id": "c67ba73a-98a9-46b8-80d9-ec301c641c97",
          "requirement_ref_id": "stakeholder_identification",
          "requirement_urn": "urn:intuitem:risk:req_node:appsec:stakeholder_identification",
          "status": "to_do",
          "result": "compliant",
          "observation": "Documented in LeanIX repository",
          "raw_answers": {
            "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1": "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1:c1"
          },
          "answers_enriched": [
            {
              "question_urn": "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1",
              "question_text": "Is there a designated business contact?",
              "question_type": "unique_choice",
              "selected_urn": "urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1:c1",
              "selected_text": "Yes"
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 3. End-to-End Workflow Guide

### Step 1: Create a Pre-Update Snapshot

Before activating a new framework version, create a snapshot of the current state:

```bash
# Using the dedicated snapshot CLI:
python3 manage_framework_snapshots.py snapshot --framework appsec --notes "Pre-v36 update snapshot"

# Or using main.py:
python3 main.py --backup framework --notes "Pre-v36 update snapshot"
```

Verify that the snapshot was created and inspect its contents:

```bash
python3 manage_framework_snapshots.py list
python3 manage_framework_snapshots.py inspect backups/framework_snapshots/framework_appsec_v35_YYYYMMDD_HHMMSS.json
```

### Step 2: Update the Framework Library in CISO Assistant

Update the loaded library via API or file upload:

```bash
# Upload updated YAML to /api/stored-libraries/upload/
# Activate update on /api/loaded-libraries/{id}/update/
```

### Step 3: Diff Pre-Update Snapshot Against Live State

Review what changed between the snapshot and the newly updated framework:

```bash
python3 manage_framework_snapshots.py diff backups/framework_snapshots/framework_appsec_v35_YYYYMMDD_HHMMSS.json live
```

The diff report highlights:
- Version transition: `v35 -> v36`
- Removed questions (e.g. `q3 Aggregation & Scope`)
- Added questions (e.g. `q1 Data Category`, `q2 Impact Level`)
- Requirements modified

### Step 4: Dry-Run Answer Restoration

Preview how answers, compliance results, and observations will be restored or remapped without modifying live data:

```bash
python3 manage_framework_snapshots.py restore backups/framework_snapshots/framework_appsec_v35_YYYYMMDD_HHMMSS.json --dry-run
```

### Step 5: Restore / Migrate Answers into CISO Assistant

Execute the live restoration:

```bash
python3 manage_framework_snapshots.py restore backups/framework_snapshots/framework_appsec_v35_YYYYMMDD_HHMMSS.json
```

The restoration engine will:
1. Match unchanged questions directly by URN and choice URN.
2. Remap re-indexed or rephrased questions using text and choice semantics.
3. Skip deprecated questions safely while preserving historical notes.
4. Keep respondent observations and compliance results intact.

---

## 4. CLI Command Reference

| Action | Command |
|---|---|
| **Create Snapshot** | `python3 manage_framework_snapshots.py snapshot [-f FRAMEWORK] [-n NOTES]` |
| **List Snapshots** | `python3 manage_framework_snapshots.py list` |
| **Inspect Snapshot** | `python3 manage_framework_snapshots.py inspect <PATH>` |
| **Simulate Restore (Dry-Run)** | `python3 manage_framework_snapshots.py restore <PATH> --dry-run` |
| **Execute Restore** | `python3 manage_framework_snapshots.py restore <PATH> [--ca-id <ID>]` |
| **Diff Two Snapshots** | `python3 manage_framework_snapshots.py diff <SNAP_A> <SNAP_B>` |
| **Diff Snapshot Against Live** | `python3 manage_framework_snapshots.py diff <SNAP_A>` |

---

## 5. Python SDK API Reference

### `classes.integrations.backup.BackupManager`

```python
from classes.integrations.backup import BackupManager

bm = BackupManager()

# 1. Create snapshot
snap_path = bm.create_framework_snapshot(
    framework_id_or_ref="appsec",
    notes="Pre-update backup",
)

# 2. Inspect snapshot
info = bm.inspect_backup(snap_path)
print(f"Library Version: v{info['framework']['version']}, Answers: {info['counts']['total_answers']}")

# 3. Diff snapshots
diff = bm.diff_framework_snapshots(snap_path, "live")
print(f"Transition: {diff['version_transition']}, Has Differences: {diff['has_differences']}")

# 4. Restore answers
report = bm.restore_framework_snapshot(
    snapshot_path=snap_path,
    dry_run=False,
)
print(f"Updated {report['total_requirements_updated']} requirements across {report['compliance_assessments_processed']} assessments.")
```

### `classes.examples_manager.ExamplesManager`

```python
from classes.examples_manager import ExamplesManager

manager = ExamplesManager()

snap_path = manager.create_framework_snapshot(framework_id_or_ref="appsec", notes="Backup before v36")
diff = manager.diff_framework_snapshots(snap_path, "live")
report = manager.restore_framework_snapshot(snap_path, dry_run=False)
```

---

## 6. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/framework-snapshots` | List discovered framework snapshots with metadata and answer counts |
| `POST` | `/api/framework-snapshots/create` | Trigger asynchronous snapshot creation (`{"framework_id": "appsec", "notes": "..."}`) |
| `POST` | `/api/framework-snapshots/restore` | Restore answers (`{"filename": "...", "dry_run": false, "compliance_assessment_id": "..."}`) |
| `POST` | `/api/framework-snapshots/diff` | Compare snapshots or compare snapshot with live state (`{"snapshot_a": "...", "snapshot_b": "live"}`) |
