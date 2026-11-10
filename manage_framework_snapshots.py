#!/usr/bin/env python3
"""CLI utility to manage CISO Assistant framework version and questionnaire answer snapshots.

Features:
- Create snapshots of framework definitions, question schemas, and user compliance answers prior to updates.
- List and inspect snapshots with integrity hashes, version info, and answer counts.
- Restore / migrate answers from snapshots back into CISO Assistant with intelligent question remapping.
- Diff snapshots across framework versions or compare against live state.
"""

import argparse
import json
import sys
from pathlib import Path

from classes.examples_manager import ExamplesManager
from classes.integrations.backup import BackupManager


def cmd_snapshot(args, bm: BackupManager):
    print("=" * 80)
    print("         CREATING FRAMEWORK & QUESTIONNAIRE ANSWERS SNAPSHOT")
    print("=" * 80)
    try:
        path = bm.create_framework_snapshot(
            framework_id_or_ref=args.framework,
            output_dir=args.output_dir,
            filename=args.filename,
            notes=args.notes,
        )
        stat = bm.inspect_backup(path)
        print("\n[SUCCESS] Snapshot created successfully!")
        print(f" File:      {stat['path']}")
        print(f" Size:      {stat['size_formatted']}")
        print(f" SHA-256:   {stat['sha256']}")
        fw = stat.get("framework", {})
        print(f" Framework: {fw.get('name')} (v{fw.get('version')})")
        counts = stat.get("counts", {})
        print(f" Assessments: {counts.get('compliance_assessments_count')} ({counts.get('total_answers')} total answers captured)")
        print(f" Notes:     {stat.get('notes')}")
        print("=" * 80)
    except Exception as e:
        print(f"\n[ERROR] Failed to create framework snapshot: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_list(args, bm: BackupManager):
    backups = bm.list_backups(args.dir)
    fw_backups = [b for b in backups if b.get("type") == "framework_snapshot"]
    print("=" * 98)
    print("                       FRAMEWORK & ANSWERS SNAPSHOTS")
    print("=" * 98)
    if not fw_backups:
        print("No framework snapshots found in backups directory.")
        print("Run 'python3 manage_framework_snapshots.py snapshot' to create one.")
        print("=" * 98)
        return

    sep = "-" * 98
    print(sep)
    print(f"{'#':<3} | {'Snapshot File':<36} | {'Fw (Ver)':<16} | {'Answers':<8} | {'Modified (UTC)':<16}")
    print(sep)
    for idx, b in enumerate(fw_backups, start=1):
        dt = b["modified_at"][:16].replace("T", " ")
        details = b.get("details", {})
        fw_desc = f"{details.get('framework_ref_id', '')} (v{details.get('framework_version', '?')})"
        ans = str(details.get("total_answers", 0))
        fname = b["filename"]
        if len(fname) > 36:
            fname = fname[:33] + "..."
        print(f"{idx:<3} | {fname:<36} | {fw_desc:<16} | {ans:<8} | {dt:<16}")
    print(sep)
    print(f"Total: {len(fw_backups)} framework snapshot(s) found.")


def cmd_inspect(args, bm: BackupManager):
    stat = bm.inspect_backup(args.path)
    if "error" in stat:
        print(f"[ERROR] {stat.get('details')}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("                     FRAMEWORK SNAPSHOT INSPECTION")
    print("=" * 80)
    print(f" File:        {stat.get('filename')}")
    print(f" Type:        {stat.get('type')}")
    print(f" Size:        {stat.get('size_formatted')}")
    print(f" SHA-256:     {stat.get('sha256')}")
    print(f" Created:     {stat.get('created_at')}")
    print(f" Source URL:  {stat.get('source_url')}")
    print(f" Notes:       {stat.get('notes')}")

    fw = stat.get("framework", {})
    if fw:
        print("\nFramework Metadata:")
        print(f"  - Name:         {fw.get('name')}")
        print(f"  - Ref ID:       {fw.get('ref_id')}")
        print(f"  - Lib Version:  v{fw.get('version')}")
        print(f"  - Library URN:  {fw.get('library_urn')}")
        print(f"  - Requirements: {fw.get('requirements_count')}")

    counts = stat.get("counts", {})
    if counts:
        print("\nCounts:")
        for k, v in counts.items():
            print(f"  - {k.replace('_', ' ').capitalize():<32}: {v}")

    cas = stat.get("compliance_assessments", [])
    if cas:
        print(f"\nCompliance Assessments ({len(cas)}):")
        for ca in cas:
            print(f"  - {ca.get('name')}")
            print(f"    Perimeter: {ca.get('perimeter')}, Answered: {ca.get('answered_requirements')}/{ca.get('total_requirements')}")
    print("=" * 80)


def cmd_restore(args, bm: BackupManager):
    print("=" * 80)
    action = "SIMULATING RESTORE (DRY-RUN)" if args.dry_run else "RESTORING FRAMEWORK ANSWERS"
    print(f"               {action}")
    print("=" * 80)
    res = bm.restore_framework_snapshot(
        snapshot_path=args.path,
        compliance_assessment_id=args.ca_id,
        dry_run=args.dry_run,
    )
    if res.get("status") != "success":
        print(f"[ERROR] Restore failed: {res.get('details')}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[SUCCESS] Restoration summary:")
    print(f" Snapshot File:            {res.get('snapshot_file')}")
    print(f" Framework:                {res.get('framework')} (v{res.get('library_version')})")
    print(f" Assessments Processed:    {res.get('compliance_assessments_processed')}")
    print(f" Requirements Updated:     {res.get('total_requirements_updated')}")
    print(f" Answers Restored:         {res.get('total_answers_restored')}")
    print(f" Answers Remapped:         {res.get('remapped_answers_count')}")
    print(f" Unmapped Questions:       {res.get('unmapped_questions_count')}")

    if res.get("unmapped_questions"):
        print("\nUnmapped Questions / Deprecations:")
        for u in res["unmapped_questions"][:5]:
            print(f"  - [{u.get('requirement_ref_id')}] {u.get('question_text') or u.get('question_urn')} ({u.get('reason')})")
        if len(res["unmapped_questions"]) > 5:
            print(f"  ... and {len(res['unmapped_questions']) - 5} more.")

    if args.dry_run:
        print("\n[NOTE] Dry run complete. No live changes were written to CISO Assistant.")
    else:
        print("\n[SUCCESS] Answers restored into live CISO Assistant.")
    print("=" * 80)


def cmd_diff(args, bm: BackupManager):
    print("=" * 80)
    print("                     FRAMEWORK SNAPSHOT DIFF")
    print("=" * 80)
    diff = bm.diff_framework_snapshots(args.snapshot_a, args.snapshot_b)
    if "error" in diff:
        print(f"[ERROR] {diff.get('details')}", file=sys.stderr)
        sys.exit(1)

    print(f" Base Snapshot:        {diff.get('source_a')}")
    print(f" Comparison Target:    {diff.get('source_b')}")
    print(f" Version Transition:   {diff.get('version_transition')}")
    print(f" Has Differences:      {diff.get('has_differences')}")

    schema = diff.get("schema_diff", {})
    if schema.get("requirements_added"):
        print(f"\nRequirements Added: {schema['requirements_added']}")
    if schema.get("requirements_removed"):
        print(f"\nRequirements Removed: {schema['requirements_removed']}")
    if schema.get("modified_requirements"):
        print(f"\nModified Requirements ({len(schema['modified_requirements'])}):")
        for m in schema["modified_requirements"]:
            print(f"  - Requirement: {m['requirement']}")
            if m.get("added_questions"):
                for q in m["added_questions"]:
                    print(f"    + Question added: {q['urn']} ({q['text']})")
            if m.get("removed_questions"):
                for q in m["removed_questions"]:
                    print(f"    - Question removed: {q['urn']} ({q['text']})")
            if m.get("changed_questions"):
                for q in m["changed_questions"]:
                    print(f"    * Question reworded: {q['urn']}")

    apps = diff.get("applications_diff", [])
    if apps:
        print(f"\nApplication Answer Differences ({len(apps)}):")
        for app in apps:
            print(f"  - {app['compliance_assessment']}: {app['changed_count']} changed requirement(s)")
            for ch in app["changes"][:3]:
                print(f"    Req '{ch['requirement']}':")
                print(f"      Base:       {ch['answers_a']}")
                print(f"      Comparison: {ch['answers_b']}")
    else:
        print("\nNo application answer differences detected.")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Manage CISO Assistant Framework Version and Questionnaire Answer Snapshots.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # snapshot
    p_snap = subparsers.add_parser("snapshot", help="Create a framework & answers snapshot")
    p_snap.add_argument("--framework", "-f", help="Framework ID, name, or ref_id (default: active framework)")
    p_snap.add_argument("--notes", "-n", help="Optional descriptive notes")
    p_snap.add_argument("--filename", help="Custom output filename")
    p_snap.add_argument("--output-dir", help="Custom output directory")

    # list
    p_list = subparsers.add_parser("list", help="List discovered framework snapshots")
    p_list.add_argument("--dir", help="Custom directory to scan")

    # inspect
    p_insp = subparsers.add_parser("inspect", help="Inspect snapshot metadata, contents, and hash")
    p_insp.add_argument("path", help="Path to snapshot JSON file")

    # restore
    p_rest = subparsers.add_parser("restore", help="Restore/migrate questionnaire answers from snapshot")
    p_rest.add_argument("path", help="Path to snapshot JSON file")
    p_rest.add_argument("--ca-id", help="Optional specific compliance assessment ID")
    p_rest.add_argument("--dry-run", action="store_true", help="Simulate restore without modifying live data")

    # diff
    p_diff = subparsers.add_parser("diff", help="Diff two snapshots or compare snapshot against live state")
    p_diff.add_argument("snapshot_a", help="Base snapshot JSON path")
    p_diff.add_argument("snapshot_b", nargs="?", default="live", help="Comparison snapshot JSON path or 'live' (default: live)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    bm = BackupManager()

    if args.command == "snapshot":
        cmd_snapshot(args, bm)
    elif args.command == "list":
        cmd_list(args, bm)
    elif args.command == "inspect":
        cmd_inspect(args, bm)
    elif args.command == "restore":
        cmd_restore(args, bm)
    elif args.command == "diff":
        cmd_diff(args, bm)


if __name__ == "__main__":
    main()
