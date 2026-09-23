#!/usr/bin/env python3
"""Main entrypoint for CISO Assistant orchestration and example applications manager.

Provides an interactive menu and CLI tool to manage CISO Assistant example applications,
simulate questionnaire responses, evaluate dynamic risk scenarios, synchronize controls,
and inspect deployment status across the live instance.

Usage:
    Interactive menu:
        python3 main.py

    CLI commands:
        python3 main.py --status
        python3 main.py --create all
        python3 main.py --create app_secure_core
        python3 main.py --link-controls all
        python3 main.py --link-controls app_secure_core
        python3 main.py --remove all --yes
        python3 main.py --remove app_vulnerable_portal
        python3 main.py --offline
        python3 main.py --pipeline
"""

import argparse
import sys
import time
from pathlib import Path

from classes import utils
from classes.examples_manager import (
    EXAMPLE_APPLICATIONS,
    EXAMPLE_FOLDER_NAME,
    ExamplesManager,
)
from classes.organization.domain import criticality_mapping
from tests.test_application_scenarios import ApplicationRiskSimulator


def print_banner():
    """Display header banner."""
    print("=" * 80)
    print("           CISO ASSISTANT - EXAMPLE APPLICATIONS MANAGER")
    print(f" Target Instance: {utils.BASE_URL}")
    print(f" Target Folder:   {EXAMPLE_FOLDER_NAME}")
    print("=" * 80)


def print_status_table(status_list):
    """Print formatted deployment summary table and resource breakdown."""
    sep = "-" * 168
    print("\n" + sep)
    print(f"{'#':<3} | {'Application Name':<25} | {'Status':<24} | {'App Created':<11} | {'Audit Answered':<15} | {'Risks Created':<13} | {'Controls':<8} | {'Linked':<8} | {'TPRM':<5} | {'User':<18} | {'Findings':<8}")
    print(sep)
    for idx, item in enumerate(status_list, start=1):
        name_str = item["name"]
        if len(name_str) > 25:
            name_str = name_str[:22] + "..."

        status_str = item.get("lifecycle_status") or item.get("status") or ("DEPLOYED" if item.get("exists") else "NOT CREATED")
        if len(status_str) > 24:
            status_str = status_str[:21] + "..."
        app_str = "YES" if (item.get("app_created") or item.get("exists")) else "NO"

        if not item.get("exists"):
            audit_str = "-"
            risks_str = "-"
            ctrl_count = "-"
            linked_str = "-"
            findings_str = "-"
        else:
            tot = item.get("total_requirements_count", 0)
            ans = item.get("answered_requirements_count", 0)
            if not item.get("compliance_assessment_id"):
                audit_str = "NO"
            elif tot > 0:
                if ans >= tot:
                    audit_str = f"YES ({ans}/{tot})"
                elif ans > 0:
                    audit_str = f"PARTIAL ({ans}/{tot})"
                else:
                    audit_str = f"NO ({ans}/{tot})"
            else:
                audit_str = "YES" if item.get("audit_answered") else "NO"

            sc_count = item.get("risk_scenarios_count", 0)
            if sc_count > 0:
                risks_str = f"YES ({sc_count})"
            elif item.get("risk_assessment_id"):
                risks_str = "NO (0)"
            else:
                risks_str = "NO"

            ctrl_count = str(item.get("applied_controls_count", 0))
            linked_str = f"{item.get('existing_controls_linked', 0)}/{item.get('planned_controls_linked', 0)}"
            findings_str = str(item.get("findings_count", 0))

        tprm_str = "YES" if item.get("entity_id") else "NO"
        user_str = item.get("user_email") or "-"
        if len(user_str) > 18:
            user_str = user_str[:15] + "..."

        print(f"{idx:<3} | {name_str:<25} | {status_str:<24} | {app_str:<11} | {audit_str:<15} | {risks_str:<13} | {ctrl_count:<8} | {linked_str:<8} | {tprm_str:<5} | {user_str:<18} | {findings_str:<8}")
    print(sep)

    # Detailed view
    deployed = [s for s in status_list if s.get("exists")]
    if deployed:
        print("\nDeployed Resources Breakdown:")
        for s in deployed:
            print(f"\n  * {s['name']}:")
            print(f"    - Lifecycle Status:         {s.get('lifecycle_status') or 'UNKNOWN'}")
            print(f"    - App Created:              {'YES' if (s.get('app_created') or s.get('exists')) else 'NO'}")
            tot = s.get("total_requirements_count", 0)
            ans = s.get("answered_requirements_count", 0)
            if tot > 0:
                is_complete = (ans >= tot) or s.get("compliance_status") == "completed"
                status_label = "YES" if is_complete else ("PARTIAL" if ans > 0 else "NO")
                print(f"    - Audit Answered:           {status_label} ({ans}/{tot} requirements answered, {s.get('audit_completion_pct', 0)}% complete)")
            else:
                print(f"    - Audit Answered:           {'YES' if s.get('audit_answered') else 'NO'}")
            print(f"    - Risks Created:            {'YES (' + str(s.get('risk_scenarios_count', 0)) + ' scenarios)' if s.get('risks_created') else 'NO'}")
            print(f"    - TPRM External Entity ID:  {s.get('entity_id') or 'None'}")
            print(f"    - TPRM Assessment ID:       {s.get('entity_assessment_id') or 'None'}")
            print(f"    - TPRM Conclusion:          {s.get('tprm_conclusion') or 'None'}")
            print(f"    - Representative User:      {s.get('user_email') or 'None'} (User ID: {s.get('user_id') or 'None'})")
            print(f"    - Perimeter ID:             {s.get('perimeter_id') or 'None'}")
            print(f"    - Asset ID:                 {s.get('asset_id') or 'None'}")
            print(f"    - Compliance Assessment:    {s.get('compliance_assessment_name') or 'None'}")
            print(f"    - Findings Assessment ID:   {s.get('findings_assessment_id') or 'None'}")
            print(f"    - Audit Findings Count:     {s.get('findings_count', 0)}")
            print(f"    - Risk Assessment ID:       {s.get('risk_assessment_id') or 'None'}")
            print(f"    - Risk Scenarios Created:   {s.get('risk_scenarios_count', 0)}")
            print(f"    - Applied Controls Created: {s.get('applied_controls_count', 0)}")
            print(f"    - Controls Linked to Risks: {s.get('existing_controls_linked', 0)} Active (Existing), {s.get('planned_controls_linked', 0)} To Do (Planned)")
            print(f"    - Vulnerabilities Linked:   {s.get('vulnerabilities_linked', 0)}")
            print(f"    - Threats Linked:           {s.get('threats_linked', 0)}")
    else:
        print("\nNo example applications currently exist in CISO Assistant.")
    print()



def show_status(manager: ExamplesManager, wait_seconds: float = 2.0):
    """Query and display deployment status of all example applications."""
    print("\nChecking deployment status in CISO Assistant...")
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[WARNING] Could not connect to API: {msg}")
        print("Ensure the CISO Assistant server is reachable and keys.py has valid credentials.")
        return

    if wait_seconds > 0:
        print(f"Waiting {int(wait_seconds)}s for CISO Assistant to finalize updates...")
        time.sleep(wait_seconds)

    status_list = manager.get_status()
    print_status_table(status_list)


def link_controls_ui(manager: ExamplesManager, target="all"):
    """Link controls to risk scenarios across target applications."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    if target == "all":
        print(f"\nLinking existing and planned controls across all {len(EXAMPLE_APPLICATIONS)} example applications...")
        results = manager.link_all_controls_to_risk_scenarios()
        print("\nLinking Summary:")
        for r in results:
            if "error" in r:
                print(f"  * {r.get('app_name', 'Unknown')}: [ERROR] {r['error']}")
            else:
                print(f"  * {r['app_name']}: {r['scenarios_updated']} scenarios updated | "
                      f"{r['existing_controls']} active controls linked, "
                      f"{r['planned_controls']} planned controls linked | "
                      f"{r.get('vulnerabilities_linked', 0)} vulnerabilities linked, "
                      f"{r.get('threats_linked', 0)} threats linked")
        print("\n[SUCCESS] Completed linking controls to risk scenarios.")
    else:
        app = next((a for a in EXAMPLE_APPLICATIONS if a["id"] == target or a["name"] == target), None)
        if not app:
            print(f"[ERROR] Unknown application: {target}")
            return
        print(f"\n---> Linking controls to risk scenarios for {app['name']}...")
        try:
            r = manager.link_controls_for_application(app["id"])
            print(f"     [OK] Scenarios updated: {r['scenarios_updated']}")
            print(f"     [OK] Active controls linked: {r['existing_controls']}")
            print(f"     [OK] Planned controls linked: {r['planned_controls']}")
            print(f"     [OK] Vulnerabilities linked: {r.get('vulnerabilities_linked', 0)}")
            print(f"     [OK] Threats linked: {r.get('threats_linked', 0)}")
            print(f"\n[SUCCESS] Successfully linked controls for {app['name']}!")
        except Exception as e:
            print(f"[ERROR] Failed to link controls for {app['name']}: {e}")


def create_examples_ui(manager: ExamplesManager, target="all"):
    """Provision example applications in CISO Assistant with answers and risk scenarios."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    if target == "all":
        print(f"\nCreating all {len(EXAMPLE_APPLICATIONS)} example applications in CISO Assistant...")
        for app in EXAMPLE_APPLICATIONS:
            print(f"\n---> Provisioning {app['label']}...")
            try:
                res = manager.create_example_application(app["id"])
                print(f"     [OK] Representative User: {res.get('user_email')} (ID: {res.get('user_id')})")
                print(f"     [OK] TPRM External Entity: {res.get('entity_id')}")
                print(f"     [OK] TPRM Entity Assessment: {res.get('entity_assessment_name')}")
                print(f"     [OK] Perimeter: {res['perimeter_id']}")
                print(f"     [OK] Compliance Assessment: {res['compliance_assessment_name']}")
                print(f"     [OK] Answers Imported: {res['answers_updated']} from {app['csv_path']}")
                print(f"     [OK] Risk Scenarios Evaluated: {res['scenarios_created']}")
                print(f"     [OK] Controls Linked: {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
                print(f"     [OK] Vulnerabilities Linked: {res.get('vulnerabilities_linked', 0)}")
                print(f"     [OK] Threats Linked: {res.get('threats_linked', 0)}")
                print(f"     [OK] Audit Findings Generated: {res.get('findings_count', 0)}")
            except Exception as e:
                print(f"     [FAILED] Error creating {app['name']}: {e}")
        print("\n[SUCCESS] Completed provisioning of all example applications.")
        print("Waiting 2s for CISO Assistant to finalize updates before checking status...")
        time.sleep(2)
        show_status(manager, wait_seconds=0)
        print(f"You can now log in to the CISO Assistant UI at {utils.BASE_URL} to visualize the results!")
    else:
        app = next((a for a in EXAMPLE_APPLICATIONS if a["id"] == target or a["name"] == target), None)
        if not app:
            print(f"[ERROR] Unknown application: {target}")
            return
        print(f"\n---> Provisioning {app['label']} in CISO Assistant...")
        try:
            res = manager.create_example_application(app["id"])
            print(f"     [OK] Representative User: {res.get('user_email')} (ID: {res.get('user_id')})")
            print(f"     [OK] TPRM External Entity: {res.get('entity_id')}")
            print(f"     [OK] TPRM Entity Assessment: {res.get('entity_assessment_name')}")
            print(f"     [OK] Perimeter: {res['perimeter_id']}")
            print(f"     [OK] Compliance Assessment: {res['compliance_assessment_name']}")
            print(f"     [OK] Answers Imported: {res['answers_updated']}")
            print(f"     [OK] Risk Scenarios Evaluated: {res['scenarios_created']}")
            print(f"     [OK] Controls Linked: {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
            print(f"     [OK] Vulnerabilities Linked: {res.get('vulnerabilities_linked', 0)}")
            print(f"     [OK] Threats Linked: {res.get('threats_linked', 0)}")
            print(f"     [OK] Audit Findings Generated: {res.get('findings_count', 0)}")
            print(f"\n[SUCCESS] Successfully created {app['name']} in CISO Assistant!")

            print("Waiting 2s for CISO Assistant to finalize updates before checking status...")
            time.sleep(2)
            show_status(manager, wait_seconds=0)
        except Exception as e:
            print(f"[ERROR] Failed to create {app['name']}: {e}")


def create_audit_demo_ui(manager: ExamplesManager, app_name: str | None = None, user_email: str | None = None):
    """Create an application and assign its compliance assessment to a user (interactive audit demo)."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    print("\n" + "=" * 80)
    print("      CREATE APPLICATION & ASSIGN AUDIT TO USER (UNANSWERED DEMO)")
    print("=" * 80)
    print("This mode demonstrates what a user sees when assigned an audit:")
    print(" - Creates the application (external entity, perimeter, asset).")
    print(" - Assigns the compliance assessment to a user (creating the user if missing).")
    print(" - Leaves all questions UNANSWERED (0% completion, in progress).")
    print(" - Generates NO risk scenarios or controls until answers are provided.")
    print("-" * 80)

    # 1. Prompt for Application Name
    if not app_name:
        default_app_name = "App-Audit-Demo"
        prompt_str = f"Enter application name [default: {default_app_name}] (or 'c' to cancel): "
        entered = input(prompt_str).strip()
        if entered.lower() in ("c", "cancel"):
            print("Operation canceled.")
            return
        app_name = entered or default_app_name

    # 2. Prompt for User Email
    if not user_email:
        while True:
            email_input = input("Enter user email to assign the compliance assessment to (or 'c' to cancel): ").strip()
            if email_input.lower() in ("c", "cancel"):
                print("Operation canceled.")
                return
            if email_input and "@" in email_input:
                user_email = email_input.lower()
                break
            print("[!] Please enter a valid email address (e.g. respondent@example.com).")

    # 3. Check if user already exists
    user_dict = manager._init_data().get("user_dict")
    user_id = user_dict.get_id_from_email(user_email) if user_dict else None
    first_name = ""
    last_name = ""
    is_third_party = True

    if user_id:
        user_obj = next((u for u in user_dict.get_users() if u.get_id() == user_id), None)
        full_name = user_obj.get_full_name() if user_obj else ""
        print(f"\n[INFO] Found existing user in CISO Assistant: {full_name} ({user_email}) [ID: {user_id}]")
    else:
        print(f"\n[INFO] User '{user_email}' does not exist in CISO Assistant. Let's create this user:")
        parts = user_email.split("@")[0].replace(".", " ").replace("-", " ").replace("_", " ").split()
        default_first = parts[0].capitalize() if parts else "Audit"
        default_last = parts[1].capitalize() if len(parts) > 1 else "Respondent"

        first_input = input(f"  First Name [default: {default_first}]: ").strip()
        first_name = first_input or default_first

        last_input = input(f"  Last Name [default: {default_last}]: ").strip()
        last_name = last_input or default_last

        tp_input = input("  Create as Third-Party Respondent? [Y/n]: ").strip().lower()
        is_third_party = tp_input not in ("n", "no")

    print(f"\n---> Provisioning application '{app_name}' and assigning audit to '{user_email}'...")
    try:
        res = manager.create_application_for_audit(
            app_name=app_name,
            user_email=user_email,
            first_name=first_name,
            last_name=last_name,
            is_third_party=is_third_party,
        )
        print("\n" + "=" * 80)
        print("          AUDIT DEMONSTRATION APPLICATION READY")
        print("=" * 80)
        print(f" Application Name:         {res['app_name']}")
        print(f" Assigned User:            {res['user_email']} (ID: {res['user_id']})")
        print(f" User Status:              {'Newly Created' if res.get('user_created') else 'Existing User Reused'}")
        print(f" TPRM External Entity:     {res['entity_id']}")
        print(f" TPRM Entity Assessment:   {res['entity_assessment_name']} (ID: {res['entity_assessment_id']})")
        print(f" Compliance Assessment:    {res['compliance_assessment_name']} (ID: {res['compliance_assessment_id']})")
        print(f" Requirements In Scope:    {res.get('requirement_assessments_count', 12)} requirements (All Unanswered)")
        print(f" Assessment Status:        {res.get('compliance_status', 'in_progress').upper()} (0% Completion)")
        print(f" Requirement Assignment:   {res.get('assignment_id') or 'Created & Started'}")
        print("-" * 80)
        print(f" To view and answer this audit, log in to CISO Assistant at:")
        print(f"   {utils.BASE_URL}")
        print(" Navigate to 'Third-Party Risk Management' -> 'Assessments' -> Click the assessment")
        print(" You will see the questionnaire in its initial, uncompleted state ready for input.")
        print("=" * 80)

        print("\nWaiting 2s for CISO Assistant to finalize updates before checking status...")
        time.sleep(2)
        show_status(manager, wait_seconds=0)

    except Exception as e:
        print(f"\n[ERROR] Failed to create audit demonstration for {app_name}: {e}")


def generate_controls_and_risks_ui(
    manager: ExamplesManager,
    app_name: str | None = None,
    answers_source: str | None = None,
    interactive: bool = True,
):
    """Generate Applied Controls and Risk Scenarios for an existing application."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    print("\n" + "=" * 80)
    print("      GENERATE CONTROLS & RISK SCENARIOS FOR AN APPLICATION")
    print("=" * 80)
    print("This option completes the compliance & risk lifecycle for an application:")
    print(" - Detects answered questions (either directly from CISO Assistant UI or answers file).")
    print(" - Generates Applied Controls with priorities calculated from risk levels.")
    print(" - Updates Asset CIA Criticality based on classification answers.")
    print(" - Evaluates dynamic Risk Scenarios using the 4x4 Risk Matrix.")
    print(" - Links Active (existing) and Planned (to do) controls to the scenarios.")
    print("-" * 80)

    # 1. Select Application if not provided
    if not app_name:
        status_list = manager.get_status()
        deployed_apps = [s for s in status_list if s["exists"]]
        if not deployed_apps:
            print("[!] No applications currently deployed in CISO Assistant.")
            entered = input("Enter application name manually (or 'c' to cancel): ").strip()
            if entered.lower() in ("c", "cancel") or not entered:
                print("Operation canceled.")
                return
            app_name = entered
        else:
            print("\nSelect target application:")
            for idx, app in enumerate(deployed_apps, start=1):
                ans_str = app.get("lifecycle_status") or ("Answered" if app.get("audit_answered") else "Unanswered")
                print(f" {idx}) {app['name']:<25} ({ans_str})")
            print(f" {len(deployed_apps) + 1}) Enter custom application name manually")

            sub_choice = input(f"Enter choice [1-{len(deployed_apps) + 1}] (or 'c' to cancel): ").strip()
            if sub_choice.lower() in ("c", "cancel"):
                print("Operation canceled.")
                return
            if sub_choice.isdigit() and 1 <= int(sub_choice) <= len(deployed_apps):
                app_name = deployed_apps[int(sub_choice) - 1]["name"]
            elif sub_choice == str(len(deployed_apps) + 1):
                custom_target = input("Enter application name: ").strip()
                if not custom_target or custom_target.lower() in ("c", "cancel"):
                    print("Operation canceled.")
                    return
                app_name = custom_target
            else:
                print("Invalid choice. Operation canceled.")
                return

    # 2. Select Answers Source if not provided
    csv_to_use = None
    if answers_source:
        csv_to_use = answers_source
    elif interactive:
        # Prompt user whether to use live UI answers or an answers file
        print(f"\nSelect answers source for '{app_name}':")
        print(" 1) Evaluate live answers already submitted in CISO Assistant UI (Default)")
        print(" 2) Load answers from an Example Profile (e.g. App-Secure-Core, App-Vulnerable-Portal)")
        print(" 3) Specify path to custom CSV/YAML file")
        src_choice = input("Enter choice [1-3, default: 1] (or 'c' to cancel): ").strip()

        if src_choice.lower() in ("c", "cancel"):
            print("Operation canceled.")
            return

        if src_choice == "2":
            print("\nSelect example profile to load answers from:")
            for idx, ex_app in enumerate(EXAMPLE_APPLICATIONS, start=1):
                print(f" {idx}) {ex_app['label']}")
            p_choice = input(f"Enter choice [1-{len(EXAMPLE_APPLICATIONS)}]: ").strip()
            if p_choice.isdigit() and 1 <= int(p_choice) <= len(EXAMPLE_APPLICATIONS):
                csv_to_use = EXAMPLE_APPLICATIONS[int(p_choice) - 1]["csv_path"]
            else:
                print("Invalid choice. Falling back to live UI answers.")
        elif src_choice == "3":
            custom_path = input("Enter path to answers file (CSV/YAML): ").strip()
            if not custom_path or not Path(custom_path).exists():
                print(f"[ERROR] File '{custom_path}' does not exist. Falling back to live UI answers.")
            else:
                csv_to_use = custom_path
        else:
            csv_to_use = None
    else:
        csv_to_use = None

    print(f"\n---> Generating controls & risk scenarios for '{app_name}'...")
    if csv_to_use:
        print(f"     Source Answers: {csv_to_use}")
    else:
        print("     Source Answers: Live answers from CISO Assistant UI")

    try:
        res = manager.generate_controls_and_risks_for_application(app_name, csv_path=csv_to_use)
        print("\n" + "=" * 80)
        print("          CONTROLS & RISK SCENARIOS SUCCESSFULLY GENERATED")
        print("=" * 80)
        print(f" Application Name:         {res['app_name']}")
        print(f" Perimeter ID:             {res['perimeter_id']}")
        print(f" Asset ID:                 {res['asset_id']}")
        print(f" Compliance Assessment:    {res['compliance_assessment_name']}")
        if res.get("answers_updated", 0) > 0:
            print(f" Answers Imported:         {res['answers_updated']}")
        print(f" Applied Controls Created: {res.get('applied_controls_count', 0)}")
        print(f" Risk Scenarios Evaluated: {res.get('scenarios_created', 0)}")
        print(f" Controls Linked:          {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
        print(f" Audit Findings Created:   {res.get('findings_count', 0)}")
        print("-" * 80)

        print(f" View the generated scenarios and controls in CISO Assistant at:")
        print(f"   {utils.BASE_URL}")
        print(" Navigate to 'Risk Management' -> 'Risk Scenarios' or 'Third-Party Risk Management'")
        print("=" * 80)

        print("\nWaiting 2s for CISO Assistant to finalize updates before checking status...")
        time.sleep(2)
        show_status(manager, wait_seconds=0)

    except ValueError as ve:
        print(f"\n[ERROR] Validation failed: {ve}")
    except Exception as e:
        print(f"\n[ERROR] Failed to generate controls and risk scenarios: {e}")


def remove_examples_ui(manager: ExamplesManager, target="all", auto_confirm=False):
    """Teardown and clean up example applications from CISO Assistant."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    if not auto_confirm:
        target_desc = "ALL example applications" if target == "all" else f"application '{target}'"
        confirm = input(f"\nAre you sure you want to remove {target_desc} from CISO Assistant? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Operation canceled.")
            return

    if target == "all":
        print("\nRemoving all example applications from CISO Assistant...")
        for app in EXAMPLE_APPLICATIONS:
            print(f"---> Deleting {app['name']}...")
            try:
                del_res = manager.remove_example_application(app["id"])
                print(f"     Deleted: {del_res.get('entity_assessments_deleted', 0)} entity assessment(s), "
                      f"{del_res.get('entities_deleted', 0)} entity(ies), "
                      f"{del_res.get('users_deleted', 0)} user(s), "
                      f"{del_res.get('findings_deleted', 0)} finding(s), "
                      f"{del_res.get('findings_assessments_deleted', 0)} findings assessment(s), "
                      f"{del_res['risk_assessments_deleted']} risk assessment(s), "
                      f"{del_res['scenarios_deleted']} scenario(s), "
                      f"{del_res['compliance_assessments_deleted']} compliance assessment(s), "
                      f"{del_res['applied_controls_deleted']} control(s), "
                      f"{del_res['assets_deleted']} asset(s), "
                      f"{del_res['perimeters_deleted']} perimeter(s).")
            except Exception as e:
                print(f"     [ERROR] Failed to delete {app['name']}: {e}")
        print("\n[SUCCESS] Completed removal of example applications.")
    else:
        app = next((a for a in EXAMPLE_APPLICATIONS if a["id"] == target or a["name"] == target), None)
        target_name = app["name"] if app else target
        print(f"\n---> Removing {target_name} from CISO Assistant...")
        try:
            del_res = manager.remove_example_application(target)
            print(f"     Deleted: {del_res.get('entity_assessments_deleted', 0)} entity assessment(s), "
                  f"{del_res.get('entities_deleted', 0)} entity(ies), "
                  f"{del_res.get('users_deleted', 0)} user(s), "
                  f"{del_res.get('findings_deleted', 0)} finding(s), "
                  f"{del_res.get('findings_assessments_deleted', 0)} findings assessment(s), "
                  f"{del_res['risk_assessments_deleted']} risk assessment(s), "
                  f"{del_res['scenarios_deleted']} scenario(s), "
                  f"{del_res['compliance_assessments_deleted']} compliance assessment(s), "
                  f"{del_res['applied_controls_deleted']} control(s), "
                  f"{del_res['assets_deleted']} asset(s), "
                  f"{del_res['perimeters_deleted']} perimeter(s).")
            print(f"\n[SUCCESS] Successfully removed {target_name} from CISO Assistant!")

        except Exception as e:
            print(f"[ERROR] Failed to remove {target_name}: {e}")


def backup_ui(manager: ExamplesManager, backup_type: str = "snapshot"):
    """Create a backup (database dump or workspace snapshot)."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    print("\n" + "=" * 80)
    print(f"               CREATING {backup_type.upper()} BACKUP")
    print("=" * 80)

    if backup_type == "dump":
        print("Initiating full database dump via /api/serdes/dump-db/...")
        dump_path = manager.create_database_dump()
        if dump_path:
            stat = manager.inspect_backup(dump_path)
            print("\n[SUCCESS] Database dump successfully created!")
            print(f" File:     {stat['path']}")
            print(f" Size:     {stat['size_formatted']}")
            print(f" SHA-256:  {stat['sha256']}")
        else:
            print("\n[ERROR] Failed to create database dump.")
    else:
        print("Exporting workspace resources to JSON snapshot...")
        snapshot_path = manager.create_workspace_snapshot()
        stat = manager.inspect_backup(snapshot_path)
        print("\n[SUCCESS] Workspace snapshot successfully created!")
        print(f" File:     {stat['path']}")
        print(f" Size:     {stat['size_formatted']}")
        print(f" SHA-256:  {stat['sha256']}")
        if "counts" in stat:
            print("\nResource Breakdown:")
            for k, v in stat["counts"].items():
                print(f"  - {k.replace('_', ' ').capitalize():<28}: {v}")


def restore_ui(manager: ExamplesManager, file_path: str):
    """Restore from a backup file (database dump or workspace snapshot)."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    path = Path(file_path)
    if not path.exists():
        print(f"\n[ERROR] Backup file not found: {file_path}")
        return

    stat = manager.inspect_backup(path)
    b_type = stat.get("type", "unknown")

    print("\n" + "=" * 80)
    print("               RESTORE FROM BACKUP")
    print("=" * 80)
    print(f" File:     {stat['filename']}")
    print(f" Type:     {b_type}")
    print(f" Size:     {stat['size_formatted']}")
    print(f" SHA-256:  {stat['sha256']}")
    print("-" * 80)

    if b_type == "database_dump" or path.suffix in (".dump", ".sql"):
        print("---> Restoring database via /api/serdes/load-backup/...")
        res = manager.restore_database_dump(path)
        if res is True or (isinstance(res, dict) and not res.get("error")):
            print("\n[SUCCESS] Database restore completed successfully!")
            show_status(manager, wait_seconds=2)
        else:
            print(f"\n[ERROR] Database restore failed: {res}")
    elif b_type == "workspace_snapshot":
        print("---> Restoring workspace resources from JSON snapshot...")
        res = manager.restore_workspace_snapshot(path)
        if res.get("status") == "success":
            print("\n[SUCCESS] Workspace snapshot restored successfully!")
            print(f" Expected Resources: {res.get('expected_counts', {})}")
            print(f" Restored Categories: {list(res.get('restored_counts', {}).keys())}")
            show_status(manager, wait_seconds=2)
        else:
            print(f"\n[ERROR] Snapshot restore failed: {res.get('details')}")
    else:
        print(f"\n[ERROR] Unrecognized backup file format: {path.name}")


def list_backups_ui(manager: ExamplesManager):
    """Display formatted table of all discovered backups."""
    backups = manager.list_backups()
    print("\n" + "=" * 80)
    print("                       DISCOVERED BACKUPS")
    print("=" * 80)
    if not backups:
        print(f"No backups found in '{manager.backup_manager.backup_dir}'.")
        print("Use option 10 or 'python3 main.py --backup' to create one.")
        print("=" * 80)
        return

    sep = "-" * 98
    print(sep)
    print(f"{'#':<3} | {'Backup File':<38} | {'Type':<20} | {'Size':<10} | {'Modified (UTC)':<16}")
    print(sep)
    for idx, b in enumerate(backups, start=1):
        f_name = b['filename']
        if len(f_name) > 38:
            f_name = f_name[:35] + "..."
        mod_str = b['modified_at'][:19].replace("T", " ")
        print(f"{idx:<3} | {f_name:<38} | {b['type']:<20} | {b['size_formatted']:<10} | {mod_str:<16}")
    print(sep)
    print(f"Total: {len(backups)} backup(s) in {manager.backup_manager.backup_dir}/")
    print("=" * 80)


def run_offline_simulation():
    """Run local calculation and matrix lookup without calling the live API."""
    print("\nRunning offline local simulation preview (no API calls)...")
    sim = ApplicationRiskSimulator("YML/newDPP.yml")
    risk_names = {0: "1 - Very Low", 1: "2 - Low", 2: "3 - Medium", 3: "4 - High", 4: "5 - Very High"}
    priority_names = {1: "1 (Urgent)", 2: "2 (High)", 3: "3 (Medium)", 4: "4 (Low)"}

    for app in EXAMPLE_APPLICATIONS:
        csv_path = app["csv_path"]
        if not Path(csv_path).exists():
            continue
        print("=" * 80)
        print(f" APPLICATION: {app['label']}")
        print(f" Profile:     {app['description']}")
        print("=" * 80)

        results = sim.evaluate_application(csv_path)
        print(f"Data Classification Impact: Level {results['impact_level']} / 4")
        print("\nRequirement Compliance Scores:")
        for req, score in sorted(results["requirement_scores"].items()):
            if not req.startswith("urn:"):
                print(f"  - {req:<30}: {score:>3}%")

        print("\nRisk Scenarios:")
        print(f"{'Scenario Name':<42} | {'LH':<3} | {'Imp':<3} | {'Matrix Risk':<15} | {'Priority':<8}")
        print("-" * 80)
        for sc_name, sc_data in results["scenarios"].items():
            short_name = sc_name[:40] + ".." if len(sc_name) > 42 else sc_name
            r_str = risk_names.get(sc_data["matrix_risk_id"], str(sc_data["matrix_risk_id"]))
            p_str = priority_names.get(sc_data["control_priority"], str(sc_data["control_priority"]))
            print(f"{short_name:<42} | {sc_data['scaled_likelihood']:<3} | {sc_data['scaled_impact']:<3} | {r_str:<15} | {p_str:<8}")
        print("\n")


def run_pipeline():
    """Run the legacy full audit, compliance, and risk orchestration pipeline."""
    print("Running full legacy CISO Assistant orchestration pipeline...")
    data = utils.initialize_data_objects()
    initial_counts = utils.capture_counts(data)

    data["asset_dict"].create_missing_assets(data["perimeter_dict"])
    data["asset_dict"].reload()

    data["compliance_assessment_dict"].create_missing_compliance_assessments(
        data["framework_dict"],
        data["perimeter_dict"],
        data["asset_dict"],
    )

    data["compliance_assessment_dict"].assign_requirements_to_perimeter_owner(
        data["perimeter_dict"],
        data["compliance_assessment_dict"],
        data["requirement_assessment_dict"],
        data["requirement_assignment_dict"],
    )

    data["entity_assessment_dict"].create_external_entity_audits(
        data["entity_dict"],
        data["framework_dict"],
    )

    data["compliance_assessment_dict"].create_risk_assessments(
        data["risk_assessment_dict"],
        data["risk_scenario_dict"],
        data["applied_control_dict"],
        data["asset_dict"],
        data["library_file"],
        data["requirement_assessment_dict"],
        data["risk_matrix_dict"],
        data["framework_dict"],
    )

    data["compliance_assessment_dict"].create_missing_applied_controls(
        data["applied_control_dict"],
        data["perimeter_dict"],
        data["reference_control_dict"],
    )

    data["compliance_assessment_dict"].update_asset_criticality(
        criticality_mapping,
        data["asset_dict"],
    )

    data["compliance_assessment_dict"].create_findings_assessments(
        data["findings_assessment_dict"],
        data["finding_dict"],
        requirement_assessment_dict=data["requirement_assessment_dict"],
        asset_dict=data["asset_dict"],
        vulnerability_dict=data.get("vulnerability_dict"),
        threat_dict=data.get("threat_dict"),
        framework_file=data.get("library_file"),
    )

    final_counts = utils.capture_counts(data)

    utils.print_run_summary(initial_counts, final_counts)


def interactive_menu(manager: ExamplesManager):
    """Run the interactive console menu for managing example applications."""
    while True:
        print_banner()
        print(" 1) List / Check Status of Examples in CISO Assistant")
        print(" 2) Create ALL Examples in CISO Assistant (Simulate Answers via API)")
        print(" 3) Create a Specific Example Application (Simulate Answers via API)")
        print(" 4) Create Application & Assign Audit to User (Interactive Demo - Unanswered)")
        print(" 5) Generate Controls & Risk Scenarios for an Application")
        print(" 6) Remove ALL Examples from CISO Assistant")
        print(" 7) Remove a Specific Application")
        print(" 8) Run Offline Simulation (Local Preview without API)")
        print(" 9) Backup & Restore Management (Dumps, Snapshots, Restores, Listing)")
        print(" 0) Exit")
        print("=" * 80)

        choice = input("Enter your choice [0-9]: ").strip()

        if choice == "1":
            show_status(manager, wait_seconds=2.0)
        elif choice == "2":
            create_examples_ui(manager, target="all")
        elif choice == "3":
            print("\nSelect application to create:")
            for idx, app in enumerate(EXAMPLE_APPLICATIONS, start=1):
                print(f" {idx}) {app['label']}")
            sub_choice = input(f"Enter choice [1-{len(EXAMPLE_APPLICATIONS)}] (or 'c' to cancel): ").strip()
            if sub_choice.isdigit() and 1 <= int(sub_choice) <= len(EXAMPLE_APPLICATIONS):
                selected = EXAMPLE_APPLICATIONS[int(sub_choice) - 1]
                create_examples_ui(manager, target=selected["id"])
        elif choice == "4":
            create_audit_demo_ui(manager)
        elif choice == "5":
            generate_controls_and_risks_ui(manager)
        elif choice == "6":
            remove_examples_ui(manager, target="all")
        elif choice == "7":
            print("\nSelect application to remove:")
            status_list = manager.get_status()
            deployed_apps = [s for s in status_list if s["exists"]]
            if not deployed_apps:
                print("No deployed applications found.")
            else:
                for idx, app in enumerate(deployed_apps, start=1):
                    print(f" {idx}) {app['name']}")
                print(f" {len(deployed_apps) + 1}) Enter custom application name manually")
                sub_choice = input(f"Enter choice [1-{len(deployed_apps) + 1}] (or 'c' to cancel): ").strip()
                if sub_choice.isdigit() and 1 <= int(sub_choice) <= len(deployed_apps):
                    selected = deployed_apps[int(sub_choice) - 1]
                    remove_examples_ui(manager, target=selected["name"])
                elif sub_choice == str(len(deployed_apps) + 1):
                    custom_target = input("Enter application name to remove: ").strip()
                    if custom_target:
                        remove_examples_ui(manager, target=custom_target)
        elif choice == "8":
            run_offline_simulation()
        elif choice == "9":
            print("\nSelect Backup & Restore action:")
            print(" 1) Create Workspace Snapshot Backup (Portable JSON export)")
            print(" 2) Create Full Database Dump (Server-side /api/serdes/dump-db/)")
            print(" 3) Restore from Backup File (Dump or Snapshot)")
            print(" 4) List Discovered Backups")
            b_choice = input("Enter choice [1-4, default: 1] (or 'c' to cancel): ").strip()
            if b_choice.lower() in ("c", "cancel"):
                pass
            elif b_choice == "2":
                backup_ui(manager, backup_type="dump")
            elif b_choice == "3":
                backups = manager.list_backups()
                if not backups:
                    print("No backups found in default directory.")
                    file_input = input("Enter backup file path (or 'c' to cancel): ").strip()
                    if file_input and file_input.lower() not in ("c", "cancel"):
                        restore_ui(manager, file_input)
                else:
                    print("\nSelect backup to restore:")
                    for idx, b in enumerate(backups, start=1):
                        print(f" {idx}) {b['filename']} ({b['type']}, {b['size_formatted']})")
                    print(f" {len(backups) + 1}) Enter custom path manually")
                    r_sub = input(f"Enter choice [1-{len(backups) + 1}] (or 'c' to cancel): ").strip()
                    if r_sub.isdigit() and 1 <= int(r_sub) <= len(backups):
                        restore_ui(manager, backups[int(r_sub) - 1]["path"])
                    elif r_sub == str(len(backups) + 1):
                        file_input = input("Enter custom backup file path: ").strip()
                        if file_input:
                            restore_ui(manager, file_input)
            elif b_choice == "4":
                list_backups_ui(manager)
            else:
                backup_ui(manager, backup_type="snapshot")
        elif choice in ("0", "q", "exit"):
            print("\nGoodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please select an option from 0 to 10.")

        input("\nPress [Enter] to return to the menu...")


def main():
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Manage CISO Assistant example applications and simulate answers in the UI via API."
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check deployment status of example applications in CISO Assistant.",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=2.0,
        help="Seconds to wait for CISO Assistant updates before checking status (default: 2.0s).",
    )
    parser.add_argument(
        "--create",
        metavar="APP_NAME",
        help="Create example application in CISO Assistant ('all' or specific name/id like 'app_secure_core').",
    )
    parser.add_argument(
        "--create-audit",
        nargs="?",
        const="App-Audit-Demo",
        metavar="APP_NAME",
        help="Create application and assign compliance assessment to user without answers ('App-Audit-Demo' or custom name).",
    )
    parser.add_argument(
        "--user",
        metavar="EMAIL",
        help="User email to assign the compliance assessment to (used with --create-audit).",
    )
    parser.add_argument(
        "--generate-risks",
        nargs="?",
        const="App-Audit-Demo",
        metavar="APP_NAME",
        help="Generate applied controls and risk scenarios for an application ('App-Audit-Demo' or custom name).",
    )
    parser.add_argument(
        "--answers",
        metavar="FILE_OR_PROFILE",
        help="Optional CSV/YAML file or example profile name/id to load answers from when generating risks.",
    )
    parser.add_argument(
        "--link-controls",
        nargs="?",
        const="all",
        metavar="APP_NAME",
        help="Link existing and planned controls to risk scenarios ('all' or specific name/id).",
    )
    parser.add_argument(
        "--remove",
        metavar="APP_NAME",
        help="Remove example application from CISO Assistant ('all' or specific name/id).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run offline local calculation without connecting to the API.",
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Run the full legacy orchestration pipeline.",
    )
    parser.add_argument(
        "--backup",
        nargs="?",
        const="snapshot",
        choices=["snapshot", "dump"],
        metavar="TYPE",
        help="Create a backup ('snapshot' for JSON export or 'dump' for database dump).",
    )
    parser.add_argument(
        "--restore",
        metavar="BACKUP_PATH",
        help="Restore CISO Assistant state from a backup file (dump or snapshot).",
    )
    parser.add_argument(
        "--list-backups",
        action="store_true",
        help="List all discovered backup files and snapshots.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging output verbosity level (default: WARNING, or LOG_LEVEL env var).",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Auto-confirm removal prompts.",
    )
    args = parser.parse_args()

    if args.log_level:
        utils.set_log_level(args.log_level)

    if args.pipeline:
        run_pipeline()
        return

    manager = ExamplesManager()

    # CLI mode
    if args.offline:
        run_offline_simulation()
        return

    if args.status:
        show_status(manager, wait_seconds=args.wait)
        return

    if args.list_backups:
        list_backups_ui(manager)
        return

    if args.backup:
        backup_ui(manager, backup_type=args.backup)
        return

    if args.restore:
        restore_ui(manager, file_path=args.restore)
        return

    if args.create_audit:
        create_audit_demo_ui(manager, app_name=args.create_audit, user_email=args.user)
        return

    if args.generate_risks:
        generate_controls_and_risks_ui(manager, app_name=args.generate_risks, answers_source=args.answers, interactive=False)
        return

    if args.create:
        create_examples_ui(manager, target=args.create)
        return

    if args.link_controls:
        link_controls_ui(manager, target=args.link_controls)
        return

    if args.remove:
        remove_examples_ui(manager, target=args.remove, auto_confirm=args.yes)
        return

    # No CLI args provided -> launch interactive menu
    interactive_menu(manager)


if __name__ == "__main__":
    main()
