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
    print("\n" + "-" * 115)
    print(f"{'#':<3} | {'Application Name':<26} | {'Status':<11} | {'TPRM Entity':<12} | {'User':<20} | {'Scenarios':<9} | {'Controls':<8} | {'Linked':<10}")
    print("-" * 115)
    for idx, item in enumerate(status_list, start=1):
        state_str = "DEPLOYED" if item["exists"] else "NOT CREATED"
        entity_str = "YES" if item.get("entity_id") else "NO"
        user_str = item.get("user_email") or "-"
        if len(user_str) > 20:
            user_str = user_str[:17] + "..."
        sc_count = str(item["risk_scenarios_count"]) if item["exists"] else "-"
        ctrl_count = str(item["applied_controls_count"]) if item["exists"] else "-"
        linked_str = f"{item.get('existing_controls_linked', 0)}/{item.get('planned_controls_linked', 0)}" if item["exists"] else "-"
        print(f"{idx:<3} | {item['name']:<26} | {state_str:<11} | {entity_str:<12} | {user_str:<20} | {sc_count:<9} | {ctrl_count:<8} | {linked_str:<10}")
    print("-" * 115)

    # Detailed view
    deployed = [s for s in status_list if s["exists"]]
    if deployed:
        print("\nDeployed Resources Breakdown:")
        for s in deployed:
            print(f"\n  * {s['name']}:")
            print(f"    - TPRM External Entity ID:  {s.get('entity_id') or 'None'}")
            print(f"    - TPRM Assessment ID:       {s.get('entity_assessment_id') or 'None'}")
            print(f"    - TPRM Conclusion:          {s.get('tprm_conclusion') or 'None'}")
            print(f"    - Representative User:      {s.get('user_email') or 'None'} (User ID: {s.get('user_id') or 'None'})")
            print(f"    - Perimeter ID:             {s['perimeter_id'] or 'None'}")
            print(f"    - Asset ID:                 {s['asset_id'] or 'None'}")
            print(f"    - Compliance Assessment:    {s['compliance_assessment_name'] or 'None'}")
            print(f"    - Risk Assessment ID:       {s['risk_assessment_id'] or 'None'}")
            print(f"    - Risk Scenarios Created:   {s['risk_scenarios_count']}")
            print(f"    - Applied Controls Created: {s['applied_controls_count']}")
            print(f"    - Controls Linked to Risks: {s.get('existing_controls_linked', 0)} Active (Existing), {s.get('planned_controls_linked', 0)} To Do (Planned)")
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
                      f"{r['planned_controls']} planned controls linked")
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
                ans_str = "Unanswered" if app.get("compliance_status") == "in_progress" and not app.get("applied_controls_count") else "Configured"
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
                  f"{del_res['risk_assessments_deleted']} risk assessment(s), "
                  f"{del_res['scenarios_deleted']} scenario(s), "
                  f"{del_res['compliance_assessments_deleted']} compliance assessment(s), "
                  f"{del_res['applied_controls_deleted']} control(s), "
                  f"{del_res['assets_deleted']} asset(s), "
                  f"{del_res['perimeters_deleted']} perimeter(s).")
            print(f"\n[SUCCESS] Successfully removed {target_name} from CISO Assistant!")
        except Exception as e:
            print(f"[ERROR] Failed to remove {target_name}: {e}")


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
        print(" 0) Exit")
        print("=" * 80)

        choice = input("Enter your choice [0-8]: ").strip()

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
        elif choice in ("0", "q", "exit"):
            print("\nGoodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please select an option from 0 to 8.")

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
        "-y", "--yes",
        action="store_true",
        help="Auto-confirm removal prompts.",
    )
    args = parser.parse_args()

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
