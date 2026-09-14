#!/usr/bin/env python3
"""Interactive menu and CLI tool to manage CISO Assistant example applications.

Allows users to simulate answers for example application profiles in the CISO Assistant UI
via the API, visualize compliance assessments and risk calculations, or clean them up.

Usage:
    Interactive menu:
        python3 manage_examples.py

    CLI commands:
        python3 manage_examples.py --status
        python3 manage_examples.py --create all
        python3 manage_examples.py --create app_secure_core
        python3 manage_examples.py --link-controls all
        python3 manage_examples.py --link-controls app_secure_core
        python3 manage_examples.py --remove all --yes
        python3 manage_examples.py --remove app_vulnerable_portal
        python3 manage_examples.py --offline
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
from tests.test_application_scenarios import ApplicationRiskSimulator


def print_banner():
    print("=" * 80)
    print("           CISO ASSISTANT - EXAMPLE APPLICATIONS MANAGER")
    print(f" Target Instance: {utils.BASE_URL}")
    print(f" Target Folder:   {EXAMPLE_FOLDER_NAME}")
    print("=" * 80)


def print_status_table(status_list):
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


def remove_examples_ui(manager: ExamplesManager, target="all", auto_confirm=False):
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    if not auto_confirm:
        target_desc = "ALL example applications" if target == "all" else f"example application '{target}'"
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
        if not app:
            print(f"[ERROR] Unknown application: {target}")
            return
        print(f"\n---> Removing {app['name']} from CISO Assistant...")
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
            print(f"\n[SUCCESS] Successfully removed {app['name']} from CISO Assistant!")
        except Exception as e:
            print(f"[ERROR] Failed to remove {app['name']}: {e}")


def run_offline_simulation():
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


def interactive_menu(manager: ExamplesManager):
    while True:
        print_banner()
        print(" 1) List / Check Status of Examples in CISO Assistant")
        print(" 2) Create ALL Examples in CISO Assistant (Simulate Answers via API)")
        print(" 3) Create a Specific Example Application")
        print(" 4) Remove ALL Examples from CISO Assistant")
        print(" 5) Remove a Specific Example Application")
        print(" 6) Run Offline Simulation (Local Preview without API)")
        print(" 0) Exit")
        print("=" * 80)

        choice = input("Enter your choice [0-6]: ").strip()

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
            remove_examples_ui(manager, target="all")
        elif choice == "5":
            print("\nSelect application to remove:")
            for idx, app in enumerate(EXAMPLE_APPLICATIONS, start=1):
                print(f" {idx}) {app['name']}")
            sub_choice = input(f"Enter choice [1-{len(EXAMPLE_APPLICATIONS)}] (or 'c' to cancel): ").strip()
            if sub_choice.isdigit() and 1 <= int(sub_choice) <= len(EXAMPLE_APPLICATIONS):
                selected = EXAMPLE_APPLICATIONS[int(sub_choice) - 1]
                remove_examples_ui(manager, target=selected["id"])
        elif choice == "6":
            run_offline_simulation()
        elif choice in ("0", "q", "exit"):
            print("\nGoodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please select an option from 0 to 6.")

        input("\nPress [Enter] to return to the menu...")


def main():
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
        "-y", "--yes",
        action="store_true",
        help="Auto-confirm removal prompts.",
    )
    args = parser.parse_args()

    manager = ExamplesManager()

    # CLI mode
    if args.offline:
        run_offline_simulation()
        return

    if args.status:
        show_status(manager, wait_seconds=args.wait)
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

