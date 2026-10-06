#!/usr/bin/env python3
"""Main entrypoint for CISO Assistant orchestration and example applications manager.

Provides an interactive menu and CLI tool to manage CISO Assistant example applications,
simulate questionnaire responses, evaluate dynamic risk scenarios, synchronize controls,
and inspect deployment status across the live instance.

Usage:
    Web UI:
        python3 main.py --web
        python3 main.py --web --web-port 8080 --web-open
        python3 web_app.py

    Interactive menu:
        python3 main.py

    CLI commands:
        python3 main.py --status
        python3 main.py --create-domain "Finance Operations"
        python3 main.py --create-domain "Core Banking" --description "Core banking systems" --parent-domain "Finance Operations"
        python3 main.py --list-domains
        python3 main.py --create all
        python3 main.py --create app_secure_core
        python3 main.py --create app_secure_core --domain "Finance Operations"
        python3 main.py --create-audit "App-Audit-Demo" --domain "Finance Operations"
        python3 main.py --link-controls all
        python3 main.py --link-controls app_secure_core
        python3 main.py --remove all --yes
        python3 main.py --provision-nis2
        python3 main.py --status-nis2
        python3 main.py --offline
        python3 main.py --pipeline
"""

import argparse
import sys
import time
from pathlib import Path

from classes import utils
from classes.examples_manager import (
    EXAMPLE_FOLDER_NAME,
    FRAMEWORK_CATALOG,
    ExamplesManager,
)
from classes.organization.domain import Domain, DomainDict, criticality_mapping
from tests.test_application_scenarios import ApplicationRiskSimulator


def print_banner(target_folder: str = EXAMPLE_FOLDER_NAME):
    """Display header banner."""
    print("=" * 80)
    print("           CISO ASSISTANT - EXAMPLE APPLICATIONS MANAGER")
    print(f" Target Instance: {utils.BASE_URL}")
    print(f" Target Folder:   {target_folder}")
    print("=" * 80)


def print_status_table(status_list):
    """Print formatted deployment summary table and resource breakdown."""
    sep = "-" * 187
    print("\n" + sep)
    print(f"{'#':<3} | {'Application Name':<25} | {'Domain':<16} | {'Status':<24} | {'App Created':<11} | {'Audit Answered':<15} | {'Risks Created':<13} | {'Controls':<8} | {'Linked':<8} | {'TPRM':<5} | {'User':<18} | {'Findings':<8}")
    print(sep)
    for idx, item in enumerate(status_list, start=1):
        name_str = item["name"]
        if len(name_str) > 25:
            name_str = name_str[:22] + "..."

        domain_str = item.get("domain_name") or item.get("domain") or item.get("folder_name") or ("Examples" if item.get("exists") else "-")
        if not item.get("exists") and not item.get("domain_name") and not item.get("domain"):
            domain_str = "-"
        if len(domain_str) > 16:
            domain_str = domain_str[:13] + "..."

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

        print(f"{idx:<3} | {name_str:<25} | {domain_str:<16} | {status_str:<24} | {app_str:<11} | {audit_str:<15} | {risks_str:<13} | {ctrl_count:<8} | {linked_str:<8} | {tprm_str:<5} | {user_str:<18} | {findings_str:<8}")
    print(sep)

    # Detailed view
    deployed = [s for s in status_list if s.get("exists")]
    if deployed:
        print("\nDeployed Resources Breakdown:")
        for s in deployed:
            print(f"\n  * {s['name']}:")
            dom_disp = s.get('domain_name') or s.get('domain') or s.get('folder_name') or 'Examples'
            dom_id_disp = f" (ID: {s['domain_id']})" if s.get('domain_id') else ""
            print(f"    - Domain:                   {dom_disp}{dom_id_disp}")
            fw_disp = s.get('framework_name') or 'Multi-level DPP'
            fw_ref_disp = f" ({s['framework_ref']})" if s.get('framework_ref') else ""
            print(f"    - Framework:                {fw_disp}{fw_ref_disp}")
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
        example_apps = manager.get_example_applications()
        print(f"\nLinking existing and planned controls across all {len(example_apps)} example applications...")
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
        app = manager.find_example_application(target)
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


def create_examples_ui(
    manager: ExamplesManager,
    target="all",
    framework_ref_or_name: str | None = None,
    domain_name: str | None = None,
):
    """Provision example applications in CISO Assistant with answers and risk scenarios."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
    if framework_ref_or_name:
        matching_fw = manager.find_target_framework(framework_ref_or_name)
        if not matching_fw:
            print(f"\n[ERROR] Framework '{framework_ref_or_name}' is not installed in CISO Assistant.")
            installed_fws = manager.get_installed_frameworks()
            if installed_fws:
                print("Available installed frameworks in CISO Assistant:")
                for idx, fw in enumerate(installed_fws, start=1):
                    ref_str = f" ({fw['ref_id']})" if fw.get("ref_id") else ""
                    print(f"  {idx}) {fw['name']}{ref_str}")
            print("\nPlease ensure the framework is imported into CISO Assistant before creating applications.")
            return

    target_domain_disp = domain_name or manager.folder_name
    if target == "all":
        example_apps = manager.get_example_applications()
        print(f"\nCreating all {len(example_apps)} example applications in CISO Assistant (Domain: {target_domain_disp})...")
        for app in example_apps:
            app_fw_ref = app.get("framework_ref")
            app_fw_name = app.get("framework_name")
            matching_fw = manager.find_target_framework(app_fw_ref or app_fw_name)
            if not matching_fw:
                print(f"\n---> [SKIPPED] {app['label']}: Associated framework '{app_fw_name}' ({app_fw_ref}) is not installed in CISO Assistant.")
                continue
            print(f"\n---> Provisioning {app['label']} in domain '{target_domain_disp}' (Framework: {matching_fw.get_name()})...")
            try:
                call_kwargs = {"framework_ref_or_name": app_fw_ref}
                if domain_name is not None:
                    call_kwargs["domain_name"] = domain_name
                res = manager.create_example_application(app["id"], **call_kwargs)
                print(f"     [OK] Domain: {res.get('domain_name')} (ID: {res.get('domain_id')})")
                print(f"     [OK] Representative User: {res.get('user_email')} (ID: {res.get('user_id')})")
                print(f"     [OK] TPRM External Entity: {res.get('entity_id')}")
                print(f"     [OK] TPRM Entity Assessment: {res.get('entity_assessment_name')}")
                print(f"     [OK] Perimeter: {res['perimeter_id']}")
                print(f"     [OK] Compliance Assessment: {res['compliance_assessment_name']}")
                print(f"     [OK] Answers Imported: {res['answers_updated']} from {app.get('yaml_path')}")
                print(f"     [OK] Risk Scenarios Evaluated: {res['scenarios_created']}")
                print(f"     [OK] Controls Linked: {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
                print(f"     [OK] Vulnerabilities Linked: {res.get('vulnerabilities_linked', 0)}")
                print(f"     [OK] Threats Linked: {res.get('threats_linked', 0)}")
                print(f"     [OK] Audit Findings Generated: {res.get('findings_count', 0)}")
            except Exception as e:
                print(f"     [FAILED] Error creating {app['name']}: {e}")
        print("\n[SUCCESS] Completed provisioning of example applications.")
        print("Waiting 2s for CISO Assistant to finalize updates before checking status...")
        time.sleep(2)
        show_status(manager, wait_seconds=0)
        print(f"You can now log in to the CISO Assistant UI at {utils.BASE_URL} to visualize the results!")
    else:
        app = manager.find_example_application(target)
        if not app:
            print(f"[ERROR] Unknown application: {target}")
            return
        app_fw_ref = app.get("framework_ref")
        app_fw_name = app.get("framework_name")
        target_fw = framework_ref_or_name or app_fw_ref
        matching_fw = manager.find_target_framework(target_fw)
        if not matching_fw:
            print(f"\n[ERROR] Cannot create {app['name']}: Associated framework '{app_fw_name}' ({app_fw_ref}) is not installed in CISO Assistant.")
            print("Please ensure the framework is installed in CISO Assistant before creating applications.")
            return
        print(f"\n---> Provisioning {app['label']} in domain '{target_domain_disp}' (Framework: {matching_fw.get_name()})...")
        try:
            call_kwargs = {"framework_ref_or_name": target_fw}
            if domain_name is not None:
                call_kwargs["domain_name"] = domain_name
            res = manager.create_example_application(app["id"], **call_kwargs)
            print(f"     [OK] Domain: {res.get('domain_name')} (ID: {res.get('domain_id')})")
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


def create_audit_demo_ui(
    manager: ExamplesManager,
    app_name: str | None = None,
    user_email: str | None = None,
    framework_ref_or_name: str | None = None,
    domain_name: str | None = None,
):
    """Create an application and assign its compliance assessment to a user (interactive audit demo)."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    # Check frameworks in CISO Assistant before offering audit creation
    installed_fws = manager.get_installed_frameworks()
    if not installed_fws:
        print("\n[ERROR] No frameworks found in CISO Assistant.")
        print("Cannot create an audit because CISO Assistant does not have any compliance frameworks installed.")
        print("Please import or load a framework into CISO Assistant first.")
        return

    # If framework explicitly provided, check if it actually exists in CISO Assistant
    if framework_ref_or_name:
        matching_fw = manager.find_target_framework(framework_ref_or_name)
        if not matching_fw:
            print(f"\n[ERROR] Framework '{framework_ref_or_name}' is not installed in CISO Assistant.")
            print("Available installed frameworks in CISO Assistant:")
            for idx, fw in enumerate(installed_fws, start=1):
                ref_str = f" ({fw['ref_id']})" if fw.get("ref_id") else ""
                print(f"  {idx}) {fw['name']}{ref_str}")
            print("\nPlease ensure the framework is imported into CISO Assistant before creating an audit with it.")
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

    # 1. Prompt for Application Name (and Domain if in interactive demo)
    is_interactive_demo = (app_name is None)
    if is_interactive_demo:
        default_app_name = "App-Audit-Demo"
        prompt_str = f"Enter application name [default: {default_app_name}] (or 'c' to cancel): "
        entered = input(prompt_str).strip()
        if entered.lower() in ("c", "cancel"):
            print("Operation canceled.")
            return
        app_name = entered or default_app_name

        if not domain_name:
            default_domain = manager.folder_name or EXAMPLE_FOLDER_NAME
            dom_prompt = f"Enter target domain [default: {default_domain}] (or 'c' to cancel): "
            dom_input = input(dom_prompt).strip()
            if dom_input.lower() in ("c", "cancel"):
                print("Operation canceled.")
                return
            domain_name = dom_input or default_domain

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

    # 4. Prompt for Framework Selection if not provided
    if not framework_ref_or_name:
        ex_spec = manager.find_example_application(app_name) if hasattr(manager, "find_example_application") else None
        if isinstance(ex_spec, dict) and (ex_spec.get("framework_ref") or ex_spec.get("framework_name")):
            assoc_fw_ref = ex_spec.get("framework_ref")
            assoc_fw_name = ex_spec.get("framework_name")
            print(f"\n[INFO] '{app_name}' is an example application associated with framework '{assoc_fw_name}' ({assoc_fw_ref}).")
            framework_ref_or_name = assoc_fw_ref
        else:
            print("\nSelect Framework for Assessment (verified in CISO Assistant):")
            for idx, fw in enumerate(installed_fws, start=1):
                ref_str = f" ({fw['ref_id']})" if fw.get("ref_id") else ""
                print(f" {idx}) {fw['name']}{ref_str}")

            # Show note about catalog frameworks that are not installed in CISO Assistant
            uninstalled_fws = [
                cat for cat in FRAMEWORK_CATALOG
                if not any(
                    f.get("ref_id", "").lower() == cat["ref_id"].lower()
                    or f.get("name", "").lower() == cat["name"].lower()
                    for f in installed_fws
                )
            ]
            if uninstalled_fws:
                uninstalled_str = ", ".join(f"{cat['name']} ({cat['ref_id']})" for cat in uninstalled_fws)
                print(f" [Note: Not installed in CISO Assistant, unavailable for audits: {uninstalled_str}]")

            fw_input = input(f"Enter choice [1-{len(installed_fws)}, default: 1] (or 'c' to cancel): ").strip()
            if fw_input.lower() in ("c", "cancel"):
                print("Operation canceled.")
                return
            if fw_input.isdigit() and 1 <= int(fw_input) <= len(installed_fws):
                selected_fw = installed_fws[int(fw_input) - 1]
                framework_ref_or_name = selected_fw.get("ref_id") or selected_fw.get("name")
            else:
                selected_fw = installed_fws[0]
                framework_ref_or_name = selected_fw.get("ref_id") or selected_fw.get("name")

    target_domain_disp = domain_name or manager.folder_name
    print(f"\n---> Provisioning application '{app_name}' in domain '{target_domain_disp}' and assigning audit to '{user_email}'...")
    try:
        audit_call_kwargs = {
            "app_name": app_name,
            "user_email": user_email,
            "first_name": first_name,
            "last_name": last_name,
            "is_third_party": is_third_party,
            "framework_ref_or_name": framework_ref_or_name,
        }
        if domain_name is not None:
            audit_call_kwargs["domain_name"] = domain_name
        res = manager.create_application_for_audit(**audit_call_kwargs)
        print("\n" + "=" * 80)
        print("          AUDIT DEMONSTRATION APPLICATION READY")
        print("=" * 80)
        print(f" Application Name:         {res['app_name']}")
        print(f" Target Domain:            {res.get('domain_name', 'Examples')} (ID: {res.get('domain_id')})")
        fw_display = res.get("framework_name", "Multi-level DPP")
        fw_ref_disp = f" ({res['framework_ref']})" if res.get("framework_ref") else ""
        print(f" Target Framework:         {fw_display}{fw_ref_disp}")
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
    answers_to_use = None
    if answers_source:
        answers_to_use = answers_source
    elif interactive:
        # Prompt user whether to use live UI answers or an answers file
        print(f"\nSelect answers source for '{app_name}':")
        print(" 1) Evaluate live answers already submitted in CISO Assistant UI (Default)")
        print(" 2) Load answers from an Example Profile (e.g. App-Secure-Core, App-Vulnerable-Portal)")
        print(" 3) Specify path to custom YAML answers file")
        src_choice = input("Enter choice [1-3, default: 1] (or 'c' to cancel): ").strip()

        if src_choice.lower() in ("c", "cancel"):
            print("Operation canceled.")
            return

        if src_choice == "2":
            example_apps = manager.get_example_applications()
            print("\nSelect example profile to load answers from:")
            for idx, ex_app in enumerate(example_apps, start=1):
                print(f" {idx}) {ex_app['label']}")
            p_choice = input(f"Enter choice [1-{len(example_apps)}]: ").strip()
            if p_choice.isdigit() and 1 <= int(p_choice) <= len(example_apps):
                answers_to_use = example_apps[int(p_choice) - 1].get("yaml_path")
            else:
                print("Invalid choice. Falling back to live UI answers.")
        elif src_choice == "3":
            custom_path = input("Enter path to answers file (YAML): ").strip()
            if not custom_path or not Path(custom_path).exists():
                print(f"[ERROR] File '{custom_path}' does not exist. Falling back to live UI answers.")
            else:
                answers_to_use = custom_path
        else:
            answers_to_use = None
    else:
        answers_to_use = None

    print(f"\n---> Generating controls & risk scenarios for '{app_name}'...")
    if answers_to_use:
        print(f"     Source Answers: {answers_to_use}")
    else:
        print("     Source Answers: Live answers from CISO Assistant UI")

    try:
        res = manager.generate_controls_and_risks_for_application(app_name, yaml_path=answers_to_use)
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

    status_list = manager.get_status()
    created_examples = [s for s in status_list if s.get("exists")]

    if target == "all":
        if not created_examples:
            print("\nNo example applications currently exist in CISO Assistant. Nothing to remove.")
            return

        print(f"\nFound {len(created_examples)} example application(s) currently created in CISO Assistant:")
        for s in created_examples:
            status_desc = s.get("status") or s.get("lifecycle_status") or "CREATED"
            print(f"  - {s['name']} ({status_desc})")

        if not auto_confirm:
            confirm = input(
                f"\nAre you sure you want to remove these {len(created_examples)} example application(s) from CISO Assistant? [y/N]: "
            ).strip().lower()
            if confirm not in ("y", "yes"):
                print("Operation canceled.")
                return

        print(f"\nRemoving {len(created_examples)} example application(s) from CISO Assistant...")
        for s in created_examples:
            app_id = s["id"]
            app_name = s["name"]
            print(f"---> Deleting {app_name}...")
            try:
                del_res = manager.remove_example_application(app_id)
                print(f"     Deleted: {del_res.get('entity_assessments_deleted', 0)} entity assessment(s), "
                      f"{del_res.get('entities_deleted', 0)} entity(ies), "
                      f"{del_res.get('users_deleted', 0)} user(s), "
                      f"{del_res.get('findings_deleted', 0)} finding(s), "
                      f"{del_res.get('findings_assessments_deleted', 0)} findings assessment(s), "
                      f"{del_res.get('risk_assessments_deleted', 0)} risk assessment(s), "
                      f"{del_res.get('scenarios_deleted', 0)} scenario(s), "
                      f"{del_res.get('compliance_assessments_deleted', 0)} compliance assessment(s), "
                      f"{del_res.get('applied_controls_deleted', 0)} control(s), "
                      f"{del_res.get('assets_deleted', 0)} asset(s), "
                      f"{del_res.get('perimeters_deleted', 0)} perimeter(s).")
            except Exception as e:
                print(f"     [ERROR] Failed to delete {app_name}: {e}")
        print("\n[SUCCESS] Completed removal of example applications.")
    else:
        target_norm = target.strip().lower()
        matching = next(
            (s for s in status_list if s["id"].lower() == target_norm or s["name"].lower() == target_norm),
            None,
        )
        target_name = matching["name"] if matching else target

        app_exists = matching.get("exists") if matching else False
        if not matching:
            data = manager.data or manager._init_data()
            perm_dict = data.get("perimeter_dict")
            ent_dict = data.get("entity_dict")
            asset_dict = data.get("asset_dict")
            p_id = perm_dict.get_id_from_name(target_name) if perm_dict else None
            e_id = ent_dict.get_id_from_name(target_name) if ent_dict else None
            a_id = asset_dict.get_asset_id_from_perimeter_name(target_name) if asset_dict else None
            app_exists = bool(p_id or e_id or a_id)

        if not app_exists:
            print(f"\n[INFO] Application '{target_name}' is not currently created in CISO Assistant. Nothing to remove.")
            return

        if not auto_confirm:
            confirm = input(f"\nAre you sure you want to remove application '{target_name}' from CISO Assistant? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Operation canceled.")
                return

        print(f"\n---> Removing {target_name} from CISO Assistant...")
        try:
            del_res = manager.remove_example_application(target)
            print(f"     Deleted: {del_res.get('entity_assessments_deleted', 0)} entity assessment(s), "
                  f"{del_res.get('entities_deleted', 0)} entity(ies), "
                  f"{del_res.get('users_deleted', 0)} user(s), "
                  f"{del_res.get('findings_deleted', 0)} finding(s), "
                  f"{del_res.get('findings_assessments_deleted', 0)} findings assessment(s), "
                  f"{del_res.get('risk_assessments_deleted', 0)} risk assessment(s), "
                  f"{del_res.get('scenarios_deleted', 0)} scenario(s), "
                  f"{del_res.get('compliance_assessments_deleted', 0)} compliance assessment(s), "
                  f"{del_res.get('applied_controls_deleted', 0)} control(s), "
                  f"{del_res.get('assets_deleted', 0)} asset(s), "
                  f"{del_res.get('perimeters_deleted', 0)} perimeter(s).")
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


def create_domain_ui(
    manager: ExamplesManager,
    name: str | None = None,
    description: str | None = None,
    parent_domain: str | None = None,
    interactive: bool = True,
):
    """Create an organizational domain/folder in CISO Assistant."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return None

    print("\n" + "=" * 80)
    print("                    CREATE A NEW DOMAIN / FOLDER")
    print("=" * 80)
    print("Domains (folders in CISO Assistant) organize perimeters, assessments, and")
    print("assets into hierarchical business units or organizational perimeters.")
    print("-" * 80)

    domains = manager.get_domains()

    # 1. Prompt for Domain Name if not provided
    if not name:
        while True:
            entered = input("Enter domain name (or 'c' to cancel): ").strip()
            if entered.lower() in ("c", "cancel"):
                print("Operation canceled.")
                return None
            if entered:
                name = entered
                break
            print("[!] Domain name cannot be empty.")
    else:
        name = name.strip()
        if not name:
            print("\n[ERROR] Domain name cannot be empty.")
            return None

    # Check if domain already exists
    existing = next((d for d in domains if d.get_name().lower() == name.lower()), None)
    if existing:
        print(f"\n[WARNING] Domain '{name}' already exists in CISO Assistant (ID: {existing.get_id()}).")
        if interactive:
            confirm = input("Do you want to re-use or view this domain? [Y/n] (or 'c' to cancel): ").strip().lower()
            if confirm in ("c", "cancel", "n", "no"):
                print("Operation canceled.")
                return None
            print(f"\nRe-using existing domain '{existing.get_name()}' [ID: {existing.get_id()}].")
            return existing.json_object if hasattr(existing, "json_object") else {"id": existing.get_id(), "name": existing.get_name()}
        else:
            return existing.json_object if hasattr(existing, "json_object") else {"id": existing.get_id(), "name": existing.get_name()}

    # 2. Prompt for Description if not provided and in interactive mode
    if description is None and interactive:
        desc_input = input("Enter domain description [optional, press Enter to skip] (or 'c' to cancel): ").strip()
        if desc_input.lower() in ("c", "cancel"):
            print("Operation canceled.")
            return None
        description = desc_input if desc_input else None

    # 3. Prompt for Parent Domain if not provided and in interactive mode
    parent_id = None
    parent_display_name = "None (Top-level)"
    if parent_domain:
        # Resolve parent domain
        match_id = next((d for d in domains if d.get_id() == parent_domain), None)
        if match_id:
            parent_id = match_id.get_id()
            parent_display_name = f"{match_id.get_name()} ({parent_id})"
        else:
            match_name = next((d for d in domains if d.get_name().lower() == parent_domain.lower()), None)
            if match_name:
                parent_id = match_name.get_id()
                parent_display_name = f"{match_name.get_name()} ({parent_id})"
            else:
                parent_id = parent_domain
                parent_display_name = parent_domain
    elif interactive and domains:
        print("\nSelect Parent Domain (Hierarchical Organization):")
        print(" 0) None (Top-level domain)")
        for idx, d in enumerate(domains, start=1):
            print(f" {idx}) {d.get_name()}")
        p_choice = input(f"Enter choice [0-{len(domains)}, default: 0] (or 'c' to cancel): ").strip()
        if p_choice.lower() in ("c", "cancel"):
            print("Operation canceled.")
            return None
        if p_choice.isdigit() and 1 <= int(p_choice) <= len(domains):
            selected_parent = domains[int(p_choice) - 1]
            parent_id = selected_parent.get_id()
            parent_display_name = f"{selected_parent.get_name()} ({parent_id})"

    print(f"\n---> Provisioning domain '{name}' in CISO Assistant...")
    try:
        res = manager.create_domain(
            name=name,
            description=description,
            parent_folder_id=parent_id,
            create_iam_groups=True,
        )
        if res and (not isinstance(res, dict) or not res.get("error")):
            domain_id = res.get("id") if isinstance(res, dict) else (res.get_id() if hasattr(res, "get_id") else str(res))
            domain_name = res.get("name") if isinstance(res, dict) else (res.get_name() if hasattr(res, "get_name") else name)
            domain_desc = res.get("description") if isinstance(res, dict) else (res.get_description() if hasattr(res, "get_description") else description)

            print("\n" + "=" * 80)
            print("                    DOMAIN SUCCESSFULLY CREATED")
            print("=" * 80)
            print(f" Domain Name:       {domain_name}")
            print(f" Domain ID:         {domain_id}")
            if domain_desc:
                print(f" Description:       {domain_desc}")
            print(f" Parent Domain:     {parent_display_name}")
            print(f" IAM Groups:        Enabled (automatically provisioned)")
            print("-" * 80)
            print(f" View and manage this domain in the CISO Assistant UI at:")
            print(f"   {utils.BASE_URL}")
            print(" Navigate to 'Settings' -> 'Domains' to configure perimeters and roles.")
            print("=" * 80)
            return res
        else:
            err = res.get("details") or res.get("error") if isinstance(res, dict) else "Unknown error"
            print(f"\n[ERROR] Failed to create domain '{name}': {err}")
            return None
    except Exception as e:
        print(f"\n[ERROR] Exception creating domain '{name}': {e}")
        return None


def list_domains_ui(manager: ExamplesManager):
    """Query and display all organizational domains/folders in CISO Assistant."""
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] API Connection Failed: {msg}")
        return

    domains = manager.get_domains()
    print("\n" + "=" * 80)
    print("                     ORGANIZATIONAL DOMAINS")
    print("=" * 80)
    if not domains:
        print("No domains found in CISO Assistant.")
        print("=" * 80)
        return

    sep = "-" * 80
    print(sep)
    print(f"{'#':<3} | {'Domain Name':<30} | {'Domain ID':<38}")
    print(sep)
    for idx, d in enumerate(domains, start=1):
        name_str = d.get_name()
        if len(name_str) > 30:
            name_str = name_str[:27] + "..."
        print(f"{idx:<3} | {name_str:<30} | {d.get_id():<38}")
    print(sep)
    print(f"Total: {len(domains)} domain(s) in CISO Assistant.")
    print("=" * 80)


def provision_nis2_ui(domain_name: str | None = None):
    """Provision the dedicated NIS2 - ReCyF domain, perimeters, and target assets."""
    from classes.integrations.recyf_domain_manager import ReCyFDomainManager, NIS2_DOMAIN_NAME
    target_domain = domain_name or NIS2_DOMAIN_NAME
    mgr = ReCyFDomainManager(domain_name=target_domain)
    print("\n" + "=" * 80)
    print("      PROVISION DEDICATED DOMAIN & ASSETS FOR NIS 2 / ANSSI RECYF")
    print("=" * 80)
    print(f" Target Domain: {target_domain}")
    print(" This will create or verify:")
    print("  - The dedicated organizational domain for NIS 2 / ReCyF.")
    print("  - 10 dedicated perimeters covering all 20 ReCyF security objectives.")
    print("  - 10 primary & support assets mapped to the 152 assessable requirements.")
    print("-" * 80)

    try:
        res = mgr.provision_nis2_recyf_environment()
        print(f"\n[SUCCESS] Domain: {res['domain_name']} (ID: {res['domain_id']})")
        print("\nProvisioned Perimeters and Assets:")
        for a in res["assets"]:
            t_label = "Primaire" if a["type"] == "PR" else "Support"
            print(f"  * [{a['type']}|{t_label}] {a['name']}")
            print(f"    - Perimeter: {a['perimeter_name']} (ID: {a['perimeter_id']})")
            print(f"    - Asset ID:  {a['id']} ({a['req_count']} ReCyF requirements evaluated)")
        print(f"\n[SUCCESS] Successfully provisioned {len(res['assets'])} assets across {len(res['perimeters'])} perimeters in domain '{res['domain_name']}'!")
    except Exception as e:
        print(f"\n[ERROR] Failed to provision NIS2 ReCyF environment: {e}")


def status_nis2_ui(domain_name: str | None = None):
    """Display status of the dedicated NIS2 - ReCyF domain, perimeters, and assets."""
    from classes.integrations.recyf_domain_manager import ReCyFDomainManager, NIS2_DOMAIN_NAME
    target_domain = domain_name or NIS2_DOMAIN_NAME
    mgr = ReCyFDomainManager(domain_name=target_domain)
    print("\n" + "=" * 80)
    print("         NIS 2 / ANSSI RECYF DEPLOYMENT & ASSET MAPPING STATUS")
    print("=" * 80)
    print(f" Target Domain: {target_domain}")
    print("-" * 80)

    try:
        st = mgr.get_nis2_recyf_status()
        if not st.get("exists"):
            print(f"[INFO] Domain '{target_domain}' does not exist in CISO Assistant.")
            print("Run 'python3 main.py --provision-nis2' to create it.")
            print("=" * 80)
            return

        print(f" Domain: {st['domain_name']} [EXISTS] (ID: {st['domain_id']})")
        print("\n" + "-" * 105)
        print(f"{'#':<3} | {'Type':<4} | {'Asset Name':<38} | {'Reqs':<4} | {'Perimeter Status':<20} | {'Asset Status':<20}")
        print("-" * 105)
        for idx, item in enumerate(st.get("items", []), start=1):
            p_st = f"EXISTS ({item['perimeter_id'][:8]}..)" if item["perimeter_exists"] else "MISSING"
            a_st = f"EXISTS ({item['asset_id'][:8]}..)" if item["asset_exists"] else "MISSING"
            print(f"{idx:<3} | {item['type']:<4} | {item['name']:<38} | {item['req_count']:<4} | {p_st:<20} | {a_st:<20}")
        print("-" * 105)
        print(f"Total: {len(st.get('items', []))} dedicated assets mapped to 152 ReCyF requirements.")
        print("=" * 105)
    except Exception as e:
        print(f"\n[ERROR] Failed to check NIS2 ReCyF status: {e}")


def run_offline_simulation():
    """Run local calculation and matrix lookup without calling the live API."""
    print("\nRunning offline local simulation preview (no API calls)...")
    simulators = {}
    risk_names = {0: "1 - Very Low", 1: "2 - Low", 2: "3 - Medium", 3: "4 - High", 4: "5 - Very High"}
    priority_names = {1: "1 (Urgent)", 2: "2 (High)", 3: "3 (Medium)", 4: "4 (Low)"}

    for app in ExamplesManager.load_example_applications():
        answers_path = app.get("yaml_path")
        if not answers_path or not Path(answers_path).exists():
            continue
        print("=" * 80)
        print(f" APPLICATION: {app['label']}")
        print(f" Profile:     {app['description']}")
        print("=" * 80)

        fw_yaml = app.get("framework_yaml", "YML/newDPP.yml")
        if fw_yaml not in simulators:
            simulators[fw_yaml] = ApplicationRiskSimulator(fw_yaml)
        sim = simulators[fw_yaml]

        results = sim.evaluate_application(answers_path)
        conf_impact = results.get("confidentiality_impact", results.get("impact_level", 1))
        avail_impact = results.get("availability_impact", conf_impact)
        if conf_impact == avail_impact:
            print(f"Data Classification Impact: Level {conf_impact} / 4")
        else:
            print(f"Classification Impact: Confidentiality Level {conf_impact} / 4, Availability Level {avail_impact} / 4")

        print("\nRequirement Compliance Scores:")
        for req, score in sorted(results["requirement_scores"].items()):
            if req in sim.req_nodes:
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
        print_banner(manager.folder_name)
        print(" 1) List / Check Status of Examples in CISO Assistant")
        print(" 2) Create ALL Examples in CISO Assistant (Simulate Answers via API)")
        print(" 3) Create a Specific Example Application (Simulate Answers via API)")
        print(" 4) Create Application & Assign Audit to User (Interactive Demo - Unanswered)")
        print(" 5) Generate Controls & Risk Scenarios for an Application")
        print(" 6) Remove ALL Examples from CISO Assistant")
        print(" 7) Remove a Specific Application")
        print(" 8) Run Offline Simulation (Local Preview without API)")
        print(" 9) Backup & Restore Management (Dumps, Snapshots, Restores, Listing)")
        print(" 10) Create a New Domain (Organizational Folder)")
        print(" 11) Launch Web UI & REST API Dashboard (http://127.0.0.1:5000)")
        print(" 12) Provision / Check NIS2 - ReCyF Dedicated Domain & Assets")
        print(" 0) Exit")
        print("=" * 80)

        choice = input("Enter your choice [0-12]: ").strip()

        if choice == "1":
            show_status(manager, wait_seconds=2.0)
        elif choice == "2":
            create_examples_ui(manager, target="all")
        elif choice == "3":
            installed_fws = manager.get_installed_frameworks()
            if not installed_fws:
                print("\n[ERROR] No frameworks found in CISO Assistant.")
                print("Cannot create example applications because CISO Assistant does not have any compliance frameworks installed.")
                continue

            example_apps = manager.get_example_applications()
            print("\nSelect example application to create:")
            for idx, app in enumerate(example_apps, start=1):
                fw_name = app.get("framework_name", "Multi-level DPP")
                fw_ref = app.get("framework_ref", "mls")
                is_fw_installed = any(
                    f.get("ref_id", "").lower() == fw_ref.lower()
                    or f.get("name", "").lower() == fw_name.lower()
                    for f in installed_fws
                )
                fw_status = f"[{fw_name}]" if is_fw_installed else f"[{fw_name} - NOT INSTALLED]"
                print(f" {idx}) {app['label']} {fw_status}")

            sub_choice = input(f"Enter choice [1-{len(example_apps)}] (or 'c' to cancel): ").strip()
            if sub_choice.lower() in ("c", "cancel"):
                pass
            elif sub_choice.isdigit() and 1 <= int(sub_choice) <= len(example_apps):
                selected = example_apps[int(sub_choice) - 1]
                assoc_fw_name = selected.get("framework_name", "Multi-level DPP")
                assoc_fw_ref = selected.get("framework_ref", "mls")

                matching_fw = manager.find_target_framework(assoc_fw_ref) or manager.find_target_framework(assoc_fw_name)
                if not matching_fw:
                    print(f"\n[ERROR] Cannot create {selected['name']}: Associated framework '{assoc_fw_name}' ({assoc_fw_ref}) is not installed in CISO Assistant.")
                    print(f"Please install or import '{assoc_fw_name}' into CISO Assistant first.")
                    continue

                # Offer only to create with the associated framework
                print(f"\nSelected Application:  {selected['label']}")
                print(f"Associated Framework:  {assoc_fw_name} ({assoc_fw_ref}) [Installed in CISO Assistant]")
                confirm = input(f"Create '{selected['name']}' with associated framework '{assoc_fw_name}'? [Y/n] (or 'c' to cancel): ").strip().lower()
                if confirm in ("c", "cancel", "n", "no"):
                    print("Operation canceled.")
                    continue

                create_examples_ui(manager, target=selected["id"], framework_ref_or_name=assoc_fw_ref)
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
        elif choice == "10":
            create_domain_ui(manager)
        elif choice == "11":
            import importlib
            import sys
            import webbrowser
            for mod_name in list(sys.modules.keys()):
                if mod_name == "web" or mod_name.startswith("web."):
                    try:
                        importlib.reload(sys.modules[mod_name])
                    except Exception:
                        pass
            from web import create_app
            url = "http://127.0.0.1:5000"
            print(f"\nLaunching CISO Assistant Web UI at {url} ...")
            print("Press Ctrl+C in this terminal to stop the Web UI and return to the menu.\n")
            try:
                webbrowser.open(url)
            except Exception:
                pass
            try:
                w_app = create_app()
                w_app.run(host="127.0.0.1", port=5000, debug=False)
            except KeyboardInterrupt:
                print("\nWeb UI server stopped.")
        elif choice == "12":
            print("\nSelect NIS2 / ReCyF action:")
            print(" 1) View NIS2 - ReCyF Domain, Perimeters & Assets Status")
            print(" 2) Provision / Ensure NIS2 - ReCyF Domain, Perimeters & Assets")
            nis_choice = input("Enter choice [1-2, default: 1] (or 'c' to cancel): ").strip()
            if nis_choice.lower() in ("c", "cancel"):
                pass
            elif nis_choice == "2":
                provision_nis2_ui()
            else:
                status_nis2_ui()
        elif choice in ("0", "q", "exit"):
            print("\nGoodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please select an option from 0 to 12.")

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
        "--framework",
        metavar="FRAMEWORK",
        help="Framework reference ID or name to use ('mls', 'vendor-due-diligence', or custom).",
    )
    parser.add_argument(
        "--domain",
        metavar="DOMAIN",
        help="Target domain/folder name to create applications in (creates domain if missing; default: 'Examples').",
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
        help="Optional YAML file or example profile name/id to load answers from when generating risks.",
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
        "--create-domain",
        nargs="?",
        const="",
        metavar="DOMAIN_NAME",
        help="Create a new domain/folder in CISO Assistant ('--create-domain' or '--create-domain \"My Domain\"').",
    )
    parser.add_argument(
        "--description",
        metavar="TEXT",
        help="Optional description for the domain (used with --create-domain).",
    )
    parser.add_argument(
        "--parent-domain",
        metavar="PARENT",
        help="Optional parent domain name or UUID (used with --create-domain).",
    )
    parser.add_argument(
        "--list-domains",
        action="store_true",
        help="List all existing organizational domains/folders in CISO Assistant.",
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
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the modern CISO Assistant Web UI and REST API dashboard.",
    )
    parser.add_argument(
        "--web-host",
        default="127.0.0.1",
        metavar="HOST",
        help="Host interface to bind the Web UI to (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=5000,
        metavar="PORT",
        help="Port to listen on for the Web UI (default: 5000).",
    )
    parser.add_argument(
        "--web-open",
        action="store_true",
        help="Automatically open the Web UI in the default browser upon launch.",
    )
    parser.add_argument(
        "--provision-nis2",
        action="store_true",
        help="Provision dedicated domain, perimeters, and assets for NIS2 / ReCyF in CISO Assistant.",
    )
    parser.add_argument(
        "--status-nis2",
        action="store_true",
        help="Check deployment status of NIS2 / ReCyF domain, perimeters, and assets in CISO Assistant.",
    )
    args = parser.parse_args()

    if args.log_level:
        utils.set_log_level(args.log_level)

    if args.web:
        from web import create_app
        import webbrowser
        url = f"http://{args.web_host}:{args.web_port}"
        print("\n" + "=" * 80)
        print("           CISO ASSISTANT - WEB UI & ORCHESTRATION CONSOLE")
        print(f" Listening on: {url}")
        print(" Press Ctrl+C to terminate the web server")
        print("=" * 80 + "\n")
        if args.web_open:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        web_app = create_app()
        web_app.run(host=args.web_host, port=args.web_port, debug=False)
        return

    if args.pipeline:
        run_pipeline()
        return

    manager = ExamplesManager(folder_name=args.domain if args.domain else EXAMPLE_FOLDER_NAME)

    # CLI mode
    if args.offline:
        run_offline_simulation()
        return

    if args.status:
        show_status(manager, wait_seconds=args.wait)
        return

    if args.status_nis2:
        status_nis2_ui(domain_name=args.domain)
        return

    if args.provision_nis2:
        provision_nis2_ui(domain_name=args.domain)
        return

    if args.list_domains:
        list_domains_ui(manager)
        return

    if args.create_domain is not None:
        create_domain_ui(
            manager,
            name=args.create_domain if args.create_domain else None,
            description=args.description,
            parent_domain=args.parent_domain,
            interactive=(not bool(args.create_domain)),
        )
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
        audit_call_kwargs = {
            "app_name": args.create_audit,
            "user_email": args.user,
            "framework_ref_or_name": args.framework,
        }
        if args.domain:
            audit_call_kwargs["domain_name"] = args.domain
        create_audit_demo_ui(
            manager,
            **audit_call_kwargs,
        )
        return

    if args.generate_risks:
        generate_controls_and_risks_ui(manager, app_name=args.generate_risks, answers_source=args.answers, interactive=False)
        return

    if args.create:
        create_call_kwargs = {
            "target": args.create,
            "framework_ref_or_name": args.framework,
        }
        if args.domain:
            create_call_kwargs["domain_name"] = args.domain
        create_examples_ui(
            manager,
            **create_call_kwargs,
        )
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
