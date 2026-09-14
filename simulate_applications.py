"""Demonstration and simulation script for application risk calculations.

Loads 4 sample application profiles from `test_data/` and evaluates their
compliance scores, risk scenarios, likelihood/impact scaling, matrix risk levels,
and applied control priorities.

Supports:
- Local offline calculations (default)
- API simulation directly in the CISO Assistant UI (`--api`)
- Interactive menu launcher (`--menu`)
"""

import argparse
from pathlib import Path
import sys

from tests.test_application_scenarios import ApplicationRiskSimulator


def print_application_summary(app_name, csv_file, simulator):
    print("=" * 80)
    print(f" APPLICATION: {app_name} ({csv_file})")
    print("=" * 80)

    results = simulator.evaluate_application(csv_file)
    print(f"Data Classification Impact Level: {results['impact_level']} / 4")
    print("\nRequirement Compliance Scores:")
    for req, score in sorted(results["requirement_scores"].items()):
        if not req.startswith("urn:"):
            print(f"  - {req:<30}: {score:>3}%")

    print("\nEvaluated Risk Scenarios:")
    print(f"{'Scenario Name':<42} | {'LH':<3} | {'Imp':<3} | {'Matrix Risk':<15} | {'Priority':<8}")
    print("-" * 80)
    
    risk_names = {0: "1 - Very Low", 1: "2 - Low", 2: "3 - Medium", 3: "4 - High", 4: "5 - Very High"}
    priority_names = {1: "1 (Urgent)", 2: "2 (High)", 3: "3 (Medium)", 4: "4 (Low)"}

    for sc_name, sc_data in results["scenarios"].items():
        short_name = sc_name[:40] + ".." if len(sc_name) > 42 else sc_name
        risk_str = risk_names.get(sc_data["matrix_risk_id"], str(sc_data["matrix_risk_id"]))
        prio_str = priority_names.get(sc_data["control_priority"], str(sc_data["control_priority"]))
        print(f"{short_name:<42} | {sc_data['scaled_likelihood']:<3} | {sc_data['scaled_impact']:<3} | {risk_str:<15} | {prio_str:<8}")
    print("\n")


def run_api_simulation(app_target="all"):
    """Simulate answers in the CISO Assistant UI by creating resources via the API."""
    from classes.examples_manager import ExamplesManager
    manager = ExamplesManager()
    ok, msg = manager.test_connection()
    if not ok:
        print(f"\n[ERROR] Could not connect to CISO Assistant API: {msg}")
        print("Please check connectivity and credentials in keys.py.")
        sys.exit(1)

    print("\n[+] Connected to CISO Assistant API. Simulating answers in the UI...")
    if app_target == "all":
        results = manager.create_all_examples()
        print(f"\n[SUCCESS] Successfully created and simulated {len(results)} applications in CISO Assistant!")
    else:
        res = manager.create_example_application(app_target)
        print(f"\n[SUCCESS] Successfully created and simulated {res['app_name']} in CISO Assistant!")

    print("\nYou can now open CISO Assistant in your browser to view:")
    print("  - Compliance Assessments & answers")
    print("  - Evaluated Risk Assessments & Scenarios")
    print("  - Applied Controls and Action Plan priorities")
    print("  - Updated Asset Criticality")


def main():
    parser = argparse.ArgumentParser(
        description="Simulate application compliance answers and risk calculations (offline or in CISO Assistant UI)."
    )
    parser.add_argument(
        "--api",
        nargs="?",
        const="all",
        metavar="APP_NAME",
        help="Simulate answers in CISO Assistant UI via API ('all' or specific name/id).",
    )
    parser.add_argument(
        "--menu",
        action="store_true",
        help="Launch interactive menu to create, inspect, or remove examples.",
    )
    args = parser.parse_args()

    if args.menu:
        import manage_examples
        manage_examples.main()
        return

    if args.api:
        run_api_simulation(args.api)
        return

    # Default: offline evaluation
    from classes.examples_manager import EXAMPLE_APPLICATIONS
    simulator = ApplicationRiskSimulator("YML/newDPP.yml")

    for app in EXAMPLE_APPLICATIONS:
        csv_path = app["csv_path"]
        if Path(csv_path).exists():
            print_application_summary(app["label"], csv_path, simulator)

    print("=" * 80)
    print(" [TIP] To simulate and visualize these answers directly in the CISO Assistant UI:")
    print("       python3 simulate_applications.py --api")
    print("       or use the interactive manager:")
    print("       python3 manage_examples.py")
    print("=" * 80)


if __name__ == "__main__":
    main()
