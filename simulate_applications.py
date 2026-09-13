"""Demonstration and verification script for application risk calculations.

Loads 4 sample application profiles from `test_data/` and evaluates their
compliance scores, risk scenarios, likelihood/impact scaling, matrix risk levels,
and applied control priorities.
"""

from pathlib import Path
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


def main():
    simulator = ApplicationRiskSimulator("YML/newDPP.yml")

    apps = [
        ("App-Secure-Core (Secret / 100% Compliant)", "test_data/app_secure_core.csv"),
        ("App-Vulnerable-Portal (Secret / 0% Non-Compliant)", "test_data/app_vulnerable_portal.csv"),
        ("App-Internal-Tool (Internal / Mixed Compliance)", "test_data/app_internal_tool.csv"),
        ("App-Public-Blog (Public / Low Sensitivity)", "test_data/app_public_blog.csv"),
    ]

    for app_name, csv_path in apps:
        if Path(csv_path).exists():
            print_application_summary(app_name, csv_path, simulator)


if __name__ == "__main__":
    main()

