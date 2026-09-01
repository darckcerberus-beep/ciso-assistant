"""Import CSV questionnaire answers into a CISO Assistant compliance assessment.

Usage:
    python3 import_csv_answers.py --csv answers.csv --compliance-assessment-id <uuid>
    python3 import_csv_answers.py --csv answers.csv --framework "Data protection policy of ACME Corp" --perimeter "My Perimeter"

See classes/csv_import.py for the expected CSV column layout.
"""

import argparse
import sys

from classes import audit, utils


def resolve_compliance_assessment_id(args, compliance_assessment_dict):
    """Resolve the target compliance assessment ID from CLI arguments."""
    if args.compliance_assessment_id:
        return args.compliance_assessment_id

    if not args.framework or not args.perimeter:
        return None

    for ca in compliance_assessment_dict.get_compliance_assessments().values():
        if ca.get_name() == f"Assessment of {args.framework} in {args.perimeter}":
            return ca.get_id()
    return None


def main():
    parser = argparse.ArgumentParser(description="Import CSV questionnaire answers into a compliance assessment.")
    parser.add_argument("--csv", required=True, help="Path to the CSV file containing the answers.")
    parser.add_argument("--compliance-assessment-id", help="Target compliance assessment UUID.")
    parser.add_argument("--framework", help="Framework name (used with --perimeter to look up the assessment).")
    parser.add_argument("--perimeter", help="Perimeter name (used with --framework to look up the assessment).")
    parser.add_argument("--delimiter", help="CSV delimiter (auto-detected when omitted).")
    args = parser.parse_args()

    compliance_assessment_dict = audit.ComplianceAssessmentDict()
    compliance_assessment_id = resolve_compliance_assessment_id(args, compliance_assessment_dict)

    if not compliance_assessment_id:
        utils.log("Could not resolve a compliance assessment from the given arguments.", level=40)
        sys.exit(1)

    from classes import csv_import

    summary = csv_import.import_compliance_answers(
        args.csv,
        compliance_assessment_id,
        compliance_assessment_dict.requirement_assessments,
        delimiter=args.delimiter,
    )

    print(f"Updated {summary['updated']} requirement assessment(s).")
    if summary["errors"]:
        print(f"{len(summary['errors'])} issue(s) encountered:")
        for error in summary["errors"]:
            print(f"  - row {error['row']}: {error['reason']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
