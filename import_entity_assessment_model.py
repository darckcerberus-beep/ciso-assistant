"""Import department/application model into domains, external entities and representatives.

Usage:
    python3 import_entity_assessment_model.py --yaml YML/sample_entity_assessment_model.yml
    python3 import_entity_assessment_model.py --yaml YML/sample_entity_assessment_model.yml --create-assessments
"""

import argparse
import sys

from classes.integrations import import_department_external_entity_model


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Import departments as domains and applications as external entities "
            "and associate representatives."
        )
    )
    parser.add_argument(
        "--yaml",
        required=True,
        help="Path to the YAML model file.",
    )
    parser.add_argument(
        "--create-assessments",
        action="store_true",
        help="Also create entity assessments (default behavior is to skip and let main.py handle it).",
    )
    args = parser.parse_args()

    summary = import_department_external_entity_model(
        yaml_path=args.yaml,
        create_entity_assessments=args.create_assessments,
    )

    print("Import summary")
    print(f"- domains_processed: {summary['domains_processed']}")
    print(f"- entities_processed: {summary['entities_processed']}")
    print(f"- representative_links_created: {summary['representative_links_created']}")
    print(f"- entity_assessments_created: {summary['entity_assessments_created']}")
    print(f"- issues: {len(summary['issues'])}")

    if summary['issues']:
        for issue in summary['issues']:
            print(f"  - {issue}")
        sys.exit(1)


if __name__ == "__main__":
    main()
