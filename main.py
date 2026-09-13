"""Main workflow script for CISO Assistant orchestration.

This script executes the end-to-end audit, compliance, and risk management pipeline:
1. Initializes all cached API collections and framework definitions.
2. Captures baseline entity counts for run summary reporting.
3. Provisions missing assets from defined organization perimeters.
4. Generates compliance assessments for all perimeter and framework pairs.
5. Assigns requirement questionnaires to designated perimeter owners and transitions them to in_progress.
6. Provisions external entity third-party assessments and links them with external representatives.
7. Computes and generates risk assessments & scenarios derived from assessment responses and matrix models.
8. Creates/synchronizes applied controls based on requirement assessment results and calculated priorities.
9. Updates asset criticality ratings from questionnaire responses based on organizational mapping rules.
10. Compares initial vs final object counts and logs a comprehensive execution summary.
"""

from classes import utils
from classes.organization.domain import criticality_mapping


def main():
    """Run the audit, compliance assessment, risk assessment, and control synchronization workflow."""
    # Step 1: Initialize API data objects and load local YAML framework definitions into memory.
    data = utils.initialize_data_objects()

    # Step 2: Capture initial counts across all resource types to compute diffs in the final summary.
    initial_counts = utils.capture_counts(data)

    # Step 3: Ensure each perimeter has a corresponding asset created (1:1 mapping between perimeter and asset).
    data["asset_dict"].create_missing_assets(data["perimeter_dict"])
    data["asset_dict"].reload()

    # Step 4: Ensure every combination of framework and perimeter has an active compliance assessment.
    data["compliance_assessment_dict"].create_missing_compliance_assessments(
        data["framework_dict"],
        data["perimeter_dict"],
        data["asset_dict"],
    )

    # Step 5: Assign unassigned requirement assessments to perimeter owners and transition status to in_progress.
    data["compliance_assessment_dict"].assign_requirements_to_perimeter_owner(
        data["perimeter_dict"],
        data["compliance_assessment_dict"],
        data["requirement_assessment_dict"],
        data["requirement_assignment_dict"],
    )

    # Step 6: Create or update external-entity audits for third-party vendors/partners (additive step).
    data["entity_assessment_dict"].create_external_entity_audits(
        data["entity_dict"],
        data["framework_dict"],
    )

    # Step 7: Create risk assessments and evaluate scenarios for compliance assessments with answered requirements.
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

    # Step 8: Generate missing applied controls and synchronize existing control priorities with risk scenario scores.
    data["compliance_assessment_dict"].create_missing_applied_controls(
        data["applied_control_dict"],
        data["perimeter_dict"],
        data["reference_control_dict"],
    )

    # Step 9: Re-evaluate and update asset criticality (Confidentiality/Integrity/Availability) from questionnaire answers.
    data["compliance_assessment_dict"].update_asset_criticality(
        criticality_mapping,
        data["asset_dict"],
    )

    # Step 10: Capture post-execution resource counts and print execution summary metrics.
    final_counts = utils.capture_counts(data)
    utils.print_run_summary(initial_counts, final_counts)


if __name__ == "__main__":
    main()
