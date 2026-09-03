from classes import utils
from classes.audits.entity_assessment import create_external_entity_audits
from classes.organization.domain import criticality_mapping


def main():
    """Run the audit and risk assessment workflow."""
    data = utils.initialize_data_objects()

    # Capture initial counts for summary
    initial_counts = utils.capture_counts(data)
    """
    # Create missing assets from the perimeter definition.
    data["asset_dict"].create_missing_assets(data["perimeter_dict"])
    data["asset_dict"].reload()

    # Create compliance assessments for each perimeter and asset based on the framework.
    data["compliance_assessment_dict"].create_missing_compliance_assessments(
        data["framework_dict"],
        data["perimeter_dict"],
        data["asset_dict"],
    )

    # Assign requirements to perimeter owners.
    data["compliance_assessment_dict"].assign_requirements_to_perimeter_owner(
        data["perimeter_dict"],
        data["compliance_assessment_dict"],
        data["requirement_assessment_dict"],
        data["requirement_assignment_dict"],
    )
    # Create risk assessments for each compliance assessment based on the framework.
    data["compliance_assessment_dict"].create_risk_assessments(
        data["risk_assessment_dict"],
        data["risk_scenario_dict"],
        data["applied_control_dict"],
        data["asset_dict"],
        data["framework_file"],
        data["requirement_assessment_dict"],
        data["risk_matrix_dict"],
        data["framework_dict"],
    )

    # Create missing applied controls for each compliance assessment (after risk assessments so priorities can be set).
    data["compliance_assessment_dict"].create_missing_applied_controls(
        data["applied_control_dict"],
        data["perimeter_dict"],
        data["reference_control_dict"],
    )

    # Update asset criticality based on the organization mapping.
    data["compliance_assessment_dict"].update_asset_criticality(
        criticality_mapping,
        data["asset_dict"],
    )

    # Create missing applied controls for each compliance assessment.
    data["compliance_assessment_dict"].create_missing_applied_controls(
        data["applied_control_dict"],
        data["perimeter_dict"],
        data["reference_control_dict"],
    )
    """
    # Add external-entity audits for third parties. This is additive and does not alter the internal perimeter-based steps.
    create_external_entity_audits(data)

    # Final counts and summary
    final_counts = utils.capture_counts(data)
    utils.print_run_summary(initial_counts, final_counts)


if __name__ == "__main__":
    main()
