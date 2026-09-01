from classes import audit, control, framework, organization, risk, user, utils


def initialize_data_objects():
    """Instantiate all required dictionaries and framework objects used in the workflow."""
    requirement_assessment_dict = audit.RequirementAssessmentDict()
    compliance_assessment_dict = audit.ComplianceAssessmentDict()
    requirement_assignment_dict = audit.RequirementAssignmentDict()
    perimeter_dict = organization.PerimeterDict()
    asset_dict = organization.AssetDict()
    framework_dict = framework.FrameworkDict()
    reference_control_dict = control.ReferenceControlDict()
    applied_control_dict = control.AppliedControlDict()
    risk_assessment_dict = risk.RiskAssessmentDict()
    risk_scenario_dict = risk.RiskScenarioDict()
    user_dict = user.UserDict()
    framework_file = framework.FrameworkFile("YML/newDPP.yml")
    risk_matrix_dict = risk.RiskMatrixDict()

    return {
        "requirement_assessment_dict": requirement_assessment_dict,
        "compliance_assessment_dict": compliance_assessment_dict,
        "requirement_assignment_dict": requirement_assignment_dict,
        "perimeter_dict": perimeter_dict,
        "asset_dict": asset_dict,
        "framework_dict": framework_dict,
        "reference_control_dict": reference_control_dict,
        "applied_control_dict": applied_control_dict,
        "risk_assessment_dict": risk_assessment_dict,
        "risk_scenario_dict": risk_scenario_dict,
        "user_dict": user_dict,
        "framework_file": framework_file,
        "risk_matrix_dict": risk_matrix_dict,
    }


def main():
    """Run the audit and risk assessment workflow."""
    data = initialize_data_objects()

    # Capture initial counts for summary
    initial_counts = utils.capture_counts(data)

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
        organization.criticality_mapping,
        data["asset_dict"],
    )
    
    # Update asset criticality based on the organization mapping.
    data["compliance_assessment_dict"].update_asset_criticality(
        organization.criticality_mapping,
        data["asset_dict"],
    )

    # Create missing applied controls for each compliance assessment.
    data["compliance_assessment_dict"].create_missing_applied_controls(
        data["applied_control_dict"],
        data["perimeter_dict"],
        data["reference_control_dict"],
    )
    
    # Final counts and summary
    final_counts = utils.capture_counts(data)
    utils.print_run_summary(initial_counts, final_counts)

if __name__ == "__main__":
    main()
