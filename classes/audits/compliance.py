"""Compliance assessment models and orchestration helpers."""

import logging
from pathlib import Path

from .. import utils
from .implementation_groups import add_default_implementation_groups
from .requirement_assessment import RequirementAssessmentDict, create_requirement_assignment
from .requirement_assignment import RequirementAssignmentDict

# Load settings from library file
_library_path = Path(__file__).parent.parent.parent / "YML" / "newDPP.yml"
_library = utils.load_yaml_file(str(_library_path))
AUDITOR_SCORE_VISIBILITY = _library.get("audit", {}).get("score_visibility", {})
AUDITOR_SCORE_METHOD = _library.get("audit", {}).get("score_method", "sum")


class ComplianceAssessment:
    """Represent a single compliance assessment returned by the API."""

    def __init__(self, json_ca):
        """Initialize the object using the API payload."""
        if isinstance(json_ca, dict) and "name" in json_ca and "framework" in json_ca:
            self.compliance_assessment_json = json_ca
        else:
            assessment_id = json_ca.get('id', '') if isinstance(json_ca, dict) else str(json_ca)
            self.compliance_assessment_json = utils.get_return(f"/api/compliance-assessments/{assessment_id}/")

    def get_json(self):
        """Return the raw JSON object."""
        return self.compliance_assessment_json

    def get_name(self) -> str:
        """Return the assessment name."""
        return self.compliance_assessment_json.get('name', '')

    def get_id(self) -> str:
        """Return the assessment UUID."""
        return self.compliance_assessment_json.get('id', '')

    def get_framework_id(self) -> str:
        """Return the linked framework identifier."""
        framework = self.compliance_assessment_json.get('framework', {})
        if isinstance(framework, dict):
            return framework.get('id', '')
        return '' if framework in (None, '', {}) else str(framework)

    def get_perimeter_id(self) -> str:
        """Return the linked perimeter identifier."""
        perimeter = self.compliance_assessment_json.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return '' if perimeter in (None, '', {}) else str(perimeter)

    def has_perimeter(self) -> bool:
        """Return whether this assessment belongs to an internal perimeter."""
        return bool(self.get_perimeter_id())

    def get_asset_id_list(self):
        """Return the asset IDs linked to this compliance assessment."""
        utils.log(f"Getting asset ID list for compliance assessment ID: {self.get_id()}")
        utils.log(f"Compliance assessment JSON: {self.compliance_assessment_json}")
        return [asset.get('id', '') for asset in self.compliance_assessment_json.get('assets', [])]

    def print_name(self):
        """Log the assessment name."""
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        """Log the assessment ID."""
        utils.log(f"ID: {self.get_id()}")

    def print_framework_id(self):
        """Log the framework ID."""
        utils.log(f"Framework ID: {self.get_framework_id()}")

    def print_perimeter_id(self):
        """Log the perimeter ID."""
        utils.log(f"Perimeter ID: {self.get_perimeter_id()}")

    def get_status(self):
        """Return the current status of the compliance assessment."""
        return self.compliance_assessment_json.get('status', '')

    def get_score_from_requirement_node_name(self, requirement_node_name):
        """Return the score for a requirement node matching the provided name."""
        utils.log(f"Searching for requirement node '{requirement_node_name}' in compliance assessment ID: {self.get_id()}")
        utils.log(f"Compliance assessment JSON: {self.compliance_assessment_json}")

        for requirement in self.compliance_assessment_json.get('requirements', []):
            utils.log(f"Checking requirement node: {requirement.get('name', '')}")
            if requirement.get('name') == requirement_node_name:
                score = requirement.get('score', '')
                utils.log(f"Found requirement node '{requirement_node_name}' with score: {score}")
                return score
        return None


class ComplianceAssessmentDict:
    """Manage a collection of compliance assessments and related API operations."""

    def __init__(self):
        utils.log("Initializing ComplianceAssessmentDict", level=logging.DEBUG)
        self.reload()
        self.requirement_assessments = RequirementAssessmentDict()
        self.requirement_assignments = RequirementAssignmentDict()
        utils.log("ComplianceAssessmentDict initialized successfully", level=logging.INFO)

    def reload(self):
        """Refresh the internal dictionary from the API."""
        utils.log("Reloading compliance assessments from API", level=logging.DEBUG)
        self.compliance_assessments = {}
        for ca in utils.get_all_results("/api/compliance-assessments/", force_reload=True):
            utils.log(f"Adding compliance assessment object for assessment ID: {ca.get('id')}")
            self.compliance_assessments[ca.get('id')] = ComplianceAssessment(ca)
        if hasattr(self, 'requirement_assessments') and self.requirement_assessments is not None:
            self.requirement_assessments.reload()
        if hasattr(self, 'requirement_assignments') and self.requirement_assignments is not None:
            self.requirement_assignments.reload()
        utils.log(f"Reload completed: {len(self.compliance_assessments)} compliance assessments loaded", level=logging.INFO)

    def get_compliance_assessments(self):
        """Return the compliance assessment dictionary."""
        return self.compliance_assessments

    def create_compliance_assessment(self, name, framework_id, perimeter_id):
        """Create a new compliance assessment via POST request."""
        utils.log(f"Creating compliance assessment: {name} with parameters framework_id={framework_id}, perimeter_id={perimeter_id} and score_method={AUDITOR_SCORE_METHOD}", level=logging.DEBUG)
        payload = {
            'name': name,
            'framework': framework_id,
            'perimeter': perimeter_id,
            'score_calculation_method': AUDITOR_SCORE_METHOD,
            'field_visibility': AUDITOR_SCORE_VISIBILITY,
        }
        add_default_implementation_groups(payload, framework_id)
        response = utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
        self.reload()
        utils.log(f"Compliance assessment created successfully: {name}", level=logging.INFO)
        return ComplianceAssessment(response)

    def create_missing_compliance_assessments(self, framework_dict, perimeter_dict, asset_dict):
        """Ensure every framework/perimeter combination has a compliance assessment."""
        utils.log("Creating missing compliance assessments...")
        created = False

        for framework in framework_dict.get_frameworks():
            for perimeter in perimeter_dict.get_perimeters():
                compliance_assessment_name = f"Assessment of {framework.get_name()} in {perimeter.get_name()}"
                if not self.check_compliance_assessment_from_name(compliance_assessment_name):
                    utils.log(f"Creating compliance assessment: {compliance_assessment_name}")
                    payload = {
                        'name': compliance_assessment_name,
                        'framework': framework.get_id(),
                        'perimeter': perimeter.get_id(),
                        'assets': [asset_dict.get_asset_id_from_perimeter_id(perimeter.get_id(), perimeter_dict)],
                        'score_calculation_method': AUDITOR_SCORE_METHOD,
                        'field_visibility': AUDITOR_SCORE_VISIBILITY,
                    }
                    add_default_implementation_groups(payload, framework.get_id())
                    utils.log(f"Payload for new compliance assessment: {payload}", level=logging.INFO)
                    utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
                    created = True

        if created:
            utils.log("Compliance assessments created.")
            self.reload()
        else:
            utils.log("No new compliance assessments created.")

    def update_asset_objectives(self, asset_dict):
        """Refresh asset objectives for the current requirement assessment context."""
        self.reload()
        for ra in self.requirement_assessments.get_requirement_assessments().values():
            self.get_asset_id_list_from_compliance_assessment_id(ra.get_compliance_assessment_id())

    def check_compliance_assessment_from_ids(self, framework_id, perimeter_id):
        """Check whether an assessment exists for a framework/perimeter pair."""
        for ca in self.compliance_assessments.values():
            if ca.get_framework_id() == framework_id and ca.get_perimeter_id() == perimeter_id:
                return True
        return False

    def check_compliance_assessment_from_name(self, name):
        """Check whether an assessment exists with the given name."""
        for ca in self.compliance_assessments.values():
            if ca.get_name() == name:
                return True
        return False

    def print_compliance_assessments(self):
        """Log every compliance assessment name."""
        for ca in self.compliance_assessments.values():
            utils.log(f"Compliance assessment name: {ca.get_name()}")

    def get_asset_id_list_from_compliance_assessment_id(self, compliance_assessment_id):
        """Return the asset IDs linked to a compliance assessment."""
        for ca in self.compliance_assessments.values():
            if ca.get_id() == compliance_assessment_id:
                utils.log(f"Getting asset ID list for compliance assessment ID: {compliance_assessment_id}")
                utils.log(f"Compliance assessment name: {ca.get_name()}")
                assets = ca.get_asset_id_list()
                utils.log(f"Compliance assessment assets: {assets}")
                return assets
        return []

    def assign_requirements_to_perimeter_owner(self, perimeter_dict, compliance_assessment_dict, requirement_assessment_dict, requirement_assignment_dict):
        """Create requirement assignments for perimeter owners when no assignment exists."""
        self.reload()
        for ca in self.compliance_assessments.values():
            if not ca.has_perimeter():
                utils.log(
                    f"Skipping perimeter-owner assignment for compliance assessment {ca.get_name()} ({ca.get_id()}): no perimeter",
                    level=logging.INFO,
                )
                continue

            requirement_assessment_ids = requirement_assessment_dict.get_requirement_assessment_id_list_from_compliance_assessment_id(ca.get_id())
            requirement_assignment_ids = requirement_assignment_dict.get_requirement_assignment_id_list_from_compliance_assessment_id(ca.get_id())

            utils.log(f"Requirement assessment IDs for compliance assessment {ca.get_name()}: {requirement_assessment_ids}")
            utils.log(f"Requirement assignment IDs for compliance assessment {ca.get_name()}: {requirement_assignment_ids}")

            if requirement_assessment_ids and not requirement_assignment_ids:
                owner_id = perimeter_dict.get_owner_id_from_perimeter_id(ca.get_perimeter_id())
                if not owner_id:
                    actor_records = utils.get_all_results("/api/actors/")
                    if actor_records and isinstance(actor_records[0], dict):
                        owner_id = actor_records[0].get("id")
                if not owner_id:
                    utils.log(
                        f"Skipping requirement assignment for compliance assessment {ca.get_name()}: no actor available",
                        level=logging.WARNING,
                    )
                    continue

                utils.log(f"Creating assignments for compliance assessment: {ca.get_name()}")
                payload = {
                    "requirement_assessments": requirement_assessment_ids,
                    "compliance_assessment": ca.get_id(),
                    "folder": perimeter_dict.get_folder_uuid_from_perimeter_id(ca.get_perimeter_id()),
                    "actor": [owner_id]
                }
                req_assign_json = create_requirement_assignment(payload)
                if not req_assign_json or (isinstance(req_assign_json, dict) and req_assign_json.get('error')):
                    utils.log(
                        f"Failed to create requirement assignment for compliance assessment {ca.get_name()}: {req_assign_json}",
                        level=logging.ERROR,
                    )
            else:
                utils.log(f"Requirement assignments already exist for compliance assessment: {ca.get_name()}")
                utils.log(f"Requirement assessment IDs: {requirement_assessment_ids}")
                utils.log(f"Requirement assignment IDs: {requirement_assignment_ids}")

    def get_score_from_requirement_node_name(self, requirement_node_name):
        """Search all assessments for a requirement node name and return its score."""
        self.reload()
        for ca in self.compliance_assessments.values():
            score = ca.get_score_from_requirement_node_name(requirement_node_name)
            if score is not None:
                return score
        return None

    def update_asset_criticality(self, criticality_mapping, asset_dict):
        """Update asset criticality based on requirement assessment answers."""
        self.reload()
        for ca in self.compliance_assessments.values():
            requirement_assessment_ids = self.requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id(ca.get_id())
            for ra_id in requirement_assessment_ids:
                ra = self.requirement_assessments.get_requirement_assessments().get(ra_id)
                if ra and not ra.is_unassessed_result():
                    for question, answer in ra.get_requirement_json().get('answers', {}).items():
                        for criteria_question, criteria_mapping in criticality_mapping.items():
                            if answer in criteria_mapping:
                                utils.log(
                                    f"Updating asset criticality for criteria question: {criteria_question} "
                                    f"in requirement assessment ID: {ra.get_id()}"
                                )
                                utils.log(
                                    f"Question: {question}, Answer: {answer}, "
                                    f"Mapped Criticality: {criteria_mapping[answer]}"
                                )
                                asset_ids = ca.get_asset_id_list()
                                utils.log(f"Associated asset IDs: {asset_ids}")
                                for asset_id in asset_ids:
                                    utils.log(f"Updating criticality for asset ID: {asset_id}")
                                    asset_dict.update_asset_criticality(asset_id, criteria_question, criteria_mapping[answer])

    def create_missing_applied_controls(self, applied_control_dict, perimeter_dict, reference_control_dict):
        """Delegate applied-control creation to requirement assessments."""
        self.requirement_assessments.create_or_update_applied_controls(applied_control_dict, perimeter_dict, reference_control_dict, self)

    def get_json(self):
        """Return the raw JSON data for all compliance assessments."""
        self.reload()
        return [ca.get_json() for ca in self.compliance_assessments.values()]

    def print_json(self):
        """Log the raw JSON data for all compliance assessments."""
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Printing JSON for compliance assessment: {ca.get_name()}")
            utils.log(ca.get_json())

    def create_risk_assessments(self, risk_assessment_dict, risk_scenario_dict, applied_control_dict, asset_dict, framework_file, requirement_assessment_dict, risk_matrix_dict, framework_dict):
        """Create risk assessments and evaluate risk scenarios for each compliance assessment.

        Logic:
        1. For each compliance assessment, check if it has at least one answered requirement.
           If unassessed/unanswered, skip risk assessment creation.
        2. Create or find the parent Risk Assessment object tied to the compliance assessment domain,
           perimeter, and associated library risk matrix.
        3. For each risk scenario definition defined in the framework YAML:
           a. Locate the corresponding requirement assessment for likelihood and impact.
           b. If the likelihood requirement has no selected answer, remove any existing scenario and skip.
           c. Determine the raw impact score (either from mapped impact answers or the requirement score).
           d. Determine the raw likelihood score (0-100 percentage score from requirement assessment).
           e. Compute scaled impact (1-4 scale) and scaled likelihood:
              - score between 76-100 -> likelihood level 1 (low risk)
              - score between 51-75  -> likelihood level 2
              - score between 26-50  -> likelihood level 3
              - score between 0-25   -> likelihood level 4 (high risk)
              Formula: scaled_likelihood = min(4, max(1, 4 - ((score - 1) // 25)))
           f. Collect existing (active) vs planned (to_do) controls linked to these requirements.
           g. Create/update the Risk Scenario with scaled likelihood, impact, assets, and owners.
        """
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Creating risk assessments for compliance assessment: {ca.get_name()}")
            utils.log(f"Using framework ID: {ca.get_framework_id()}, perimeter ID: {ca.get_perimeter_id()}")
            
            # Skip creating risk assessments when the compliance assessment has no answered requirement assessments
            if not requirement_assessment_dict.has_answers_for_compliance_assessment(ca.get_id()):
                utils.log(f"Skipping risk creation for compliance assessment {ca.get_name()} ({ca.get_id()}): no answered requirements", level=20)
                continue
            requirement_assessment_dict.log_assessment_results_for_compliance_assessment_id(ca.get_id())

            # Load requirement assessments once for this compliance assessment to avoid repeated API calls
            requirement_assessments = requirement_assessment_dict.get_requirement_assessments()

            # Ensure parent Risk Assessment exists in the API for this compliance assessment
            risk_assessment = risk_assessment_dict.create_risk_assessments(
                ca.get_name() + " Risk Assessment",
                ca.get_framework_id(),
                ca.get_perimeter_id(),
                risk_matrix_dict.get_risk_matrix_id_by_library_id(
                    framework_dict.get_library_id_from_framework_id(ca.get_framework_id())
                )
            )

            # Evaluate each scenario defined in the framework configuration
            for risk_scenario in framework_file.get_risk_scenarios():
                utils.log(f"Creating risk scenario: {risk_scenario.get('name', '')} for compliance assessment: {ca.get_name()}")
                utils.log(f"Risk scenario description: {risk_scenario.get('description', '')}")
                utils.log(f"Risk scenario impact node: {risk_scenario.get('impact', '')}")
                utils.log(f"Risk scenario likelihood node: {risk_scenario.get('likelihood', '')}")

                impact_mapping = framework_file.get_impact_mapping()
                impact = None
                likelihood_assessment = None

                # Search requirement assessments for matching likelihood and impact nodes
                for requirement_assessment in requirement_assessments.values():
                    if requirement_assessment.get_compliance_assessment_id() != ca.get_id():
                        continue
                    if requirement_assessment.get_urn() == risk_scenario.get('likelihood', ''):
                        likelihood_assessment = requirement_assessment
                    if requirement_assessment.get_urn() != risk_scenario.get('impact', ''):
                        continue

                    # Check if any answer matches configured impact mappings
                    for answer in requirement_assessment.get_requirement_json().get('answers', {}).values():
                        if answer in impact_mapping:
                            impact = impact_mapping[answer] + 1
                            break

                # If the likelihood requirement assessment was never answered, clean up and skip
                if likelihood_assessment is None or not likelihood_assessment.has_selected_answer():
                    utils.log(
                        f"Skipping risk scenario '{risk_scenario.get('name', '')}': "
                        "its likelihood requirement has no selected answer"
                    )
                    risk_scenario_dict.delete_risk_scenario(
                        risk_scenario.get('name', ''),
                        risk_assessment.get('id', ''),
                    )
                    continue

                # Fallback to direct requirement score if impact was not mapped from answer choices
                if impact is None:
                    impact = requirement_assessment_dict.get_score_from_compliance_assessment_id_and_urn(
                        ca.get_id(), risk_scenario.get('impact', ''), refresh=False
                    )

                likelihood = requirement_assessment_dict.get_score_from_compliance_assessment_id_and_urn(
                    ca.get_id(), risk_scenario.get('likelihood', ''), refresh=False
                )

                # Identify requirement assessment IDs associated with this scenario's likelihood (mitigating controls)
                requirement_assessment_ids = [
                    requirement_assessment.get_id()
                    for requirement_assessment in requirement_assessments.values()
                    if requirement_assessment.get_compliance_assessment_id() == ca.get_id()
                    and requirement_assessment.get_urn() == risk_scenario.get('likelihood', '')
                ]

                # Categorize linked applied controls into active ("existing") and to_do ("planned")
                controls_by_status = applied_control_dict.get_control_ids_by_status_for_requirement_assessments(
                    requirement_assessment_ids
                )
                asset_ids = ca.get_asset_id_list()
                owner_ids = asset_dict.get_owner_ids_for_assets(asset_ids)

                if likelihood is not None and impact is not None:
                    utils.log(f"Risk scenario impact value: {impact}")
                    scaled_impact = max(1, int(impact))
                    utils.log(f"Scaled impact: {scaled_impact}")

                    # Likelihood scaling: inverse relationship (higher compliance score -> lower risk likelihood)
                    utils.log(f"Risk scenario likelihood value: {likelihood}")
                    score = max(0, min(100, int(likelihood)))
                    scaled_likelihood = min(4, max(1, 4 - ((score - 1) // 25)))
                    utils.log(f"Scaled likelihood: {scaled_likelihood}")

                    # Create or update the risk scenario in the API
                    risk_scenario_dict.create_risk_scenario(
                        risk_scenario.get('name', ''),
                        risk_scenario.get('description', ''),
                        risk_assessment.get('id', ''),
                        scaled_likelihood,
                        scaled_impact,
                        1,
                        scaled_impact,
                        controls_by_status["existing"],
                        controls_by_status["planned"],
                        asset_ids,
                        owner_ids,
                    )

    def delete_compliance_assessment(self, compliance_assessment_id):
        """Delete a compliance assessment via DELETE request."""
        utils.log(f"Deleting compliance assessment ID: {compliance_assessment_id}", level=logging.INFO)
        response = utils.get_return(
            f"/api/compliance-assessments/{compliance_assessment_id}/",
            method="DELETE",
        )
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.compliance_assessments.pop(compliance_assessment_id, None)
            utils.log(f"Successfully deleted compliance assessment ID: {compliance_assessment_id}", level=logging.INFO)
            return True
        utils.log(f"Failed to delete compliance assessment ID {compliance_assessment_id}: {response}", level=logging.ERROR)
        return False
