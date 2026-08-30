"""Helpers and models for compliance assessments, requirement assessments, and assignments."""

import logging
from pathlib import Path

from . import utils

# Load settings from framework file
_framework_path = Path(__file__).parent.parent / "YML" / "newDPP.yml"
_framework = utils.load_yaml_file(str(_framework_path))
AUDITOR_SCORE_VISIBILITY = _framework.get("audit", {}).get("score_visibility", {})
AUDITOR_SCORE_METHOD = _framework.get("audit", {}).get("score_method", "sum")



class ComplianceAssessment:
    """Represent a single compliance assessment returned by the API."""

    def __init__(self, json_ca):
        """Initialize the object using the API payload."""
        assessment_id = json_ca.get('id', '')
        utils.log(f"Creating compliance assessment with ID: {assessment_id}")
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
        return str(framework)

    def get_perimeter_id(self) -> str:
        """Return the linked perimeter identifier."""
        perimeter = self.compliance_assessment_json.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return str(perimeter)

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
        for ca in utils.get_all_results("/api/compliance-assessments/"):
            utils.log(f"Adding compliance assessment object for assessment ID: {ca.get('id')}")
            self.compliance_assessments[ca.get('id')] = ComplianceAssessment(ca)
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
            requirement_assessment_ids = requirement_assessment_dict.get_requirement_assessment_id_list_from_compliance_assessment_id(ca.get_id())
            requirement_assignment_ids = requirement_assignment_dict.get_requirement_assignment_id_list_from_compliance_assessment_id(ca.get_id())

            utils.log(f"Requirement assessment IDs for compliance assessment {ca.get_name()}: {requirement_assessment_ids}")
            utils.log(f"Requirement assignment IDs for compliance assessment {ca.get_name()}: {requirement_assignment_ids}")

            if requirement_assessment_ids and not requirement_assignment_ids:
                utils.log(f"Creating assignments for compliance assessment: {ca.get_name()}")
                payload = {
                    "requirement_assessments": requirement_assessment_ids,
                    "compliance_assessment": ca.get_id(),
                    "folder": perimeter_dict.get_folder_uuid_from_perimeter_id(ca.get_perimeter_id()),
                    "actor": [perimeter_dict.get_owner_id_from_perimeter_id(ca.get_perimeter_id())]
                }
                req_assign_json = utils.get_return("/api/requirement-assignments/", method="POST", payload=payload)
                utils.get_return(
                    f"/api/requirement-assignments/{req_assign_json.get('id')}/set_status/",
                    method="POST",
                    payload={"status": "in_progress"}
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
        """Create risk assessments and scenarios for each compliance assessment."""
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Creating risk assessments for compliance assessment: {ca.get_name()}")
            utils.log(f"Using framework ID: {ca.get_framework_id()}, perimeter ID: {ca.get_perimeter_id()}")
            requirement_assessment_dict.log_assessment_results_for_compliance_assessment_id(ca.get_id())

            risk_assessment = risk_assessment_dict.create_risk_assessments(
                ca.get_name() + " Risk Assessment",
                ca.get_framework_id(),
                ca.get_perimeter_id(),
                risk_matrix_dict.get_risk_matrix_id_by_library_id(
                    framework_dict.get_library_id_from_framework_id(ca.get_framework_id())
                )
            )

            for risk_scenario in framework_file.get_risk_scenarios():
                utils.log(f"Creating risk scenario: {risk_scenario.get('name', '')} for compliance assessment: {ca.get_name()}")
                utils.log(f"Risk scenario description: {risk_scenario.get('description', '')}")
                utils.log(f"Risk scenario impact node: {risk_scenario.get('impact', '')}")
                utils.log(f"Risk scenario likelihood node: {risk_scenario.get('likelihood', '')}")

                impact_mapping = framework_file.get_impact_mapping()
                impact = None
                likelihood_assessment = None
                for requirement_assessment in requirement_assessment_dict.get_requirement_assessments().values():
                    if requirement_assessment.get_compliance_assessment_id() != ca.get_id():
                        continue
                    if requirement_assessment.get_urn() == risk_scenario.get('likelihood', ''):
                        likelihood_assessment = requirement_assessment
                    if requirement_assessment.get_urn() != risk_scenario.get('impact', ''):
                        continue

                    for answer in requirement_assessment.get_requirement_json().get('answers', {}).values():
                        if answer in impact_mapping:
                            impact = impact_mapping[answer] + 1
                            break

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

                if impact is None:
                    impact = requirement_assessment_dict.get_score_from_compliance_assessment_id_and_urn(
                        ca.get_id(), risk_scenario.get('impact', '')
                    )

                likelihood = requirement_assessment_dict.get_score_from_compliance_assessment_id_and_urn(
                    ca.get_id(), risk_scenario.get('likelihood', '')
                )
                requirement_assessment_ids = [
                    requirement_assessment.get_id()
                    for requirement_assessment in requirement_assessment_dict.get_requirement_assessments().values()
                    if requirement_assessment.get_compliance_assessment_id() == ca.get_id()
                    and requirement_assessment.get_urn() in {
                        risk_scenario.get('impact', ''),
                        risk_scenario.get('likelihood', ''),
                    }
                ]
                controls_by_status = applied_control_dict.get_control_ids_by_status_for_requirement_assessments(
                    requirement_assessment_ids
                )
                asset_ids = ca.get_asset_id_list()
                owner_ids = asset_dict.get_owner_ids_for_assets(asset_ids)

                if likelihood is not None and impact is not None:
                    utils.log(f"Risk scenario impact value: {impact}")
                    scaled_impact = max(1, int(impact))
                    utils.log(f"Scaled impact: {scaled_impact}")

                    utils.log(f"Risk scenario likelihood value: {likelihood}")
                    score = max(0, min(100, int(likelihood)))
                    scaled_likelihood = min(4, max(1, 4 - ((score - 1) // 25)))
                    utils.log(f"Scaled likelihood: {scaled_likelihood}")

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


class RequirementAssessment:
    """Represent a requirement assessment linked to a compliance assessment."""

    def __init__(self, json_ra):
        """Initialize from the API payload."""
        self.json_object = json_ra

    def get_name(self):
        """Return the requirement assessment name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the requirement assessment UUID."""
        return self.json_object.get('id', '')

    def get_framework_id(self):
        """Return the framework ID."""
        return self.json_object.get('framework', '')

    def get_perimeter_id(self):
        """Return the perimeter ID."""
        perimeter = self.json_object.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return str(perimeter)

    def get_compliance_assessment_id(self):
        """Return the parent compliance assessment ID."""
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '')
        return str(compliance_assessment)

    def get_requirement_id(self):
        """Return the underlying requirement ID."""
        return self.json_object.get('requirement', '')

    def get_requirement_assignment_status(self):
        """Return the current requirement assessment status."""
        return self.json_object.get('status', '')

    def get_requirement_json(self):
        """Return the raw JSON payload."""
        return self.json_object

    def get_answers(self):
        """Return the selected answers for this requirement assessment."""
        return self.json_object.get('answers', {})

    def has_selected_answer(self):
        """Return whether at least one question in this requirement was answered."""
        answers = self.get_answers()
        return isinstance(answers, dict) and any(answer is not None for answer in answers.values())

    def get_associated_reference_controls(self):
        """Return the reference controls attached to the underlying requirement."""
        requirement = self.json_object.get('requirement', {})
        if isinstance(requirement, dict):
            return requirement.get('associated_reference_controls', [])
        return []

    def get_associated_reference_control_ids(self):
        """Return the IDs of the reference controls attached to the requirement."""
        return [control.get('id', '') for control in self.get_associated_reference_controls() if isinstance(control, dict)]

    def get_assessment_status(self):
        """Return the assessment status."""
        return self.json_object.get('status', '')

    def get_assessment_results(self):
        """Return the assessment result."""
        return self.json_object.get('result', '')

    def is_unassessed_result(self):
        """Return True when the result is missing, null, or explicitly unassessed."""
        result = self.get_assessment_results()
        if result is None:
            return True
        if isinstance(result, str):
            return result.strip().lower() in ['', 'not_assessed', 'null', 'none']
        return False

    def get_asset_id_list(self):
        """Return the asset IDs linked to the requirement assessment."""
        return self.json_object.get('assets', [])

    def get_score(self):
        """Return the assessment score."""
        return self.json_object.get('score', '')

    def get_urn(self):
        """Return the requirement URN."""
        requirement = self.json_object.get('requirement', {})
        if isinstance(requirement, dict):
            return requirement.get('urn', '')
        return ''

    def print_name(self):
        """Print the requirement assessment name."""
        print(f"Name: {self.get_name()}")

    def print_id(self):
        """Print the requirement assessment ID."""
        print(f"ID: {self.get_id()}")

    def print_perimeter_id(self):
        """Print the associated perimeter ID."""
        print(f"Perimeter ID: {self.get_perimeter_id()}")

    def print_compliance_assessment_id(self):
        """Print the parent compliance assessment ID."""
        print(f"Compliance Assessment ID: {self.get_compliance_assessment_id()}")

    def print_requirement_id(self):
        """Print the specific requirement ID."""
        print(f"Requirement ID: {self.get_requirement_id()}")

    def print_associated_reference_controls(self):
        """Print the associated reference controls."""
        print(f"Associated Reference Controls: {self.get_associated_reference_controls()}")

    def print_assets(self):
        """Print the associated assets."""
        print(f"Assets: {self.get_asset_id_list()}")

    def create_and_assign_applied_controls(self):
        """Placeholder for future logic creating applied controls from assessment results."""
        for results in self.get_assessment_results():
            for control in self.get_associated_reference_controls():
                utils.log("Creating applied control for control " + control.get('id', '') + " based on assessment results: " + results)

    def print_score(self):
        """Log the requirement assessment score."""
        utils.log(f"Score: {self.get_score()}")

    def print_urn(self):
        """Log the requirement URN."""
        utils.log(f"URN: {self.get_urn()}")


class RequirementAssessmentDict:
    """Handle a collection of requirement assessments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Refresh the internal requirement assessment dictionary from the API."""
        self.requirement_assessments = {}
        for ra in utils.get_all_results("/api/requirement-assessments/"):
            self.requirement_assessments[ra.get('id')] = RequirementAssessment(ra)

    def get_requirement_assessments(self):
        """Return the current requirement assessment dictionary."""
        self.reload()
        return self.requirement_assessments

    def print_requirement_assessments(self):
        """Log details for all requirement assessments."""
        self.reload()
        for ra in self.requirement_assessments.values():
            ra.print_name()
            ra.print_id()
            ra.print_perimeter_id()
            ra.print_compliance_assessment_id()
            ra.print_requirement_id()
            ra.print_associated_reference_controls()
            ra.print_assets()
            ra.print_score()
            ra.print_urn()

    def print_requirement_assessment_json(self):
        """Log the raw JSON data for all requirement assessments."""
        self.reload()
        for ra in self.requirement_assessments.values():
            utils.log(f"Requirement assessment JSON for ID: {ra.get_id()}")
            utils.log(ra.get_requirement_json())
            utils.log("\n")

    def log_assessment_results_for_compliance_assessment_id(self, compliance_assessment_id):
        """Log each requirement assessment result and selected answer for a compliance assessment."""
        self.reload()
        found = False
        for ra in self.requirement_assessments.values():
            if ra.get_compliance_assessment_id() != compliance_assessment_id:
                continue
            found = True
            utils.log(
                f"Assessment debug | CA={compliance_assessment_id} | "
                f"URN={ra.get_urn()} | result={ra.get_assessment_results()} | "
                f"score={ra.get_score()} | answers={ra.get_answers()}"
            )
        if not found:
            utils.log(
                f"Assessment debug | CA={compliance_assessment_id} | no requirement assessments found"
            )
        return found

    def get_requirement_assessment_id_list_from_compliance_assessment_id(self, compliance_assessment_id):
        """Return all requirement assessment IDs belonging to one compliance assessment."""
        self.reload()
        requirement_assessment_ids = []
        for ra in self.requirement_assessments.values():
            if ra.get_compliance_assessment_id() == compliance_assessment_id:
                requirement_assessment_ids.append(ra.get_id())
        return requirement_assessment_ids

    def assign_requirements_to_perimeter_owner(self, perimeter_dict, compliance_assessment_dict, requirement_assessment_dict, requirement_assignment_dict):
        """Create assignments for all non-assigned requirement assessments."""
        assigned_assessments = requirement_assignment_dict.get_requirement_assignment_id_list()
        created = False

        for ca in compliance_assessment_dict.get_compliance_assessments().values():
            req_assigned_ids = requirement_assignment_dict.get_requirement_assignment_id_list_from_compliance_assessment_id(ca.get_id())
            req_assessment_ids = self.get_requirement_assessment_id_list_from_compliance_assessment_id(ca.get_id())
            unassigned_assessments = list(set(assigned_assessments) ^ set(req_assessment_ids))

            if req_assigned_ids == []:
                utils.log(
                    "Creating assignment for unassigned requirement assessments: "
                    + str(unassigned_assessments)
                    + " in compliance assessment: "
                    + ca.get_name()
                )
                payload = {
                    "requirement_assessments": unassigned_assessments,
                    "compliance_assessment": ca.get_id(),
                    "folder": perimeter_dict.get_folder_uuid_from_perimeter_id(ca.get_perimeter_id()),
                    "actor": [perimeter_dict.get_owner_id_from_perimeter_id(ca.get_perimeter_id())]
                }
                req_assign_json = utils.get_return("/api/requirement-assignments/", method="POST", payload=payload)
                utils.get_return(
                    f"/api/requirement-assignments/{req_assign_json.get('id')}/set_status/",
                    method="POST",
                    payload={"status": "in_progress"}
                )
                created = True
            else:
                utils.log(f"Requirement assessments are already assigned for compliance assessment: {ca.get_name()}")
                utils.log(f"Requirement assessments: {req_assessment_ids}")

        if created:
            self.reload()
            requirement_assignment_dict.reload()

    def get_associated_reference_controls(self):
        """Log associated reference controls for requirement assessments with results."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if not ra.is_unassessed_result():
                utils.log(f"Assessment results: {ra.get_assessment_results()}")
                utils.log(f"Associated reference controls: {ra.get_associated_reference_controls()}")

    def get_associated_reference_control_ids(self):
        """Return the unique reference control IDs linked to current assessments."""
        self.reload()
        control_ids = []
        for ra in self.requirement_assessments.values():
            control_ids.extend(ra.get_associated_reference_control_ids())
        return list(set(control_ids))

    def print_assessment_results(self):
        """Log assessment results and associated reference controls."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if not ra.is_unassessed_result():
                utils.log(f"Assessment results: {ra.get_assessment_results()}")
                utils.log(f"Associated reference controls: {ra.get_associated_reference_control_ids()}")

    def create_or_update_applied_controls(self, applied_control_dict, perimeter_dict, reference_control_dict, compliance_assessment_dict):
        """Create or update applied controls from current requirement assessments."""
        self.reload()
        applied_control_dict.reload()
        applied_control_dict.create_missing_applied_controls(perimeter_dict, self, reference_control_dict, compliance_assessment_dict)

    def update_asset_criticality(self, criticality_mapping, asset_dict):
        """Update asset criticality fields using assessment answers and mapping rules."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if not ra.is_unassessed_result():
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
                            asset_ids = ra.get_asset_id_list()
                            utils.log(f"Associated asset IDs: {asset_ids}")
                            for asset_id in asset_ids:
                                utils.log(f"Updating criticality for asset ID: {asset_id}")
                                asset_dict.update_asset_criticality(asset_id, 'criticality', criteria_mapping[answer])

    def create_applied_controls(self, perimeter_dict, reference_control_dict, compliance_assessment_dict):
        """Generate applied controls based on requirement assessment results."""
        self.reload()
        utils.log("Creating applied controls...")
        created = 0

        for ra in self.requirement_assessments.values():
            if ra.is_unassessed_result():
                continue

            for control_id in ra.get_associated_reference_control_ids():
                payload = {
                    "name": f"{reference_control_dict.get_name_from_id(control_id)} on {perimeter_dict.get_name_from_id(ra.get_perimeter_id())}",
                    "reference_control": control_id,
                    "owner": [perimeter_dict.get_owner_id_from_perimeter_id(ra.get_perimeter_id())],
                    "assets": compliance_assessment_dict.get_asset_id_list_from_compliance_assessment_id(ra.get_compliance_assessment_id()),
                    "compliance_assessments": [ra.get_compliance_assessment_id()],
                    "requirement_assessments": [ra.get_id()],
                    "status": "active" if ra.get_assessment_results() == "compliant" else "to_do"
                }
                utils.get_return("/api/applied-controls/", method="POST", payload=payload)
                created += 1

        if created > 0:
            utils.log(f"Created {created} applied controls.")
        else:
            utils.log("No new applied controls created.")

    def get_score_from_compliance_assessment_id_and_urn(self, compliance_assessment_id, requirement_node_urn):
        """Return the score for a requirement node within a given compliance assessment."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.get_compliance_assessment_id() == compliance_assessment_id and ra.get_urn() == requirement_node_urn:
                return ra.get_score()
        return None


class RequirementAssignment:
    """Represent a task assigning requirement assessments to an actor."""

    def __init__(self, json_ra):
        """Initialize from the API payload."""
        self.json_object = json_ra

    def get_name(self):
        """Return the assignment name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the assignment UUID."""
        return self.json_object.get('id', '')

    def get_compliance_assessment_id(self):
        """Return the linked compliance assessment ID."""
        utils.log(self.json_object.get('compliance_assessment', ''))
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '')
        return str(compliance_assessment)

    def get_requirement_assessment_id_list(self):
        """Return the list of requirement assessment IDs included in this assignment."""
        requirement_assessments = self.json_object.get('requirement_assessments', [])
        if not isinstance(requirement_assessments, list):
            return []
        return [ra.get('id', '') for ra in requirement_assessments if isinstance(ra, dict)]

    def print_id(self):
        """Log the assignment ID."""
        utils.log(f"Requirement assignment ID: {self.get_id()}")

    def print_name(self):
        """Log the assignment name."""
        utils.log(f"Requirement assignment name: {self.get_name()}")

    def print_json(self):
        """Log the raw JSON data."""
        utils.log(self.json_object)


class RequirementAssignmentDict:
    """Manage a collection of requirement assignments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Refresh the internal assignment list from the API."""
        self.requirement_assignments = [
            RequirementAssignment(ra) for ra in utils.get_all_results("/api/requirement-assignments/")
        ]

    def get_requirement_assignments(self):
        """Return the assignment objects."""
        return self.requirement_assignments

    def print_requirement_assignments(self):
        """Log details for all assignments."""
        for ra in self.requirement_assignments:
            ra.print_id()
            ra.print_name()
            print(ra.get_requirement_assessment_id_list())

    def print_requirement_assignment_id_list(self):
        """Log the list of requirement IDs for every assignment."""
        for ra in self.requirement_assignments:
            utils.log("Requirement assignment ID list:")
            utils.log(ra.get_requirement_assessment_id_list())

    def print_requirement_assignment_json(self):
        """Log the raw JSON for all assignments."""
        for ra in self.requirement_assignments:
            ra.print_json()

    def get_requirement_assignment_id_list(self):
        """Return the IDs of all requirement assessments assigned across all assignments."""
        requirement_assignment_ids = []
        for ra in self.requirement_assignments:
            requirement_assignment_ids.extend(ra.get_requirement_assessment_id_list())
        return requirement_assignment_ids

    def get_requirement_assignment_id_list_from_compliance_assessment_id(self, compliance_assessment_id):
        """Return the assignment IDs for a specific compliance assessment."""
        self.reload()
        requirement_assignment_ids = []
        for ra in self.requirement_assignments:
            if ra.get_compliance_assessment_id() == compliance_assessment_id:
                requirement_assignment_ids.append(ra.get_id())
        return requirement_assignment_ids    
    

             
