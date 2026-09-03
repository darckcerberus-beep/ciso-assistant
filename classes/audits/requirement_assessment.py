"""Requirement assessment models and collection helpers."""

import logging

from .. import utils


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
        framework = self.json_object.get('framework', {})
        if isinstance(framework, dict):
            return framework.get('id', '')
        return '' if framework in (None, '', {}) else str(framework)

    def get_perimeter_id(self):
        """Return the perimeter ID."""
        perimeter = self.json_object.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return '' if perimeter in (None, '', {}) else str(perimeter)

    def get_compliance_assessment_id(self):
        """Return the parent compliance assessment ID."""
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '') or ''
        if compliance_assessment in (None, '', {}):
            return ''
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

    def get_requirement_ref_id(self):
        """Return the underlying requirement's ref_id."""
        requirement = self.json_object.get('requirement', {})
        if isinstance(requirement, dict):
            return requirement.get('ref_id', '')
        return ''

    def get_questions(self):
        """Return the question definitions ({question_urn: {type, text, choices}}) for this requirement."""
        requirement = self.json_object.get('requirement', {})
        if isinstance(requirement, dict):
            return requirement.get('questions', {}) or {}
        return {}

    def update_answers(self, answers, result=None, observation=None, merge=True):
        """PATCH this requirement assessment's answers (and optionally result/observation).

        Args:
            answers: dict mapping question URN to the answer value (choice URN string for
                unique_choice questions, list of choice URNs for multiple_choice questions).
            result: optional assessment result to set (e.g. "compliant", "non_compliant").
            observation: optional observation/comment text to set.
            merge: when True (default), merge the provided answers onto the existing ones
                instead of replacing them outright.

        Returns:
            The updated requirement assessment JSON, or None if the request failed.
        """
        payload = {}
        if merge:
            merged_answers = dict(self.get_answers())
            merged_answers.update(answers)
            payload['answers'] = merged_answers
        else:
            payload['answers'] = answers

        if result is not None:
            payload['result'] = result
        if observation is not None:
            payload['observation'] = observation

        utils.log(f"Updating answers for requirement assessment ID: {self.get_id()} with payload: {payload}")
        response = utils.get_return(f"/api/requirement-assessments/{self.get_id()}/", method="PATCH", payload=payload)
        if not response or 'error' in response:
            utils.log(f"Failed to update requirement assessment ID {self.get_id()}: {response}", level=logging.ERROR)
            return None
        self.json_object = response
        return response

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
        for ra in utils.get_all_results("/api/requirement-assessments/", force_reload=True):
            self.requirement_assessments[ra.get('id')] = RequirementAssessment(ra)

    def get_requirement_assessments(self):
        """Return the current requirement assessment dictionary."""
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

    def has_answers_for_compliance_assessment(self, compliance_assessment_id) -> bool:
        """Return True when at least one requirement assessment in the compliance assessment has an answer.

        This is used to decide whether it makes sense to create derived objects
        (applied controls, risk assessments) for a compliance assessment.
        """
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.get_compliance_assessment_id() != compliance_assessment_id:
                continue
            # If any requirement assessment has a selected answer and is not unassessed, consider the CA answered
            if not ra.is_unassessed_result() and ra.has_selected_answer():
                return True
        return False

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
                if isinstance(req_assign_json, dict):
                    utils.start_requirement_assignment(req_assign_json.get('id', ''))
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

    def get_score_from_compliance_assessment_id_and_urn(self, compliance_assessment_id, requirement_node_urn, refresh: bool = True):
        """Return the score for a requirement node within a given compliance assessment.

        Args:
            compliance_assessment_id: ID of the compliance assessment to search within.
            requirement_node_urn: URN of the requirement node to match.
            refresh: When True (default), reload from the API before searching. Set to False when the caller already has fresh data.
        """
        if refresh:
            self.reload()
        for ra in self.requirement_assessments.values():
            if ra.get_compliance_assessment_id() == compliance_assessment_id and ra.get_urn() == requirement_node_urn:
                return ra.get_score()
        return None

    def get_requirement_assessment_by_identifier(self, compliance_assessment_id, identifier, refresh: bool = False):
        """Find a requirement assessment within a compliance assessment by URN or ref_id.

        Args:
            compliance_assessment_id: ID of the compliance assessment to search within.
            identifier: The requirement's URN or ref_id (matched case-insensitively).
            refresh: When True, reload from the API before searching.

        Returns:
            The matching RequirementAssessment, or None if not found.
        """
        if refresh:
            self.reload()
        identifier_normalized = str(identifier).strip().lower()
        for ra in self.requirement_assessments.values():
            if ra.get_compliance_assessment_id() != compliance_assessment_id:
                continue
            if ra.get_urn().strip().lower() == identifier_normalized:
                return ra
            if ra.get_requirement_ref_id().strip().lower() == identifier_normalized:
                return ra
        return None
