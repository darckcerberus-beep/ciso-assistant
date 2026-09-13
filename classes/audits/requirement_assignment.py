"""Requirement assignment models and collection helpers."""

import logging

from .. import utils


def start_requirement_assignment(assignment_id: str) -> bool:
    """Transition a newly created requirement assignment to ``in_progress``."""
    if not assignment_id:
        return False

    response = utils.get_return(
        f'/api/requirement-assignments/{assignment_id}/set_status/',
        method='POST',
        payload={'status': 'in_progress'},
    )
    if not isinstance(response, dict) or response.get('status') != 'in_progress':
        utils.log(
            f"Failed to start requirement assignment {assignment_id}: {response}",
            level=logging.ERROR,
        )
        return False

    assignment = utils.get_return(f'/api/requirement-assignments/{assignment_id}/')
    if isinstance(assignment, dict) and assignment.get('status') == 'in_progress':
        return True

    utils.log(
        f"Requirement assignment {assignment_id} did not persist in_progress status: {assignment}",
        level=logging.ERROR,
    )
    return False


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
        """Return the parent compliance assessment ID."""
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '') or ''
        if compliance_assessment in (None, '', {}):
            return ''
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
            RequirementAssignment(ra) for ra in utils.get_all_results("/api/requirement-assignments/", force_reload=True)
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
