"""Risk assessment, scenario modeling, risk matrix, and vulnerability models.

This module provides the core data structures and API synchronization mechanisms for
CISO Assistant's risk engine:
1. RiskAssessment & RiskAssessmentDict: High-level risk containers associated with perimeters.
2. RiskScenario & RiskScenarioDict: Specific threat/vulnerability realizations with calculated
   likelihood, impact, and associated mitigating controls.
3. RiskMatrix & RiskMatrixDict: 4x4 or custom probability/impact matrix structures.
4. Vulnerability & VulnerabilityDict: Technical or organizational weaknesses linked to threats.
"""

import logging
import pprint

from .. import utils


class RiskAssessment:
    """Represents a single risk assessment object."""

    def __init__(self, json_risk):
        """Initialize risk assessment from API payload or fetch if needed.

        Args:
            json_risk (dict or str): Dictionary payload containing risk assessment data or its UUID.
        """
        if isinstance(json_risk, dict) and "name" in json_risk:
            self.json_object = json_risk
        else:
            risk_id = json_risk.get('id', '') if isinstance(json_risk, dict) else str(json_risk)
            self.json_object = utils.get_return(f"/api/risk-assessments/{risk_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the risk assessment name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')

    def get_risk_id(self):
        """Return the associated risk identifier."""
        return self.json_object.get('risk', '')

    def get_status(self):
        """Return the assessment lifecycle status."""
        return self.json_object.get('status', '')

    def print_name(self):
        """Log the risk assessment name."""
        utils.log(f"Risk Assessment Name: {self.get_name()}")

    def print_id(self):
        """Log the risk assessment UUID."""
        utils.log(f"Risk Assessment ID: {self.get_id()}")


class RiskAssessmentDict:
    """Handles a collection of risk assessments loaded from the API."""

    def __init__(self):
        """Initialize and fetch all risk assessments from the API."""
        self.reload()

    def reload(self):
        """Reload the dictionary of risk assessments from the API."""
        self.risk_assessments = {}
        for ra in utils.get_all_results("/api/risk-assessments/", force_reload=True):
            self.risk_assessments[ra.get('id')] = RiskAssessment(ra)

    def get_risk_assessments(self):
        """Return dictionary of risk assessments keyed by UUID."""
        return self.risk_assessments

    def print_risk_assessments(self):
        """Print names and IDs for all risk assessments."""
        for ra in self.risk_assessments.values():
            ra.print_name()
            ra.print_id()

    def create_risk_assessments(self, name, domain, perimeter, risk_matrix):
        """Create a risk assessment if it does not already exist.

        Args:
            name (str): Unique name for the risk assessment.
            domain (str): Associated domain or framework identifier.
            perimeter (str): Organizational perimeter UUID.
            risk_matrix (str): Risk matrix UUID to bind for probability/impact scoring.

        Returns:
            dict: Raw API JSON dictionary of the existing or newly created risk assessment.
        """
        for ra in self.risk_assessments.values():
            if ra.get_name() == name:
                return ra.get_json()

        payload = {
            "name": name,
            "domain": domain,
            "perimeter": perimeter,
            "risk_matrix": risk_matrix,
        }
        created = utils.get_return("/api/risk-assessments/", method="POST", payload=payload)
        if isinstance(created, dict) and created.get("id"):
            self.risk_assessments[created.get("id")] = RiskAssessment(created)
        return created


class RiskScenario:
    """Represents a single risk scenario object."""

    def __init__(self, json_scenario):
        """Initialize risk scenario from API payload or fetch if needed.

        Args:
            json_scenario (dict or str): Dictionary payload or UUID of the scenario.
        """
        if isinstance(json_scenario, dict) and "name" in json_scenario:
            self.json_object = json_scenario
        else:
            scenario_id = json_scenario.get('id', '') if isinstance(json_scenario, dict) else str(json_scenario)
            self.json_object = utils.get_return(f"/api/risk-scenarios/{scenario_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the risk scenario name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')

    def get_related_ids(self, field_name):
        """Return IDs from a many-to-many scenario field.

        Args:
            field_name (str): Field name containing list of object dicts or IDs.

        Returns:
            list[str]: Clean list of string UUIDs.
        """
        related_objects = self.json_object.get(field_name, [])
        if not isinstance(related_objects, list):
            return []
        return [
            related_object.get('id', '') if isinstance(related_object, dict) else related_object
            for related_object in related_objects
        ]

    def update_relationships(self, existing_control_ids, planned_control_ids, asset_ids, owner_ids):
        """Add controls, assets, and owners without removing existing links.

        Performs an idempotent PATCH only when relationships have changed.

        Args:
            existing_control_ids (list[str]): Implemented / active applied control UUIDs.
            planned_control_ids (list[str]): To-do / planned applied control UUIDs.
            asset_ids (list[str]): Linked perimeter asset UUIDs.
            owner_ids (list[str]): Asset owner user UUIDs.

        Returns:
            dict: API response payload.
        """
        relationship_updates = {
            "existing_applied_controls": existing_control_ids,
            "applied_controls": planned_control_ids,
            "assets": asset_ids,
            "owner": owner_ids,
        }
        payload = {}
        for field_name, related_ids in relationship_updates.items():
            merged_ids = list(dict.fromkeys(self.get_related_ids(field_name) + related_ids))
            if merged_ids != self.get_related_ids(field_name):
                payload[field_name] = merged_ids

        if not payload:
            return self.json_object

        response = utils.get_return(
            f"/api/risk-scenarios/{self.get_id()}/",
            method="PATCH",
            payload=payload,
        )
        if isinstance(response, dict) and not response.get("error"):
            self.json_object = response
        return response


class RiskScenarioDict:
    """Handles a collection of risk scenarios and evaluation logic."""

    def __init__(self):
        """Initialize and fetch all risk scenarios from the API."""
        self.reload()

    def reload(self):
        """Reload all risk scenarios from the API."""
        self.risk_scenarios = {}
        for rs in utils.get_all_results("/api/risk-scenarios/", force_reload=True):
            self.risk_scenarios[rs.get('id')] = RiskScenario(rs)

    def get_risk_scenarios(self):
        """Return dictionary of risk scenarios keyed by UUID."""
        return self.risk_scenarios

    def print_risk_scenarios(self):
        """Log names and IDs of all scenarios."""
        for rs in self.risk_scenarios.values():
            utils.log(f"Scenario Name: {rs.get_name()}, ID: {rs.get_id()}")

    def print_risk_scenario_json(self):
        """Log raw JSON payload for all scenarios."""
        for rs in self.risk_scenarios.values():
            utils.log(f"Risk Scenario JSON:\n{pprint.pformat(rs.get_json())}")

    def delete_risk_scenario(self, name, risk_assessment_id):
        """Delete the matching scenario when its prerequisite is no longer applicable.

        Args:
            name (str): Scenario name.
            risk_assessment_id (str): Parent risk assessment UUID.

        Returns:
            bool or dict: API response result.
        """
        for scenario in list(self.risk_scenarios.values()):
            scenario_json = scenario.get_json()
            scenario_risk_assessment = scenario_json.get("risk_assessment")
            if isinstance(scenario_risk_assessment, dict):
                scenario_risk_assessment = scenario_risk_assessment.get("id")
            if scenario.get_name() != name or scenario_risk_assessment != risk_assessment_id:
                continue

            response = utils.get_return(
                f"/api/risk-scenarios/{scenario.get_id()}/",
                method="DELETE",
            )
            if response is True:
                self.risk_scenarios.pop(scenario.get_id(), None)
                utils.log(f"Deleted no-longer-applicable risk scenario: {name}")
            return response
        return True

    def create_risk_scenario(
        self,
        name,
        description,
        risk_assessment_id,
        current_proba,
        current_impact,
        residual_proba,
        residual_impact,
        existing_applied_controls=None,
        applied_controls=None,
        assets=None,
        owners=None,
    ):
        """Create or update a risk scenario payload for the API.

        Note:
            The CISO Assistant API expects 0-based index values (0 to 3 for a 4x4 matrix),
            while callers pass 1-based domain scores (1 to 4). This method performs the
            `value - 1` conversion automatically.

        Args:
            name (str): Scenario title.
            description (str): Detailed scenario description.
            risk_assessment_id (str): Parent risk assessment UUID.
            current_proba (int): 1-based current probability level (1 to 4).
            current_impact (int): 1-based current impact level (1 to 4).
            residual_proba (int): 1-based residual probability level (1 to 4).
            residual_impact (int): 1-based residual impact level (1 to 4).
            existing_applied_controls (list[str], optional): UUIDs of implemented controls.
            applied_controls (list[str], optional): UUIDs of planned controls.
            assets (list[str], optional): UUIDs of linked perimeter assets.
            owners (list[str], optional): UUIDs of asset owners.

        Returns:
            dict: Created or updated API object.
        """
        if existing_applied_controls is None:
            existing_applied_controls = []
        if applied_controls is None:
            applied_controls = []
        if assets is None:
            assets = []
        if owners is None:
            owners = []

        payload = {
            "name": name,
            "description": description,
            "risk_assessment": risk_assessment_id,
            "current_proba": current_proba - 1,
            "current_impact": current_impact - 1,
            "residual_proba": residual_proba - 1,
            "residual_impact": residual_impact - 1,
            "existing_applied_controls": existing_applied_controls,
            "applied_controls": applied_controls,
            "assets": assets,
            "owner": owners,
        }

        # Check if an existing scenario with the same name exists under this risk assessment
        for scenario in self.risk_scenarios.values():
            scenario_json = scenario.get_json()
            risk_assessment = scenario_json.get("risk_assessment")
            if isinstance(risk_assessment, dict):
                risk_assessment = risk_assessment.get("id")
            if (
                scenario.get_name() == name
                and risk_assessment == risk_assessment_id
            ):
                update_payload = {
                    key: value for key, value in payload.items()
                    if value not in (None, [], {})
                }
                scenario_response = utils.get_return(
                    f"/api/risk-scenarios/{scenario.get_id()}/",
                    method="PATCH",
                    payload=update_payload,
                )
                if isinstance(scenario_response, dict) and not scenario_response.get("error"):
                    scenario.json_object = scenario_response
                    self.risk_scenarios[scenario.get_id()] = scenario
                return scenario_response

        utils.log(f"Creating risk scenario with payload: {payload}", level=logging.DEBUG)
        created = utils.get_return("/api/risk-scenarios/", method="POST", payload=payload)
        if isinstance(created, dict) and created.get("id"):
            self.risk_scenarios[created.get("id")] = RiskScenario(created)
        return created


class RiskMatrix:
    """Represents a single risk matrix object."""

    def __init__(self, json_matrix):
        """Initialize risk matrix from API payload or fetch if needed.

        Args:
            json_matrix (dict or str): Dictionary payload or UUID of the matrix.
        """
        if isinstance(json_matrix, dict) and "name" in json_matrix:
            self.json_object = json_matrix
        else:
            matrix_id = json_matrix.get('id', '') if isinstance(json_matrix, dict) else str(json_matrix)
            self.json_object = utils.get_return(f"/api/risk-matrices/{matrix_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object


class RiskMatrixDict:
    """Handles a collection of risk matrices loaded from the API."""

    def __init__(self):
        """Initialize and fetch all risk matrices from the API."""
        self.reload()

    def reload(self):
        """Reload all risk matrices from the API."""
        self.risk_matrices = {}
        for rm in utils.get_all_results("/api/risk-matrices/", force_reload=True):
            self.risk_matrices[rm.get('id')] = RiskMatrix(rm)

    def get_risk_matrices(self):
        """Return dictionary of risk matrices keyed by UUID."""
        return self.risk_matrices

    def print_risk_matrices(self):
        """Log raw JSON representation of each risk matrix."""
        for rm in self.risk_matrices.values():
            utils.log(pprint.pformat(rm.get_json()))

    def get_risk_matrix_id_by_library_id(self, library_id):
        """Return the matrix ID matching a given library ID.

        Args:
            library_id (str): Library UUID.

        Returns:
            str or None: Matrix UUID if found, None otherwise.
        """
        for rm in self.risk_matrices.values():
            library = rm.get_json().get('library') or {}
            if library.get('id') == library_id:
                return rm.get_json().get('id')
        return None


class Vulnerability:
    """Represents a single vulnerability object."""

    def __init__(self, json_vulnerability):
        """Initialize vulnerability from API payload or fetch if needed.

        Args:
            json_vulnerability (dict or str): Dictionary payload or UUID of the vulnerability.
        """
        if isinstance(json_vulnerability, dict) and "name" in json_vulnerability:
            self.json_object = json_vulnerability
        else:
            vuln_id = json_vulnerability.get('id', '') if isinstance(json_vulnerability, dict) else str(json_vulnerability)
            self.json_object = utils.get_return(f"/api/vulnerabilities/{vuln_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the vulnerability name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')


class VulnerabilityDict:
    """Handles a collection of vulnerabilities."""

    def __init__(self):
        """Initialize and fetch all vulnerabilities from the API."""
        self.reload()

    def reload(self):
        """Reload all vulnerabilities from the API."""
        self.vulnerabilities = {}
        for v in utils.get_all_results("/api/vulnerabilities/", force_reload=True):
            self.vulnerabilities[v.get('id')] = Vulnerability(v)

    def get_vulnerabilities(self):
        """Return dictionary of vulnerabilities keyed by UUID."""
        return self.vulnerabilities

    def print_vulnerabilities(self):
        """Log names and IDs of all vulnerabilities."""
        for v in self.vulnerabilities.values():
            utils.log(f"Vulnerability: {v.get_name()}, ID: {v.get_id()}")

    def print_vulnerability_json(self):
        """Log raw JSON payload for all vulnerabilities."""
        for v in self.vulnerabilities.values():
            utils.log(f"Vulnerability JSON:\n{pprint.pformat(v.get_json())}")
