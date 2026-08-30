import logging
import pprint

from . import utils


class RiskAssessment:
    """Represents a single risk assessment object."""

    def __init__(self, json_risk):
        # Fetch the full record for this risk assessment.
        self.json_object = utils.get_return(
            "/api/risk-assessments/" + json_risk.get('id') + "/"
        )

    def get_json(self):
        return self.json_object

    def get_name(self):
        return self.json_object.get('name', '')

    def get_id(self):
        return self.json_object.get('id', '')

    def get_risk_id(self):
        return self.json_object.get('risk', '')

    def get_status(self):
        return self.json_object.get('status', '')

    def print_name(self):
        utils.log(f"Risk Assessment Name: {self.get_name()}")

    def print_id(self):
        utils.log(f"Risk Assessment ID: {self.get_id()}")


class RiskAssessmentDict:
    """Handles a collection of risk assessments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload the dictionary from the API."""
        self.risk_assessments = {}
        for ra in utils.get_all_results("/api/risk-assessments/"):
            self.risk_assessments[ra.get('id')] = RiskAssessment(ra)

    def get_risk_assessments(self):
        return self.risk_assessments

    def print_risk_assessments(self):
        """Print names and IDs for all risk assessments."""
        for ra in self.risk_assessments.values():
            ra.print_name()
            ra.print_id()

    def create_risk_assessments(self, name, domain, perimeter, risk_matrix):
        """Create a risk assessment if it does not already exist."""
        for ra in self.risk_assessments.values():
            if ra.get_name() == name:
                return ra.get_json()

        payload = {
            "name": name,
            "domain": domain,
            "perimeter": perimeter,
            "risk_matrix": risk_matrix,
        }
        return utils.get_return("/api/risk-assessments/", method="POST", payload=payload)


class RiskScenario:
    """Represents a single risk scenario object."""

    def __init__(self, json_scenario):
        self.json_object = utils.get_return(
            "/api/risk-scenarios/" + json_scenario.get('id') + "/"
        )

    def get_json(self):
        return self.json_object

    def get_name(self):
        return self.json_object.get('name', '')

    def get_id(self):
        return self.json_object.get('id', '')

    def get_related_ids(self, field_name):
        """Return IDs from a many-to-many scenario field."""
        related_objects = self.json_object.get(field_name, [])
        if not isinstance(related_objects, list):
            return []
        return [
            related_object.get('id', '') if isinstance(related_object, dict) else related_object
            for related_object in related_objects
        ]

    def update_relationships(self, existing_control_ids, planned_control_ids, asset_ids, owner_ids):
        """Add controls, assets, and owners without removing existing links."""
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
    """Handles a collection of risk scenarios."""

    def __init__(self):
        self.reload()

    def reload(self):
        self.risk_scenarios = {}
        for rs in utils.get_all_results("/api/risk-scenarios/"):
            self.risk_scenarios[rs.get('id')] = RiskScenario(rs)

    def get_risk_scenarios(self):
        return self.risk_scenarios

    def print_risk_scenarios(self):
        for rs in self.risk_scenarios.values():
            print(rs.get_name())
            print(rs.get_id())

    def print_risk_scenario_json(self):
        for rs in self.risk_scenarios.values():
            print("Risk Scenario JSON:")
            print(rs.get_json())

    def delete_risk_scenario(self, name, risk_assessment_id):
        """Delete the matching scenario when its prerequisite is no longer applicable."""
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
        """Create a risk scenario payload for the API.

        The API expects 0-based values, while the inputs are typically 1-based.
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
        self.json_object = utils.get_return(
            "/api/risk-matrices/" + json_matrix.get('id') + "/"
        )

    def get_json(self):
        return self.json_object


class RiskMatrixDict:
    """Handles a collection of risk matrices."""

    def __init__(self):
        self.reload()

    def reload(self):
        self.risk_matrices = {}
        for rm in utils.get_all_results("/api/risk-matrices/"):
            self.risk_matrices[rm.get('id')] = RiskMatrix(rm)

    def get_risk_matrices(self):
        return self.risk_matrices

    def print_risk_matrices(self):
        for rm in self.risk_matrices.values():
            pprint.pprint(rm.get_json())

    def get_risk_matrix_id_by_library_id(self, library_id):
        """Return the matrix ID matching a given library ID."""
        for rm in self.risk_matrices.values():
            library = rm.get_json().get('library') or {}
            if library.get('id') == library_id:
                return rm.get_json().get('id')
        return None


class Vulnerability:
    """Represents a single vulnerability object."""

    def __init__(self, json_vulnerability):
        self.json_object = utils.get_return(
            "/api/vulnerabilities/" + json_vulnerability.get('id') + "/"
        )

    def get_json(self):
        return self.json_object

    def get_name(self):
        return self.json_object.get('name', '')

    def get_id(self):
        return self.json_object.get('id', '')


class VulnerabilityDict:
    """Handles a collection of vulnerabilities."""

    def __init__(self):
        self.reload()

    def reload(self):
        self.vulnerabilities = {}
        for v in utils.get_all_results("/api/vulnerabilities/"):
            self.vulnerabilities[v.get('id')] = Vulnerability(v)

    def get_vulnerabilities(self):
        return self.vulnerabilities

    def print_vulnerabilities(self):
        for v in self.vulnerabilities.values():
            print(v.get_name())
            print(v.get_id())

    def print_vulnerability_json(self):
        for v in self.vulnerabilities.values():
            print("Vulnerability JSON:")
            print(v.get_json())



