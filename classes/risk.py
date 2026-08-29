from . import utils
import pprint


class RiskAssessment:
    """Represents a single risk assessment object."""

    def __init__(self, json_risk):
        # Fetch the full record for this risk assessment.
        self.json_object = utils.get_return(
            "/api/risk-assessments/" + json_risk.get('id') + "/"
        )

    def getJSON(self):
        return self.json_object

    def getName(self):
        return self.json_object.get('name', '')

    def getID(self):
        return self.json_object.get('id', '')

    def getRiskID(self):
        return self.json_object.get('risk', '')

    def getStatus(self):
        return self.json_object.get('status', '')

    def printName(self):
        utils.log(f"Risk Assessment Name: {self.getName()}")

    def printID(self):
        utils.log(f"Risk Assessment ID: {self.getID()}")


class RiskAssessmentDict:
    """Handles a collection of risk assessments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload the dictionary from the API."""
        self.risk_assessments = {}
        for ra in utils.get_all_results("/api/risk-assessments/"):
            self.risk_assessments[ra.get('id')] = RiskAssessment(ra)

    def getRiskAssessments(self):
        return self.risk_assessments

    def printRiskAssessments(self):
        """Print names and IDs for all risk assessments."""
        for ra in self.risk_assessments.values():
            ra.printName()
            ra.printID()

    def CreateRiskAssessments(self, name, domain, perimeter, risk_matrix):
        """Create a risk assessment if it does not already exist."""
        for ra in self.risk_assessments.values():
            if ra.getName() == name:
                return ra.getJSON()

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

    def getJSON(self):
        return self.json_object

    def getName(self):
        return self.json_object.get('name', '')

    def getID(self):
        return self.json_object.get('id', '')

    def getRelatedIDs(self, field_name):
        """Return IDs from a many-to-many scenario field."""
        related_objects = self.json_object.get(field_name, [])
        if not isinstance(related_objects, list):
            return []
        return [
            related_object.get('id', '') if isinstance(related_object, dict) else related_object
            for related_object in related_objects
        ]

    def updateRelationships(self, existing_control_ids, planned_control_ids, asset_ids, owner_ids):
        """Add controls, assets, and owners without removing existing links."""
        relationship_updates = {
            "existing_applied_controls": existing_control_ids,
            "applied_controls": planned_control_ids,
            "assets": asset_ids,
            "owner": owner_ids,
        }
        payload = {}
        for field_name, related_ids in relationship_updates.items():
            merged_ids = list(dict.fromkeys(self.getRelatedIDs(field_name) + related_ids))
            if merged_ids != self.getRelatedIDs(field_name):
                payload[field_name] = merged_ids

        if not payload:
            return self.json_object

        response = utils.get_return(
            f"/api/risk-scenarios/{self.getID()}/",
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

    def getRiskScenarios(self):
        return self.risk_scenarios

    def printRiskScenarios(self):
        for rs in self.risk_scenarios.values():
            print(rs.getName())
            print(rs.getID())

    def printRiskScenarioJSON(self):
        for rs in self.risk_scenarios.values():
            print("Risk Scenario JSON:")
            print(rs.getJSON())

    def createRiskScenario(
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
        for scenario in self.risk_scenarios.values():
            scenario_json = scenario.getJSON()
            risk_assessment = scenario_json.get("risk_assessment")
            if isinstance(risk_assessment, dict):
                risk_assessment = risk_assessment.get("id")
            if (
                scenario.getName() == name
                and risk_assessment == risk_assessment_id
            ):
                return scenario.updateRelationships(
                    existing_applied_controls or [],
                    applied_controls or [],
                    assets or [],
                    owners or [],
                )

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
        return utils.get_return("/api/risk-scenarios/", method="POST", payload=payload)


class RiskMatrix:
    """Represents a single risk matrix object."""

    def __init__(self, json_matrix):
        self.json_object = utils.get_return(
            "/api/risk-matrices/" + json_matrix.get('id') + "/"
        )

    def getJSON(self):
        return self.json_object


class RiskMatrixDict:
    """Handles a collection of risk matrices."""

    def __init__(self):
        self.reload()

    def reload(self):
        self.risk_matrices = {}
        for rm in utils.get_all_results("/api/risk-matrices/"):
            self.risk_matrices[rm.get('id')] = RiskMatrix(rm)

    def getRiskMatrices(self):
        return self.risk_matrices

    def printRiskMatrices(self):
        for rm in self.risk_matrices.values():
            pprint.pprint(rm.getJSON())

    def getRiskMatrixIDByLibraryID(self, library_id):
        """Return the matrix ID matching a given library ID."""
        for rm in self.risk_matrices.values():
            library = rm.getJSON().get('library') or {}
            if library.get('id') == library_id:
                return rm.getJSON().get('id')
        return None


class Vulnerability:
    """Represents a single vulnerability object."""

    def __init__(self, json_vulnerability):
        self.json_object = utils.get_return(
            "/api/vulnerabilities/" + json_vulnerability.get('id') + "/"
        )

    def getJSON(self):
        return self.json_object

    def getName(self):
        return self.json_object.get('name', '')

    def getID(self):
        return self.json_object.get('id', '')


class VulnerabilityDict:
    """Handles a collection of vulnerabilities."""

    def __init__(self):
        self.reload()

    def reload(self):
        self.vulnerabilities = {}
        for v in utils.get_all_results("/api/vulnerabilities/"):
            self.vulnerabilities[v.get('id')] = Vulnerability(v)

    def getVulnerabilities(self):
        return self.vulnerabilities

    def printVulnerabilities(self):
        for v in self.vulnerabilities.values():
            print(v.getName())
            print(v.getID())

    def printVulnerabilityJSON(self):
        for v in self.vulnerabilities.values():
            print("Vulnerability JSON:")
            print(v.getJSON())



