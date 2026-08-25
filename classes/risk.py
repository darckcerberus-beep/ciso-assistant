from . import utils
import pprint

class RiskAssessment:
    """Represents a single risk assessment object."""
    def __init__(self, json_risk):
        self.json_object = utils.get_return("/api/risk-assessments/"+json_risk.get('id')+"/")

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
        print(f"Risk Assessment Name: {self.getName()}")

    def printID(self):
        print(f"Risk Assessment ID: {self.getID()}")

class RiskAssessmentDict:
    """Handles a collection of RiskAssessments."""
    def __init__(self):
        self.reload()

    def reload(self):
        self.risk_assessments = {}
        for ra in utils.get_all_results("/api/risk-assessments/"):
            self.risk_assessments[ra.get('id')] = RiskAssessment(ra)

    def getRiskAssessments(self):
        return self.risk_assessments



    def getRiskAssessments(self):
        return self.risk_assessments

    def printRiskAssessments(self):
        for ra in self.risk_assessments.values():
            ra.printName()
            ra.printID()

class RiskScenario:
    """Represents a single risk scenario object."""
    def __init__(self, json_scenario):
        self.json_object = utils.get_return("/api/risk-scenarios/"+json_scenario.get('id')+"/")

    def getJSON(self):
        return self.json_object

    def getName(self):
        return self.json_object.get('name', '')

    def getID(self):
        return self.json_object.get('id', '')

class RiskScenarioDict:
    """Handles a collection of RiskScenarios."""
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
    def createRiskScenario(self, name, description, risk_assessment_id, current_proba, current_impact, residual_proba, residual_impact, existing_applied_controls=[]):
        payload = {
            "name": name,
            "description": description,
            "risk_assessment": risk_assessment_id,
            "current_proba": current_proba-1,
            "current_impact": current_impact-1,
            "residual_proba": residual_proba-1,
            "residual_impact": residual_impact-1,
            "existing_applied_controls": existing_applied_controls,
        }
        return utils.get_return("/api/risk-scenarios/", method="POST", payload=payload)


class RiskMatrix:
    """Represents a single risk matrix object."""
    def __init__(self, json_matrix):
        self.json_object = utils.get_return("/api/risk-matrices/"+json_matrix.get('id')+"/")

    def getJSON(self):
        return self.json_object
    
class RiskMatrixDict:
    """Handles a collection of RiskMatrices."""
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


class Vulnerability:
    """Represents a single vulnerability object."""
    def __init__(self, json_vulnerability):
        self.json_object = utils.get_return("/api/vulnerabilities/"+json_vulnerability.get('id')+"/")

    def getJSON(self):
        return self.json_object
    def getName(self):
        return self.json_object.get('name', '')

    def getID(self):
        return self.json_object.get('id', '')


class VulnerabilityDict:
    """Handles a collection of Vulnerabilities."""
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



