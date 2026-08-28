import classes.framework as framework
import classes.audit as audit
import classes.organization as organization
import classes.control as control
import classes.risk as risk
import classes.user as user
import classes.task as task
import classes.utils as utils
import json



def main():
    RequirementAssessmentDict = audit.RequirementAssessmentDict()
    RequirementAssessmentDict.printRequirementAssessments()
    ComplianceAssessmentDict = audit.ComplianceAssessmentDict()
    RequirementAssignmentDict = audit.RequirementAssignmentDict()
    PerimeterDict = organization.PerimeterDict()
    AssetDict = organization.AssetDict()
    FrameworkDict = framework.FrameworkDict()
    Framework = framework.FrameworkFile("YML/newDPP.yml")
    ReferenceControlDict = control.ReferenceControlDict()
    AppliedControlDict = control.AppliedControlDict()
    RiskAssessmentDict = risk.RiskAssessmentDict()
    RiskScenarioDict = risk.RiskScenarioDict()
    UserDict = user.UserDict()
    ComplianceAssessmentDict.CreateRiskAssessments(RiskAssessmentDict,RiskScenarioDict,Framework,RequirementAssessmentDict)
    """
    Framework = framework.FrameworkFile("YML/newDPP.yml")
    Framework.printRiskScenario()
    
    PerimeterDict = organization.PerimeterDict()
    AssetDict = organization.AssetDict()
    FrameworkDict = framework.FrameworkDict()
    ComplianceAssessmentDict = audit.ComplianceAssessmentDict()
    ComplianceAssessmentDict.getScoreFromRequirementNodeName("urn:intuitem:risk:req_node:mls:stakeholder_identifications")
    #RequirementAssessmentDict = audit.RequirementAssessmentDict()
    #RequirementAssessmentDict.printRequirementAssessments()
    RequirementAssignmentDict = audit.RequirementAssignmentDict()
    RequirementAssignmentDict.printRequirementAssignmentJSON()
    FrameworkDict = framework.FrameworkDict()
    FrameworkDict.printFrameworkJSON()
    Framework = framework.FrameworkFile("YML/newDPP.yml")
    ReferenceControlDict = control.ReferenceControlDict()
    AppliedControlDict = control.AppliedControlDict()
    RequirementAssessmentDict = audit.RequirementAssessmentDict()
    RequirementAssignmentDict = audit.RequirementAssignmentDict()

    UserDict = user.UserDict()

    ActorDict = user.ActorDict()

    PerimeterDict = organization.PerimeterDict()
    RiskAssessmentDict = risk.RiskAssessmentDict()
    RiskScenarioDict = risk.RiskScenarioDict()
    AssetDict.createMissingAssets(PerimeterDict)
    AssetDict.reload()
    
    ComplianceAssessmentDict.CreateMissingComplianceAssessments(FrameworkDict, PerimeterDict, AssetDict)
    ComplianceAssessmentDict.assignRequirementsToPerimeterOwner(PerimeterDict,ComplianceAssessmentDict,RequirementAssessmentDict,RequirementAssignmentDict)

    ComplianceAssessmentDict.CreateMissingAppliedControls(AppliedControlDict,PerimeterDict,ReferenceControlDict)
    ComplianceAssessmentDict.UpdateAssetCriticality(organization.CRITICALITY_MAPPING, AssetDict)
    ComplianceAssessmentDict.CreateRiskAssessments(RiskAssessmentDict,RiskScenarioDict,Framework)
    #AppliedControlDict.printJSON()

   
    #ComplianceAssessmentDict.printJSON()

    #RiskAssessmentDict = risk.RiskAssessmentDict()
    #RiskAssessmentDict.printRiskAssessments()

    #RiskScenarioDict = risk.RiskScenarioDict()
    #RiskScenarioDict.printRiskScenarioJSON()
    #RiskScenarioDict.createRiskScenario("Nom de toto","description de toto","03029b82-9cfc-4c0a-a99f-8a863bcfe81a",2,3,1,1,[])
    #AssetDict.printAssets()
    #print(RiskScenarioDict.CreateRiskScenario("Nom de toto","description de toto","02c55898-a664-4207-a63f-f9776574b039"))

    #RiskMatrixDict = risk.RiskMatrixDict()
    #RiskMatrixDict.printRiskMatrices()
    #VulnerabilityDict = risk.VulnerabilityDict()
    #VulnerabilityDict.printVulnerabilityJSON()
    
"""

if __name__ == "__main__":
    main()
