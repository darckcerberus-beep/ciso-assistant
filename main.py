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

    
    PerimeterDict = organization.PerimeterDict()
    AssetDict = organization.AssetDict()
    FrameworkDict = framework.FrameworkDict()
    ComplianceAssessmentDict = audit.ComplianceAssessmentDict()
    FrameworkDict = framework.FrameworkDict()
    ReferenceControlDict = control.ReferenceControlDict()
    AppliedControlDict = control.AppliedControlDict()
    RequirementAssessmentDict = audit.RequirementAssessmentDict()
    RequirementAssignmentDict = audit.RequirementAssignmentDict()
    #RequirementAssignmentDict.printRequirementAssignmentJSON()
    #DomainDict = organization.DomainDict()
    UserDict = user.UserDict()

    ActorDict = user.ActorDict()

    PerimeterDict = organization.PerimeterDict()

    AssetDict.createMissingAssets(PerimeterDict)
    AssetDict.reload()
    ComplianceAssessmentDict.CreateMissingComplianceAssessments(FrameworkDict, PerimeterDict, AssetDict)
    ComplianceAssessmentDict.assignRequirementsToPerimeterOwner(PerimeterDict,ComplianceAssessmentDict,RequirementAssessmentDict,RequirementAssignmentDict)
    #ComplianceAssessmentDict.CreateAppliedControls(PerimeterDict, ReferenceControlDict) 
    ComplianceAssessmentDict.CreateMissingAppliedControls(AppliedControlDict,PerimeterDict,ReferenceControlDict)
    #AppliedControlDict.printJSON()

    #RiskAssessmentDict = risk.RiskAssessmentDict()
    #RiskAssessmentDict.printRiskAssessments()

    #RiskScenarioDict = risk.RiskScenarioDict()
    #RiskScenarioDict.printRiskScenarioJSON()
    #AssetDict.printAssets()
    #print(RiskScenarioDict.CreateRiskScenario("Nom de toto","description de toto","02c55898-a664-4207-a63f-f9776574b039"))

    #RiskMatrixDict = risk.RiskMatrixDict()
    #RiskMatrixDict.printRiskMatrices()
    #VulnerabilityDict = risk.VulnerabilityDict()
    #VulnerabilityDict.printVulnerabilityJSON()



if __name__ == "__main__":
    main()
