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

    """
    PerimeterDict = organization.PerimeterDict()
    AssetDict = organization.AssetDict()
    FrameworkDict = framework.FrameworkDict()
    ComplianceAssessmentDict = audit.ComplianceAssessmentDict()
    FrameworkDict = framework.FrameworkDict()
    ReferenceControlDict = control.ReferenceControlDict()
    AppliedControlDict = control.AppliedControlDict()
    """

    DomainDict = organization.DomainDict()
    DomainDict.UpsertFolder("TestFolder")

    DomainDict.printDomains()
    UserDict = user.UserDict()
    UserDict.printUsers()

    TaskDict = task.TaskDict()
    TaskDict.printTasks()
    TaskTemplateDict = task.TaskTemplateDict()
    TaskTemplateDict.printTaskTemplates()
    UserDict.upsertUser("John", "Doe", "john.doe@example.com","Finance")
    UserDict.deleteUser("john.doe@example.com")
    TeamDict = user.TeamDict()
    TeamDict.printTeams()
    TeamDict.AddUserToTeam("Finance", "athiriez@redoute.fr")
    TeamDict.RemoveUserFromTeam("Finance", "elegendre-prest@redoute.fr")

    #ComplianceAssessmentDict.CreateMissingComplianceAssessments(FrameworkDict, PerimeterDict, AssetDict)
    #ComplianceAssessmentDict.assignRequirementsToPerimeterOwner(PerimeterDict)
    #ComplianceAssessmentDict.CreateAppliedControls(PerimeterDict, ReferenceControlDict) 
    #ComplianceAssessmentDict.CreateMissingAppliedControls(AppliedControlDict,PerimeterDict,ReferenceControlDict)
    #ComplianceAssessmentDict.UpdateAssetCriticality(AssetDict)


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
