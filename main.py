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
    # Objects initialization    
    RequirementAssessmentDict = audit.RequirementAssessmentDict()
    ComplianceAssessmentDict = audit.ComplianceAssessmentDict()
    RequirementAssignmentDict = audit.RequirementAssignmentDict()
    PerimeterDict = organization.PerimeterDict()
    AssetDict = organization.AssetDict()
    FrameworkDict = framework.FrameworkDict()
    ReferenceControlDict = control.ReferenceControlDict()
    AppliedControlDict = control.AppliedControlDict()
    RiskAssessmentDict = risk.RiskAssessmentDict()
    RiskScenarioDict = risk.RiskScenarioDict()
    UserDict = user.UserDict()
    Framework = framework.FrameworkFile("YML/newDPP.yml")
    RiskMatrixDict = risk.RiskMatrixDict()
    
    # Create missing assets from perimeter
    AssetDict.createMissingAssets(PerimeterDict)
    AssetDict.reload()

    #Create compliance assessments for each perimeter and asset based on the framework
    ComplianceAssessmentDict.CreateMissingComplianceAssessments(FrameworkDict, PerimeterDict, AssetDict)

    #Assign requirements to perimeter owners
    ComplianceAssessmentDict.assignRequirementsToPerimeterOwner(PerimeterDict,ComplianceAssessmentDict,RequirementAssessmentDict,RequirementAssignmentDict)

    #Create missing applied controls for each compliance assessment
    ComplianceAssessmentDict.CreateMissingAppliedControls(AppliedControlDict,PerimeterDict,ReferenceControlDict)

    #Update asset criticality based on the mapping defined in organization.py
    ComplianceAssessmentDict.UpdateAssetCriticality(organization.CRITICALITY_MAPPING, AssetDict)

    #Create risk assessments for each compliance assessment based on the framework
    ComplianceAssessmentDict.CreateRiskAssessments(RiskAssessmentDict,RiskScenarioDict,Framework,RequirementAssessmentDict,RiskMatrixDict,FrameworkDict)




if __name__ == "__main__":
    main()
