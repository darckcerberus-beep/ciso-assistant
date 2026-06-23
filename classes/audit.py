"""
This module handles the logic for Compliance Assessments, Requirement Assessments,
and Requirement Assignments within the CISO Assistant framework.
"""
from . import utils

class ComplianceAssessment:
    """Represents a single compliance assessment object."""
    def __init__(self, json_ca):
        """Initialize with JSON data from the API."""
        print("Creating Compliance Assessment with ID: " + json_ca.get('id'))
        call = "/api/compliance-assessments/"+json_ca.get('id')+"/"
        print("Calling: " + call)
        self.compliance_assessment_json = utils.get_return("/api/compliance-assessments/"+json_ca.get('id')+"/")

    def getJSON(self):
        """Return the raw JSON object."""
        return self.compliance_assessment_json

    def getName(self) -> str:
        """Get the name of the compliance assessment."""
        return self.compliance_assessment_json.get('name', '')

    def getID(self) -> str:
        """Get the unique identifier (UUID) of the assessment."""
        return self.compliance_assessment_json.get('id', '')

    def getFrameworkID(self) -> str:
        """
        Get the ID of the associated framework. 
        Note: This usually returns the UUID string directly from the JSON.
        """
        return self.compliance_assessment_json.get('framework', '')

    def getPerimeterID(self) -> str:
        """Get the ID of the associated perimeter by accessing the nested 'id' field."""
        return self.compliance_assessment_json.get('perimeter', '').get('id', '')
    def getAssetsIDList(self):
        return [asset_id.get('id', '') for asset_id in self.compliance_assessment_json.get('assets', [])]
   
    def printName(self):        
        """Print the assessment name to console."""
        print(f"Name: {self.getName()}")
    def printID(self):
        """Print the assessment ID to console."""
        print(f"ID: {self.getID()}")
    def printFrameworkID(self):
        """Print the framework ID to console."""
        print(f"Framework ID: {self.getFrameworkID()}")
    def printPerimeterID(self):
        """Print the perimeter ID to console."""
        print(f"Perimeter ID: {self.getPerimeterID()}")

class ComplianceAssessmentDict:
    """Handles a collection of ComplianceAssessments and API interactions."""
    def __init__(self):
       self.reload()
       self.requirement_assessments = RequirementAssessmentDict()
       self.requirement_assignments = RequirementAssignmentDict()


    def reload(self):
        """Fetch all compliance assessments from the API and store them as objects."""
        self.compliance_assessments = {}
        for ca in utils.get_all_results("/api/compliance-assessments/"):
            print("Adding Compliance Assessment object to dict for  assessment ID: " + ca.get('id'))            
            self.compliance_assessments[ca.get('id')] = ComplianceAssessment(ca)
        print(type(self.compliance_assessments))    

    def getComplianceAssessments(self):
        """Return the list of ComplianceAssessment objects."""
        return self.compliance_assessments

    def CreateComplianceAssessment(self, name, framework_id, perimeter_id):
        """Create a new compliance assessment via POST request."""
        payload = {'name': name, 'framework': framework_id, 'perimeter': perimeter_id}
        res = utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
        self.reload()
        return ComplianceAssessment(res)

    def CreateMissingComplianceAssessments(self, FrameworkDict, PerimeterDict,AssetDict):
        """Iterate through frameworks and perimeters to ensure an assessment exists for every combination."""
        print("Creating missing compliance assessments...")
        created = False
        for f in FrameworkDict.getFrameworks():
            for p in PerimeterDict.getPerimeters():
                compliance_assessment_name = "Assessment of " + f.getName()  + " in " + p.getName()
                if not self.CheckComplianceAssessmentFromName(compliance_assessment_name):
                    print("Creating compliance Assessment Name: " + compliance_assessment_name)
                    payload = {'name': compliance_assessment_name, 'framework': f.getID(), 'perimeter': p.getID(),'assets': [AssetDict.getAssetIDfromPerimeterID(p.getID(), PerimeterDict)]}
                    utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
                    created = True
        if created:
            print("Compliance Assessments created.")
            self.reload()
        else:
            print("No new compliance assessments created.")
    def UpdateAssetObjectives(self,AssetDict):
        self.reload()
        for ra in self.requirement_assessments.getRequirementAssessments().values():
            self.getAssetIDListfromComplianceassessmentID(ra.getComplianceAssessmentID())       



    def CheckComplianceAssessmentFromIDs(self, framework_id, perimeter_id):
        """Check if an assessment exists for a specific framework and perimeter ID pair."""
        for ca in self.compliance_assessments:
            if ca.getFrameworkID() == framework_id and ca.getPerimeterID() == perimeter_id:
                return True
        return False

    def CheckComplianceAssessmentFromName(self, name):
        """Check if an assessment exists with the given name."""
        for ca in self.compliance_assessments.values():
            if ca.getName() == name:
                return True
        return False
    def printComplianceAssessments(self):
        """Print details of all compliance assessments in the dictionary."""
        for ca in self.compliance_assessments.values():            
            print("Compliance Assessment Name: " + ca.getName())
    def getAssetIDListfromComplianceassessmentID(self, compliance_assessment_id):
        for ca in self.compliance_assessments.values():
            if ca.getID() == compliance_assessment_id:
                print("Compliance Assessment ID: " + ca.getID())
                print("Compliance Assessment Assets: " + str(ca.getAssetsIDList()))
                return ca.getAssetsIDList()
                
        return []
    def assignRequirementsToPerimeterOwner(self,PerimeterDict):
        self.requirement_assessments.assignRequirementsToPerimeterOwner(PerimeterDict,self,self.requirement_assignments)

    def UpdateAssetCriticality(self,AssetDict):
        self.reload()
        self.requirement_assessments.UpdateAssetCriticality()



    def CreateMissingAppliedControls(self,AppliedControlDict,PerimeterDict,ReferenceControlDict):
        self.requirement_assessments.CreateorUpdateAppliedControls(AppliedControlDict,PerimeterDict,ReferenceControlDict,self)    







class RequirementAssessment:
    """Represents an individual requirement assessment within a compliance assessment."""
    def __init__(self, json_ra):
        """Initialize with JSON data from the API."""
        self.json_object = json_ra
    def getName(self):
        """Get the name of the requirement assessment."""
        return self.json_object.get('name', '')

    def getID(self):
        """Get the unique identifier (UUID)."""
        return self.json_object.get('id', '')

    def getFrameworkID(self):
        """Get the ID of the framework this requirement belongs to."""
        return self.json_object.get('framework', '')

    def getPerimeterID(self):
        """Get the ID of the perimeter this requirement is assessed against."""
        return self.json_object.get('perimeter', '').get('id', '')

    def getComplianceAssessmentID(self):
        """Get the ID of the parent compliance assessment."""
        return self.json_object.get('compliance_assessment', '').get('id', '')

    def getRequirementID(self):
        """Get the ID of the specific requirement being assessed."""
        return self.json_object.get('requirement', '')

    def GetRequirementAssignmentStatus(self):
        """Get the current status of the assessment (e.g., 'not_started', 'in_progress')."""
        return self.json_object.get('status', '')

    def getRequirementJSON(self):
        """Return the raw JSON object."""
        return self.json_object

    def getAssociatedReferenceControls(self):
        """Retrieve reference controls associated with the underlying requirement."""
        return self.json_object.get('requirement', '').get('associated_reference_controls', '')
    def getAssociatedReferenceControlIDs(self):
        """Extract and return a list of IDs for the associated reference controls."""
        return [rc.get('id', '') for rc in self.json_object.get('requirement', '').get('associated_reference_controls', '')]
    
    def getAssessmentStatus(self):
        """Get the current status of the requirement assessment."""
        return self.json_object.get('status', '')
    
    def getAssessmentResults(self):
        """Get the results of the requirement assessment, if available."""
        return self.json_object.get('result', '')
    def getAssetsIDList(self):
        """Get the list of asset IDs associated with this requirement assessment."""
        return self.json_object.get('assets', [])

    def printName(self):
        """Print the requirement assessment name."""
        print(f"Name: {self.getName()}")
    def printID(self):
        """Print the requirement assessment ID."""
        print(f"ID: {self.getID()}")
    def printPerimeterID(self):
        """Print the associated perimeter ID."""
        print(f"Perimeter ID: {self.getPerimeterID()}")
    def printComplianceAssessmentID(self):
        """Print the parent compliance assessment ID."""
        print(f"Compliance Assessment ID: {self.getComplianceAssessmentID()}")
    def printRequirementID(self):
        """Print the specific requirement ID."""
        print(f"Requirement ID: {self.getRequirementID()}")
    def printAssociatedReferenceControls(self):
        """Print the associated reference controls."""
        print(f"Associated Reference Controls: {self.getAssociatedReferenceControls()}")
    def printAssets(self):
        """Print the associated assets."""
        print(f"Assets: {self.getAssetsIDList()}")    

    def CreateAndAssignAppliedControls(self):
        for results in self.getAssessmentResults():
            for control in self.getAssociatedReferenceControls():
                print("Creating applied control for control " + control.get('id', '') + " based on assessment results: " + results)
                # Placeholder for logic to create applied controls based on assessment results and associated reference controls.
                pass
           






class RequirementAssessmentDict:    
    """Handles a collection of RequirementAssessments."""
    def __init__(self):
        self.reload()

    def reload(self):
        """Fetch all requirement assessments from the API."""
        self.requirement_assessments = {}
        for ra in utils.get_all_results("/api/requirement-assessments/"):
            self.requirement_assessments[ra.get('id')] = RequirementAssessment(ra)        

    def getRequirementAssessments(self):
        """Return the list of RequirementAssessment objects."""
        self.reload()
        return self.requirement_assessments
    
    def printRequirementAssessments(self):
        """Print details for all requirement assessments."""
        self.reload()
        for ra in self.requirement_assessments:
            ra.printName()
            ra.printID()
            ra.printPerimeterID()
            ra.printComplianceAssessmentID()
            ra.printRequirementID()
            ra.printAssociatedReferenceControls()
            ra.printAssets()


    def getRequirementAssessmentIDListfromComplianceassessmentID(self, compliance_assessment_id):
        """Filter and return a list of IDs for requirements belonging to a specific compliance assessment."""
        self.reload()
        requirement_assessment_ids = []
        for ra in self.requirement_assessments.values():
            if ra.getComplianceAssessmentID() == compliance_assessment_id:              
                requirement_assessment_ids.append(ra.getID())
        return requirement_assessment_ids

    def assignRequirementsToPerimeterOwner(self, PerimeterDict, ComplianceAssessmentDict,RequirementAssignmentDict):
        """Create assignments for all non-already assigned requirements in an assessment, assigning them to the perimeter owner."""
        # Extract already-assigned assessments
        assigned_assessments = RequirementAssignmentDict.getRequirementAssignmentIDList()
        created = False
        for ca in ComplianceAssessmentDict.getComplianceAssessments().values():
            # Gather all requirements for this specific assessment
            ra_ids = self.getRequirementAssessmentIDListfromComplianceassessmentID(ca.getID())
            # determine if some assessments are not assigned
            unassigned_assessments = list(set(assigned_assessments) ^ set(ra_ids))
            if unassigned_assessments != []:                
                payload = {"requirement_assessments":unassigned_assessments ,"compliance_assessment" : ca.getID(), "folder": PerimeterDict.getFolderUUIDfromPerimeterID(ca.getPerimeterID()),"actor" : [PerimeterDict.getOwnerIDfromPerimeterID(ca.getPerimeterID())]}            
                # Create the assignment
                req_assing_json = utils.get_return(f"/api/requirement-assignments/", method="POST", payload=payload)                       
                # Update the status of the newly created assignment to 'in_progress'
                utils.get_return(f"/api/requirement-assignments/"+req_assing_json.get('id')+"/set_status/", method="POST", payload={"status": "in_progress"})
                created = True

        if created:
            self.reload()
            RequirementAssignmentDict.reload()

    def getAssociatedReferenceControls(self):
        """Placeholder for future logic to generate applied controls based on assessments."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.getAssessmentResults() != '' and ra.getAssessmentResults() != "not_assessed":
                print("Assessment results: " + ra.getAssessmentResults())
                print("Associated reference controls: " + str(ra.getAssociatedReferenceControls()))
        pass

    def getAssociatedReferenceControlIDs(self):
        """Return a flat list of all reference control IDs associated with current assessments."""
        self.reload()
        control_ids = []
        for ra in self.requirement_assessments.values():
            control_ids.extend(ra.getAssociatedReferenceControlIDs())
        return list(set(control_ids))
    
    def printAssessmentResults(self):
        self.reload()
        for ra in self.requirement_assessments.values():
            if  ra.getAssessmentResults() != '' and ra.getAssessmentResults() != "not_assessed":                  
                print("Assessment results: " + ra.getAssessmentResults())
                print("Associated Reference controls : " + str(ra.getAssociatedReferenceControlIDs()))
    def CreateorUpdateAppliedControls(self,AppliedControlDict,PerimeterDict,ReferenceControlDict,ComplianceAssessmentDict):
        self.reload()
        AppliedControlDict.reload()
        AppliedControlDict.CreateMissingAppliedControls(PerimeterDict,self,ReferenceControlDict,ComplianceAssessmentDict)

    def UpdateAssetCriticality(self):
        self.reload()
        for ra in self.requirement_assessments.values():
            if  ra.getAssessmentResults() != '' and ra.getAssessmentResults() != "not_assessed":   
                print(type(ra.getRequirementJSON().get('answers')))
                print(ra.getRequirementJSON().get('answers'))

            
        
    def CreateAppliedControls(self, PerimeterDict, ReferenceControlDict,ComplianceAssessmentDict):
        """Generates applied controls based on requirement assessment results."""
        self.reload()
        print("Creating applied controls...")
        created = 0
        for ra in self.requirement_assessments.values():            
            if ra.getAssessmentResults() in ['', 'not_assessed']:
                continue 

            
            for control_id in ra.getAssociatedReferenceControlIDs():
                payload = {
                    "name": f"{ReferenceControlDict.getNamefromID(control_id)} on {PerimeterDict.getNamefromID(ra.getPerimeterID())}",
                    "reference_control": control_id,
                    "owner": [PerimeterDict.getOwnerIDfromPerimeterID(ra.getPerimeterID())],
                    "assets": ComplianceAssessmentDict.getAssetIDListfromComplianceassessmentID(ra.getComplianceAssessmentID()),
                    "compliance_assessments": [ra.getComplianceAssessmentID()],
                    "requirement_assessments": [ra.getID()],
                    "status": "active" if ra.getAssessmentResults() == "compliant" else "to_do"
                }                
                utils.get_return("/api/applied-controls/", method="POST", payload=payload)
                created = created + 1
        if created > 0:
            print(f"Created {created} applied controls.")
        else:
            print("No new applied controls created.")


                





    


            


        


class RequirementAssignment:
    """Represents a task assigning requirement assessments to an actor."""
    def __init__(self, json_ra):
        """Initialize with JSON data from the API."""
        self.json_object = json_ra

    def getName(self):
        """Get the name of the assignment."""
        return self.json_object.get('name', '')

    def getID(self):
        """Get the unique identifier (UUID) of the assignment."""
        return self.json_object.get('id', '')

    def getRequirementAssessmentIDList(self):
        """Extract the list of requirement assessment IDs included in this assignment."""
        return [ra.get('id', '') for ra in self.json_object.get('requirement_assessments', '')]    

    def printID(self):
        """Print the assignment ID."""
        print(f"Requirement Assignment ID: {self.getID()}")
    def printName(self):
        """Print the assignment name."""
        print(f"Requirement Assignment Name: {self.getName()}")
    def printJSON(self):
        """Print the raw JSON data."""
        print(self.json_object)
    

class RequirementAssignmentDict:
    """Handles a collection of RequirementAssignments."""
    def __init__(self):
        self.reload()

    def reload(self):
        """Fetch all requirement assignments from the API."""
        self.requirement_assignments = [RequirementAssignment(ra) for ra in utils.get_all_results("/api/requirement-assignments/")]

    def getRequirementAssignments(self):
        """Return the list of RequirementAssignment objects."""
        return self.requirement_assignments

    def printRequirementAssignments(self):
        """Print details for all assignments."""
        for ra in self.requirement_assignments:
            ra.printID()
            ra.printName()
            print(ra.getRequirementAssessmentList())

    def printRequirementAssignmentIDList(self):
        """Print the list of requirement IDs for every assignment."""
        for ra in self.requirement_assignments:
            print("Requirement Assignment ID List:")
            print(ra.getRequirementAssessmentIDList())

    def getRequirementAssignmentIDList(self):
        """Return a list of all requirement assignment IDs."""
        requirement_assignment_ids = []
        for ra in self.requirement_assignments:
            requirement_assignment_ids = requirement_assignment_ids + ra.getRequirementAssessmentIDList()
        return requirement_assignment_ids
    

             
