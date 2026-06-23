from . import utils

class AppliedControl:
    def __init__(self, json_control):
        self.json_object = utils.get_return("/api/applied-controls/"+json_control.get('id')+"/")
    def getJSON(self):
        return self.json_object    
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}")
    # create applied control based on attribute of requirement assessment and associated reference control
    @classmethod
    def createAppliedControl(cls, name, control, requirement_assessment, status):
        payload = {
            "name": name,
            "control": control,
            "requirement_assessment": requirement_assessment,
            "status": status
        }
        print("Payload for creating applied control: " + str(payload))
        return utils.get_return("/api/applied-controls/", method="POST", payload=payload)
       


class AppliedControlDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.controls = {}
        for c in utils.get_all_results("/api/applied-controls/"):
            self.controls[c.get('id')] = AppliedControl(c)


    def getControls(self):
        return self.controls
    def printControls(self):
        for c in self.controls:
            c.printName()
            c.printID()
    def printJSON(self):
        for c in self.controls:
            print(c.getJSON())
    def CheckAppliedControlFromName(self, name):
        for c in self.controls.values():
            if c.getName() == name:
                return True
        return False

    def CreateMissingAppliedControls(self,PerimeterDict,
 RequirementAssessment,ReferenceControlDict,ComplianceAssessmentDict):
        RequirementAssessment.reload()
        created = 0
        for ra in RequirementAssessment.getRequirementAssessments().values():
            if ra.getAssessmentResults() in ['', 'not_assessed']:
                continue
            for control_id in ra.getAssociatedReferenceControlIDs():
                name = f"{ReferenceControlDict.getNamefromID(control_id)} on {PerimeterDict.getNamefromID(ra.getPerimeterID())}"
                if not self.CheckAppliedControlFromName(name):
                    payload = {
                        "name": f"{ReferenceControlDict.getNamefromID(control_id)} on {PerimeterDict.getNamefromID(ra.getPerimeterID())}",
                        "reference_control": control_id,
                        "owner": [PerimeterDict.getOwnerIDfromPerimeterID(ra.getPerimeterID())],
                        "assets": ComplianceAssessmentDict.getAssetIDListfromComplianceassessmentID(ra.getComplianceAssessmentID()),
                        "compliance_assessments": [ra.getComplianceAssessmentID()],
                        "requirement_assessments": [ra.getID()],
                        "status": "active" if ra.getAssessmentResults() == "compliant" else "to_do"
                    }                
                    print("Payload for creating applied control: " + str(payload))
                    utils.get_return("/api/applied-controls/", method="POST", payload=payload)
                    created = created + 1
        if created > 0:
            print(f"Created {created} applied control(s).")
        else:
            print("No new applied controls created.")
                
                

class ReferenceControlDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.controls = [ReferenceControl(c) for c in utils.get_all_results("/api/reference-controls/")]

    def getControls(self):
        return self.controls
    def printControls(self):
        for c in self.controls:
            c.printName()
            c.printID()
    def getNamefromID(self, id):
        for c in self.controls:
            if c.getID() == id:
                return c.getName()
        return None        

class ReferenceControl:
    def __init__(self, json_control):
        self.json_object = json_control
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}")
