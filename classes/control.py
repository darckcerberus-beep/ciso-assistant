from . import utils


class AppliedControl:
    """Represents an applied control from the API."""

    def __init__(self, json_control):
        """Initialize with control data from API."""
        control_id = json_control.get('id')
        self.json_object = utils.get_return(f"/api/applied-controls/{control_id}/")

    def getJSON(self):
        """Return the full JSON object."""
        return self.json_object

    def getName(self):
        """Return the control name."""
        return self.json_object.get('name', '')

    def getID(self):
        """Return the control ID."""
        return self.json_object.get('id', '')

    def getRequirementAssessmentIDs(self):
        """Return IDs of requirement assessments linked to this control."""
        assessments = self.json_object.get('requirement_assessments', [])
        if not isinstance(assessments, list):
            return []
        return [
            assessment.get('id', '') if isinstance(assessment, dict) else assessment
            for assessment in assessments
        ]

    def getStatus(self):
        """Return the implementation status of this control."""
        return self.json_object.get('status', '')

    def printName(self):
        """Print the control name."""
        utils.log(f"Name: {self.getName()}")

    def printID(self):
        """Print the control ID."""
        utils.log(f"ID: {self.getID()}")

    @classmethod
    def createAppliedControl(cls, name, control, requirement_assessment, status):
        """Create an applied control based on requirement assessment and reference control.
        
        Args:
            name: Control name
            control: Control reference
            requirement_assessment: Associated requirement assessment
            status: Control status
            
        Returns:
            API response with created control data
        """
        payload = {
            "name": name,
            "control": control,
            "requirement_assessment": requirement_assessment,
            "status": status
        }
        utils.log(f"Payload for creating applied control: {payload}")
        return utils.get_return("/api/applied-controls/", method="POST", payload=payload)
       


class AppliedControlDict:
    """Dictionary of applied controls with management functionality."""

    def __init__(self):
        """Initialize and load all applied controls."""
        self.reload()

    def reload(self):
        """Reload all applied controls from the API."""
        self.controls = {}
        for c in utils.get_all_results("/api/applied-controls/"):
            self.controls[c.get('id')] = AppliedControl(c)

    def getControls(self):
        """Return all controls."""
        return self.controls

    def printControls(self):
        """Print all control names and IDs."""
        for c in self.controls.values():
            c.printName()
            c.printID()

    def printJSON(self):
        """Print JSON representation of all controls."""
        for c in self.controls.values():
            utils.log(c.getJSON())

    def getControlIDsByStatusForRequirementAssessments(self, requirement_assessment_ids):
        """Group controls by implementation status for the supplied assessments."""
        assessment_ids = set(requirement_assessment_ids)
        controls_by_status = {"existing": [], "planned": []}
        for control in self.controls.values():
            if not assessment_ids.intersection(control.getRequirementAssessmentIDs()):
                continue

            status_group = "existing" if control.getStatus() == "active" else "planned"
            controls_by_status[status_group].append(control.getID())
        return controls_by_status

    def CheckAppliedControlFromName(self, name):
        """Check if a control with the given name exists.
        
        Args:
            name: Control name to search for
            
        Returns:
            True if control exists, False otherwise
        """
        for c in self.controls.values():
            if c.getName() == name:
                return True
        return False

    def CreateMissingAppliedControls(self, perimeter_dict, requirement_assessment,
                                     reference_control_dict, compliance_assessment_dict):
        """Create missing applied controls based on requirement assessments.
        
        Args:
            perimeter_dict: Dictionary of perimeters
            requirement_assessment: Requirement assessment object
            reference_control_dict: Dictionary of reference controls
            compliance_assessment_dict: Dictionary of compliance assessments
        """
        requirement_assessment.reload()
        created = 0

        for ra in requirement_assessment.getRequirementAssessments().values():
            # Skip non-assessed or empty results
            if ra.getAssessmentResults() in ['', 'not_assessed']:
                continue

            for control_id in ra.getAssociatedReferenceControlIDs():
                control_name = reference_control_dict.getNamefromID(control_id)
                perimeter_name = perimeter_dict.getNamefromID(ra.getPerimeterID())
                name = f"{control_name} on {perimeter_name}"

                # Skip if control already exists
                if self.CheckAppliedControlFromName(name):
                    continue

                # Determine owner and status based on assessment results
                is_compliant = ra.getAssessmentResults() == "compliant"
                payload = {
                    "name": name,
                    "reference_control": control_id,
                    "owner": [perimeter_dict.getOwnerIDfromPerimeterID(ra.getPerimeterID())] if not is_compliant else [],
                    "assets": compliance_assessment_dict.getAssetIDListfromComplianceassessmentID(ra.getComplianceAssessmentID()),
                    "compliance_assessments": [ra.getComplianceAssessmentID()],
                    "requirement_assessments": [ra.getID()],
                    "status": "active" if is_compliant else "to_do"
                }
                utils.log(f"Payload for creating applied control: {payload}")
                utils.get_return("/api/applied-controls/", method="POST", payload=payload)
                created += 1

        # Log completion status
        if created > 0:
            utils.log(f"Created {created} applied control(s).")
        else:
            utils.log("No new applied controls created.")
                
                

class ReferenceControlDict:
    """Dictionary of reference controls."""

    def __init__(self):
        """Initialize and load all reference controls."""
        self.reload()

    def reload(self):
        """Reload all reference controls from the API."""
        self.controls = [ReferenceControl(c) for c in utils.get_all_results("/api/reference-controls/")]

    def getControls(self):
        """Return all controls."""
        return self.controls

    def printControls(self):
        """Print all control names and IDs."""
        for c in self.controls:
            c.printName()
            c.printID()

    def getNamefromID(self, control_id):  # noqa: A002
        """Get control name by ID.
        
        Args:
            control_id: The control ID to search for
            
        Returns:
            Control name if found, None otherwise
        """
        for c in self.controls:
            if c.getID() == control_id:
                return c.getName()
        return None        

class ReferenceControl:
    """Represents a reference control."""

    def __init__(self, json_control):
        """Initialize with control data."""
        self.json_object = json_control

    def getName(self):
        """Return the control name."""
        return self.json_object.get('name', '')

    def getID(self):
        """Return the control ID."""
        return self.json_object.get('id', '')

    def printName(self):
        """Print the control name."""
        utils.log(f"Name: {self.getName()}")

    def printID(self):
        """Print the control ID."""
        utils.log(f"ID: {self.getID()}")
