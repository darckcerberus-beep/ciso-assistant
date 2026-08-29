"""Helpers and models for compliance assessments, requirement assessments, and assignments."""

from . import utils


AUDITOR_SCORE_VISIBILITY = {
    "score": {"auditor": "edit", "respondent": "hidden"},
}


class ComplianceAssessment:
    """Represent a single compliance assessment returned by the API."""

    def __init__(self, json_ca):
        """Initialize the object using the API payload."""
        assessment_id = json_ca.get('id', '')
        utils.log(f"Creating compliance assessment with ID: {assessment_id}")
        self.compliance_assessment_json = utils.get_return(f"/api/compliance-assessments/{assessment_id}/")

    def getJSON(self):
        """Return the raw JSON object."""
        return self.compliance_assessment_json

    def getName(self) -> str:
        """Return the assessment name."""
        return self.compliance_assessment_json.get('name', '')

    def getID(self) -> str:
        """Return the assessment UUID."""
        return self.compliance_assessment_json.get('id', '')

    def getFrameworkID(self) -> str:
        """Return the linked framework identifier."""
        framework = self.compliance_assessment_json.get('framework', {})
        if isinstance(framework, dict):
            return framework.get('id', '')
        return str(framework)

    def getPerimeterID(self) -> str:
        """Return the linked perimeter identifier."""
        perimeter = self.compliance_assessment_json.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return str(perimeter)

    def getAssetsIDList(self):
        """Return the asset IDs linked to this compliance assessment."""
        utils.log(f"Getting asset ID list for compliance assessment ID: {self.getID()}")
        utils.log(f"Compliance assessment JSON: {self.compliance_assessment_json}")
        return [asset.get('id', '') for asset in self.compliance_assessment_json.get('assets', [])]

    def printName(self):
        """Log the assessment name."""
        utils.log(f"Name: {self.getName()}")

    def printID(self):
        """Log the assessment ID."""
        utils.log(f"ID: {self.getID()}")

    def printFrameworkID(self):
        """Log the framework ID."""
        utils.log(f"Framework ID: {self.getFrameworkID()}")

    def printPerimeterID(self):
        """Log the perimeter ID."""
        utils.log(f"Perimeter ID: {self.getPerimeterID()}")

    def getStatus(self):
        """Return the current status of the compliance assessment."""
        return self.compliance_assessment_json.get('status', '')

    def getScoreFromRequirementNodeName(self, requirement_node_name):
        """Return the score for a requirement node matching the provided name."""
        utils.log(f"Searching for requirement node '{requirement_node_name}' in compliance assessment ID: {self.getID()}")
        utils.log(f"Compliance assessment JSON: {self.compliance_assessment_json}")

        for requirement in self.compliance_assessment_json.get('requirements', []):
            utils.log(f"Checking requirement node: {requirement.get('name', '')}")
            if requirement.get('name') == requirement_node_name:
                score = requirement.get('score', '')
                utils.log(f"Found requirement node '{requirement_node_name}' with score: {score}")
                return score
        return None


class ComplianceAssessmentDict:
    """Manage a collection of compliance assessments and related API operations."""

    def __init__(self):
        self.reload()
        self.requirement_assessments = RequirementAssessmentDict()
        self.requirement_assignments = RequirementAssignmentDict()

    def reload(self):
        """Refresh the internal dictionary from the API."""
        self.compliance_assessments = {}
        for ca in utils.get_all_results("/api/compliance-assessments/"):
            utils.log(f"Adding compliance assessment object for assessment ID: {ca.get('id')}")
            self.compliance_assessments[ca.get('id')] = ComplianceAssessment(ca)
        utils.log(type(self.compliance_assessments))

    def getComplianceAssessments(self):
        """Return the compliance assessment dictionary."""
        return self.compliance_assessments

    def CreateComplianceAssessment(self, name, framework_id, perimeter_id):
        """Create a new compliance assessment via POST request."""
        payload = {
            'name': name,
            'framework': framework_id,
            'perimeter': perimeter_id,
            'field_visibility': AUDITOR_SCORE_VISIBILITY,
        }
        response = utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
        self.reload()
        return ComplianceAssessment(response)

    def CreateMissingComplianceAssessments(self, FrameworkDict, PerimeterDict, AssetDict):
        """Ensure every framework/perimeter combination has a compliance assessment."""
        utils.log("Creating missing compliance assessments...")
        created = False

        for framework in FrameworkDict.getFrameworks():
            for perimeter in PerimeterDict.getPerimeters():
                compliance_assessment_name = f"Assessment of {framework.getName()} in {perimeter.getName()}"
                if not self.CheckComplianceAssessmentFromName(compliance_assessment_name):
                    utils.log(f"Creating compliance assessment: {compliance_assessment_name}")
                    payload = {
                        'name': compliance_assessment_name,
                        'framework': framework.getID(),
                        'perimeter': perimeter.getID(),
                        'assets': [AssetDict.getAssetIDfromPerimeterID(perimeter.getID(), PerimeterDict)],
                        'field_visibility': AUDITOR_SCORE_VISIBILITY,
                    }
                    utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
                    created = True

        if created:
            utils.log("Compliance assessments created.")
            self.reload()
        else:
            utils.log("No new compliance assessments created.")

    def UpdateAssetObjectives(self, AssetDict):
        """Refresh asset objectives for the current requirement assessment context."""
        self.reload()
        for ra in self.requirement_assessments.getRequirementAssessments().values():
            self.getAssetIDListfromComplianceassessmentID(ra.getComplianceAssessmentID())

    def CheckComplianceAssessmentFromIDs(self, framework_id, perimeter_id):
        """Check whether an assessment exists for a framework/perimeter pair."""
        for ca in self.compliance_assessments.values():
            if ca.getFrameworkID() == framework_id and ca.getPerimeterID() == perimeter_id:
                return True
        return False

    def CheckComplianceAssessmentFromName(self, name):
        """Check whether an assessment exists with the given name."""
        for ca in self.compliance_assessments.values():
            if ca.getName() == name:
                return True
        return False

    def printComplianceAssessments(self):
        """Log every compliance assessment name."""
        for ca in self.compliance_assessments.values():
            utils.log(f"Compliance assessment name: {ca.getName()}")

    def getAssetIDListfromComplianceassessmentID(self, compliance_assessment_id):
        """Return the asset IDs linked to a compliance assessment."""
        for ca in self.compliance_assessments.values():
            if ca.getID() == compliance_assessment_id:
                utils.log(f"Getting asset ID list for compliance assessment ID: {compliance_assessment_id}")
                utils.log(f"Compliance assessment name: {ca.getName()}")
                assets = ca.getAssetsIDList()
                utils.log(f"Compliance assessment assets: {assets}")
                return assets
        return []

    def assignRequirementsToPerimeterOwner(self, PerimeterDict, ComplianceAssessmentDict, RequirementAssessmentDict, RequirementAssignmentDict):
        """Create requirement assignments for perimeter owners when no assignment exists."""
        self.reload()
        for ca in self.compliance_assessments.values():
            requirement_assessment_ids = RequirementAssessmentDict.getRequirementAssessmentIDListfromComplianceAssessmentID(ca.getID())
            requirement_assignment_ids = RequirementAssignmentDict.getRequirementAssignmentIDListfromComplianceassessmentID(ca.getID())

            utils.log(f"Requirement assessment IDs for compliance assessment {ca.getName()}: {requirement_assessment_ids}")
            utils.log(f"Requirement assignment IDs for compliance assessment {ca.getName()}: {requirement_assignment_ids}")

            if requirement_assessment_ids and not requirement_assignment_ids:
                utils.log(f"Creating assignments for compliance assessment: {ca.getName()}")
                payload = {
                    "requirement_assessments": requirement_assessment_ids,
                    "compliance_assessment": ca.getID(),
                    "folder": PerimeterDict.getFolderUUIDfromPerimeterID(ca.getPerimeterID()),
                    "actor": [PerimeterDict.getOwnerIDfromPerimeterID(ca.getPerimeterID())]
                }
                req_assign_json = utils.get_return("/api/requirement-assignments/", method="POST", payload=payload)
                utils.get_return(
                    f"/api/requirement-assignments/{req_assign_json.get('id')}/set_status/",
                    method="POST",
                    payload={"status": "in_progress"}
                )
            else:
                utils.log(f"Requirement assignments already exist for compliance assessment: {ca.getName()}")
                utils.log(f"Requirement assessment IDs: {requirement_assessment_ids}")
                utils.log(f"Requirement assignment IDs: {requirement_assignment_ids}")

    def getScoreFromRequirementNodeName(self, requirement_node_name):
        """Search all assessments for a requirement node name and return its score."""
        self.reload()
        for ca in self.compliance_assessments.values():
            score = ca.getScoreFromRequirementNodeName(requirement_node_name)
            if score is not None:
                return score
        return None

    def UpdateAssetCriticality(self, CRITICALITY_MAPPING, AssetDict):
        """Update asset criticality based on requirement assessment answers."""
        self.reload()
        for ca in self.compliance_assessments.values():
            requirement_assessment_ids = self.requirement_assessments.getRequirementAssessmentIDListfromComplianceAssessmentID(ca.getID())
            for ra_id in requirement_assessment_ids:
                ra = self.requirement_assessments.getRequirementAssessments().get(ra_id)
                if ra and ra.getAssessmentResults() not in ['', 'not_assessed']:
                    for question, answer in ra.getRequirementJSON().get('answers', {}).items():
                        for criteria_question, criteria_mapping in CRITICALITY_MAPPING.items():
                            if answer in criteria_mapping:
                                utils.log(
                                    f"Updating asset criticality for criteria question: {criteria_question} "
                                    f"in requirement assessment ID: {ra.getID()}"
                                )
                                utils.log(
                                    f"Question: {question}, Answer: {answer}, "
                                    f"Mapped Criticality: {criteria_mapping[answer]}"
                                )
                                asset_ids = ca.getAssetsIDList()
                                utils.log(f"Associated asset IDs: {asset_ids}")
                                for asset_id in asset_ids:
                                    utils.log(f"Updating criticality for asset ID: {asset_id}")
                                    AssetDict.UpdateAssetCriticality(asset_id, criteria_question, criteria_mapping[answer])

    def CreateMissingAppliedControls(self, AppliedControlDict, PerimeterDict, ReferenceControlDict):
        """Delegate applied-control creation to requirement assessments."""
        self.requirement_assessments.CreateorUpdateAppliedControls(AppliedControlDict, PerimeterDict, ReferenceControlDict, self)

    def getJSON(self):
        """Return the raw JSON data for all compliance assessments."""
        self.reload()
        return [ca.getJSON() for ca in self.compliance_assessments.values()]

    def printJSON(self):
        """Log the raw JSON data for all compliance assessments."""
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Printing JSON for compliance assessment: {ca.getName()}")
            utils.log(ca.getJSON())

    def CreateRiskAssessments(self, RiskAssessmentDict, RiskScenarioDict, AppliedControlDict, AssetDict, FrameworkFile, RequirementAssessmentDict, RiskMatrixDict, FrameworkDict):
        """Create risk assessments and scenarios for each compliance assessment."""
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Creating risk assessments for compliance assessment: {ca.getName()}")
            utils.log(f"Using framework ID: {ca.getFrameworkID()}, perimeter ID: {ca.getPerimeterID()}")

            risk_assessment = RiskAssessmentDict.CreateRiskAssessments(
                ca.getName() + " Risk Assessment",
                ca.getFrameworkID(),
                ca.getPerimeterID(),
                RiskMatrixDict.getRiskMatrixIDByLibraryID(
                    FrameworkDict.getLibraryIDfromFrameworkID(ca.getFrameworkID())
                )
            )

            for risk_scenario in FrameworkFile.getRiskScenarios():
                utils.log(f"Creating risk scenario: {risk_scenario.get('name', '')} for compliance assessment: {ca.getName()}")
                utils.log(f"Risk scenario description: {risk_scenario.get('description', '')}")
                utils.log(f"Risk scenario impact node: {risk_scenario.get('impact', '')}")
                utils.log(f"Risk scenario likelihood node: {risk_scenario.get('likelihood', '')}")

                impact = RequirementAssessmentDict.getScorefromcomplianceAsseesmentIDandURN(ca.getID(), risk_scenario.get('impact', ''))
                likelihood = RequirementAssessmentDict.getScorefromcomplianceAsseesmentIDandURN(ca.getID(), risk_scenario.get('likelihood', ''))
                requirement_assessment_ids = [
                    requirement_assessment.getID()
                    for requirement_assessment in RequirementAssessmentDict.getRequirementAssessments().values()
                    if requirement_assessment.getComplianceAssessmentID() == ca.getID()
                    and requirement_assessment.getURN() in {
                        risk_scenario.get('impact', ''),
                        risk_scenario.get('likelihood', ''),
                    }
                ]
                controls_by_status = AppliedControlDict.getControlIDsByStatusForRequirementAssessments(
                    requirement_assessment_ids
                )
                asset_ids = ca.getAssetsIDList()
                owner_ids = AssetDict.getOwnerIDsForAssets(asset_ids)

                if likelihood is not None and impact is not None:
                    utils.log(f"Risk scenario impact value: {impact}")
                    scaled_impact = max(1, int(impact / 25))
                    utils.log(f"Scaled impact: {scaled_impact}")

                    utils.log(f"Risk scenario likelihood value: {likelihood}")
                    scaled_likelihood = max(1, int((100 - likelihood) / 25))
                    utils.log(f"Scaled likelihood: {scaled_likelihood}")

                    RiskScenarioDict.createRiskScenario(
                        risk_scenario.get('name', ''),
                        risk_scenario.get('description', ''),
                        risk_assessment.get('id', ''),
                        scaled_likelihood,
                        scaled_impact,
                        1,
                        scaled_impact,
                        controls_by_status["existing"],
                        controls_by_status["planned"],
                        asset_ids,
                        owner_ids,
                    )


class RequirementAssessment:
    """Represent a requirement assessment linked to a compliance assessment."""

    def __init__(self, json_ra):
        """Initialize from the API payload."""
        self.json_object = json_ra

    def getName(self):
        """Return the requirement assessment name."""
        return self.json_object.get('name', '')

    def getID(self):
        """Return the requirement assessment UUID."""
        return self.json_object.get('id', '')

    def getFrameworkID(self):
        """Return the framework ID."""
        return self.json_object.get('framework', '')

    def getPerimeterID(self):
        """Return the perimeter ID."""
        perimeter = self.json_object.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return str(perimeter)

    def getComplianceAssessmentID(self):
        """Return the parent compliance assessment ID."""
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '')
        return str(compliance_assessment)

    def getRequirementID(self):
        """Return the underlying requirement ID."""
        return self.json_object.get('requirement', '')

    def GetRequirementAssignmentStatus(self):
        """Return the current requirement assessment status."""
        return self.json_object.get('status', '')

    def getRequirementJSON(self):
        """Return the raw JSON payload."""
        return self.json_object

    def getAssociatedReferenceControls(self):
        """Return the reference controls attached to the underlying requirement."""
        requirement = self.json_object.get('requirement', {})
        if isinstance(requirement, dict):
            return requirement.get('associated_reference_controls', [])
        return []

    def getAssociatedReferenceControlIDs(self):
        """Return the IDs of the reference controls attached to the requirement."""
        return [control.get('id', '') for control in self.getAssociatedReferenceControls() if isinstance(control, dict)]

    def getAssessmentStatus(self):
        """Return the assessment status."""
        return self.json_object.get('status', '')

    def getAssessmentResults(self):
        """Return the assessment result."""
        return self.json_object.get('result', '')

    def getAssetsIDList(self):
        """Return the asset IDs linked to the requirement assessment."""
        return self.json_object.get('assets', [])

    def getScore(self):
        """Return the assessment score."""
        return self.json_object.get('score', '')

    def getURN(self):
        """Return the requirement URN."""
        requirement = self.json_object.get('requirement', {})
        if isinstance(requirement, dict):
            return requirement.get('urn', '')
        return ''

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
        """Placeholder for future logic creating applied controls from assessment results."""
        for results in self.getAssessmentResults():
            for control in self.getAssociatedReferenceControls():
                utils.log("Creating applied control for control " + control.get('id', '') + " based on assessment results: " + results)
                pass

    def printScore(self):
        """Log the requirement assessment score."""
        utils.log(f"Score: {self.getScore()}")

    def printURN(self):
        """Log the requirement URN."""
        utils.log(f"URN: {self.getURN()}")


class RequirementAssessmentDict:
    """Handle a collection of requirement assessments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Refresh the internal requirement assessment dictionary from the API."""
        self.requirement_assessments = {}
        for ra in utils.get_all_results("/api/requirement-assessments/"):
            self.requirement_assessments[ra.get('id')] = RequirementAssessment(ra)

    def getRequirementAssessments(self):
        """Return the current requirement assessment dictionary."""
        self.reload()
        return self.requirement_assessments

    def printRequirementAssessments(self):
        """Log details for all requirement assessments."""
        self.reload()
        for ra in self.requirement_assessments.values():
            ra.printName()
            ra.printID()
            ra.printPerimeterID()
            ra.printComplianceAssessmentID()
            ra.printRequirementID()
            ra.printAssociatedReferenceControls()
            ra.printAssets()
            ra.printScore()
            ra.printURN()

    def printRequirementAssessmentJSON(self):
        """Log the raw JSON data for all requirement assessments."""
        self.reload()
        for ra in self.requirement_assessments.values():
            utils.log(f"Requirement assessment JSON for ID: {ra.getID()}")
            utils.log(ra.getRequirementJSON())
            utils.log("\n")

    def getRequirementAssessmentIDListfromComplianceAssessmentID(self, compliance_assessment_id):
        """Return all requirement assessment IDs belonging to one compliance assessment."""
        self.reload()
        requirement_assessment_ids = []
        for ra in self.requirement_assessments.values():
            if ra.getComplianceAssessmentID() == compliance_assessment_id:
                requirement_assessment_ids.append(ra.getID())
        return requirement_assessment_ids

    def assignRequirementsToPerimeterOwner(self, PerimeterDict, ComplianceAssessmentDict, RequirementAssessmentDict, RequirementAssignmentDict):
        """Create assignments for all non-assigned requirement assessments."""
        assigned_assessments = RequirementAssignmentDict.getRequirementAssignmentIDList()
        created = False

        for ca in ComplianceAssessmentDict.getComplianceAssessments().values():
            req_assigned_ids = RequirementAssignmentDict.getRequirementAssignmentIDListfromComplianceassessmentID(ca.getID())
            req_assessment_ids = self.getRequirementAssessmentIDListfromComplianceAssessmentID(ca.getID())
            unassigned_assessments = list(set(assigned_assessments) ^ set(req_assessment_ids))

            if req_assigned_ids == []:
                utils.log(
                    "Creating assignment for unassigned requirement assessments: "
                    + str(unassigned_assessments)
                    + " in compliance assessment: "
                    + ca.getName()
                )
                payload = {
                    "requirement_assessments": unassigned_assessments,
                    "compliance_assessment": ca.getID(),
                    "folder": PerimeterDict.getFolderUUIDfromPerimeterID(ca.getPerimeterID()),
                    "actor": [PerimeterDict.getOwnerIDfromPerimeterID(ca.getPerimeterID())]
                }
                req_assign_json = utils.get_return("/api/requirement-assignments/", method="POST", payload=payload)
                utils.get_return(
                    f"/api/requirement-assignments/{req_assign_json.get('id')}/set_status/",
                    method="POST",
                    payload={"status": "in_progress"}
                )
                created = True
            else:
                utils.log(f"Requirement assessments are already assigned for compliance assessment: {ca.getName()}")
                utils.log(f"Requirement assessments: {req_assessment_ids}")

        if created:
            self.reload()
            RequirementAssignmentDict.reload()

    def getAssociatedReferenceControls(self):
        """Log associated reference controls for requirement assessments with results."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.getAssessmentResults() not in ['', 'not_assessed']:
                utils.log(f"Assessment results: {ra.getAssessmentResults()}")
                utils.log(f"Associated reference controls: {ra.getAssociatedReferenceControls()}")

    def getAssociatedReferenceControlIDs(self):
        """Return the unique reference control IDs linked to current assessments."""
        self.reload()
        control_ids = []
        for ra in self.requirement_assessments.values():
            control_ids.extend(ra.getAssociatedReferenceControlIDs())
        return list(set(control_ids))

    def printAssessmentResults(self):
        """Log assessment results and associated reference controls."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.getAssessmentResults() not in ['', 'not_assessed']:
                utils.log(f"Assessment results: {ra.getAssessmentResults()}")
                utils.log(f"Associated reference controls: {ra.getAssociatedReferenceControlIDs()}")

    def CreateorUpdateAppliedControls(self, AppliedControlDict, PerimeterDict, ReferenceControlDict, ComplianceAssessmentDict):
        """Create or update applied controls from current requirement assessments."""
        self.reload()
        AppliedControlDict.reload()
        AppliedControlDict.CreateMissingAppliedControls(PerimeterDict, self, ReferenceControlDict, ComplianceAssessmentDict)

    def UpdateAssetCriticality(self, CRITICALITY_MAPPING, AssetDict):
        """Update asset criticality fields using assessment answers and mapping rules."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.getAssessmentResults() not in ['', 'not_assessed']:
                for question, answer in ra.getRequirementJSON().get('answers', {}).items():
                    for criteria_question, criteria_mapping in CRITICALITY_MAPPING.items():
                        if answer in criteria_mapping:
                            utils.log(
                                f"Updating asset criticality for criteria question: {criteria_question} "
                                f"in requirement assessment ID: {ra.getID()}"
                            )
                            utils.log(
                                f"Question: {question}, Answer: {answer}, "
                                f"Mapped Criticality: {criteria_mapping[answer]}"
                            )
                            asset_ids = ra.getAssetsIDList()
                            utils.log(f"Associated asset IDs: {asset_ids}")
                            for asset_id in asset_ids:
                                utils.log(f"Updating criticality for asset ID: {asset_id}")
                                payload = {"criticality": criteria_mapping[answer]}
                                AssetDict.updateAssetCriticality(asset_id, payload)

    def CreateAppliedControls(self, PerimeterDict, ReferenceControlDict, ComplianceAssessmentDict):
        """Generate applied controls based on requirement assessment results."""
        self.reload()
        utils.log("Creating applied controls...")
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
                created += 1

        if created > 0:
            utils.log(f"Created {created} applied controls.")
        else:
            utils.log("No new applied controls created.")

    def getScorefromcomplianceAsseesmentIDandURN(self, compliance_assessment_id, requirement_node_urn):
        """Return the score for a requirement node within a given compliance assessment."""
        self.reload()
        for ra in self.requirement_assessments.values():
            if ra.getComplianceAssessmentID() == compliance_assessment_id and ra.getURN() == requirement_node_urn:
                return ra.getScore()
        return None


class RequirementAssignment:
    """Represent a task assigning requirement assessments to an actor."""

    def __init__(self, json_ra):
        """Initialize from the API payload."""
        self.json_object = json_ra

    def getName(self):
        """Return the assignment name."""
        return self.json_object.get('name', '')

    def getID(self):
        """Return the assignment UUID."""
        return self.json_object.get('id', '')

    def getComplianceAssessmentID(self):
        """Return the linked compliance assessment ID."""
        utils.log(self.json_object.get('compliance_assessment', ''))
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '')
        return str(compliance_assessment)

    def getRequirementAssessmentIDList(self):
        """Return the list of requirement assessment IDs included in this assignment."""
        requirement_assessments = self.json_object.get('requirement_assessments', [])
        if not isinstance(requirement_assessments, list):
            return []
        return [ra.get('id', '') for ra in requirement_assessments if isinstance(ra, dict)]

    def printID(self):
        """Log the assignment ID."""
        utils.log(f"Requirement assignment ID: {self.getID()}")

    def printName(self):
        """Log the assignment name."""
        utils.log(f"Requirement assignment name: {self.getName()}")

    def printJSON(self):
        """Log the raw JSON data."""
        utils.log(self.json_object)


class RequirementAssignmentDict:
    """Manage a collection of requirement assignments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Refresh the internal assignment list from the API."""
        self.requirement_assignments = [
            RequirementAssignment(ra) for ra in utils.get_all_results("/api/requirement-assignments/")
        ]

    def getRequirementAssignments(self):
        """Return the assignment objects."""
        return self.requirement_assignments

    def printRequirementAssignments(self):
        """Log details for all assignments."""
        for ra in self.requirement_assignments:
            ra.printID()
            ra.printName()
            print(ra.getRequirementAssessmentIDList())

    def printRequirementAssignmentIDList(self):
        """Log the list of requirement IDs for every assignment."""
        for ra in self.requirement_assignments:
            utils.log("Requirement assignment ID list:")
            utils.log(ra.getRequirementAssessmentIDList())

    def printRequirementAssignmentJSON(self):
        """Log the raw JSON for all assignments."""
        for ra in self.requirement_assignments:
            ra.printJSON()

    def getRequirementAssignmentIDList(self):
        """Return the IDs of all requirement assessments assigned across all assignments."""
        requirement_assignment_ids = []
        for ra in self.requirement_assignments:
            requirement_assignment_ids.extend(ra.getRequirementAssessmentIDList())
        return requirement_assignment_ids

    def getRequirementAssignmentIDListfromComplianceassessmentID(self, compliance_assessment_id):
        """Return the assignment IDs for a specific compliance assessment."""
        self.reload()
        requirement_assignment_ids = []
        for ra in self.requirement_assignments:
            if ra.getComplianceAssessmentID() == compliance_assessment_id:
                requirement_assignment_ids.append(ra.getID())
        return requirement_assignment_ids    
    

             
