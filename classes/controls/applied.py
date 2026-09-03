import logging

from .. import utils


class AppliedControl:
    """Represents an applied control from the API."""

    def __init__(self, json_control):
        """Initialize with control data from API."""
        control_id = json_control.get('id')
        self.json_object = utils.get_return(f"/api/applied-controls/{control_id}/")

    def get_json(self):
        """Return the full JSON object."""
        return self.json_object

    def get_name(self):
        """Return the control name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the control ID."""
        return self.json_object.get('id', '')

    def get_requirement_assessment_ids(self):
        """Return IDs of requirement assessments linked to this control."""
        assessments = self.json_object.get('requirement_assessments', [])
        if not isinstance(assessments, list):
            return []
        return [
            assessment.get('id', '') if isinstance(assessment, dict) else assessment
            for assessment in assessments
        ]

    def get_status(self):
        """Return the implementation status of this control."""
        return self.json_object.get('status', '')

    def print_name(self):
        """Print the control name."""
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        """Print the control ID."""
        utils.log(f"ID: {self.get_id()}")

    @classmethod
    def create_applied_control(cls, name, control, requirement_assessment, status):
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
        for c in utils.get_all_results("/api/applied-controls/", force_reload=True):
            self.controls[c.get('id')] = AppliedControl(c)

    def get_controls(self):
        """Return all controls."""
        return self.controls

    def print_controls(self):
        """Print all control names and IDs."""
        for c in self.controls.values():
            c.print_name()
            c.print_id()

    def print_json(self):
        """Print JSON representation of all controls."""
        for c in self.controls.values():
            utils.log(c.get_json())

    def get_control_ids_by_status_for_requirement_assessments(self, requirement_assessment_ids):
        """Group controls by implementation status for the supplied assessments."""
        assessment_ids = set(requirement_assessment_ids)
        controls_by_status = {"existing": [], "planned": []}
        for control in self.controls.values():
            if not assessment_ids.intersection(control.get_requirement_assessment_ids()):
                continue

            status_group = "existing" if control.get_status() == "active" else "planned"
            controls_by_status[status_group].append(control.get_id())
        return controls_by_status

    def get_priority_from_risk_level(self, risk_level):
        """Translate a risk level ID into the API priority integer: 1 is highest, 4 is lowest."""
        if isinstance(risk_level, dict):
            risk_level = risk_level.get("id", risk_level.get("value"))
        try:
            risk_level = int(risk_level)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid risk level value: {risk_level!r}")

        # Risk level 4 (critical) => priority 1 (highest urgency)
        # Risk level 3 => 2
        # Risk level 2 => 3
        # Risk level 1/0 => 4 (lowest urgency)
        if risk_level >= 4:
            return 1
        if risk_level == 3:
            return 2
        if risk_level == 2:
            return 3
        return 4

    def get_priority_for_compliance_assessment_id(self, compliance_assessment_id, requirement_urn):
        """Return priority from the current level of the scenario associated with a requirement."""
        from ..core.framework import FrameworkFile

        compliance_assessment = None
        for ca in utils.get_all_results("/api/compliance-assessments/"):
            if ca.get("id") == compliance_assessment_id:
                compliance_assessment = ca
                break

        if compliance_assessment is None:
            raise LookupError(
                f"Compliance assessment with id {compliance_assessment_id!r} not found"
            )

        compliance_name = compliance_assessment.get("name", "")
        risk_assessment_id = None
        for risk_assessment in utils.get_all_results("/api/risk-assessments/"):
            if risk_assessment.get("name", "") == f"{compliance_name} Risk Assessment":
                risk_assessment_id = risk_assessment.get("id")
                break

        if risk_assessment_id is None:
            raise LookupError(
                f"Risk assessment for compliance '{compliance_name}' not found"
            )

        scenario_names = {
            scenario.get("name", "")
            for scenario in FrameworkFile("YML/newDPP.yml").get_risk_scenarios()
            if scenario.get("likelihood") == requirement_urn
        }
        if not scenario_names:
            raise LookupError(
                f"No risk scenarios reference requirement urn {requirement_urn!r}"
            )

        for scenario in utils.get_all_results("/api/risk-scenarios/"):
            risk_assessment = scenario.get("risk_assessment", {})
            if isinstance(risk_assessment, dict):
                scenario_risk_assessment_id = risk_assessment.get("id")
            else:
                scenario_risk_assessment_id = risk_assessment

            if (
                scenario_risk_assessment_id != risk_assessment_id
                or scenario.get("name", "") not in scenario_names
            ):
                continue

            # Prefer explicit current_level if present
            current_level = scenario.get("current_level")
            if isinstance(current_level, dict):
                return self.get_priority_from_risk_level(
                    current_level.get("id", current_level.get("value"))
                )
            # Fallback: some API representations use numeric current_proba (0-based)
            current_proba = scenario.get("current_proba")
            if isinstance(current_proba, int):
                # convert 0-based proba to 1-based risk level
                risk_level = current_proba + 1
                utils.log(f"Using fallback current_proba={current_proba} -> risk_level={risk_level} for scenario {scenario.get('name','')}")
                return self.get_priority_from_risk_level(risk_level)
        raise LookupError(
            f"No matching risk scenario with a current level for compliance assessment {compliance_assessment_id!r} and requirement {requirement_urn!r}"
        )

    def check_applied_control_from_name(self, name):
        """Check if a control with the given name exists.

        Args:
            name: Control name to search for

        Returns:
            True if control exists, False otherwise
        """
        for c in self.controls.values():
            if c.get_name() == name:
                return True
        return False

    def update_priority_for_requirement_assessment(self, name, compliance_assessment_id, requirement_urn):
        """Synchronize an existing to-do control with its associated scenario risk level."""
        try:
            priority = self.get_priority_for_compliance_assessment_id(
                compliance_assessment_id, requirement_urn
            )
        except (LookupError, ValueError) as e:
            utils.log(f"Could not determine priority for {compliance_assessment_id!r} / {requirement_urn!r}: {e}", level=logging.WARNING)
            return None
        for control in self.controls.values():
            if control.get_name() != name or control.get_status() != "to_do":
                continue
            response = utils.get_return(
                f"/api/applied-controls/{control.get_id()}/",
                method="PATCH",
                payload={"priority": priority},
            )
            if isinstance(response, dict) and not response.get("error"):
                control.json_object = response
            return response
        return None

    def update_folder_for_control(self, name, folder_id):
        """Synchronize an existing control with its perimeter folder."""
        if not folder_id:
            return None
        for control in self.controls.values():
            if control.get_name() != name:
                continue
            response = utils.get_return(
                f"/api/applied-controls/{control.get_id()}/",
                method="PATCH",
                payload={"folder": folder_id},
            )
            if isinstance(response, dict) and not response.get("error"):
                control.json_object = response
            return response
        return None

    def create_missing_applied_controls(self, perimeter_dict, requirement_assessment,
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

        # Determine which compliance assessments have at least one answered requirement assessment
        answered_ca_ids = set()
        for _ra in requirement_assessment.get_requirement_assessments().values():
            if not _ra.is_unassessed_result() and _ra.has_selected_answer():
                answered_ca_ids.add(_ra.get_compliance_assessment_id())

        external_context_by_compliance_id = {}
        for entity_assessment in utils.get_all_results('/api/entity-assessments/', force_reload=True):
            from ..audits.entity_assessment import EntityAssessment

            compliance_assessment = entity_assessment.get('compliance_assessment', {})
            compliance_assessment_id = (
                compliance_assessment.get('id')
                if isinstance(compliance_assessment, dict)
                else compliance_assessment
            )
            if not compliance_assessment_id:
                continue

            entity = entity_assessment.get('entity', {})
            entity_name = entity.get('name') or entity.get('str') if isinstance(entity, dict) else ''
            folder = entity_assessment.get('folder', {})
            folder_id = folder.get('id') if isinstance(folder, dict) else folder
            assessment = EntityAssessment(entity_assessment)
            external_context_by_compliance_id[compliance_assessment_id] = {
                'entity_name': entity_name,
                'folder_id': folder_id,
                'owner_ids': assessment.resolve_actor_ids(assessment.get_representative_ids()),
            }

        for ra in requirement_assessment.get_requirement_assessments().values():
            # Skip entire compliance assessments that have no answered requirement assessments
            if ra.get_compliance_assessment_id() not in answered_ca_ids:
                utils.log(f"Skipping applied-control creation for compliance assessment {ra.get_compliance_assessment_id()} because it has no answered requirements", level=20)
                continue
            # Skip non-assessed or empty results
            if ra.is_unassessed_result() or not ra.has_selected_answer():
                continue

            perimeter_id = ra.get_perimeter_id()
            if not perimeter_id:
                external_context = external_context_by_compliance_id.get(ra.get_compliance_assessment_id())
                if not external_context:
                    utils.log(
                        f"Skipping applied-control creation for requirement assessment {ra.get_id()}: no perimeter or entity assessment",
                        level=logging.INFO,
                    )
                    continue

            for control_id in ra.get_associated_reference_control_ids():
                control_name = reference_control_dict.get_name_from_id(control_id)
                if perimeter_id:
                    scope_name = perimeter_dict.get_name_from_id(perimeter_id)
                    folder_id = perimeter_dict.get_folder_uuid_from_perimeter_id(perimeter_id)
                    owner_ids = [perimeter_dict.get_owner_id_from_perimeter_id(perimeter_id)]
                else:
                    scope_name = external_context['entity_name']
                    folder_id = external_context['folder_id']
                    owner_ids = external_context['owner_ids']
                name = f"{control_name} on {scope_name}"

                # Skip if control already exists
                if self.check_applied_control_from_name(name):
                    self.update_folder_for_control(name, folder_id)
                    if ra.get_assessment_results() != "compliant":
                        self.update_priority_for_requirement_assessment(
                            name, ra.get_compliance_assessment_id(), ra.get_urn()
                        )
                    continue

                # Determine owner and status based on assessment results
                is_compliant = ra.get_assessment_results() == "compliant"
                priority = None
                if not is_compliant:
                    try:
                        priority = self.get_priority_for_compliance_assessment_id(
                            ra.get_compliance_assessment_id(), ra.get_urn()
                        )
                    except (LookupError, ValueError) as e:
                            utils.log(
                                f"Could not determine priority for compliance {ra.get_compliance_assessment_id()!r} / {ra.get_urn()!r}: {e}",
                                level=logging.WARNING,
                            )
                payload = {
                    "name": name,
                    "reference_control": control_id,
                    "owner": owner_ids if not is_compliant else [],
                    "folder": folder_id,
                    "assets": compliance_assessment_dict.get_asset_id_list_from_compliance_assessment_id(ra.get_compliance_assessment_id()),
                    "compliance_assessments": [ra.get_compliance_assessment_id()],
                    "requirement_assessments": [ra.get_id()],
                    "status": "active" if is_compliant else "to_do",
                    **({"priority": priority} if priority is not None else {})
                }
                utils.log(f"Payload for creating applied control: {payload}")
                utils.get_return("/api/applied-controls/", method="POST", payload=payload)
                created += 1

        # Log completion status
        if created > 0:
            utils.log(f"Created {created} applied control(s).")
        else:
            utils.log("No new applied controls created.")
