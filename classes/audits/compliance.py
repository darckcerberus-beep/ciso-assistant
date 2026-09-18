"""Compliance assessment models and orchestration helpers."""

import logging
from pathlib import Path

from .. import utils
from .implementation_groups import add_default_implementation_groups
from .requirement_assessment import RequirementAssessmentDict, create_requirement_assignment
from .requirement_assignment import RequirementAssignmentDict

# Load settings from library file
_library_path = Path(__file__).parent.parent.parent / "YML" / "newDPP.yml"
_library = utils.load_yaml_file(str(_library_path))
AUDITOR_SCORE_VISIBILITY = _library.get("audit", {}).get("field_visibility") or _library.get("audit", {}).get("score_visibility", {})
AUDITOR_FIELD_VISIBILITY = AUDITOR_SCORE_VISIBILITY
AUDITOR_SCORE_METHOD = _library.get("audit", {}).get("score_method", "sum")


class ComplianceAssessment:
    """Represent a single compliance assessment returned by the API."""

    def __init__(self, json_ca):
        """Initialize the object using the API payload."""
        if isinstance(json_ca, dict) and "name" in json_ca and "framework" in json_ca:
            self.compliance_assessment_json = json_ca
        else:
            assessment_id = json_ca.get('id', '') if isinstance(json_ca, dict) else str(json_ca)
            self.compliance_assessment_json = utils.get_return(f"/api/compliance-assessments/{assessment_id}/")

    def get_json(self):
        """Return the raw JSON object."""
        return self.compliance_assessment_json

    def get_name(self) -> str:
        """Return the assessment name."""
        return self.compliance_assessment_json.get('name', '')

    def get_id(self) -> str:
        """Return the assessment UUID."""
        return self.compliance_assessment_json.get('id', '')

    def get_framework_id(self) -> str:
        """Return the linked framework identifier."""
        framework = self.compliance_assessment_json.get('framework', {})
        if isinstance(framework, dict):
            return framework.get('id', '')
        return '' if framework in (None, '', {}) else str(framework)

    def get_perimeter_id(self) -> str:
        """Return the linked perimeter identifier."""
        perimeter = self.compliance_assessment_json.get('perimeter', {})
        if isinstance(perimeter, dict):
            return perimeter.get('id', '')
        return '' if perimeter in (None, '', {}) else str(perimeter)

    def has_perimeter(self) -> bool:
        """Return whether this assessment belongs to an internal perimeter."""
        return bool(self.get_perimeter_id())

    def get_asset_id_list(self):
        """Return the asset IDs linked to this compliance assessment."""
        raw_assets = self.compliance_assessment_json.get('assets', [])
        asset_ids = []
        for asset in raw_assets:
            if isinstance(asset, dict):
                aid = asset.get('id', '')
            else:
                aid = str(asset)
            if aid:
                asset_ids.append(str(aid))
        return asset_ids

    def print_name(self):
        """Log the assessment name."""
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        """Log the assessment ID."""
        utils.log(f"ID: {self.get_id()}")

    def print_framework_id(self):
        """Log the framework ID."""
        utils.log(f"Framework ID: {self.get_framework_id()}")

    def print_perimeter_id(self):
        """Log the perimeter ID."""
        utils.log(f"Perimeter ID: {self.get_perimeter_id()}")

    def get_status(self):
        """Return the current status of the compliance assessment."""
        return self.compliance_assessment_json.get('status', '')

    def get_score_from_requirement_node_name(self, requirement_node_name):
        """Return the score for a requirement node matching the provided name."""
        utils.log(f"Searching for requirement node '{requirement_node_name}' in compliance assessment ID: {self.get_id()}")
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
        utils.log("Initializing ComplianceAssessmentDict", level=logging.DEBUG)
        self.reload()
        self.requirement_assessments = RequirementAssessmentDict()
        self.requirement_assignments = RequirementAssignmentDict()
        utils.log("ComplianceAssessmentDict initialized successfully", level=logging.INFO)

    def reload(self):
        """Refresh the internal dictionary from the API."""
        utils.log("Reloading compliance assessments from API", level=logging.DEBUG)
        self.compliance_assessments = {}
        for ca in utils.get_all_results("/api/compliance-assessments/", force_reload=True):
            utils.log(f"Adding compliance assessment object for assessment ID: {ca.get('id')}")
            self.compliance_assessments[ca.get('id')] = ComplianceAssessment(ca)
        if hasattr(self, 'requirement_assessments') and self.requirement_assessments is not None:
            self.requirement_assessments.reload()
        if hasattr(self, 'requirement_assignments') and self.requirement_assignments is not None:
            self.requirement_assignments.reload()
        utils.log(f"Reload completed: {len(self.compliance_assessments)} compliance assessments loaded", level=logging.INFO)

    def get_compliance_assessments(self):
        """Return the compliance assessment dictionary."""
        return self.compliance_assessments

    def create_compliance_assessment(self, name, framework_id, perimeter_id):
        """Create a new compliance assessment via POST request."""
        utils.log(f"Creating compliance assessment: {name} with parameters framework_id={framework_id}, perimeter_id={perimeter_id} and score_method={AUDITOR_SCORE_METHOD}", level=logging.DEBUG)
        payload = {
            'name': name,
            'framework': framework_id,
            'perimeter': perimeter_id,
            'score_calculation_method': AUDITOR_SCORE_METHOD,
            'field_visibility': AUDITOR_SCORE_VISIBILITY,
        }
        add_default_implementation_groups(payload, framework_id)
        response = utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
        self.reload()
        utils.log(f"Compliance assessment created successfully: {name}", level=logging.INFO)
        return ComplianceAssessment(response)

    def create_missing_compliance_assessments(self, framework_dict, perimeter_dict, asset_dict):
        """Ensure every framework/perimeter combination has a compliance assessment."""
        utils.log("Creating missing compliance assessments...")
        created = False

        for framework in framework_dict.get_frameworks():
            for perimeter in perimeter_dict.get_perimeters():
                compliance_assessment_name = f"Assessment of {framework.get_name()} in {perimeter.get_name()}"
                if not self.check_compliance_assessment_from_name(compliance_assessment_name):
                    utils.log(f"Creating compliance assessment: {compliance_assessment_name}")
                    payload = {
                        'name': compliance_assessment_name,
                        'framework': framework.get_id(),
                        'perimeter': perimeter.get_id(),
                        'assets': [asset_dict.get_asset_id_from_perimeter_id(perimeter.get_id(), perimeter_dict)],
                        'score_calculation_method': AUDITOR_SCORE_METHOD,
                        'field_visibility': AUDITOR_SCORE_VISIBILITY,
                    }
                    add_default_implementation_groups(payload, framework.get_id())
                    utils.log(f"Payload for new compliance assessment: {payload}", level=logging.INFO)
                    utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
                    created = True

        self.synchronize_field_visibility()

        if created:
            utils.log("Compliance assessments created.")
            self.reload()
        else:
            utils.log("No new compliance assessments created.")

    def synchronize_field_visibility(self):
        """Ensure all compliance assessments have the configured field visibility and score method."""
        for ca in self.compliance_assessments.values():
            ca_json = ca.get_json()
            changed = {}
            if ca_json.get("field_visibility") != AUDITOR_SCORE_VISIBILITY:
                changed["field_visibility"] = AUDITOR_SCORE_VISIBILITY
            if ca_json.get("score_calculation_method") != AUDITOR_SCORE_METHOD:
                changed["score_calculation_method"] = AUDITOR_SCORE_METHOD
            if changed:
                utils.log(f"Updating field visibility for compliance assessment '{ca.get_name()}' ({ca.get_id()})", level=logging.INFO)
                utils.get_return(f"/api/compliance-assessments/{ca.get_id()}/", method="PATCH", payload=changed)
        self.reload()

    def update_asset_objectives(self, asset_dict):
        """Refresh asset objectives for the current requirement assessment context."""
        self.reload()
        for ra in self.requirement_assessments.get_requirement_assessments().values():
            self.get_asset_id_list_from_compliance_assessment_id(ra.get_compliance_assessment_id())

    def check_compliance_assessment_from_ids(self, framework_id, perimeter_id):
        """Check whether an assessment exists for a framework/perimeter pair."""
        for ca in self.compliance_assessments.values():
            if ca.get_framework_id() == framework_id and ca.get_perimeter_id() == perimeter_id:
                return True
        return False

    def check_compliance_assessment_from_name(self, name):
        """Check whether an assessment exists with the given name."""
        for ca in self.compliance_assessments.values():
            if ca.get_name() == name:
                return True
        return False

    def print_compliance_assessments(self):
        """Log every compliance assessment name."""
        for ca in self.compliance_assessments.values():
            utils.log(f"Compliance assessment name: {ca.get_name()}")

    def get_asset_id_list_from_compliance_assessment_id(self, compliance_assessment_id):
        """Return the asset IDs linked to a compliance assessment."""
        for ca in self.compliance_assessments.values():
            if ca.get_id() == compliance_assessment_id:
                utils.log(f"Getting asset ID list for compliance assessment ID: {compliance_assessment_id}")
                utils.log(f"Compliance assessment name: {ca.get_name()}")
                assets = ca.get_asset_id_list()
                utils.log(f"Compliance assessment assets: {assets}")
                return assets
        return []

    def assign_requirements_to_perimeter_owner(self, perimeter_dict, compliance_assessment_dict, requirement_assessment_dict, requirement_assignment_dict):
        """Create requirement assignments for perimeter owners when no assignment exists."""
        self.reload()
        for ca in self.compliance_assessments.values():
            if not ca.has_perimeter():
                utils.log(
                    f"Skipping perimeter-owner assignment for compliance assessment {ca.get_name()} ({ca.get_id()}): no perimeter",
                    level=logging.INFO,
                )
                continue

            requirement_assessment_ids = requirement_assessment_dict.get_requirement_assessment_id_list_from_compliance_assessment_id(ca.get_id())
            requirement_assignment_ids = requirement_assignment_dict.get_requirement_assignment_id_list_from_compliance_assessment_id(ca.get_id())

            utils.log(f"Requirement assessment IDs for compliance assessment {ca.get_name()}: {requirement_assessment_ids}")
            utils.log(f"Requirement assignment IDs for compliance assessment {ca.get_name()}: {requirement_assignment_ids}")

            if requirement_assessment_ids and not requirement_assignment_ids:
                owner_id = perimeter_dict.get_owner_id_from_perimeter_id(ca.get_perimeter_id())
                if not owner_id:
                    actor_records = utils.get_all_results("/api/actors/")
                    if actor_records and isinstance(actor_records[0], dict):
                        owner_id = actor_records[0].get("id")
                if not owner_id:
                    utils.log(
                        f"Skipping requirement assignment for compliance assessment {ca.get_name()}: no actor available",
                        level=logging.WARNING,
                    )
                    continue

                utils.log(f"Creating assignments for compliance assessment: {ca.get_name()}")
                payload = {
                    "requirement_assessments": requirement_assessment_ids,
                    "compliance_assessment": ca.get_id(),
                    "folder": perimeter_dict.get_folder_uuid_from_perimeter_id(ca.get_perimeter_id()),
                    "actor": [owner_id]
                }
                req_assign_json = create_requirement_assignment(payload)
                if not req_assign_json or (isinstance(req_assign_json, dict) and req_assign_json.get('error')):
                    utils.log(
                        f"Failed to create requirement assignment for compliance assessment {ca.get_name()}: {req_assign_json}",
                        level=logging.ERROR,
                    )
            else:
                utils.log(f"Requirement assignments already exist for compliance assessment: {ca.get_name()}")
                utils.log(f"Requirement assessment IDs: {requirement_assessment_ids}")
                utils.log(f"Requirement assignment IDs: {requirement_assignment_ids}")

    def get_score_from_requirement_node_name(self, requirement_node_name):
        """Search all assessments for a requirement node name and return its score."""
        self.reload()
        for ca in self.compliance_assessments.values():
            score = ca.get_score_from_requirement_node_name(requirement_node_name)
            if score is not None:
                return score
        return None

    def update_asset_criticality(self, criticality_mapping, asset_dict):
        """Update asset criticality based on requirement assessment answers."""
        self.reload()
        for ca in self.compliance_assessments.values():
            requirement_assessment_ids = self.requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id(ca.get_id())
            for ra_id in requirement_assessment_ids:
                ra = self.requirement_assessments.get_requirement_assessments().get(ra_id)
                if ra and ra.has_selected_answer():
                    for question, answer in ra.get_requirement_json().get('answers', {}).items():
                        for criteria_question, criteria_mapping in criticality_mapping.items():
                            if answer in criteria_mapping:
                                utils.log(
                                    f"Updating asset criticality for criteria question: {criteria_question} "
                                    f"in requirement assessment ID: {ra.get_id()}"
                                )
                                utils.log(
                                    f"Question: {question}, Answer: {answer}, "
                                    f"Mapped Criticality: {criteria_mapping[answer]}"
                                )
                                asset_ids = ca.get_asset_id_list()
                                if not asset_ids and ca.get_perimeter_id():
                                    for a in asset_dict.get_assets():
                                        if a.get_name() in ca.get_name() or a.get_folder_id() == ca.get_perimeter_id():
                                            asset_ids = [a.get_id()]
                                            break
                                utils.log(f"Associated asset IDs: {asset_ids}")
                                for asset_id in asset_ids:
                                    utils.log(f"Updating criticality for asset ID: {asset_id}")
                                    asset_dict.update_asset_criticality(asset_id, criteria_question, criteria_mapping[answer])

    def create_missing_applied_controls(self, applied_control_dict, perimeter_dict, reference_control_dict):
        """Delegate applied-control creation to requirement assessments."""
        self.requirement_assessments.create_or_update_applied_controls(applied_control_dict, perimeter_dict, reference_control_dict, self)

    def get_json(self):
        """Return the raw JSON data for all compliance assessments."""
        self.reload()
        return [ca.get_json() for ca in self.compliance_assessments.values()]

    def print_json(self):
        """Log the raw JSON data for all compliance assessments."""
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Printing JSON for compliance assessment: {ca.get_name()}")
            utils.log(ca.get_json())

    def create_risk_assessments(self, risk_assessment_dict, risk_scenario_dict, applied_control_dict, asset_dict, framework_file, requirement_assessment_dict, risk_matrix_dict, framework_dict, vulnerability_dict=None, threat_dict=None):
        """Create risk assessments and evaluate risk scenarios for each compliance assessment.

        Logic:
        1. For each compliance assessment, check if it has at least one answered requirement.
           If unassessed/unanswered, skip risk assessment creation.
        2. Create or find the parent Risk Assessment object tied to the compliance assessment domain,
           perimeter, and associated library risk matrix.
        3. For each risk scenario definition defined in the framework YAML:
           a. Locate the corresponding requirement assessment for likelihood and impact.
           b. If the likelihood requirement has no selected answer, remove any existing scenario and skip.
           c. Determine the raw impact score (either from mapped impact answers or the requirement score).
           d. Determine the raw likelihood score (0-100 percentage score from requirement assessment).
           e. Compute scaled impact (1-4 scale) and scaled likelihood:
              - score between 76-100 -> likelihood level 1 (low risk)
              - score between 51-75  -> likelihood level 2
              - score between 26-50  -> likelihood level 3
              - score between 0-25   -> likelihood level 4 (high risk)
              Formula: scaled_likelihood = min(4, max(1, 4 - ((score - 1) // 25)))
           f. Collect existing (active) vs planned (to_do) controls linked to these requirements.
           g. Create/update the Risk Scenario with scaled likelihood, impact, assets, and owners.
        """
        self.reload()
        for ca in self.compliance_assessments.values():
            utils.log(f"Creating risk assessments for compliance assessment: {ca.get_name()}")
            utils.log(f"Using framework ID: {ca.get_framework_id()}, perimeter ID: {ca.get_perimeter_id()}")
            
            # Skip creating risk assessments when the compliance assessment has no answered requirement assessments
            if not requirement_assessment_dict.has_answers_for_compliance_assessment(ca.get_id()):
                utils.log(f"Skipping risk creation for compliance assessment {ca.get_name()} ({ca.get_id()}): no answered requirements", level=20)
                continue
            requirement_assessment_dict.log_assessment_results_for_compliance_assessment_id(ca.get_id())

            # Load requirement assessments once for this compliance assessment to avoid repeated API calls
            requirement_assessments = requirement_assessment_dict.get_requirement_assessments()

            # Ensure parent Risk Assessment exists in the API for this compliance assessment
            risk_assessment = risk_assessment_dict.create_risk_assessments(
                ca.get_name() + " Risk Assessment",
                ca.get_framework_id(),
                ca.get_perimeter_id(),
                risk_matrix_dict.get_risk_matrix_id_by_library_id(
                    framework_dict.get_library_id_from_framework_id(ca.get_framework_id())
                )
            )

            # Evaluate each scenario defined in the framework configuration
            for risk_scenario in framework_file.get_risk_scenarios():
                utils.log(f"Creating risk scenario: {risk_scenario.get('name', '')} for compliance assessment: {ca.get_name()}")
                utils.log(f"Risk scenario description: {risk_scenario.get('description', '')}")
                utils.log(f"Risk scenario impact node: {risk_scenario.get('impact', '')}")
                utils.log(f"Risk scenario likelihood node: {risk_scenario.get('likelihood', '')}")

                impact_mapping = framework_file.get_impact_mapping()
                impact = None
                impact_assessment = None
                likelihood_assessment = None

                # Search requirement assessments for matching likelihood and impact nodes
                for requirement_assessment in requirement_assessments.values():
                    if requirement_assessment.get_compliance_assessment_id() != ca.get_id():
                        continue
                    if requirement_assessment.get_urn() == risk_scenario.get('likelihood', ''):
                        likelihood_assessment = requirement_assessment
                    if requirement_assessment.get_urn() == risk_scenario.get('impact', ''):
                        impact_assessment = requirement_assessment
                        # Check if any answer matches configured impact mappings
                        for answer in requirement_assessment.get_requirement_json().get('answers', {}).values():
                            if answer in impact_mapping:
                                impact = impact_mapping[answer] + 1
                                break

                # If either the likelihood or impact requirement assessment was never answered, clean up and skip
                if (
                    likelihood_assessment is None
                    or not likelihood_assessment.has_selected_answer()
                    or likelihood_assessment.is_unassessed_result()
                    or impact_assessment is None
                    or not impact_assessment.has_selected_answer()
                    or impact_assessment.is_unassessed_result()
                ):
                    utils.log(
                        f"Skipping risk scenario '{risk_scenario.get('name', '')}': "
                        "its likelihood or impact requirement has no selected answer"
                    )
                    risk_scenario_dict.delete_risk_scenario(
                        risk_scenario.get('name', ''),
                        risk_assessment.get('id', ''),
                    )
                    continue

                # Fallback to direct requirement score if impact was not mapped from answer choices
                if impact is None:
                    impact = requirement_assessment_dict.get_score_from_compliance_assessment_id_and_urn(
                        ca.get_id(), risk_scenario.get('impact', ''), refresh=False
                    )

                likelihood = requirement_assessment_dict.get_score_from_compliance_assessment_id_and_urn(
                    ca.get_id(), risk_scenario.get('likelihood', ''), refresh=False
                )

                # Identify requirement assessment IDs associated with this scenario's likelihood (mitigating controls)
                requirement_assessment_ids = [
                    requirement_assessment.get_id()
                    for requirement_assessment in requirement_assessments.values()
                    if requirement_assessment.get_compliance_assessment_id() == ca.get_id()
                    and requirement_assessment.get_urn() == risk_scenario.get('likelihood', '')
                ]

                # Categorize linked applied controls into active ("existing") and to_do ("planned")
                controls_by_status = applied_control_dict.get_control_ids_by_status_for_requirement_assessments(
                    requirement_assessment_ids
                )
                asset_ids = ca.get_asset_id_list()
                owner_ids = asset_dict.get_owner_ids_for_assets(asset_ids)
                ca_asset_id = asset_ids[0] if asset_ids else None
                ca_asset_name = None
                if asset_dict and ca_asset_id:
                    assets_list = getattr(asset_dict, "assets", [])
                    if hasattr(asset_dict, "get_assets"):
                        assets_list = asset_dict.get_assets()
                    ca_asset_obj = next((a for a in assets_list if a.get_id() == ca_asset_id), None)
                    if ca_asset_obj:
                        ca_asset_name = ca_asset_obj.get_name()

                if likelihood is not None and impact is not None:
                    utils.log(f"Risk scenario impact value: {impact}")
                    scaled_impact = max(1, int(impact))
                    utils.log(f"Scaled impact: {scaled_impact}")

                    # Likelihood scaling: inverse relationship (higher compliance score -> lower risk likelihood)
                    utils.log(f"Risk scenario likelihood value: {likelihood}")
                    score = max(0, min(100, int(likelihood)))
                    scaled_likelihood = min(4, max(1, 4 - ((score - 1) // 25)))
                    utils.log(f"Scaled likelihood: {scaled_likelihood}")

                    vuln_ids = []
                    scenario_vuln_urns = risk_scenario.get("vulnerabilities", [])
                    if vulnerability_dict and scenario_vuln_urns:
                        for vu in scenario_vuln_urns:
                            vid = vulnerability_dict.get_id_by_urn(vu) or vulnerability_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                            vid = None
                            if hasattr(vulnerability_dict, "get_vulnerability_id_for_asset"):
                                vid = vulnerability_dict.get_vulnerability_id_for_asset(
                                    vu, asset_id=ca_asset_id, asset_name=ca_asset_name
                                )
                            if not vid:
                                vid = vulnerability_dict.get_id_by_urn(vu) or vulnerability_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                            if not vid and hasattr(vulnerability_dict, "resolve_vulnerability_id"):
                                vid = vulnerability_dict.resolve_vulnerability_id(vu)
                            if vid and vid not in vuln_ids:
                                vuln_ids.append(vid)

                    threat_ids = []
                    scenario_threat_urns = risk_scenario.get("threats", [])
                    if threat_dict and scenario_threat_urns:
                        for tu in scenario_threat_urns:
                            tid = threat_dict.get_id_by_urn(tu) or threat_dict.get_id_by_ref_id(tu.rsplit(":", 1)[-1])
                            if not tid and hasattr(threat_dict, "resolve_threat_id"):
                                tid = threat_dict.resolve_threat_id(tu)
                            if tid and tid not in threat_ids:
                                threat_ids.append(tid)

                    # Create or update the risk scenario in the API
                    risk_scenario_dict.create_risk_scenario(
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
                        vulnerabilities=vuln_ids,
                        threats=threat_ids,
                    )

    def create_findings_assessments(
        self,
        findings_assessment_dict,
        finding_dict,
        requirement_assessment_dict=None,
        asset_dict=None,
        vulnerability_dict=None,
        threat_dict=None,
        framework_file=None,
        compliance_assessment_id: str | None = None,
    ) -> list[dict]:
        """Create findings assessments and individual findings for compliance gaps.

        Evaluates requirement assessment answers from compliance assessments (both internal
        perimeters and TPRM entity assessments) and creates actionable findings for any
        non-conformity (result in ('non_compliant', 'partially_compliant') or score < 100%).

        Args:
            findings_assessment_dict: FindingsAssessmentDict collection instance.
            finding_dict: FindingDict collection instance.
            requirement_assessment_dict: Optional RequirementAssessmentDict instance.
            asset_dict: Optional AssetDict instance.
            vulnerability_dict: Optional VulnerabilityDict instance.
            threat_dict: Optional ThreatDict instance.
            framework_file: Optional FrameworkFile instance for vulnerability/threat metadata.
            compliance_assessment_id: Optional UUID to evaluate only a specific assessment.

        Returns:
            List of summary dicts with findings assessments and findings counts.
        """
        if not self.compliance_assessments:
            self.reload()
        ra_dict = requirement_assessment_dict or self.requirement_assessments

        # Build vulnerability and threat lookup maps from framework YAML if available
        vuln_to_threats_map: dict[str, list[str]] = {}
        req_to_vulns_map: dict[str, list[str]] = {}
        if framework_file and hasattr(framework_file, "json_object") and isinstance(framework_file.json_object, dict):
            raw_vulns = framework_file.json_object.get("objects", {}).get("vulnerabilities", [])
            for v in raw_vulns:
                if isinstance(v, dict) and v.get("urn"):
                    vuln_to_threats_map[v["urn"]] = v.get("threats", []) or []

            fw_obj = framework_file.json_object.get("objects", {}).get("framework", {})
            if isinstance(fw_obj, dict):
                for rn in fw_obj.get("requirement_nodes", []):
                    if isinstance(rn, dict):
                        vulns = rn.get("vulnerabilities", []) or []
                        if rn.get("urn"):
                            req_to_vulns_map[rn["urn"]] = vulns
                        if rn.get("ref_id"):
                            req_to_vulns_map[rn["ref_id"]] = vulns

        summaries = []
        target_cas = (
            [self.compliance_assessments[compliance_assessment_id]]
            if compliance_assessment_id and compliance_assessment_id in self.compliance_assessments
            else list(self.compliance_assessments.values())
        )

        for ca in target_cas:
            ca_id = ca.get_id()
            ca_name = ca.get_name()
            perimeter_id = ca.get_perimeter_id() or None

            if not ra_dict.has_answers_for_compliance_assessment(ca_id):
                utils.log(f"Skipping findings creation for {ca_name}: no answered requirements", level=logging.DEBUG)
                continue

            # Resolve folder
            ca_json = ca.get_json()
            folder_id = ca_json.get("folder")
            if isinstance(folder_id, dict):
                folder_id = folder_id.get("id")
            if not folder_id and perimeter_id:
                folder_id = perimeter_id

            # Create or resolve parent FindingsAssessment
            fa_name = f"{ca_name} Findings"
            fa_res = findings_assessment_dict.create_findings_assessment(
                name=fa_name,
                folder_id=folder_id or "",
                perimeter_id=perimeter_id,
                category="audit",
                status="in_progress",
                description=f"Audit findings assessment generated from compliance questionnaire answers for {ca_name}.",
            )
            fa_id = fa_res.get("id") if isinstance(fa_res, dict) else findings_assessment_dict.get_id_from_name(fa_name)
            if not fa_id:
                utils.log(f"Failed to create findings assessment container for {ca_name}", level=logging.WARNING)
                continue

            app_ras = [
                ra for ra in ra_dict.get_requirement_assessments().values()
                if ra.get_compliance_assessment_id() == ca_id
            ]

            created_findings_count = 0
            for ra in app_ras:
                if not ra.has_selected_answer() or ra.is_unassessed_result():
                    continue

                result = (ra.get_assessment_results() or "").strip().lower()
                if result in ("not_applicable", "n/a", "na"):
                    continue

                score_raw = ra.get_score()
                score = None
                if score_raw is not None and score_raw != "":
                    try:
                        score = float(score_raw)
                    except (ValueError, TypeError):
                        score = None

                # Determine if this requirement is an audit finding / gap
                is_gap = False
                if result in ("non_compliant", "partially_compliant"):
                    is_gap = True
                elif score is not None and score < 100.0 and result != "compliant":
                    is_gap = True

                if not is_gap:
                    continue

                req_json = ra.get_requirement_json()
                req_obj = req_json.get("requirement", {}) if isinstance(req_json, dict) else {}
                req_name = ra.get_name() or (req_obj.get("name") if isinstance(req_obj, dict) else "") or ra.get_urn()
                req_urn = ra.get_urn()
                req_ref_id = ra.get_requirement_ref_id()

                # Severity & Priority derivation
                asset_ids = ra.get_asset_id_list() or ca.get_asset_id_list()
                asset_id = asset_ids[0] if asset_ids else None

                is_high_sensitivity = False
                asset_name = None
                if asset_dict and asset_id:
                    asset_obj = next((a for a in asset_dict.get_assets() if a.get_id() == asset_id), None)
                    if asset_obj:
                        asset_name = asset_obj.get_name()
                        sec_obj = asset_obj.get_security_objectives() if hasattr(asset_obj, "get_security_objectives") else {}
                        conf = sec_obj.get("confidentiality") if isinstance(sec_obj, dict) else None
                        if conf in (3, 4, "3", "4", "secret", "critical"):
                            is_high_sensitivity = True

                if result == "non_compliant" or (score is not None and score <= 25.0):
                    severity = 4 if is_high_sensitivity else 3
                elif result == "partially_compliant" or (score is not None and score <= 75.0):
                    severity = 2
                elif score is not None and score < 100.0:
                    severity = 1
                else:
                    severity = 2

                priority_map = {4: 1, 3: 2, 2: 3, 1: 4}
                priority = priority_map.get(severity, 3)

                obs = req_json.get("observation") if isinstance(req_json, dict) else ""
                req_desc = req_obj.get("description", "") if isinstance(req_obj, dict) else ""
                desc_lines = [
                    f"Audit gap identified during assessment '{ca_name}'.",
                    f"Requirement: {req_name} (Result: {result or 'gap'}, Score: {score if score is not None else 'N/A'}%).",
                ]
                if req_desc:
                    desc_lines.append(f"Requirement Description: {req_desc}")
                if obs:
                    desc_lines.append(f"Auditor Observation: {obs}")

                req_node_id = req_obj.get("id") if isinstance(req_obj, dict) else None
                if not req_node_id:
                    req_node_id = ra.get_requirement_id()
                if isinstance(req_node_id, dict):
                    req_node_id = req_node_id.get("id")

                # Resolve Vulnerabilities and Threats
                vuln_urns = req_to_vulns_map.get(req_urn, []) or req_to_vulns_map.get(req_ref_id, [])
                if not vuln_urns and isinstance(req_obj, dict):
                    vuln_urns = req_obj.get("vulnerabilities", []) or []

                vuln_ids = []
                threat_ids = []
                if vulnerability_dict and vuln_urns:
                    for vu in vuln_urns:
                        vid = vulnerability_dict.get_id_by_urn(vu) or vulnerability_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                        vid = None
                        if hasattr(vulnerability_dict, "get_vulnerability_id_for_asset"):
                            vid = vulnerability_dict.get_vulnerability_id_for_asset(
                                vu, asset_id=asset_id, asset_name=asset_name
                            )
                        if not vid:
                            vid = vulnerability_dict.get_id_by_urn(vu) or vulnerability_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                        if not vid and hasattr(vulnerability_dict, "resolve_vulnerability_id"):
                            vid = vulnerability_dict.resolve_vulnerability_id(vu)
                        if vid and vid not in vuln_ids:
                            vuln_ids.append(vid)
                        # Threat mapping
                        if threat_dict:
                            for tu in vuln_to_threats_map.get(vu, []):
                                tid = threat_dict.get_id_by_urn(tu) or threat_dict.get_id_by_ref_id(tu.rsplit(":", 1)[-1])
                                if not tid and hasattr(threat_dict, "resolve_threat_id"):
                                    tid = threat_dict.resolve_threat_id(tu)
                                if tid and tid not in threat_ids:
                                    threat_ids.append(tid)

                owner_ids = []
                if asset_dict and asset_ids:
                    owner_ids = asset_dict.get_owner_ids_for_assets(asset_ids)

                finding_title = f"Audit Finding: Non-compliance on {req_name}"
                created_f = finding_dict.create_finding(
                    findings_assessment_id=fa_id,
                    name=finding_title,
                    description="\n".join(desc_lines),
                    observation=obs or None,
                    severity=severity,
                    priority=priority,
                    status="identified",
                    requirement_node=str(req_node_id) if req_node_id else None,
                    asset=asset_id,
                    threats=threat_ids,
                    vulnerabilities=vuln_ids,
                    reference_controls=ra.get_associated_reference_control_ids(),
                    applied_controls=ra.get_applied_control_ids(),
                    owner=owner_ids,
                    ref_id=req_ref_id or None,
                )
                if created_f and (not isinstance(created_f, dict) or not created_f.get("error")):
                    created_findings_count += 1

            summaries.append({
                "compliance_assessment_id": ca_id,
                "compliance_assessment_name": ca_name,
                "findings_assessment_id": fa_id,
                "findings_assessment_name": fa_name,
                "findings_count": created_findings_count,
            })

        return summaries

    def delete_compliance_assessment(self, compliance_assessment_id):
        """Delete a compliance assessment via DELETE request."""
        utils.log(f"Deleting compliance assessment ID: {compliance_assessment_id}", level=logging.INFO)
        response = utils.get_return(
            f"/api/compliance-assessments/{compliance_assessment_id}/",
            method="DELETE",
        )
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.compliance_assessments.pop(compliance_assessment_id, None)
            utils.log(f"Successfully deleted compliance assessment ID: {compliance_assessment_id}", level=logging.INFO)
            return True
        utils.log(f"Failed to delete compliance assessment ID {compliance_assessment_id}: {response}", level=logging.ERROR)
        return False

