"""Example Application Simulation and Lifecycle Manager for CISO Assistant.

Orchestrates the creation and removal of example applications in CISO Assistant
via the REST API so that compliance assessments, questionnaire answers, risk scenarios,
applied controls, and asset criticalities can be visualized directly in the CISO Assistant UI.
"""

import logging
from pathlib import Path
import time
from typing import Any

from classes import utils
from classes.core.framework import FrameworkDict, FrameworkFile
from classes.core.risk import RiskAssessmentDict, RiskMatrixDict, RiskScenarioDict
from classes.core.user import UserDict
from classes.controls.applied import AppliedControlDict
from classes.controls.reference import ReferenceControlDict
from classes.audits.compliance import ComplianceAssessmentDict, AUDITOR_SCORE_METHOD, AUDITOR_SCORE_VISIBILITY
from classes.audits.entity_assessment import EntityAssessmentDict
from classes.audits.implementation_groups import add_default_implementation_groups
from classes.audits.requirement_assessment import create_requirement_assignment
from classes.organization.asset import AssetDict
from classes.organization.domain import DomainDict, criticality_mapping
from classes.organization.entity import EntityDict, EntityRepresentativeDict
from classes.organization.perimeter import PerimeterDict
from classes.integrations import csv_import

LOGGER = logging.getLogger(__name__)

EXAMPLE_APPLICATIONS = [
    {
        "id": "app_secure_core",
        "name": "App-Secure-Core",
        "label": "App-Secure-Core (Secret / 100% Compliant)",
        "csv_path": "test_data/app_secure_core.csv",
        "classification": "Secret",
        "compliance_target": "100%",
        "expected_risk": "Low (Acceptable)",
        "description": "High classification (Secret) + Full compliance (100%) -> Low Risk",
        "user": {
            "email": "alice.secure@example-core.com",
            "first_name": "Alice",
            "last_name": "Secure",
        },
        "tprm": {
            "criticality": 4,
            "maturity": 4,
            "trust": 4,
            "conclusion": "ok",
        },
    },
    {
        "id": "app_vulnerable_portal",
        "name": "App-Vulnerable-Portal",
        "label": "App-Vulnerable-Portal (Secret / 0% Non-Compliant)",
        "csv_path": "test_data/app_vulnerable_portal.csv",
        "classification": "Secret",
        "compliance_target": "0%",
        "expected_risk": "Very High / Critical -> Urgent Remediation",
        "description": "High classification (Secret) + Non-compliant (0%) -> Critical Risk -> Urgent Priority",
        "user": {
            "email": "victor.vulnerable@example-portal.com",
            "first_name": "Victor",
            "last_name": "Vulnerable",
        },
        "tprm": {
            "criticality": 4,
            "maturity": 1,
            "trust": 1,
            "conclusion": "blocker",
        },
    },
    {
        "id": "app_internal_tool",
        "name": "App-Internal-Tool",
        "label": "App-Internal-Tool (Internal / Mixed Compliance)",
        "csv_path": "test_data/app_internal_tool.csv",
        "classification": "Internal",
        "compliance_target": "Mixed",
        "expected_risk": "Medium (Scenario-dependent)",
        "description": "Medium classification (Internal) + Mixed compliance -> Scenario-dependent Risks",
        "user": {
            "email": "ian.internal@example-tool.com",
            "first_name": "Ian",
            "last_name": "Internal",
        },
        "tprm": {
            "criticality": 2,
            "maturity": 2,
            "trust": 2,
            "conclusion": "warning",
        },
    },
    {
        "id": "app_public_blog",
        "name": "App-Public-Blog",
        "label": "App-Public-Blog (Public / Low Sensitivity)",
        "csv_path": "test_data/app_public_blog.csv",
        "classification": "Public",
        "compliance_target": "Mixed / Low Impact",
        "expected_risk": "Low (Capped at 1)",
        "description": "Low classification (Public) + Mixed compliance -> Low Impact & Low Risk",
        "user": {
            "email": "paula.public@example-blog.com",
            "first_name": "Paula",
            "last_name": "Public",
        },
        "tprm": {
            "criticality": 1,
            "maturity": 3,
            "trust": 3,
            "conclusion": "ok",
        },
    },
    {
        "id": "app_hr_people_system",
        "name": "App-HR-People-System",
        "label": "App-HR-People-System (Confidential / HR & Privacy Gaps)",
        "csv_path": "test_data/app_hr_people_system.csv",
        "classification": "Confidential",
        "compliance_target": "Mixed / Privacy Gaps",
        "expected_risk": "High (GDPR & Data Retention)",
        "description": "Confidential classification + Strong encryption + Unmasked non-prod retention & missing deletion -> High Privacy Risk",
        "user": {
            "email": "hannah.hr@example-peoplesys.com",
            "first_name": "Hannah",
            "last_name": "HR",
        },
        "tprm": {
            "criticality": 3,
            "maturity": 2,
            "trust": 2,
            "conclusion": "warning",
        },
    },
    {
        "id": "app_customer_payment_api",
        "name": "App-Customer-Payment-API",
        "label": "App-Customer-Payment-API (Secret / PCI-DSS Aligned)",
        "csv_path": "test_data/app_customer_payment_api.csv",
        "classification": "Secret",
        "compliance_target": "High (95%)",
        "expected_risk": "Low-to-Medium (Vendor SLA Gaps)",
        "description": "Secret classification + High technical compliance + Single clearinghouse notification SLA gap",
        "user": {
            "email": "peter.pay@example-paymentapi.com",
            "first_name": "Peter",
            "last_name": "Payment",
        },
        "tprm": {
            "criticality": 4,
            "maturity": 3,
            "trust": 3,
            "conclusion": "warning",
        },
    },
    {
        "id": "app_legacy_erp_production",
        "name": "App-Legacy-ERP-Production",
        "label": "App-Legacy-ERP-Production (Internal / On-Prem Legacy)",
        "csv_path": "test_data/app_legacy_erp_production.csv",
        "classification": "Internal",
        "compliance_target": "Low / Legacy Gaps",
        "expected_risk": "Medium (Cleartext LAN & Unencrypted DB)",
        "description": "Internal classification + In-house hosting + Unencrypted LAN/DB + Legacy authentication",
        "user": {
            "email": "larry.legacy@example-legacyerp.com",
            "first_name": "Larry",
            "last_name": "Legacy",
        },
        "tprm": {
            "criticality": 2,
            "maturity": 2,
            "trust": 1,
            "conclusion": "warning",
        },
    },
    {
        "id": "app_ai_analytics_workbench",
        "name": "App-AI-Analytics-Workbench",
        "label": "App-AI-Analytics-Workbench (Confidential / Cloud GenAI)",
        "csv_path": "test_data/app_ai_analytics_workbench.csv",
        "classification": "Confidential",
        "compliance_target": "Mixed / GenAI Risks",
        "expected_risk": "High (External LLM Transfer & Prompt Data Leakage)",
        "description": "Confidential classification + SaaS hosting + External LLM transfer without contract + Unmasked prompt logs",
        "user": {
            "email": "arthur.ai@example-aiworkbench.com",
            "first_name": "Arthur",
            "last_name": "AI",
        },
        "tprm": {
            "criticality": 3,
            "maturity": 2,
            "trust": 2,
            "conclusion": "warning",
        },
    },
]

EXAMPLE_FOLDER_NAME = "Example Applications"
DEFAULT_FRAMEWORK_NAME = "Multi-level DPP"
DEFAULT_FRAMEWORK_REF = "mls"
FRAMEWORK_YAML_PATH = "YML/newDPP.yml"


class ExamplesManager:
    """Manages the creation, status discovery, and deletion of example applications in CISO Assistant."""

    def __init__(self, folder_name: str = EXAMPLE_FOLDER_NAME):
        self.folder_name = folder_name
        self.framework_yaml = Path(FRAMEWORK_YAML_PATH)
        self.data: dict[str, Any] | None = None

    def _init_data(self, force_reload: bool = False):
        """Initialize or refresh cached API resource collections."""
        if self.data is None or force_reload:
            utils.clear_get_all_results_cache()
            self.data = {
                "domain_dict": DomainDict(),
                "perimeter_dict": PerimeterDict(),
                "asset_dict": AssetDict(),
                "framework_dict": FrameworkDict(),
                "compliance_assessment_dict": ComplianceAssessmentDict(),
                "risk_assessment_dict": RiskAssessmentDict(),
                "risk_scenario_dict": RiskScenarioDict(),
                "risk_matrix_dict": RiskMatrixDict(),
                "reference_control_dict": ReferenceControlDict(),
                "applied_control_dict": AppliedControlDict(),
                "user_dict": UserDict(),
                "entity_dict": EntityDict(),
                "entity_assessment_dict": EntityAssessmentDict(),
                "entity_representative_dict": EntityRepresentativeDict(),
                "framework_file": FrameworkFile(str(self.framework_yaml)),
            }
        return self.data

    def test_connection(self) -> tuple[bool, str]:
        """Verify API connectivity and authentication.

        Returns:
            Tuple of (success_bool, message_str)
        """
        try:
            response = utils.get_return("/api/users/", log_errors=False)
            if response is None:
                return False, f"Connection failed to {utils.BASE_URL}. Check network and BASE_URL in keys.py."
            if isinstance(response, dict) and response.get("error"):
                return False, f"API returned error: {response.get('error')}. Verify API_TOKEN in keys.py."
            return True, f"Connected successfully to {utils.BASE_URL}."
        except Exception as e:
            return False, f"Connection exception: {e}"

    def get_or_create_folder(self) -> str | None:
        """Retrieve or create the destination folder/domain for example applications."""
        data = self._init_data()
        domain_dict: DomainDict = data["domain_dict"]

        folder_id = domain_dict.get_id_from_name(self.folder_name)
        if folder_id:
            return folder_id

        # Fall back to any existing folder if creation fails, or create it
        new_folder = domain_dict.upsert_folder(self.folder_name)
        if isinstance(new_folder, dict) and new_folder.get("id"):
            return new_folder.get("id")

        domains = domain_dict.get_domains()
        if domains:
            fallback = domains[0]
            utils.log(f"Using fallback domain '{fallback.get_name()}' ({fallback.get_id()})", level=logging.WARNING)
            return fallback.get_id()

        return None

    def get_default_assignee_id(self) -> str | None:
        """Find an active actor to assign as owner of perimeters and assets."""
        data = self._init_data()

        # 1. First, check if any existing perimeter already has a configured default assignee
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        for p in perimeter_dict.get_perimeters():
            assignee_id = p.get_default_assignee_id()
            if assignee_id:
                return assignee_id

        # 2. Query /api/actors/ directly (CISO Assistant expects Actor UUIDs for default_assignee)
        actor_records = utils.get_all_results("/api/actors/", force_reload=True)
        if actor_records:
            for actor in actor_records:
                if isinstance(actor, dict) and actor.get("id"):
                    return actor["id"]

        return None

    def find_target_framework(self) -> Any | None:
        """Find the matching framework in CISO Assistant (by name or ref_id)."""
        data = self._init_data()
        framework_dict: FrameworkDict = data["framework_dict"]
        frameworks = framework_dict.get_frameworks()

        for fw in frameworks:
            if fw.get_name() == DEFAULT_FRAMEWORK_NAME:
                return fw
            fw_json = fw.json_object if hasattr(fw, "json_object") else {}
            if fw_json.get("ref_id") == DEFAULT_FRAMEWORK_REF:
                return fw

        # If not exact match, return first available framework
        if frameworks:
            utils.log(
                f"Default framework '{DEFAULT_FRAMEWORK_NAME}' not found; using '{frameworks[0].get_name()}'",
                level=logging.WARNING,
            )
            return frameworks[0]
        return None

    def find_target_risk_matrix(self, framework_id: str) -> str | None:
        """Resolve a suitable risk matrix UUID for the risk assessment."""
        data = self._init_data()
        risk_matrix_dict: RiskMatrixDict = data["risk_matrix_dict"]
        framework_dict: FrameworkDict = data["framework_dict"]

        library_id = framework_dict.get_library_id_from_framework_id(framework_id)
        if library_id:
            matrix_id = risk_matrix_dict.get_risk_matrix_id_by_library_id(library_id)
            if matrix_id:
                return matrix_id

        matrices = risk_matrix_dict.get_risk_matrices()
        if matrices:
            return next(iter(matrices.keys()))
        return None

    def get_status(self, wait_seconds: float = 0) -> list[dict[str, Any]]:
        """Return the current deployment status of all example applications.

        Args:
            wait_seconds: Optional sleep before reloading data to allow backend updates to finalize.
        """
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        data = self._init_data(force_reload=True)
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        asset_dict: AssetDict = data["asset_dict"]
        compliance_dict: ComplianceAssessmentDict = data["compliance_assessment_dict"]
        risk_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenarios_dict: RiskScenarioDict = data["risk_scenario_dict"]
        applied_ctrl_dict: AppliedControlDict = data["applied_control_dict"]
        entity_dict: EntityDict = data["entity_dict"]
        entity_assessment_dict: EntityAssessmentDict = data["entity_assessment_dict"]
        user_dict: UserDict = data["user_dict"]

        status_list = []
        for app in EXAMPLE_APPLICATIONS:
            app_name = app["name"]
            perimeter_id = perimeter_dict.get_id_from_name(app_name)
            asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)

            ca_obj = None
            for ca in compliance_dict.get_compliance_assessments().values():
                if perimeter_id and ca.get_perimeter_id() == perimeter_id:
                    ca_obj = ca
                    break
                if app_name in ca.get_name():
                    ca_obj = ca
                    break

            ra_obj = None
            ra_scenarios_count = 0
            for ra in risk_dict.get_risk_assessments().values():
                if perimeter_id and ra.json_object.get("perimeter") == perimeter_id:
                    ra_obj = ra
                    break
                if app_name in ra.get_name():
                    ra_obj = ra
                    break

            existing_ctrls_linked = 0
            planned_ctrls_linked = 0
            if ra_obj:
                ra_id = ra_obj.get_id()
                for sc in risk_scenarios_dict.get_risk_scenarios().values():
                    sc_ra = sc.get_json().get("risk_assessment")
                    if isinstance(sc_ra, dict):
                        sc_ra = sc_ra.get("id")
                    if sc_ra == ra_id:
                        ra_scenarios_count += 1
                        existing_ctrls_linked += len(sc.get_json().get("existing_applied_controls") or [])
                        planned_ctrls_linked += len(sc.get_json().get("applied_controls") or [])

            ctrl_count = 0
            for ctrl in applied_ctrl_dict.get_controls().values():
                ctrl_name = ctrl.get_name()
                if f"on {app_name}" in ctrl_name:
                    ctrl_count += 1

            entity_id = entity_dict.get_id_from_name(app_name)
            ea_obj = None
            for ea in entity_assessment_dict.get_entity_assessments():
                if entity_id and ea.get_entity_id() == entity_id:
                    ea_obj = ea
                    break
                if app_name in ea.get_name():
                    ea_obj = ea
                    break

            user_spec = app.get("user", {})
            user_email = user_spec.get("email")
            user_id = user_dict.get_id_from_email(user_email) if user_email else None

            status_list.append({
                "id": app["id"],
                "name": app_name,
                "label": app["label"],
                "csv_path": app["csv_path"],
                "exists": bool(perimeter_id or ca_obj or ra_obj or entity_id or ea_obj),
                "perimeter_id": perimeter_id,
                "asset_id": asset_id,
                "compliance_assessment_id": ca_obj.get_id() if ca_obj else None,
                "compliance_assessment_name": ca_obj.get_name() if ca_obj else None,
                "compliance_status": ca_obj.get_status() if ca_obj else None,
                "risk_assessment_id": ra_obj.get_id() if ra_obj else None,
                "risk_scenarios_count": ra_scenarios_count,
                "applied_controls_count": ctrl_count,
                "existing_controls_linked": existing_ctrls_linked,
                "planned_controls_linked": planned_ctrls_linked,
                "entity_id": entity_id,
                "entity_assessment_id": ea_obj.get_id() if ea_obj else None,
                "entity_assessment_name": ea_obj.get_name() if ea_obj else None,
                "user_email": user_email,
                "user_id": user_id,
                "user_exists": bool(user_id),
                "tprm_conclusion": ea_obj.json_object.get("conclusion") if ea_obj and isinstance(ea_obj.json_object, dict) else None,
            })
        return status_list

    def create_example_application(self, app_id_or_name: str) -> dict[str, Any]:
        """Create a complete example application simulation in CISO Assistant.

        Steps:
        1. Resolve Folder and Default Assignee.
        2. Create Perimeter (`App-Name`).
        3. Create Asset (`App-Name`) and link to folder/owner.
        4. Create Compliance Assessment bound to target framework.
        5. Assign requirements to perimeter owner and start assignment.
        6. Import questionnaire answers from CSV using csv_import.
        7. Create Risk Assessment and generate all Risk Scenarios.
        8. Create Applied Controls with calculated priorities.
        9. Update Asset CIA Criticality security objectives.

        Args:
            app_id_or_name: Application ID (e.g. 'app_secure_core') or Name ('App-Secure-Core').

        Returns:
            Summary dict with created IDs and status.
        """
        app_spec = next(
            (a for a in EXAMPLE_APPLICATIONS if a["id"] == app_id_or_name or a["name"] == app_id_or_name),
            None,
        )
        if not app_spec:
            raise ValueError(f"Unknown example application: {app_id_or_name}")

        app_name = app_spec["name"]
        csv_path = app_spec["csv_path"]

        utils.log(f"Starting simulation creation for {app_name} from {csv_path}...", level=logging.INFO)

        data = self._init_data()
        folder_id = self.get_or_create_folder()
        assignee_id = self.get_default_assignee_id()
        framework = self.find_target_framework()

        if not framework:
            raise RuntimeError(f"No suitable framework found in CISO Assistant for {app_name}.")

        framework_id = framework.get_id()
        framework_name = framework.get_name()

        # Step 0: Ensure Third-Party User Exists for TPRM
        user_dict: UserDict = data["user_dict"]
        user_spec = app_spec.get("user", {})
        user_email = user_spec.get("email")
        user_id = None
        if user_email:
            user_res = user_dict.create_user_if_missing(
                email=user_email,
                first_name=user_spec.get("first_name", ""),
                last_name=user_spec.get("last_name", ""),
                is_third_party=True,
            )
            if isinstance(user_res, dict):
                user_id = user_res.get("id")
            if not user_id:
                user_id = user_dict.get_id_from_email(user_email)
            utils.log(f"Third-party user '{user_email}' ready with ID: {user_id}", level=logging.INFO)

        # Step 1: Create External Entity for TPRM
        entity_dict: EntityDict = data["entity_dict"]
        entity_rep_dict: EntityRepresentativeDict = data["entity_representative_dict"]
        entity_assessment_dict: EntityAssessmentDict = data["entity_assessment_dict"]

        entity_res = entity_dict.create_entity(
            name=app_name,
            folder_id=folder_id,
            description=app_spec.get("description", ""),
        )
        entity_id = entity_res.get("id") if isinstance(entity_res, dict) else entity_dict.get_id_from_name(app_name)
        if not entity_id:
            raise RuntimeError(f"Failed to create or find external entity '{app_name}'")
        utils.log(f"External Entity '{app_name}' ready with ID: {entity_id}", level=logging.INFO)

        # Step 1b: Link Representative User to External Entity
        if user_id and entity_id:
            entity_rep_dict.upsert_entity_representative(
                entity_id=entity_id,
                user_id=user_id,
                role="representative",
            )

        # Step 2: Create Perimeter
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        applied_control_dict: AppliedControlDict = data["applied_control_dict"]
        reference_control_dict: ReferenceControlDict = data["reference_control_dict"]
        perimeter = perimeter_dict.create_perimeter(app_name, assignee_id, folder_id)
        perimeter_dict.reload()
        perimeter_id = perimeter_dict.get_id_from_name(app_name)
        if not perimeter_id:
            raise RuntimeError(f"Failed to create or find perimeter '{app_name}'")

        # Step 3: Create Asset
        asset_dict: AssetDict = data["asset_dict"]
        asset = asset_dict.create_asset(app_name, "PR", folder_id, owner_id=assignee_id)
        asset_dict.reload()
        asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)
        if asset_id and assignee_id:
            for a in asset_dict.get_assets():
                if a.get_id() == asset_id:
                    a.set_owner_if_missing(assignee_id)
                    break

        # Step 4: Create Compliance Assessment
        compliance_dict: ComplianceAssessmentDict = data["compliance_assessment_dict"]
        ca_name = f"Assessment of {framework_name} in {app_name}"

        ca_obj = None
        for ca in compliance_dict.get_compliance_assessments().values():
            if ca.get_name() == ca_name or (ca.get_perimeter_id() == perimeter_id and ca.get_framework_id() == framework_id):
                ca_obj = ca
                break

        if not ca_obj:
            payload = {
                "name": ca_name,
                "framework": framework_id,
                "perimeter": perimeter_id,
                "assets": [asset_id] if asset_id else [],
                "score_calculation_method": AUDITOR_SCORE_METHOD,
                "field_visibility": AUDITOR_SCORE_VISIBILITY,
            }
            add_default_implementation_groups(payload, framework_id)
            ca_response = utils.get_return("/api/compliance-assessments/", method="POST", payload=payload)
            if not ca_response or isinstance(ca_response, dict) and ca_response.get("error"):
                raise RuntimeError(f"Failed to create compliance assessment '{ca_name}': {ca_response}")
            compliance_dict.reload()
            ca_id = ca_response.get("id") if isinstance(ca_response, dict) else ""
            ca_obj = compliance_dict.get_compliance_assessments().get(ca_id)

        ca_id = ca_obj.get_id()

        # Step 4b: Create TPRM Entity Assessment linking external entity & compliance assessment
        tprm_spec = app_spec.get("tprm", {})
        ea_name = f"Third-party assessment for {app_name}"
        ea_res = entity_assessment_dict.create_entity_assessment(
            name=ea_name,
            entity_id=entity_id,
            compliance_assessment_id=ca_id,
            representative_ids=[user_id] if user_id else None,
            criticality=tprm_spec.get("criticality"),
            maturity=tprm_spec.get("maturity"),
            trust=tprm_spec.get("trust"),
            conclusion=tprm_spec.get("conclusion"),
        )
        ea_id = ea_res.get("id") if isinstance(ea_res, dict) else ""
        if not ea_id:
            for ea in entity_assessment_dict.get_entity_assessments():
                if ea.get_entity_id() == entity_id:
                    ea_id = ea.get_id()
                    break
        utils.log(f"Entity Assessment '{ea_name}' ready with ID: {ea_id}", level=logging.INFO)

        # Step 5: Ensure requirement assessments are populated and loaded from API
        utils.log(f"Waiting for requirement assessments to populate for {ca_name}...", level=logging.INFO)
        for _ in range(10):
            compliance_dict.requirement_assessments.reload()
            req_ids = compliance_dict.requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id(ca_id)
            if req_ids:
                utils.log(f"Loaded {len(req_ids)} requirement assessment(s) for {ca_name}", level=logging.INFO)
                break
            time.sleep(0.5)

        compliance_dict.requirement_assignments.reload()

        # Assign requirements to perimeter owner and transition status
        compliance_dict.assign_requirements_to_perimeter_owner(
            perimeter_dict,
            compliance_dict,
            compliance_dict.requirement_assessments,
            compliance_dict.requirement_assignments,
        )

        # Step 5: Import questionnaire answers from CSV
        if not Path(csv_path).exists():
            raise FileNotFoundError(f"CSV answers file not found: {csv_path}")

        csv_summary = csv_import.import_compliance_answers(
            csv_path,
            ca_id,
            compliance_dict.requirement_assessments,
        )
        utils.log(f"Imported {csv_summary['updated']} answers from {csv_path} into assessment {ca_name}")

        # Reload after importing answers
        compliance_dict.requirement_assessments.reload()

        # Step 6: Create Applied Controls with calculated priorities
        compliance_dict.create_missing_applied_controls(
            applied_control_dict,
            perimeter_dict,
            reference_control_dict,
        )
        applied_control_dict.reload()

        # Ensure applied controls have asset linked
        if asset_id:
            for c in applied_control_dict.get_controls().values():
                if f"on {app_name}" in c.get_name():
                    applied_control_dict.ensure_assets_for_control(c.get_name(), [asset_id])

        # Step 7: Update Asset Criticality
        compliance_dict.update_asset_criticality(criticality_mapping, asset_dict)

        # Step 8: Create Risk Assessment & evaluate Risk Scenarios
        from tests.test_application_scenarios import ApplicationRiskSimulator
        simulator = ApplicationRiskSimulator(str(self.framework_yaml))
        sim_results = simulator.evaluate_application(csv_path)

        risk_assessment_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenario_dict: RiskScenarioDict = data["risk_scenario_dict"]
        framework_file = data["framework_file"]

        risk_matrix_id = self.find_target_risk_matrix(framework_id)
        ra_name = f"{ca_name} Risk Assessment"

        risk_assessment = risk_assessment_dict.create_risk_assessments(
            ra_name,
            framework_id,
            perimeter_id,
            risk_matrix_id,
        )
        ra_id = risk_assessment.get("id") if isinstance(risk_assessment, dict) else ""

        # Reload requirement assessments so their applied_controls field contains the controls
        compliance_dict.requirement_assessments.reload()
        req_assessments = compliance_dict.requirement_assessments.get_requirement_assessments()

        app_ras = [
            ra for ra in req_assessments.values()
            if ra.get_compliance_assessment_id() == ca_id
        ]
        app_controls = {
            c.get_id(): c
            for c in applied_control_dict.get_controls().values()
            if f"on {app_name}" in c.get_name()
        }

        scenarios_created = 0
        asset_ids = [asset_id] if asset_id else []
        owner_ids = [assignee_id] if assignee_id else []

        for risk_scenario in framework_file.get_risk_scenarios():
            sc_name = risk_scenario.get("name", "")
            sim_sc = sim_results.get("scenarios", {}).get(sc_name)

            if sim_sc:
                scaled_likelihood = sim_sc["scaled_likelihood"]
                scaled_impact = sim_sc["scaled_impact"]
            else:
                scaled_impact = sim_results.get("impact_level", 1)
                scaled_likelihood = 1

            lh_urn = risk_scenario.get("likelihood", "")
            matching_ra = next(
                (ra for ra in app_ras if ra.get_urn() == lh_urn or (ra.get_requirement_json().get("requirement", {}) or {}).get("urn") == lh_urn),
                None,
            )

            existing_controls = []
            planned_controls = []
            if matching_ra:
                for ac_id in matching_ra.get_applied_control_ids():
                    ctrl = app_controls.get(ac_id)
                    if ctrl:
                        if ctrl.get_status() == "active":
                            existing_controls.append(ac_id)
                        else:
                            planned_controls.append(ac_id)

            risk_scenario_dict.create_risk_scenario(
                sc_name,
                risk_scenario.get("description", ""),
                ra_id,
                scaled_likelihood,
                scaled_impact,
                1,
                scaled_impact,
                existing_controls,
                planned_controls,
                asset_ids,
                owner_ids,
            )
            scenarios_created += 1

        # Step 9: Guarantee complete control & asset link synchronization
        time.sleep(1)
        link_res = self.link_controls_for_application(app_name)

        # Reload for fresh state
        time.sleep(1)
        self._init_data(force_reload=True)

        return {
            "app_name": app_name,
            "entity_id": entity_id,
            "entity_assessment_id": ea_id,
            "entity_assessment_name": ea_name,
            "user_email": user_email,
            "user_id": user_id,
            "perimeter_id": perimeter_id,
            "asset_id": asset_id,
            "compliance_assessment_id": ca_id,
            "compliance_assessment_name": ca_name,
            "risk_assessment_id": ra_id,
            "answers_updated": csv_summary["updated"],
            "scenarios_created": scenarios_created,
            "existing_controls_linked": link_res.get("existing_controls", 0),
            "planned_controls_linked": link_res.get("planned_controls", 0),
        }

    def link_controls_for_application(self, app_id_or_name: str) -> dict[str, Any]:
        """Link existing (active) and planned (to_do) controls and assets to risk scenarios.

        Args:
            app_id_or_name: Application ID or Name.

        Returns:
            Dict summary of linked controls and scenarios.
        """
        app_spec = next(
            (a for a in EXAMPLE_APPLICATIONS if a["id"] == app_id_or_name or a["name"] == app_id_or_name),
            None,
        )
        if not app_spec:
            raise ValueError(f"Unknown example application: {app_id_or_name}")

        app_name = app_spec["name"]
        data = self._init_data(force_reload=True)

        asset_dict: AssetDict = data["asset_dict"]
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        compliance_dict: ComplianceAssessmentDict = data["compliance_assessment_dict"]
        risk_assessment_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenario_dict: RiskScenarioDict = data["risk_scenario_dict"]
        applied_control_dict: AppliedControlDict = data["applied_control_dict"]
        framework_file = data["framework_file"]

        perimeter_id = perimeter_dict.get_id_from_name(app_name)
        asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)
        assignee_id = perimeter_dict.get_owner_id_from_perimeter_id(perimeter_id) if perimeter_id else None

        # Ensure assets are linked on all applied controls for this app
        if asset_id:
            for c in applied_control_dict.get_controls().values():
                if f"on {app_name}" in c.get_name():
                    applied_control_dict.ensure_assets_for_control(c.get_name(), [asset_id])

        # Find compliance assessment for this application
        ca_obj = None
        for ca in compliance_dict.get_compliance_assessments().values():
            if ca.get_perimeter_id() == perimeter_id or f"in {app_name}" in ca.get_name():
                ca_obj = ca
                break

        if not ca_obj:
            utils.log(f"No compliance assessment found for {app_name}", level=logging.WARNING)
            return {"app_name": app_name, "scenarios_updated": 0, "existing_controls": 0, "planned_controls": 0}

        ca_id = ca_obj.get_id()

        # Find risk assessment for this application
        ra_obj = None
        for ra in risk_assessment_dict.get_risk_assessments().values():
            if (perimeter_id and ra.get_perimeter_id() == perimeter_id) or app_name in ra.get_name():
                ra_obj = ra
                break

        if not ra_obj:
            utils.log(f"No risk assessment found for {app_name}", level=logging.WARNING)
            return {"app_name": app_name, "scenarios_updated": 0, "existing_controls": 0, "planned_controls": 0}

        ra_id = ra_obj.get_id()

        # Reload RAs and applied controls
        compliance_dict.requirement_assessments.reload()
        applied_control_dict.reload()

        req_assessments = compliance_dict.requirement_assessments.get_requirement_assessments()
        app_ras = [
            ra for ra in req_assessments.values()
            if ra.get_compliance_assessment_id() == ca_id
        ]
        app_controls = {
            c.get_id(): c
            for c in applied_control_dict.get_controls().values()
            if f"on {app_name}" in c.get_name()
        }

        # Find scenarios for this risk assessment
        app_scenarios = [
            s for s in risk_scenario_dict.get_risk_scenarios().values()
            if s.get_json().get("risk_assessment") == ra_id
            or (isinstance(s.get_json().get("risk_assessment"), dict) and s.get_json().get("risk_assessment", {}).get("id") == ra_id)
        ]

        total_existing_linked = 0
        total_planned_linked = 0
        scenarios_updated = 0

        for sc_def in framework_file.get_risk_scenarios():
            sc_name = sc_def.get("name")
            matching_sc = next((s for s in app_scenarios if s.get_name() == sc_name), None)
            if not matching_sc:
                continue

            lh_urn = sc_def.get("likelihood")
            matching_ra = next(
                (ra for ra in app_ras if ra.get_urn() == lh_urn or (ra.get_requirement_json().get("requirement", {}) or {}).get("urn") == lh_urn),
                None,
            )
            if not matching_ra:
                continue

            ra_ctrl_ids = matching_ra.get_applied_control_ids()
            existing = [cid for cid in ra_ctrl_ids if cid in app_controls and app_controls[cid].get_status() == "active"]
            planned = [cid for cid in ra_ctrl_ids if cid in app_controls and app_controls[cid].get_status() != "active"]

            # Also check if any controls match by name if not in ra_ctrl_ids
            if not existing and not planned:
                for cid, c in app_controls.items():
                    rc_id = c.get_reference_control_id()
                    if rc_id and rc_id in matching_ra.get_associated_reference_control_ids():
                        if c.get_status() == "active":
                            existing.append(cid)
                        else:
                            planned.append(cid)

            patch_payload = {
                "existing_applied_controls": existing,
                "applied_controls": planned,
            }
            if asset_id:
                patch_payload["assets"] = [asset_id]
            if assignee_id:
                patch_payload["owner"] = [assignee_id]

            utils.log(f"Updating scenario '{sc_name}' on {app_name}: existing={existing}, planned={planned}")
            res = utils.get_return(f"/api/risk-scenarios/{matching_sc.get_id()}/", method="PATCH", payload=patch_payload)
            if isinstance(res, dict) and not res.get("error"):
                matching_sc.json_object = res
                scenarios_updated += 1
                total_existing_linked += len(existing)
                total_planned_linked += len(planned)

        return {
            "app_name": app_name,
            "scenarios_updated": scenarios_updated,
            "existing_controls": total_existing_linked,
            "planned_controls": total_planned_linked,
        }

    def link_all_controls_to_risk_scenarios(self) -> list[dict[str, Any]]:
        """Link existing and planned controls across all example applications."""
        results = []
        for app in EXAMPLE_APPLICATIONS:
            try:
                res = self.link_controls_for_application(app["id"])
                results.append(res)
            except Exception as e:
                utils.log(f"Error linking controls for {app['name']}: {e}", level=logging.WARNING)
                results.append({"app_name": app["name"], "error": str(e)})
        return results

    def remove_example_application(self, app_id_or_name: str) -> dict[str, Any]:
        """Cleanly remove an example application and all its associated objects from CISO Assistant.

        Deletes in reverse dependency order:
        1. Risk Scenarios and Risk Assessment
        2. Applied Controls
        3. Compliance Assessment (cascades requirement assessments/assignments)
        4. Asset
        5. Perimeter

        Args:
            app_id_or_name: Application ID or Name.

        Returns:
            Summary dict of deleted resources.
        """
        app_spec = next(
            (a for a in EXAMPLE_APPLICATIONS if a["id"] == app_id_or_name or a["name"] == app_id_or_name),
            None,
        )
        if not app_spec:
            raise ValueError(f"Unknown example application: {app_id_or_name}")

        app_name = app_spec["name"]
        data = self._init_data(force_reload=True)

        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        asset_dict: AssetDict = data["asset_dict"]
        compliance_dict: ComplianceAssessmentDict = data["compliance_assessment_dict"]
        risk_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenario_dict: RiskScenarioDict = data["risk_scenario_dict"]
        applied_ctrl_dict: AppliedControlDict = data["applied_control_dict"]
        entity_dict: EntityDict = data["entity_dict"]
        entity_rep_dict: EntityRepresentativeDict = data["entity_representative_dict"]
        entity_assessment_dict: EntityAssessmentDict = data["entity_assessment_dict"]
        user_dict: UserDict = data["user_dict"]

        perimeter_id = perimeter_dict.get_id_from_name(app_name)
        entity_id = entity_dict.get_id_from_name(app_name)

        deleted = {
            "app_name": app_name,
            "entity_assessments_deleted": 0,
            "entity_representatives_deleted": 0,
            "entities_deleted": 0,
            "users_deleted": 0,
            "scenarios_deleted": 0,
            "risk_assessments_deleted": 0,
            "applied_controls_deleted": 0,
            "compliance_assessments_deleted": 0,
            "assets_deleted": 0,
            "perimeters_deleted": 0,
        }

        # 0. Delete TPRM Entity Assessments
        for ea in list(entity_assessment_dict.get_entity_assessments()):
            if (entity_id and ea.get_entity_id() == entity_id) or app_name in ea.get_name():
                if entity_assessment_dict.delete_entity_assessment(ea.get_id()):
                    deleted["entity_assessments_deleted"] += 1

        # 0b. Delete Entity Representatives & External Entity
        if entity_id:
            deleted["entity_representatives_deleted"] += entity_rep_dict.delete_representatives_for_entity(entity_id)
            if entity_dict.delete_entity(entity_id):
                deleted["entities_deleted"] += 1

        # 0c. Delete Associated Third-Party User
        user_spec = app_spec.get("user", {})
        user_email = user_spec.get("email")
        if user_email:
            u_id = user_dict.get_id_from_email(user_email)
            if u_id:
                if user_dict.delete_user_by_id(u_id):
                    deleted["users_deleted"] += 1

        # 1. Delete Risk Assessment and Risk Scenarios
        for ra in list(risk_dict.get_risk_assessments().values()):
            ra_perimeter = ra.json_object.get("perimeter")
            if (perimeter_id and ra_perimeter == perimeter_id) or app_name in ra.get_name():
                ra_id = ra.get_id()
                count = risk_scenario_dict.delete_scenarios_for_risk_assessment(ra_id)
                deleted["scenarios_deleted"] += count
                if risk_dict.delete_risk_assessment(ra_id):
                    deleted["risk_assessments_deleted"] += 1

        # 2. Delete Applied Controls
        for ctrl in list(applied_ctrl_dict.get_controls().values()):
            ctrl_name = ctrl.get_name()
            if f"on {app_name}" in ctrl_name:
                if applied_ctrl_dict.delete_applied_control(ctrl.get_id()):
                    deleted["applied_controls_deleted"] += 1

        # 3. Delete Compliance Assessment
        for ca in list(compliance_dict.get_compliance_assessments().values()):
            if (perimeter_id and ca.get_perimeter_id() == perimeter_id) or app_name in ca.get_name():
                if compliance_dict.delete_compliance_assessment(ca.get_id()):
                    deleted["compliance_assessments_deleted"] += 1

        # 4. Delete Asset
        asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)
        if asset_id:
            if asset_dict.delete_asset(asset_id):
                deleted["assets_deleted"] += 1

        # 5. Delete Perimeter
        if perimeter_id:
            if perimeter_dict.delete_perimeter(perimeter_id):
                deleted["perimeters_deleted"] += 1

        # Refresh cached state
        self._init_data(force_reload=True)

        return deleted

    def create_all_examples(self) -> list[dict[str, Any]]:
        """Create all 4 example applications in CISO Assistant."""
        results = []
        for app in EXAMPLE_APPLICATIONS:
            res = self.create_example_application(app["id"])
            results.append(res)
        return results

    def remove_all_examples(self) -> list[dict[str, Any]]:
        """Remove all 4 example applications from CISO Assistant."""
        results = []
        for app in EXAMPLE_APPLICATIONS:
            res = self.remove_example_application(app["id"])
            results.append(res)
        return results

