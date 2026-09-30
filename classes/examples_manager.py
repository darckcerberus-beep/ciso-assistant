"""Example Application Simulation and Lifecycle Manager for CISO Assistant.

Orchestrates the creation and removal of example applications in CISO Assistant
via the REST API so that compliance assessments, questionnaire answers, risk scenarios,
applied controls, and asset criticalities can be visualized directly in the CISO Assistant UI.
"""

import logging
from pathlib import Path
import re
import time
from typing import Any
import yaml

from classes import utils
from classes.core.framework import FrameworkDict, FrameworkFile
from classes.core.risk import RiskAssessmentDict, RiskMatrixDict, RiskScenarioDict, ThreatDict, VulnerabilityDict
from classes.core.task import TaskDict, TaskTemplateDict
from classes.core.user import UserDict
from classes.controls.applied import AppliedControlDict
from classes.controls.reference import ReferenceControlDict
from classes.audits.compliance import ComplianceAssessmentDict, AUDITOR_SCORE_METHOD, AUDITOR_SCORE_VISIBILITY
from classes.audits.entity_assessment import EntityAssessmentDict
from classes.audits.finding import FindingDict, FindingsAssessmentDict
from classes.audits.implementation_groups import add_default_implementation_groups
from classes.audits.requirement_assessment import create_requirement_assignment
from classes.organization.asset import AssetDict
from classes.organization.domain import DomainDict, criticality_mapping
from classes.organization.entity import EntityDict, EntityRepresentativeDict
from classes.organization.perimeter import PerimeterDict
from classes.integrations import answers_import
from classes.integrations.backup import BackupManager

LOGGER = logging.getLogger(__name__)


def load_example_applications(test_data_dir: str | Path | None = None) -> list[dict[str, Any]]:
    """Load example application definitions dynamically from individual YAML files.

    Scans the test_data directory for YAML files containing an 'application' block,
    ensuring each application's configuration, metadata, framework reference,
    user assignment, and TPRM specs are loaded directly from the individual example file.
    """
    if test_data_dir is None:
        repo_root = Path(__file__).resolve().parent.parent
        test_data_path = repo_root / "test_data"
        if not test_data_path.exists():
            test_data_path = Path("test_data")
    else:
        test_data_path = Path(test_data_dir)

    apps: list[dict[str, Any]] = []
    if not test_data_path.exists():
        return apps

    yaml_files = sorted(test_data_path.glob("*.yml")) + sorted(test_data_path.glob("*.yaml"))
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            app_spec = data.get("application")
            if not app_spec or not isinstance(app_spec, dict):
                continue

            entry = dict(app_spec)
            try:
                rel_path = yaml_file.relative_to(Path.cwd())
                entry["yaml_path"] = str(rel_path)
            except ValueError:
                entry["yaml_path"] = str(yaml_file)

            if "label" not in entry and "name" in entry:
                entry["label"] = entry["name"]

            apps.append(entry)
        except Exception as e:
            LOGGER.warning("Could not load example application from %s: %s", yaml_file, e)

    # Sort applications by explicit 'order' field, then by name
    apps.sort(key=lambda a: (a.get("order", 999), a.get("name", "")))
    return apps


EXAMPLE_APPLICATIONS = load_example_applications()


EXAMPLE_FOLDER_NAME = "Example Applications"
DEFAULT_FRAMEWORK_NAME = "Multi-level DPP"
DEFAULT_FRAMEWORK_REF = "mls"
FRAMEWORK_YAML_PATH = "YML/newDPP.yml"

FRAMEWORK_CATALOG = [
    {
        "ref_id": "mls",
        "name": "Multi-level DPP",
        "yaml_path": "YML/newDPP.yml",
        "description": "Multi-level Digital Product Passport cybersecurity assessment",
    },
    {
        "ref_id": "vendor-due-diligence",
        "name": "Vendor Due Diligence (VDD) - simple",
        "yaml_path": "YML/vendor-due-diligence.yaml",
        "description": "Simple framework for rapid due diligence review of vendors",
    },
]


class ExamplesManager:
    """Manages the creation, status discovery, and deletion of example applications in CISO Assistant."""

    def __init__(self, folder_name: str = EXAMPLE_FOLDER_NAME):
        self.folder_name = folder_name
        self.framework_yaml = Path(FRAMEWORK_YAML_PATH)
        self.data: dict[str, Any] | None = None
        self.backup_manager = BackupManager()

    @staticmethod
    def load_example_applications(test_data_dir: str | Path | None = None) -> list[dict[str, Any]]:
        """Load example application definitions from individual YAML example files."""
        return load_example_applications(test_data_dir)

    def get_example_applications(self) -> list[dict[str, Any]]:
        """Return all example applications loaded dynamically from individual YAML example files."""
        return load_example_applications()

    def find_example_application(self, app_id_or_name: str) -> dict[str, Any] | None:
        """Find an example application specification by ID or name (case-insensitive)."""
        target = app_id_or_name.lower().strip()
        for app in self.get_example_applications():
            if app.get("id", "").lower() == target or app.get("name", "").lower() == target:
                return app
        return None

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
                "findings_assessment_dict": FindingsAssessmentDict(),
                "finding_dict": FindingDict(),
                "vulnerability_dict": VulnerabilityDict(),
                "threat_dict": ThreatDict(),
                "task_template_dict": TaskTemplateDict(),
                "task_dict": TaskDict(),
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

    def get_or_create_folder(self, folder_name: str | None = None) -> str | None:
        """Retrieve or create the destination folder/domain for example applications.

        If the specified domain does not exist in CISO Assistant, it will be automatically created.

        Args:
            folder_name: Optional domain/folder name or UUID. Defaults to self.folder_name.

        Returns:
            Domain/Folder UUID or None.
        """
        target = (folder_name or self.folder_name or "").strip()
        if not target:
            target = self.folder_name

        data = self._init_data()
        domain_dict = data.get("domain_dict")
        if not domain_dict:
            return None

        # 1. Check if target is already a valid domain ID
        if hasattr(domain_dict, "get_domain_by_id"):
            domain_by_id = domain_dict.get_domain_by_id(target)
            if domain_by_id:
                return domain_by_id.get_id()

        # 2. Check if target matches an existing domain name
        folder_id = domain_dict.get_id_from_name(target)
        if folder_id:
            return folder_id

        # 3. Domain does not exist -> Create it automatically
        utils.log(f"Domain '{target}' does not exist in CISO Assistant. Automatically creating domain...", level=logging.INFO)
        new_domain = None
        if hasattr(domain_dict, "create_domain"):
            new_domain = domain_dict.create_domain(name=target, description=f"Domain for {target}")
        elif hasattr(domain_dict, "upsert_folder"):
            new_domain = domain_dict.upsert_folder(target)

        if isinstance(new_domain, dict) and new_domain.get("id"):
            utils.log(f"Successfully created domain '{target}' (ID: {new_domain.get('id')})", level=logging.INFO)
            return new_domain.get("id")
        if hasattr(new_domain, "get_id"):
            utils.log(f"Successfully created domain '{target}' (ID: {new_domain.get_id()})", level=logging.INFO)
            return new_domain.get_id()

        # 4. Check if reload populated the newly created domain by name
        folder_id = domain_dict.get_id_from_name(target)
        if folder_id:
            return folder_id

        # 5. Fall back to any existing folder if creation fails
        domains = domain_dict.get_domains()
        if domains:
            fallback = domains[0]
            utils.log(f"Using fallback domain '{fallback.get_name()}' ({fallback.get_id()})", level=logging.WARNING)
            return fallback.get_id()

        return None

    def create_domain(
        self,
        name: str,
        description: str | None = None,
        parent_folder_id: str | None = None,
        create_iam_groups: bool = True,
    ) -> dict | None:
        """Create a new domain/folder in CISO Assistant.

        Args:
            name: Domain name.
            description: Optional domain description.
            parent_folder_id: Optional parent domain name or UUID.
            create_iam_groups: Whether to automatically provision IAM groups (default: True).

        Returns:
            Dict containing domain data, or None on failure.
        """
        if not name or not name.strip():
            raise ValueError("Domain name cannot be empty.")

        name = name.strip()
        data = self._init_data()
        domain_dict: DomainDict = data["domain_dict"]

        resolved_parent_id = None
        if parent_folder_id:
            matched_by_id = domain_dict.get_domain_by_id(parent_folder_id) if hasattr(domain_dict, "get_domain_by_id") else None
            if matched_by_id:
                resolved_parent_id = matched_by_id.get_id()
            else:
                matched_name_id = domain_dict.get_id_from_name(parent_folder_id)
                if matched_name_id:
                    resolved_parent_id = matched_name_id
                else:
                    resolved_parent_id = parent_folder_id

        return domain_dict.create_domain(
            name=name,
            description=description,
            parent_folder_id=resolved_parent_id,
            create_iam_groups=create_iam_groups,
        )

    def get_domains(self) -> list:
        """Retrieve all domains/folders from CISO Assistant."""
        data = self._init_data()
        domain_dict: DomainDict = data["domain_dict"]
        domain_dict.reload()
        return domain_dict.get_domains()

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

    def resolve_actor_id(self, user_id: str | None = None, user_email: str | None = None) -> str | None:
        """Resolve an Actor UUID from a User UUID or email, falling back to default assignee."""
        actor_records = utils.get_all_results("/api/actors/", force_reload=False)
        if actor_records:
            for actor in actor_records:
                if isinstance(actor, dict):
                    spec = actor.get("specific")
                    spec_id = spec.get("id") if isinstance(spec, dict) else None
                    if user_id and spec_id == user_id:
                        return actor.get("id")
                    if user_email and actor.get("str") == user_email:
                        return actor.get("id")
        return self.get_default_assignee_id()

    @staticmethod
    def resolve_framework_yaml_path(target_framework: str | None = None) -> Path:
        """Resolve the local YAML file path for a given framework identifier or name."""
        if not target_framework:
            return Path(FRAMEWORK_YAML_PATH)

        # Check if already a path to an existing file
        target_path = Path(target_framework)
        if target_path.exists() and target_path.is_file():
            return target_path

        yml_dir = Path("YML")
        if (yml_dir / target_path.name).exists() and (yml_dir / target_path.name).is_file():
            return yml_dir / target_path.name

        target_str = str(target_framework).strip().lower()

        # Check catalog matches
        for cat in FRAMEWORK_CATALOG:
            if (
                cat["ref_id"].lower() == target_str
                or cat["name"].lower() == target_str
                or Path(cat["yaml_path"]).stem.lower() == target_str
            ):
                cat_path = Path(cat["yaml_path"])
                if cat_path.exists():
                    return cat_path

        # Check YML directory for matching file
        for ext in (".yml", ".yaml"):
            candidate = yml_dir / f"{target_framework}{ext}"
            if candidate.exists():
                return candidate

        return Path(FRAMEWORK_YAML_PATH)

    def resolve_framework_file(
        self,
        target_framework: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        """Return a FrameworkFile instance for the specified framework, preserving mocks in tests."""
        if data and "framework_file" in data:
            candidate = data["framework_file"]
            if hasattr(candidate, "_mock_return_value") or candidate.__class__.__name__ in ("MagicMock", "Mock"):
                return candidate
        yaml_path = self.resolve_framework_yaml_path(target_framework)
        return FrameworkFile(str(yaml_path))

    def get_installed_frameworks(self) -> list[dict[str, Any]]:
        """Return list of frameworks that are confirmed to be installed in CISO Assistant."""
        frameworks_list = []
        try:
            data = self._init_data()
            framework_dict: FrameworkDict = data.get("framework_dict")
            if framework_dict:
                for fw in framework_dict.get_frameworks():
                    fw_id = fw.get_id()
                    if not fw_id:
                        continue
                    fw_name = fw.get_name()
                    fw_json = getattr(fw, "json_object", {}) or {}
                    ref_id = fw_json.get("ref_id", "")
                    urn = fw_json.get("urn", "")
                    description = fw_json.get("description", "")
                    yaml_path = str(self.resolve_framework_yaml_path(ref_id or fw_name))
                    entry = {
                        "id": fw_id,
                        "name": fw_name,
                        "ref_id": ref_id,
                        "urn": urn,
                        "description": description,
                        "yaml_path": yaml_path,
                        "installed": True,
                        "in_ciso_assistant": True,
                    }
                    for cat in FRAMEWORK_CATALOG:
                        if cat["ref_id"].lower() == ref_id.lower() or cat["name"].lower() == fw_name.lower():
                            entry["catalog_name"] = cat["name"]
                            break
                    frameworks_list.append(entry)
        except Exception as e:
            utils.log(f"Error querying installed frameworks from CISO Assistant: {e}", level=logging.DEBUG)

        return frameworks_list

    def is_framework_in_ciso_assistant(self, framework_ref_or_name: str | None) -> bool:
        """Check if a specific framework is actually present/installed in CISO Assistant."""
        if not framework_ref_or_name:
            return False
        return self.find_target_framework(framework_ref_or_name) is not None

    def get_available_frameworks(self, installed_only: bool = False) -> list[dict[str, Any]]:
        """Return list of available frameworks discovered from CISO Assistant and local catalog.

        Args:
            installed_only: If True, only returns frameworks verified present in CISO Assistant.
                            If False, also includes uninstalled catalog frameworks with id=None.
        """
        installed = self.get_installed_frameworks()
        if installed_only:
            return installed

        frameworks_list = list(installed)
        seen_identifiers = set()
        for fw in installed:
            if fw.get("ref_id"):
                seen_identifiers.add(fw["ref_id"].lower())
            if fw.get("name"):
                seen_identifiers.add(fw["name"].lower())
            if fw.get("catalog_name"):
                seen_identifiers.add(fw["catalog_name"].lower())

        # Merge catalog frameworks not found in API
        for cat in FRAMEWORK_CATALOG:
            cat_ref = cat["ref_id"].lower()
            cat_name = cat["name"].lower()
            if cat_ref not in seen_identifiers and cat_name not in seen_identifiers:
                frameworks_list.append({
                    "id": None,
                    "name": cat["name"],
                    "ref_id": cat["ref_id"],
                    "urn": "",
                    "description": cat.get("description", ""),
                    "yaml_path": cat["yaml_path"],
                    "installed": False,
                    "in_ciso_assistant": False,
                })
                seen_identifiers.add(cat_ref)
                seen_identifiers.add(cat_name)

        return frameworks_list

    def find_target_framework(self, target_framework: str | None = None) -> Any | None:
        """Find the matching framework in CISO Assistant (by identifier, name, or ref_id)."""
        data = self._init_data()
        framework_dict: FrameworkDict = data["framework_dict"]
        frameworks = framework_dict.get_frameworks()
        if not frameworks:
            return None

        # 1. If explicit target given, attempt to find exact match in CISO Assistant
        if target_framework:
            fw = framework_dict.get_framework_by_identifier(target_framework)
            if fw:
                return fw
            for cat in FRAMEWORK_CATALOG:
                if (
                    cat["ref_id"].lower() == str(target_framework).lower()
                    or cat["name"].lower() == str(target_framework).lower()
                ):
                    fw = framework_dict.get_framework_by_identifier(cat["ref_id"]) or framework_dict.get_framework_by_identifier(cat["name"])
                    if fw:
                        return fw

            # Explicit framework was requested but NOT found in CISO Assistant.
            # Do NOT silently fall back to a different framework!
            utils.log(
                f"Target framework '{target_framework}' not found in CISO Assistant.",
                level=logging.WARNING,
            )
            return None

        # 2. Match default framework (Multi-level DPP / mls) when no target specified
        default_fw = framework_dict.get_framework_by_identifier(DEFAULT_FRAMEWORK_NAME) or framework_dict.get_framework_by_identifier(DEFAULT_FRAMEWORK_REF)
        if default_fw:
            return default_fw

        # 3. Fallback: return first available framework
        utils.log(
            f"Default framework '{DEFAULT_FRAMEWORK_NAME}' not found; using '{frameworks[0].get_name()}'",
            level=logging.WARNING,
        )
        return frameworks[0]

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

    @staticmethod
    def _extract_ra_ref_id(ra: Any) -> str:
        """Extract requirement ref_id or URN suffix from a requirement assessment."""
        if hasattr(ra, "get_requirement_ref_id"):
            ref = ra.get_requirement_ref_id()
            if ref:
                return ref
        if hasattr(ra, "get_urn"):
            urn = ra.get_urn()
            if urn:
                return urn.rsplit(":", 1)[-1]
        if hasattr(ra, "get_requirement_json"):
            rjson = ra.get_requirement_json()
            if isinstance(rjson, dict):
                req = rjson.get("requirement")
                if isinstance(req, dict):
                    ref = req.get("ref_id") or req.get("urn", "").rsplit(":", 1)[-1]
                    if ref:
                        return ref
        if isinstance(ra, dict):
            req = ra.get("requirement")
            if isinstance(req, dict):
                ref = req.get("ref_id") or req.get("urn", "").rsplit(":", 1)[-1]
                if ref:
                    return ref
            ref = ra.get("ref_id") or ra.get("urn", "").rsplit(":", 1)[-1]
            if ref:
                return ref
        return ""

    @staticmethod
    def _is_ra_answered(ra: Any) -> bool:
        """Check if a requirement assessment has a valid selected answer or assessed result."""
        if hasattr(ra, "has_selected_answer") and ra.has_selected_answer():
            return True
        if hasattr(ra, "is_unassessed_result") and not ra.is_unassessed_result():
            return True
        if isinstance(ra, dict):
            answers = ra.get("answers")
            if isinstance(answers, dict) and any(v is not None for v in answers.values()):
                return True
            result = ra.get("result")
            if result not in (None, "", "not_assessed", "null", "none"):
                return True
        return False

    @staticmethod
    def _is_ra_assessable(ra: Any) -> bool:
        """Check if requirement is an assessable node (not a chapter header or splash screen)."""
        non_assessable_headers = {
            "info",
            "advanced_reqs",
            "advanced",
            "saas_chapter",
            "instructions_splash",
            "thank_you_splash",
        }
        ref_id = ExamplesManager._extract_ra_ref_id(ra)
        if ref_id in non_assessable_headers:
            return False

        if hasattr(ra, "get_requirement_json"):
            rjson = ra.get_requirement_json()
            if isinstance(rjson, dict):
                req = rjson.get("requirement")
                if isinstance(req, dict):
                    if req.get("assessable") is False or req.get("display_mode") == "splash":
                        return False
                if rjson.get("assessable") is False or rjson.get("display_mode") == "splash":
                    return False
        elif isinstance(ra, dict):
            req = ra.get("requirement")
            if isinstance(req, dict):
                if req.get("assessable") is False or req.get("display_mode") == "splash":
                    return False
            if ra.get("assessable") is False or ra.get("display_mode") == "splash":
                return False

        if hasattr(ra, "get_questions"):
            questions = ra.get_questions()
            if isinstance(questions, dict) and len(questions) == 0:
                return False

        return True

    _framework_metadata_cache: dict[str, Any] = {}

    @classmethod
    def _load_framework_metadata(
        cls,
        framework_identifier: str | None = None,
        yaml_path: str = "",
        ca_reqs: list[Any] | None = None,
    ) -> dict[str, Any] | None:
        """Load implementation groups definition and requirement nodes from local framework file or CISO Assistant API."""
        candidate = framework_identifier

        # 1. Determine framework identifier from answers YAML file header if not provided
        if not candidate and yaml_path and Path(yaml_path).exists():
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                if isinstance(doc, dict):
                    app = doc.get("application", {})
                    if isinstance(app, dict):
                        candidate = app.get("framework_yaml") or app.get("framework_ref") or app.get("framework")
                    if not candidate and "objects" in doc and "framework" in doc.get("objects", {}):
                        fw_obj = doc.get("objects", {}).get("framework", {})
                        return {
                            "implementation_groups_definition": fw_obj.get("implementation_groups_definition", []),
                            "requirement_nodes": fw_obj.get("requirement_nodes", []),
                        }
            except Exception:
                pass

        # 2. Determine framework identifier from requirement assessment URNs or framework IDs
        if not candidate and ca_reqs:
            for ra in ca_reqs:
                urn = ""
                if hasattr(ra, "get_urn"):
                    urn_val = ra.get_urn()
                    if isinstance(urn_val, str):
                        urn = urn_val
                elif isinstance(ra, dict):
                    raw_urn = ra.get("urn") or (ra.get("requirement", {}).get("urn") if isinstance(ra.get("requirement"), dict) else "")
                    if isinstance(raw_urn, str):
                        urn = raw_urn
                if urn:
                    m = re.search(r"urn:intuitem:risk:req_node:([^:]+):", urn)
                    if m:
                        candidate = m.group(1)
                        break

                if hasattr(ra, "get_framework_id"):
                    fw_id = ra.get_framework_id()
                    if isinstance(fw_id, str) and fw_id.strip() and not fw_id.startswith("<MagicMock"):
                        candidate = fw_id.strip()
                        break

        cache_key = f"{candidate}:{yaml_path}"
        if cache_key in cls._framework_metadata_cache:
            return cls._framework_metadata_cache[cache_key]

        # 3. Try resolving from local framework YAML file
        target_path = None
        if candidate:
            target_path = cls.resolve_framework_yaml_path(candidate)
        elif yaml_path:
            target_path = cls.resolve_framework_yaml_path(None)

        if target_path and target_path.exists() and target_path.is_file():
            try:
                fw_doc = utils.load_yaml_file(str(target_path))
                if isinstance(fw_doc, dict):
                    fw_obj = fw_doc.get("objects", {}).get("framework", {})
                    if not fw_obj:
                        fw_obj = fw_doc.get("framework", {}) or fw_doc
                    ig_defs = fw_obj.get("implementation_groups_definition", [])
                    nodes = fw_obj.get("requirement_nodes", [])
                    if ig_defs or nodes:
                        res = {
                            "implementation_groups_definition": ig_defs,
                            "requirement_nodes": nodes or [],
                        }
                        cls._framework_metadata_cache[cache_key] = res
                        return res
            except Exception:
                pass

        # 4. Try resolving via CISO Assistant API
        try:
            fw_obj = None
            if candidate:
                if len(candidate) == 36 and "-" in candidate:
                    fw_obj = utils.get_return(f"/api/frameworks/{candidate}/", log_errors=False)
                else:
                    all_fws = utils.get_all_results("/api/frameworks/", force_reload=False)
                    for fw in all_fws or []:
                        if isinstance(fw, dict):
                            if (
                                str(fw.get("id")) == candidate
                                or str(fw.get("ref_id", "")).lower() == candidate.lower()
                                or str(fw.get("name", "")).lower() == candidate.lower()
                            ):
                                fw_obj = fw
                                break
            if fw_obj and isinstance(fw_obj, dict):
                fw_id = fw_obj.get("id")
                ig_defs = fw_obj.get("implementation_groups_definition", [])
                nodes = utils.get_all_results(f"/api/requirement-nodes/?framework={fw_id}", force_reload=False)
                if ig_defs or nodes:
                    res = {
                        "implementation_groups_definition": ig_defs,
                        "requirement_nodes": nodes or [],
                    }
                    cls._framework_metadata_cache[cache_key] = res
                    return res
        except Exception:
            pass

        # 5. Fallback to default framework YAML file only if no specific non-default candidate was specified
        if not candidate or candidate.lower() in ("mls", "newdpp", "default"):
            default_path = Path(FRAMEWORK_YAML_PATH)
            if default_path.exists():
                try:
                    fw_doc = utils.load_yaml_file(str(default_path))
                    if isinstance(fw_doc, dict):
                        fw_obj = fw_doc.get("objects", {}).get("framework", {})
                        if not fw_obj:
                            fw_obj = fw_doc.get("framework", {}) or fw_doc
                        ig_defs = fw_obj.get("implementation_groups_definition", [])
                        nodes = fw_obj.get("requirement_nodes", [])
                        res = {
                            "implementation_groups_definition": ig_defs,
                            "requirement_nodes": nodes or [],
                        }
                        cls._framework_metadata_cache[cache_key] = res
                        return res
                except Exception:
                    pass

        return None

    @staticmethod
    def _resolve_triggered_requirements(
        ca_reqs: list[Any],
        yaml_path: str = "",
        framework_ref: str | None = None,
    ) -> tuple[int, int]:
        """Determine (answered_count, triggered_count) for compliance assessment requirements.

        Framework-independent: dynamically inspects the framework definition (via framework file or
        API) to identify default implementation groups and evaluates questionnaire answers (from live
        requirements or answers profile) to activate implementation groups. Only requirements
        belonging to active groups (or with no group restrictions, or already answered) are triggered.
        """
        if not ca_reqs:
            return 0, 0

        assessable = [ra for ra in ca_reqs if ExamplesManager._is_ra_assessable(ra)]
        if not assessable:
            assessable = ca_reqs

        answered_ras = [ra for ra in assessable if ExamplesManager._is_ra_answered(ra)]
        answered_count = len(answered_ras)

        fw_meta = ExamplesManager._load_framework_metadata(
            framework_identifier=framework_ref,
            yaml_path=yaml_path,
            ca_reqs=ca_reqs,
        )

        if not fw_meta:
            return answered_count, len(assessable)

        answered_req_refs: set[str] = set()
        active_groups: set[str] = set()

        ig_defs = fw_meta.get("implementation_groups_definition", []) or []
        for g in ig_defs:
            if isinstance(g, dict) and g.get("default_selected"):
                if g.get("ref_id"):
                    active_groups.add(str(g.get("ref_id")).strip())
                if g.get("name"):
                    active_groups.add(str(g.get("name")).strip())
                if g.get("urn"):
                    active_groups.add(str(g.get("urn")).strip())

        fw_nodes = fw_meta.get("requirement_nodes", []) or []
        nodes_by_ref: dict[str, dict[str, Any]] = {}
        nodes_by_urn: dict[str, dict[str, Any]] = {}
        for n in fw_nodes:
            if not isinstance(n, dict):
                continue
            ref = n.get("ref_id")
            urn = n.get("urn")
            if ref:
                nodes_by_ref[str(ref).strip()] = n
            if urn:
                nodes_by_urn[str(urn).strip()] = n

        def _get_node_choices(node_dict: dict[str, Any], question_key_or_text: str = "") -> list[dict[str, Any]]:
            qs = node_dict.get("questions", {})
            q_items: list[dict[str, Any]] = []
            if isinstance(qs, dict):
                q_items = [v for v in qs.values() if isinstance(v, dict)]
            elif isinstance(qs, list):
                q_items = [v for v in qs if isinstance(v, dict)]

            norm_q = str(question_key_or_text).strip().lower()
            target_q = None
            if norm_q:
                for q in q_items:
                    q_ref = str(q.get("ref_id", "")).strip().lower()
                    q_urn = str(q.get("urn", "")).strip().lower()
                    q_text = str(q.get("text", "")).strip().lower()
                    if (
                        norm_q == q_ref
                        or norm_q == q_urn
                        or norm_q == q_text
                        or (q_ref and norm_q.endswith(f":{q_ref}"))
                        or (q_ref and norm_q.endswith(q_ref))
                        or (q_urn and norm_q in q_urn)
                        or (q_text and (norm_q in q_text or q_text in norm_q))
                    ):
                        target_q = q
                        break

            if target_q and isinstance(target_q, dict):
                return [c for c in target_q.get("choices", []) if isinstance(c, dict)]

            all_choices: list[dict[str, Any]] = []
            for q in q_items:
                all_choices.extend([c for c in q.get("choices", []) if isinstance(c, dict)])
            return all_choices

        def _match_choice(choice: dict[str, Any], answer_val: Any) -> bool:
            if answer_val is None:
                return False
            if isinstance(answer_val, (list, tuple, set)):
                return any(_match_choice(choice, single_val) for single_val in answer_val)

            a_str = str(answer_val).strip()
            if not a_str:
                return False

            norm_ans = a_str.lower()
            c_urn = str(choice.get("urn", "")).strip().lower()
            c_ref = str(choice.get("ref_id", "")).strip().lower()
            c_val = str(choice.get("value", "")).strip().lower()

            if c_urn and norm_ans == c_urn:
                return True
            if c_ref and norm_ans == c_ref:
                return True
            if c_val and norm_ans == c_val:
                return True
            if c_ref and norm_ans.endswith(f":{c_ref}"):
                return True
            if c_val and (norm_ans.startswith(c_val) or c_val.startswith(norm_ans)):
                return True
            return False

        # 1. Read answers from YAML answers file if provided
        if yaml_path and Path(yaml_path).exists():
            try:
                rows = answers_import.read_answers_file(yaml_path)
                for row in rows:
                    req_ref = row.get("requirement", "").strip()
                    if req_ref:
                        answered_req_refs.add(req_ref)
                    q_key = row.get("question", "").strip()
                    ans_val = row.get("answer")
                    node = nodes_by_ref.get(req_ref) or nodes_by_urn.get(req_ref)
                    if node:
                        choices = _get_node_choices(node, q_key)
                        for c in choices:
                            if _match_choice(c, ans_val):
                                for grp in c.get("select_implementation_groups", []) or []:
                                    active_groups.add(str(grp).strip())
            except Exception:
                pass

        # 2. Read live answers from ca_reqs
        for ra in assessable:
            ra_ref = ExamplesManager._extract_ra_ref_id(ra)
            ra_urn = ra.get_urn() if hasattr(ra, "get_urn") else (ra.get("urn", "") if isinstance(ra, dict) else "")
            node = nodes_by_ref.get(ra_ref) or nodes_by_urn.get(ra_urn) or nodes_by_ref.get(ra_urn)
            answers = ra.get_answers() if hasattr(ra, "get_answers") else (ra.get("answers") if isinstance(ra, dict) else {})
            if isinstance(answers, dict):
                for q_key, ans_val in answers.items():
                    if ans_val is None:
                        continue
                    if node:
                        choices = _get_node_choices(node, str(q_key))
                    elif hasattr(ra, "get_questions"):
                        qs = ra.get_questions()
                        q_def = qs.get(q_key, {}) if isinstance(qs, dict) else {}
                        choices = [c for c in q_def.get("choices", []) if isinstance(c, dict)]
                    else:
                        choices = []

                    for c in choices:
                        if _match_choice(c, ans_val):
                            for grp in c.get("select_implementation_groups", []) or []:
                                active_groups.add(str(grp).strip())

        # Check if assessable requirements match any framework node
        has_matching_nodes = any(
            (ExamplesManager._extract_ra_ref_id(ra) in nodes_by_ref)
            or (hasattr(ra, "get_urn") and ra.get_urn() in nodes_by_urn)
            for ra in assessable
        )
        if not has_matching_nodes and not answered_req_refs:
            return answered_count, len(assessable)

        triggered_ras = []
        for ra in assessable:
            ref = ExamplesManager._extract_ra_ref_id(ra)
            urn = ra.get_urn() if hasattr(ra, "get_urn") else (ra.get("urn", "") if isinstance(ra, dict) else "")
            is_answered = ExamplesManager._is_ra_answered(ra)

            if is_answered:
                triggered_ras.append(ra)
                continue

            if answered_req_refs and (ref in answered_req_refs or urn in answered_req_refs):
                triggered_ras.append(ra)
                continue

            node = nodes_by_ref.get(ref) or nodes_by_urn.get(urn) or nodes_by_ref.get(urn)
            req_groups = None
            if node:
                req_groups = node.get("implementation_groups")
            elif hasattr(ra, "get_implementation_groups"):
                req_groups = ra.get_implementation_groups()

            if not req_groups:
                triggered_ras.append(ra)
            elif any(str(g).strip() in active_groups for g in req_groups):
                triggered_ras.append(ra)

        triggered_count = max(len(triggered_ras), answered_count)
        return answered_count, triggered_count

    @staticmethod
    def _build_status_dict(
        app_id: str,
        app_name: str,
        label: str,
        perimeter_id: str | None = None,
        asset_id: str | None = None,
        ca_obj: Any = None,
        ra_obj: Any = None,
        ra_scenarios_count: int = 0,
        ctrl_count: int = 0,
        existing_ctrls_linked: int = 0,
        planned_ctrls_linked: int = 0,
        vulns_linked: int = 0,
        threats_linked: int = 0,
        fa_id: str | None = None,
        findings_count: int = 0,
        entity_id: str | None = None,
        ea_obj: Any = None,
        user_email: str | None = None,
        user_id: str | None = None,
        req_by_ca: dict[str, list[Any]] | None = None,
        framework_id: str | None = None,
        framework_name: str | None = None,
        framework_ref: str | None = None,
        yaml_path: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
    ) -> dict[str, Any]:
        """Construct a standardized status dictionary for an application."""
        total_reqs = 0
        answered_reqs = 0
        all_reqs_count = 0
        if ca_obj:
            ca_id = ca_obj.get_id() if hasattr(ca_obj, "get_id") else str(ca_obj)
            ca_reqs = (req_by_ca or {}).get(ca_id, [])
            all_reqs_count = len(ca_reqs)
            answered_reqs, total_reqs = ExamplesManager._resolve_triggered_requirements(
                ca_reqs,
                yaml_path=yaml_path,
                framework_ref=framework_ref or framework_name or framework_id,
            )

        item_exists = bool(perimeter_id or ca_obj or ra_obj or entity_id or ea_obj)
        app_created = bool(perimeter_id or asset_id or (ea_obj and entity_id) or item_exists)
        audit_created = bool(ca_obj)
        ca_status_val = (ca_obj.get_status() or "") if (ca_obj and hasattr(ca_obj, "get_status")) else ""
        audit_status = ca_status_val.lower() if isinstance(ca_status_val, str) else ""
        audit_answered = bool(ca_obj and (answered_reqs > 0 or audit_status == "completed"))
        completion_pct = min(100, round(answered_reqs / total_reqs * 100)) if total_reqs > 0 else (100 if audit_answered else 0)
        risks_created = bool(ra_obj and ra_scenarios_count > 0)
        controls_created = bool(ctrl_count > 0)
        controls_linked = bool(existing_ctrls_linked > 0 or planned_ctrls_linked > 0)

        # Lifecycle status determination (granular, specific progression stages)
        if not item_exists:
            lifecycle_status = "NOT CREATED"
        elif not ca_obj:
            lifecycle_status = "APP ONLY (NO AUDIT)"
        elif total_reqs > 0 and answered_reqs == 0:
            lifecycle_status = f"AUDIT PENDING (0/{total_reqs})"
        elif total_reqs > 0 and answered_reqs < total_reqs and audit_status != "completed":
            lifecycle_status = f"AUDIT PARTIAL ({answered_reqs}/{total_reqs})"
        elif not audit_answered:
            lifecycle_status = "AUDIT PENDING"
        elif not risks_created:
            lifecycle_status = "RISKS PENDING"
        elif not controls_created:
            lifecycle_status = "CONTROLS PENDING"
        elif not controls_linked:
            lifecycle_status = "LINKING PENDING"
        else:
            lifecycle_status = "FULLY CONFIGURED"

        return {
            "id": app_id,
            "name": app_name,
            "label": label,
            "domain_id": domain_id,
            "domain_name": domain_name,
            "domain": domain_name,
            "yaml_path": yaml_path or "",
            "framework_id": framework_id,
            "framework_name": framework_name,
            "framework_ref": framework_ref,
            "exists": item_exists,
            "app_created": app_created,
            "audit_created": audit_created,
            "audit_answered": audit_answered,
            "total_requirements_count": total_reqs,
            "triggered_requirements_count": total_reqs,
            "all_requirements_count": all_reqs_count,
            "answered_requirements_count": answered_reqs,
            "audit_completion_pct": completion_pct,
            "risks_created": risks_created,
            "controls_created": controls_created,
            "controls_linked": controls_linked,
            "lifecycle_status": lifecycle_status,
            "status": lifecycle_status,
            "perimeter_id": perimeter_id,
            "asset_id": asset_id,
            "compliance_assessment_id": ca_obj.get_id() if (ca_obj and hasattr(ca_obj, "get_id")) else None,
            "compliance_assessment_name": ca_obj.get_name() if (ca_obj and hasattr(ca_obj, "get_name")) else None,
            "compliance_status": ca_obj.get_status() if (ca_obj and hasattr(ca_obj, "get_status")) else None,
            "risk_assessment_id": ra_obj.get_id() if (ra_obj and hasattr(ra_obj, "get_id")) else None,
            "risk_scenarios_count": ra_scenarios_count,
            "applied_controls_count": ctrl_count,
            "existing_controls_linked": existing_ctrls_linked,
            "planned_controls_linked": planned_ctrls_linked,
            "vulnerabilities_linked": vulns_linked,
            "threats_linked": threats_linked,
            "findings_assessment_id": fa_id,
            "findings_count": findings_count,
            "entity_id": entity_id,
            "entity_assessment_id": ea_obj.get_id() if (ea_obj and hasattr(ea_obj, "get_id")) else None,
            "entity_assessment_name": ea_obj.get_name() if (ea_obj and hasattr(ea_obj, "get_name")) else None,
            "user_email": user_email,
            "user_id": user_id,
            "user_exists": bool(user_id),
            "tprm_conclusion": ea_obj.json_object.get("conclusion") if ea_obj and isinstance(getattr(ea_obj, "json_object", None), dict) else None,
        }

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

        # Index requirement assessments by compliance assessment ID for quick lookup
        req_by_ca: dict[str, list[Any]] = {}
        req_assessments_obj = getattr(compliance_dict, "requirement_assessments", None)
        if req_assessments_obj and hasattr(req_assessments_obj, "get_requirement_assessments"):
            try:
                ras_dict = req_assessments_obj.get_requirement_assessments()
                if isinstance(ras_dict, dict):
                    for ra in ras_dict.values():
                        if hasattr(ra, "get_compliance_assessment_id"):
                            ca_id = ra.get_compliance_assessment_id()
                            if ca_id:
                                req_by_ca.setdefault(ca_id, []).append(ra)
            except Exception as e:
                utils.log(f"Error indexing requirement assessments: {e}", level=logging.DEBUG)

        status_list = []
        known_names = set()
        for app in self.get_example_applications():
            app_name = app["name"]
            known_names.add(app_name)
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
            vulns_linked = 0
            threats_linked = 0
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
                        vulns_linked += len(sc.get_vulnerability_ids() if hasattr(sc, "get_vulnerability_ids") else (sc.get_json().get("vulnerabilities") or []))
                        threats_linked += len(sc.get_threat_ids() if hasattr(sc, "get_threat_ids") else (sc.get_json().get("threats") or []))

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

            fa_id = None
            findings_count = 0
            findings_fa_dict = data.get("findings_assessment_dict")
            finding_dict = data.get("finding_dict")
            if findings_fa_dict and finding_dict:
                for fa in findings_fa_dict.get_findings_assessments().values():
                    if (perimeter_id and fa.get_perimeter_id() == perimeter_id) or app_name in fa.get_name():
                        fa_id = fa.get_id()
                        findings_count = len(finding_dict.get_findings_for_assessment(fa_id))
                        break

            fw_id = ca_obj.get_framework_id() if (ca_obj and hasattr(ca_obj, "get_framework_id")) else None
            fw_name = None
            fw_ref = None
            if fw_id and data.get("framework_dict"):
                fw_obj = data["framework_dict"].get_framework_by_identifier(fw_id)
                if fw_obj:
                    fw_name = fw_obj.get_name()
                    fw_json = getattr(fw_obj, "json_object", {}) or {}
                    fw_ref = fw_json.get("ref_id")
            if not fw_name:
                fw_name = app.get("framework_name", DEFAULT_FRAMEWORK_NAME)
            if not fw_ref:
                fw_ref = app.get("framework_ref", DEFAULT_FRAMEWORK_REF)

            # Resolve domain / folder
            app_domain_id = None
            if perimeter_id:
                p_obj = next((p for p in perimeter_dict.get_perimeters() if p.get_id() == perimeter_id), None)
                if p_obj:
                    app_domain_id = p_obj.get_folder_uuid()
            if not app_domain_id and asset_id:
                a_obj = next((a for a in asset_dict.get_assets() if a.get_id() == asset_id), None)
                if a_obj:
                    app_domain_id = a_obj.get_folder_id()
            if not app_domain_id and entity_id:
                e_obj = next((e for e in entity_dict.get_entities() if e.get_id() == entity_id), None)
                if e_obj:
                    ent_f = e_obj.json_object.get("folder", {})
                    app_domain_id = ent_f.get("id") if isinstance(ent_f, dict) else ent_f

            app_domain_name = None
            domain_dict = data.get("domain_dict")
            if app_domain_id and domain_dict and hasattr(domain_dict, "get_name_from_id"):
                app_domain_name = domain_dict.get_name_from_id(app_domain_id)

            if not app_domain_name:
                app_domain_name = self.folder_name
                if not app_domain_id and domain_dict and hasattr(domain_dict, "get_id_from_name"):
                    app_domain_id = domain_dict.get_id_from_name(self.folder_name)

            status_list.append(self._build_status_dict(
                app_id=app["id"],
                app_name=app_name,
                label=app["label"],
                perimeter_id=perimeter_id,
                asset_id=asset_id,
                ca_obj=ca_obj,
                ra_obj=ra_obj,
                ra_scenarios_count=ra_scenarios_count,
                ctrl_count=ctrl_count,
                existing_ctrls_linked=existing_ctrls_linked,
                planned_ctrls_linked=planned_ctrls_linked,
                vulns_linked=vulns_linked,
                threats_linked=threats_linked,
                fa_id=fa_id,
                findings_count=findings_count,
                entity_id=entity_id,
                ea_obj=ea_obj,
                user_email=user_email,
                user_id=user_id,
                req_by_ca=req_by_ca,
                framework_id=fw_id,
                framework_name=fw_name,
                framework_ref=fw_ref,
                yaml_path=app.get("yaml_path", ""),
                domain_id=app_domain_id,
                domain_name=app_domain_name,
            ))

        # Discover custom applications created in the example folder or target domain
        folder_id = None
        domain_dict = data.get("domain_dict")
        if domain_dict and hasattr(domain_dict, "get_domains"):
            for d in domain_dict.get_domains():
                if d.get_name() == self.folder_name:
                    folder_id = d.get_id()
                    break

        custom_entities = []
        for ent in entity_dict.get_entities():
            ent_name = ent.get_name()
            if ent_name and ent_name not in known_names:
                ent_folder = ent.json_object.get("folder", {})
                ent_fid = ent_folder.get("id") if isinstance(ent_folder, dict) else ent_folder
                # Match application in target folder, or discover custom entity with associated folder
                if folder_id and ent_fid == folder_id:
                    custom_entities.append((ent_name, ent_fid))
                elif ent_fid:
                    custom_entities.append((ent_name, ent_fid))

        for app_name, ent_fid in custom_entities:
            known_names.add(app_name)
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
            vulns_linked = 0
            threats_linked = 0
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
                        vulns_linked += len(sc.get_vulnerability_ids() if hasattr(sc, "get_vulnerability_ids") else (sc.get_json().get("vulnerabilities") or []))
                        threats_linked += len(sc.get_threat_ids() if hasattr(sc, "get_threat_ids") else (sc.get_json().get("threats") or []))

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

            user_id = None
            user_email = None
            entity_rep_dict = data.get("entity_representative_dict")
            rep_ids = ea_obj.get_representative_ids() if ea_obj else []
            if not rep_ids and entity_id and entity_rep_dict:
                rep_ids = [r.get_user_id() for r in entity_rep_dict.get_representatives_for_entity(entity_id)]
            if rep_ids:
                for u in user_dict.get_users():
                    if u.get_id() in rep_ids:
                        user_id = u.get_id()
                        user_email = u.get_email()
                        break

            fa_id = None
            findings_count = 0
            if findings_fa_dict and finding_dict:
                for fa in findings_fa_dict.get_findings_assessments().values():
                    if (perimeter_id and fa.get_perimeter_id() == perimeter_id) or app_name in fa.get_name():
                        fa_id = fa.get_id()
                        findings_count = len(finding_dict.get_findings_for_assessment(fa_id))
                        break

            fw_id = ca_obj.get_framework_id() if (ca_obj and hasattr(ca_obj, "get_framework_id")) else None
            fw_name = None
            fw_ref = None
            if fw_id and data.get("framework_dict"):
                fw_obj = data["framework_dict"].get_framework_by_identifier(fw_id)
                if fw_obj:
                    fw_name = fw_obj.get_name()
                    fw_json = getattr(fw_obj, "json_object", {}) or {}
                    fw_ref = fw_json.get("ref_id")

            custom_domain_name = None
            if ent_fid and domain_dict and hasattr(domain_dict, "get_name_from_id"):
                custom_domain_name = domain_dict.get_name_from_id(ent_fid)
            if not custom_domain_name:
                custom_domain_name = self.folder_name

            status_list.append(self._build_status_dict(
                app_id=f"custom_{app_name.lower().replace(' ', '_')}",
                app_name=app_name,
                label=f"{app_name} (Custom Audit Demo)",
                perimeter_id=perimeter_id,
                asset_id=asset_id,
                ca_obj=ca_obj,
                ra_obj=ra_obj,
                ra_scenarios_count=ra_scenarios_count,
                ctrl_count=ctrl_count,
                existing_ctrls_linked=existing_ctrls_linked,
                planned_ctrls_linked=planned_ctrls_linked,
                vulns_linked=vulns_linked,
                threats_linked=threats_linked,
                fa_id=fa_id,
                findings_count=findings_count,
                entity_id=entity_id,
                ea_obj=ea_obj,
                user_email=user_email,
                user_id=user_id,
                req_by_ca=req_by_ca,
                framework_id=fw_id,
                framework_name=fw_name,
                framework_ref=fw_ref,
                yaml_path="-",
                domain_id=ent_fid or folder_id,
                domain_name=custom_domain_name,
            ))

        return status_list

    def create_example_application(
        self,
        app_id_or_name: str,
        framework_ref_or_name: str | None = None,
        domain_name: str | None = None,
    ) -> dict[str, Any]:
        """Create a complete example application simulation in CISO Assistant.

        Steps:
        1. Resolve Folder/Domain and Default Assignee (creates domain if missing).
        2. Create Perimeter (`App-Name`).
        3. Create Asset (`App-Name`) and link to folder/owner.
        4. Create Compliance Assessment bound to target framework.
        5. Assign requirements to perimeter owner and start assignment.
        6. Import questionnaire answers from YAML answers profile using answers_import.
        7. Create Risk Assessment and generate all Risk Scenarios.
        8. Create Applied Controls with calculated priorities.
        9. Update Asset CIA Criticality security objectives.

        Args:
            app_id_or_name: Application ID (e.g. 'app_secure_core') or Name ('App-Secure-Core').
            framework_ref_or_name: Optional framework ref_id, name, or identifier to override app default.
            domain_name: Optional target domain/folder name or UUID (default: self.folder_name).

        Returns:
            Summary dict with created IDs and status.
        """
        app_spec = self.find_example_application(app_id_or_name)
        if not app_spec:
            raise ValueError(f"Unknown example application: {app_id_or_name}")

        app_name = app_spec["name"]
        answers_path = app_spec.get("yaml_path")

        utils.log(f"Starting simulation creation for {app_name} from {answers_path}...", level=logging.INFO)

        data = self._init_data()
        folder_id = self.get_or_create_folder(domain_name)
        domain_dict = data.get("domain_dict")
        resolved_domain_name = (
            domain_dict.get_name_from_id(folder_id)
            if (domain_dict and hasattr(domain_dict, "get_name_from_id") and folder_id)
            else (domain_name or self.folder_name)
        )
        assignee_id = self.get_default_assignee_id()

        target_fw_spec = framework_ref_or_name or app_spec.get("framework_ref") or app_spec.get("framework_name")
        framework = self.find_target_framework(target_fw_spec)

        if not framework:
            fw_label = f"'{target_fw_spec}'" if target_fw_spec else "default framework"
            raise RuntimeError(f"Framework {fw_label} not found in CISO Assistant for {app_name}. Please verify the framework is installed in CISO Assistant.")

        framework_id = framework.get_id()
        framework_name = framework.get_name()
        fw_json = framework.json_object if hasattr(framework, "json_object") else {}
        framework_ref = fw_json.get("ref_id") or app_spec.get("framework_ref")

        framework_yaml_path = self.resolve_framework_yaml_path(target_fw_spec or framework_name)
        framework_file = self.resolve_framework_file(target_fw_spec or framework_name, data=data)

        # Step 0a: Ensure Vulnerabilities & Threats are provisioned from framework file
        vuln_dict = data.get("vulnerability_dict")
        # Step 0a: Ensure Threats are provisioned from framework file
        threat_dict = data.get("threat_dict")
        if vuln_dict and folder_id and framework_file and hasattr(vuln_dict, "provision_vulnerabilities_from_framework"):
            vuln_dict.provision_vulnerabilities_from_framework(framework_file, folder_id)
        if threat_dict and framework_file and hasattr(threat_dict, "provision_threats_from_framework"):
            threat_dict.provision_threats_from_framework(framework_file)

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

        # Step 3b: Provision Vulnerabilities for this Asset
        vuln_dict = data.get("vulnerability_dict")
        if vuln_dict and folder_id and framework_file and hasattr(vuln_dict, "provision_vulnerabilities_from_framework"):
            vuln_dict.provision_vulnerabilities_from_framework(
                framework_file,
                folder_id=folder_id,
                asset_id=asset_id,
                asset_name=app_name,
            )

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

        # Step 5: Import questionnaire answers
        if not Path(answers_path).exists():
            raise FileNotFoundError(f"Answers file not found: {answers_path}")

        import_summary = answers_import.import_compliance_answers(
            answers_path,
            ca_id,
            compliance_dict.requirement_assessments,
        )
        utils.log(f"Imported {import_summary['updated']} answers from {answers_path} into assessment {ca_name}")

        # Reload after importing answers
        compliance_dict.requirement_assessments.reload()

        # Step 6: Update Asset Criticality
        compliance_dict.update_asset_criticality(criticality_mapping, asset_dict)

        # Step 7: Create Risk Assessment & evaluate Risk Scenarios
        from tests.test_application_scenarios import ApplicationRiskSimulator
        simulator = ApplicationRiskSimulator(str(framework_yaml_path))
        sim_results = simulator.evaluate_application(answers_path)

        risk_assessment_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenario_dict: RiskScenarioDict = data["risk_scenario_dict"]
        vuln_dict = data.get("vulnerability_dict")
        threat_dict = data.get("threat_dict")

        risk_matrix_id = self.find_target_risk_matrix(framework_id)
        ra_name = f"{ca_name} Risk Assessment"

        risk_assessment = risk_assessment_dict.create_risk_assessments(
            ra_name,
            framework_id,
            perimeter_id,
            risk_matrix_id,
        )
        ra_id = risk_assessment.get("id") if isinstance(risk_assessment, dict) else ""

        # Reload requirement assessments
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

            lh_urn = risk_scenario.get("likelihood", "")
            matching_ra = next(
                (ra for ra in app_ras if ra.get_urn() == lh_urn or (ra.get_requirement_json().get("requirement", {}) or {}).get("urn") == lh_urn),
                None,
            )

            if not sim_sc or matching_ra is None or matching_ra.is_unassessed_result() or not matching_ra.has_selected_answer():
                utils.log(f"Skipping scenario '{sc_name}' for {app_name}: requirement not answered / out of scope")
                risk_scenario_dict.delete_risk_scenario(sc_name, ra_id)
                continue

            scaled_likelihood = sim_sc["scaled_likelihood"]
            scaled_impact = sim_sc["scaled_impact"]

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

            # Resolve Vulnerabilities and Threats
            scenario_vuln_urns = risk_scenario.get("vulnerabilities", [])
            scenario_threat_urns = risk_scenario.get("threats", [])
            if not scenario_vuln_urns and matching_ra:
                req_json = matching_ra.get_requirement_json()
                req_obj = req_json.get("requirement", {}) if isinstance(req_json, dict) else {}
                scenario_vuln_urns = req_obj.get("vulnerabilities", []) or []

            vuln_ids = []
            if vuln_dict and scenario_vuln_urns:
                for vu in scenario_vuln_urns:
                    vid = vuln_dict.get_id_by_urn(vu) or vuln_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                    vid = None
                    if hasattr(vuln_dict, "get_vulnerability_id_for_asset"):
                        vid = vuln_dict.get_vulnerability_id_for_asset(vu, asset_id=asset_id, asset_name=app_name)
                    if not vid:
                        vid = vuln_dict.get_id_by_urn(vu) or vuln_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                    if not vid and hasattr(vuln_dict, "resolve_vulnerability_id"):
                        vid = vuln_dict.resolve_vulnerability_id(vu)
                    if vid and vid not in vuln_ids:
                        vuln_ids.append(vid)

            threat_ids = []
            if threat_dict and scenario_threat_urns:
                for tu in scenario_threat_urns:
                    tid = threat_dict.get_id_by_urn(tu) or threat_dict.get_id_by_ref_id(tu.rsplit(":", 1)[-1])
                    if not tid and hasattr(threat_dict, "resolve_threat_id"):
                        tid = threat_dict.resolve_threat_id(tu)
                    if tid and tid not in threat_ids:
                        threat_ids.append(tid)

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
                vulnerabilities=vuln_ids,
                threats=threat_ids,
            )
            scenarios_created += 1

        # Step 8: Create Applied Controls with calculated priorities (created after risk scenarios)
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

        # Step 9: Guarantee complete control & asset link synchronization
        time.sleep(1)
        link_res = self.link_controls_for_application(app_name)

        # Step 10: Generate Findings from Audit Answers
        findings_res = self.create_findings_for_application(app_name)

        # Step 11: Create recurring tasks for recurrent applied controls
        task_templates_created = []
        task_template_dict = data.get("task_template_dict")
        if applied_control_dict and reference_control_dict:
            try:
                task_templates_created = applied_control_dict.create_tasks_for_applied_controls(
                    reference_control_dict,
                    task_template_dict=task_template_dict,
                    perimeter_dict=perimeter_dict,
                    user_id=assignee_id,
                )
            except Exception as e:
                utils.log(f"Error creating tasks for recurrent controls: {e}", level=logging.WARNING)

        # Reload for fresh state
        time.sleep(1)
        self._init_data(force_reload=True)

        return {
            "app_name": app_name,
            "domain_id": folder_id,
            "domain_name": resolved_domain_name,
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
            "answers_updated": import_summary["updated"],
            "scenarios_created": scenarios_created,
            "existing_controls_linked": link_res.get("existing_controls", 0),
            "planned_controls_linked": link_res.get("planned_controls", 0),
            "vulnerabilities_linked": link_res.get("vulnerabilities_linked", 0),
            "threats_linked": link_res.get("threats_linked", 0),
            "findings_assessment_id": findings_res.get("findings_assessment_id"),
            "findings_count": findings_res.get("findings_count", 0),
            "task_templates_created": len(task_templates_created),
            "framework_id": framework_id,
            "framework_name": framework_name,
            "framework_ref": framework_ref,
        }


    def create_application_for_audit(
        self,
        app_name: str,
        user_email: str,
        first_name: str = "",
        last_name: str = "",
        is_third_party: bool = True,
        framework_ref_or_name: str | None = None,
        domain_name: str | None = None,
    ) -> dict[str, Any]:
        """Create an application in CISO Assistant for an audit demonstration.

        Sets up:
        1. Third-party or internal user account (created if missing).
        2. External Entity in TPRM and Entity Representative link.
        3. Perimeter and Asset (in target domain/folder; creates domain if missing).
        4. Compliance Assessment bound to target framework.
        5. TPRM Entity Assessment linking entity, compliance assessment, and representative user.
        6. Requirement assignment in progress for the user.

        NOTE:
        Questions are left completely UNANSWERED (0% completion), with no risk scenarios
        and no applied controls created, allowing demonstration of what an assigned
        respondent sees when opening an audit to answer it.

        Args:
            app_name: Application name (e.g. 'App-Audit-Demo').
            user_email: Email of the user to assign the assessment to.
            first_name: Optional first name if creating a new user.
            last_name: Optional last name if creating a new user.
            is_third_party: Whether newly created user should be third-party (default True).
            framework_ref_or_name: Optional framework ref_id, name, or identifier to use.
            domain_name: Optional target domain/folder name or UUID (default: self.folder_name).

        Returns:
            Dict summary of created resources and assignment details.
        """
        app_name = (app_name or "").strip()
        user_email = (user_email or "").strip().lower()
        if not app_name:
            raise ValueError("Application name cannot be empty.")
        if not user_email:
            raise ValueError("User email cannot be empty.")

        utils.log(f"Starting audit demonstration creation for {app_name} assigned to {user_email}...", level=logging.INFO)

        data = self._init_data(force_reload=True)
        folder_id = self.get_or_create_folder(domain_name)
        domain_dict = data.get("domain_dict")
        resolved_domain_name = (
            domain_dict.get_name_from_id(folder_id)
            if (domain_dict and hasattr(domain_dict, "get_name_from_id") and folder_id)
            else (domain_name or self.folder_name)
        )
        assignee_id = self.get_default_assignee_id()
        framework = self.find_target_framework(framework_ref_or_name)

        if not framework:
            fw_label = f"'{framework_ref_or_name}'" if framework_ref_or_name else "default framework"
            raise RuntimeError(f"Framework {fw_label} not found in CISO Assistant for {app_name}. Please verify the framework is installed in CISO Assistant.")

        framework_id = framework.get_id()
        framework_name = framework.get_name()
        fw_json = framework.json_object if hasattr(framework, "json_object") else {}
        framework_ref = fw_json.get("ref_id", "")

        # Step 1: Ensure User exists (create if missing)
        user_dict: UserDict = data["user_dict"]
        user_id = user_dict.get_id_from_email(user_email)
        user_created = False
        if not user_id:
            user_res = user_dict.create_user_if_missing(
                email=user_email,
                first_name=first_name,
                last_name=last_name,
                is_third_party=is_third_party,
            )
            if isinstance(user_res, dict):
                user_id = user_res.get("id")
            if not user_id:
                user_id = user_dict.get_id_from_email(user_email)
            user_created = True
            utils.log(f"Created new user '{user_email}' with ID: {user_id}", level=logging.INFO)
        else:
            utils.log(f"Found existing user '{user_email}' with ID: {user_id}", level=logging.INFO)

        # Step 2: Create External Entity for TPRM
        entity_dict: EntityDict = data["entity_dict"]
        entity_rep_dict: EntityRepresentativeDict = data["entity_representative_dict"]
        entity_assessment_dict: EntityAssessmentDict = data["entity_assessment_dict"]

        entity_res = entity_dict.create_entity(
            name=app_name,
            folder_id=folder_id,
            description=f"External entity for {app_name} (audit demonstration)",
        )
        entity_id = entity_res.get("id") if isinstance(entity_res, dict) else entity_dict.get_id_from_name(app_name)
        if not entity_id:
            raise RuntimeError(f"Failed to create or find external entity '{app_name}'")
        utils.log(f"External Entity '{app_name}' ready with ID: {entity_id}", level=logging.INFO)

        # Step 3: Link Representative User to External Entity
        if user_id and entity_id:
            entity_rep_dict.upsert_entity_representative(
                entity_id=entity_id,
                user_id=user_id,
                role="representative",
            )

        # Step 4: Create Perimeter
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        perimeter = perimeter_dict.create_perimeter(app_name, assignee_id, folder_id)
        perimeter_dict.reload()
        perimeter_id = perimeter_dict.get_id_from_name(app_name)
        if not perimeter_id:
            raise RuntimeError(f"Failed to create or find perimeter '{app_name}'")

        # Step 5: Create Asset
        asset_dict: AssetDict = data["asset_dict"]
        asset = asset_dict.create_asset(app_name, "PR", folder_id, owner_id=assignee_id)
        asset_dict.reload()
        asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)
        if asset_id and assignee_id:
            for a in asset_dict.get_assets():
                if a.get_id() == asset_id:
                    a.set_owner_if_missing(assignee_id)
                    break

        # Step 6: Create Compliance Assessment
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
            if not ca_response or (isinstance(ca_response, dict) and ca_response.get("error")):
                raise RuntimeError(f"Failed to create compliance assessment '{ca_name}': {ca_response}")
            compliance_dict.reload()
            ca_id = ca_response.get("id") if isinstance(ca_response, dict) else ""
            ca_obj = compliance_dict.get_compliance_assessments().get(ca_id)

        ca_id = ca_obj.get_id()

        # Step 7: Create TPRM Entity Assessment linking external entity & compliance assessment
        ea_name = f"Third-party assessment for {app_name}"
        ea_res = entity_assessment_dict.create_entity_assessment(
            name=ea_name,
            entity_id=entity_id,
            compliance_assessment_id=ca_id,
            representative_ids=[user_id] if user_id else None,
            status="in_progress",
        )
        ea_id = ea_res.get("id") if isinstance(ea_res, dict) else ""
        if not ea_id:
            for ea in entity_assessment_dict.get_entity_assessments():
                if ea.get_entity_id() == entity_id:
                    ea_id = ea.get_id()
                    break
        utils.log(f"Entity Assessment '{ea_name}' ready with ID: {ea_id}", level=logging.INFO)

        # Step 8: Ensure requirement assessments are populated and loaded from API
        utils.log(f"Waiting for requirement assessments to populate for {ca_name}...", level=logging.INFO)
        req_ids = []
        for _ in range(10):
            compliance_dict.requirement_assessments.reload()
            req_ids = compliance_dict.requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id(ca_id)
            if req_ids:
                utils.log(f"Loaded {len(req_ids)} requirement assessment(s) for {ca_name}", level=logging.INFO)
                break
            time.sleep(0.5)

        # Step 9: Verify requirement assignment is created and started
        compliance_dict.requirement_assignments.reload()
        assignment_ids = compliance_dict.requirement_assignments.get_requirement_assignment_id_list_from_compliance_assessment_id(ca_id)
        if not assignment_ids and req_ids and ea_id:
            for ea in entity_assessment_dict.get_entity_assessments():
                if ea.get_id() == ea_id:
                    ea.assign_requirements_to_representatives([user_id] if user_id else None)
                    break
            compliance_dict.requirement_assignments.reload()
            assignment_ids = compliance_dict.requirement_assignments.get_requirement_assignment_id_list_from_compliance_assessment_id(ca_id)

        assignment_id = assignment_ids[0] if assignment_ids else None
        utils.log(f"Requirement assignment ID for {ca_name}: {assignment_id}", level=logging.INFO)

        # Step 10: Refresh cached state
        self._init_data(force_reload=True)

        return {
            "app_name": app_name,
            "domain_id": folder_id,
            "domain_name": resolved_domain_name,
            "user_email": user_email,
            "user_id": user_id,
            "user_created": user_created,
            "entity_id": entity_id,
            "entity_assessment_id": ea_id,
            "entity_assessment_name": ea_name,
            "perimeter_id": perimeter_id,
            "asset_id": asset_id,
            "compliance_assessment_id": ca_id,
            "compliance_assessment_name": ca_name,
            "compliance_status": ca_obj.get_status() if ca_obj else "in_progress",
            "requirement_assessments_count": len(req_ids),
            "assignment_id": assignment_id,
            "direct_url": f"{utils.BASE_URL}/",
            "framework_id": framework_id,
            "framework_name": framework_name,
            "framework_ref": framework_ref,
        }

    def generate_controls_and_risks_for_application(
        self,
        app_id_or_name: str | None = None,
        yaml_path: str | None = None,
        app_name: str | None = None,
    ) -> dict[str, Any]:
        """Generate applied controls and dynamic risk scenarios for an application.

        Can evaluate from either:
        1. Live requirement assessment answers already submitted in CISO Assistant UI.
        2. A YAML answers file or example profile (e.g. 'app_secure_core', 'App-Secure-Core').

        Steps:
        1. Resolve application perimeter, asset, and compliance assessment.
        2. If yaml_path provided, import answers into the compliance assessment.
        3. Validate that at least one requirement is answered (raise ValueError if none).
        4. Create missing applied controls and link them to the application asset.
        5. Update asset CIA criticality.
        6. Create or resolve risk assessment with target risk matrix.
        7. Evaluate dynamic risk scenarios using ApplicationRiskSimulator (from YAML or live UI answers).
        8. Create in-scope risk scenarios and delete out-of-scope scenarios.
        9. Synchronize control links (existing active vs. planned to_do) on risk scenarios.

        Args:
            app_id_or_name: Application ID or Name (e.g. 'App-Audit-Demo' or 'app_secure_core').
            yaml_path: Optional path to YAML answers file, or example application ID/name to use its YAML.
            app_name: Alias for app_id_or_name for keyword argument compatibility.

        Returns:
            Dict summary of generated controls, risk assessment, and scenarios.
        """
        resolved_name = (app_name or app_id_or_name or "").strip()
        app_spec = self.find_example_application(resolved_name)
        if app_spec:
            app_name = app_spec["name"]
        else:
            app_name = resolved_name

        utils.log(f"Starting controls & risk generation for {app_name}...", level=logging.INFO)

        data = self._init_data(force_reload=True)
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        asset_dict: AssetDict = data["asset_dict"]
        compliance_dict: ComplianceAssessmentDict = data["compliance_assessment_dict"]
        applied_control_dict: AppliedControlDict = data["applied_control_dict"]
        reference_control_dict: ReferenceControlDict = data["reference_control_dict"]
        risk_assessment_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenario_dict: RiskScenarioDict = data["risk_scenario_dict"]
        framework_file = data["framework_file"]

        perimeter_id = perimeter_dict.get_id_from_name(app_name)
        asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)
        assignee_id = perimeter_dict.get_owner_id_from_perimeter_id(perimeter_id) if perimeter_id else None
        if not assignee_id:
            assignee_id = self.get_default_assignee_id()

        # Find compliance assessment for this application
        ca_obj = None
        for ca in compliance_dict.get_compliance_assessments().values():
            if (perimeter_id and ca.get_perimeter_id() == perimeter_id) or f"in {app_name}" in ca.get_name():
                ca_obj = ca
                break

        if not ca_obj:
            raise ValueError(f"No compliance assessment found for application '{app_name}'. Please ensure the application was created.")

        ca_id = ca_obj.get_id()
        ca_name = ca_obj.get_name()
        framework_id = ca_obj.get_framework_id()
        if not framework_id:
            fw = self.find_target_framework(app_spec.get("framework_ref") if app_spec else None)
            framework_id = fw.get_id() if fw else None

        fw_dict = data.get("framework_dict")
        fw_obj = fw_dict.get_framework_by_identifier(framework_id) if (fw_dict and framework_id) else None
        target_fw_ident = fw_obj.get_name() if fw_obj else (app_spec.get("framework_ref") if app_spec else framework_id)
        framework_yaml_path = self.resolve_framework_yaml_path(target_fw_ident)
        framework_file = self.resolve_framework_file(target_fw_ident, data=data)

        # Resolve answers path if provided
        answers_source = yaml_path
        resolved_answers_path = None
        if answers_source:
            target_file = Path(answers_source)
            if target_file.exists():
                resolved_answers_path = str(target_file)
            else:
                ex_profile = self.find_example_application(answers_source)
                if ex_profile:
                    candidate = ex_profile.get("yaml_path")
                    if candidate and Path(candidate).exists():
                        resolved_answers_path = candidate
                if not resolved_answers_path:
                    raise FileNotFoundError(f"Specified answers file or profile not found: {answers_source}")

        answers_updated = 0
        if resolved_answers_path:
            utils.log(f"Importing compliance answers from '{resolved_answers_path}' into {ca_name}...", level=logging.INFO)
            import_summary = answers_import.import_compliance_answers(
                resolved_answers_path,
                ca_id,
                compliance_dict.requirement_assessments,
            )
            answers_updated = import_summary.get("updated", 0)
            compliance_dict.requirement_assessments.reload()

        # Check that we have answered requirements
        compliance_dict.requirement_assessments.reload()
        req_assessments = compliance_dict.requirement_assessments.get_requirement_assessments()
        app_ras = [
            ra for ra in req_assessments.values()
            if ra.get_compliance_assessment_id() == ca_id
        ]
        answered_ras = [
            ra for ra in app_ras
            if ra.has_selected_answer() and not ra.is_unassessed_result()
        ]

        if not answered_ras:
            raise ValueError(
                f"Application '{app_name}' has 0 answered requirements in assessment '{ca_name}'. "
                f"Please answer questions in CISO Assistant UI, or supply an answers file/profile."
            )

        # Update Asset Criticality
        compliance_dict.update_asset_criticality(criticality_mapping, asset_dict)

        # Find or create Risk Assessment
        risk_matrix_id = self.find_target_risk_matrix(framework_id) if framework_id else None
        ra_name = f"{ca_name} Risk Assessment"

        ra_obj = None
        for ra in risk_assessment_dict.get_risk_assessments().values():
            ra_perimeter = ra.json_object.get("perimeter")
            if (perimeter_id and ra_perimeter == perimeter_id) or app_name in ra.get_name():
                ra_obj = ra
                break

        if not ra_obj:
            risk_assessment = risk_assessment_dict.create_risk_assessments(
                ra_name,
                framework_id,
                perimeter_id,
                risk_matrix_id,
            )
            ra_id = risk_assessment.get("id") if isinstance(risk_assessment, dict) else ""
        else:
            ra_id = ra_obj.get_id()

        # Evaluate Scenarios with Simulator
        from tests.test_application_scenarios import ApplicationRiskSimulator
        simulator = ApplicationRiskSimulator(str(framework_yaml_path))

        compliance_dict.requirement_assessments.reload()
        req_assessments = compliance_dict.requirement_assessments.get_requirement_assessments()
        app_ras = [
            ra for ra in req_assessments.values()
            if ra.get_compliance_assessment_id() == ca_id
        ]

        if resolved_answers_path:
            sim_results = simulator.evaluate_application(resolved_answers_path)
        else:
            sim_results = simulator.evaluate_application(app_ras)

        app_controls = {
            c.get_id(): c
            for c in applied_control_dict.get_controls().values()
            if f"on {app_name}" in c.get_name()
        }

        vuln_dict = data.get("vulnerability_dict")
        threat_dict = data.get("threat_dict")
        if vuln_dict and framework_file and hasattr(vuln_dict, "provision_vulnerabilities_from_framework"):
            target_folder_id = perimeter_dict.get_folder_uuid_from_perimeter_id(perimeter_id) if perimeter_dict and perimeter_id else None
            if not target_folder_id:
                target_folder_id = self.get_or_create_folder()
            if target_folder_id:
                vuln_dict.provision_vulnerabilities_from_framework(framework_file, target_folder_id)
                vuln_dict.provision_vulnerabilities_from_framework(
                    framework_file,
                    target_folder_id,
                    asset_id=asset_id,
                    asset_name=app_name,
                )
        if threat_dict and framework_file and hasattr(threat_dict, "provision_threats_from_framework"):
            threat_dict.provision_threats_from_framework(framework_file)

        scenarios_created = 0
        asset_ids = [asset_id] if asset_id else []
        owner_ids = [assignee_id] if assignee_id else []

        for risk_scenario in framework_file.get_risk_scenarios():
            sc_name = risk_scenario.get("name", "")
            sim_sc = sim_results.get("scenarios", {}).get(sc_name)

            lh_urn = risk_scenario.get("likelihood", "")
            matching_ra = next(
                (ra for ra in app_ras if ra.get_urn() == lh_urn or (ra.get_requirement_json().get("requirement", {}) or {}).get("urn") == lh_urn),
                None,
            )

            if not sim_sc or matching_ra is None or not matching_ra.has_selected_answer():
                utils.log(f"Skipping scenario '{sc_name}' for {app_name}: requirement not answered / out of scope")
                risk_scenario_dict.delete_risk_scenario(sc_name, ra_id)
                continue

            scaled_likelihood = sim_sc["scaled_likelihood"]
            scaled_impact = sim_sc["scaled_impact"]

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

            # Resolve Vulnerabilities and Threats
            scenario_vuln_urns = risk_scenario.get("vulnerabilities", [])
            scenario_threat_urns = risk_scenario.get("threats", [])
            if not scenario_vuln_urns and matching_ra:
                req_json = matching_ra.get_requirement_json()
                req_obj = req_json.get("requirement", {}) if isinstance(req_json, dict) else {}
                scenario_vuln_urns = req_obj.get("vulnerabilities", []) or []

            vuln_ids = []
            if vuln_dict and scenario_vuln_urns:
                for vu in scenario_vuln_urns:
                    vid = vuln_dict.get_id_by_urn(vu) or vuln_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                    vid = None
                    if hasattr(vuln_dict, "get_vulnerability_id_for_asset"):
                        vid = vuln_dict.get_vulnerability_id_for_asset(vu, asset_id=asset_id, asset_name=app_name)
                    if not vid:
                        vid = vuln_dict.get_id_by_urn(vu) or vuln_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                    if not vid and hasattr(vuln_dict, "resolve_vulnerability_id"):
                        vid = vuln_dict.resolve_vulnerability_id(vu)
                    if vid and vid not in vuln_ids:
                        vuln_ids.append(vid)

            threat_ids = []
            if threat_dict and scenario_threat_urns:
                for tu in scenario_threat_urns:
                    tid = threat_dict.get_id_by_urn(tu) or threat_dict.get_id_by_ref_id(tu.rsplit(":", 1)[-1])
                    if not tid and hasattr(threat_dict, "resolve_threat_id"):
                        tid = threat_dict.resolve_threat_id(tu)
                    if tid and tid not in threat_ids:
                        threat_ids.append(tid)

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
                vulnerabilities=vuln_ids,
                threats=threat_ids,
            )
            scenarios_created += 1

        # Create missing applied controls (after risk scenarios so priorities can be computed)
        compliance_dict.create_missing_applied_controls(
            applied_control_dict,
            perimeter_dict,
            reference_control_dict,
        )
        applied_control_dict.reload()

        if asset_id:
            for c in applied_control_dict.get_controls().values():
                if f"on {app_name}" in c.get_name():
                    applied_control_dict.ensure_assets_for_control(c.get_name(), [asset_id])

        time.sleep(1)
        link_res = self.link_controls_for_application(app_name)

        # Generate Findings from Audit Answers
        findings_res = self.create_findings_for_application(app_name)

        # Generate recurring tasks for recurrent applied controls
        task_templates_created = []
        task_template_dict = data.get("task_template_dict")
        if applied_control_dict and reference_control_dict:
            try:
                task_templates_created = applied_control_dict.create_tasks_for_applied_controls(
                    reference_control_dict,
                    task_template_dict=task_template_dict,
                    perimeter_dict=perimeter_dict,
                    user_id=assignee_id,
                )
            except Exception as e:
                utils.log(f"Error creating tasks for recurrent controls: {e}", level=logging.WARNING)

        applied_control_dict.reload()
        app_controls = {
            c.get_id(): c
            for c in applied_control_dict.get_controls().values()
            if f"on {app_name}" in c.get_name()
        }

        time.sleep(1)
        self._init_data(force_reload=True)

        return {
            "app_name": app_name,
            "perimeter_id": perimeter_id,
            "asset_id": asset_id,
            "compliance_assessment_id": ca_id,
            "compliance_assessment_name": ca_name,
            "risk_assessment_id": ra_id,
            "answers_updated": answers_updated,
            "scenarios_created": scenarios_created,
            "applied_controls_count": len(app_controls),
            "existing_controls_linked": link_res.get("existing_controls", 0),
            "planned_controls_linked": link_res.get("planned_controls", 0),
            "vulnerabilities_linked": link_res.get("vulnerabilities_linked", 0),
            "threats_linked": link_res.get("threats_linked", 0),
            "findings_assessment_id": findings_res.get("findings_assessment_id"),
            "findings_count": findings_res.get("findings_count", 0),
            "task_templates_created": len(task_templates_created),
        }

    def create_findings_for_application(self, app_id_or_name: str) -> dict[str, Any]:
        """Create or update findings for an application from its audit answers.

        Works for both:
        - Internal applications (bound to internal perimeter).
        - TPRM applications (bound to external entity / entity assessment).

        Args:
            app_id_or_name: Application ID or Name.

        Returns:
            Dict summary of findings assessment ID, name, and count of findings.
        """
        app_spec = self.find_example_application(app_id_or_name)
        app_name = app_spec["name"] if app_spec else app_id_or_name

        data = self._init_data()
        perimeter_dict = data.get("perimeter_dict")
        compliance_dict = data.get("compliance_assessment_dict")
        entity_dict = data.get("entity_dict")
        entity_assessment_dict = data.get("entity_assessment_dict")
        findings_fa_dict = data.get("findings_assessment_dict")
        finding_dict = data.get("finding_dict")
        asset_dict = data.get("asset_dict")
        vuln_dict = data.get("vulnerability_dict")
        threat_dict = data.get("threat_dict")
        framework_file = data.get("framework_file")

        if not compliance_dict or not findings_fa_dict or not finding_dict:
            return {"app_name": app_name, "findings_assessment_id": None, "findings_count": 0}

        perimeter_id = perimeter_dict.get_id_from_name(app_name) if perimeter_dict else None
        entity_id = entity_dict.get_id_from_name(app_name) if entity_dict else None

        # Resolve compliance assessment (check perimeter or name or TPRM entity assessment)
        ca_obj = None
        for ca in compliance_dict.get_compliance_assessments().values():
            if (perimeter_id and ca.get_perimeter_id() == perimeter_id) or f"in {app_name}" in ca.get_name():
                ca_obj = ca
                break

        if not ca_obj and entity_id and entity_assessment_dict:
            for ea in entity_assessment_dict.get_entity_assessments():
                if ea.get_entity_id() == entity_id:
                    ca_id = ea.get_compliance_assessment_id()
                    if ca_id:
                        ca_obj = compliance_dict.get_compliance_assessments().get(ca_id)
                        if ca_obj:
                            break

        if not ca_obj:
            utils.log(f"No compliance assessment found for {app_name}; skipping findings creation", level=logging.WARNING)
            return {
                "app_name": app_name,
                "findings_assessment_id": None,
                "findings_assessment_name": None,
                "findings_count": 0,
            }

        # Dynamically resolve framework_file for this assessment
        fw_dict = data.get("framework_dict")
        ca_fw_id = ca_obj.get_framework_id() if ca_obj else None
        fw_obj = fw_dict.get_framework_by_identifier(ca_fw_id) if (fw_dict and ca_fw_id) else None
        fw_ident = fw_obj.get_name() if fw_obj else (app_spec.get("framework_ref") if app_spec else ca_fw_id)
        framework_yaml_path = self.resolve_framework_yaml_path(fw_ident)
        framework_file = self.resolve_framework_file(fw_ident, data=data)

        summaries = compliance_dict.create_findings_assessments(
            findings_assessment_dict=findings_fa_dict,
            finding_dict=finding_dict,
            requirement_assessment_dict=compliance_dict.requirement_assessments,
            asset_dict=asset_dict,
            vulnerability_dict=vuln_dict,
            threat_dict=threat_dict,
            framework_file=framework_file,
            compliance_assessment_id=ca_obj.get_id(),
        )

        if summaries:
            summary = dict(summaries[0])
            summary["app_name"] = app_name
            return summary

        return {
            "app_name": app_name,
            "compliance_assessment_id": ca_obj.get_id(),
            "findings_assessment_id": None,
            "findings_assessment_name": None,
            "findings_count": 0,
        }



    def link_controls_for_application(self, app_id_or_name: str) -> dict[str, Any]:

        """Link existing (active) and planned (to_do) controls and assets to risk scenarios.

        Args:
            app_id_or_name: Application ID or Name.

        Returns:
            Dict summary of linked controls and scenarios.
        """
        app_spec = self.find_example_application(app_id_or_name)
        app_name = app_spec["name"] if app_spec else app_id_or_name
        data = self._init_data(force_reload=True)

        asset_dict: AssetDict = data["asset_dict"]
        perimeter_dict: PerimeterDict = data["perimeter_dict"]
        compliance_dict: ComplianceAssessmentDict = data["compliance_assessment_dict"]
        risk_assessment_dict: RiskAssessmentDict = data["risk_assessment_dict"]
        risk_scenario_dict: RiskScenarioDict = data["risk_scenario_dict"]
        applied_control_dict: AppliedControlDict = data["applied_control_dict"]

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

        # Resolve framework YAML and framework_file from compliance assessment
        fw_dict = data.get("framework_dict")
        ca_fw_id = ca_obj.get_framework_id() if ca_obj else None
        fw_obj = fw_dict.get_framework_by_identifier(ca_fw_id) if (fw_dict and ca_fw_id) else None
        fw_ident = fw_obj.get_name() if fw_obj else (app_spec.get("framework_ref") if app_spec else ca_fw_id)
        framework_yaml_path = self.resolve_framework_yaml_path(fw_ident)
        framework_file = self.resolve_framework_file(fw_ident, data=data)

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

        # Purge any out-of-scope scenarios from previous runs
        answers_path = app_spec.get("yaml_path") if app_spec else None
        from tests.test_application_scenarios import ApplicationRiskSimulator
        simulator = ApplicationRiskSimulator(str(framework_yaml_path))
        if answers_path:
            sim_results = simulator.evaluate_application(answers_path)
        else:
            sim_results = simulator.evaluate_application(app_ras)
        in_scope_scenarios = sim_results.get("scenarios", {})

        for sc in list(app_scenarios):
            if sc.get_name() not in in_scope_scenarios:
                utils.log(f"Deleting out-of-scope scenario '{sc.get_name()}' from {app_name}", level=logging.INFO)
                risk_scenario_dict.delete_risk_scenario(sc.get_name(), ra_id)
                app_scenarios = [s for s in app_scenarios if s.get_id() != sc.get_id()]

        # Provision framework vulnerabilities and threats if missing
        vuln_dict = data.get("vulnerability_dict")
        threat_dict = data.get("threat_dict")
        if vuln_dict and framework_file and hasattr(vuln_dict, "provision_vulnerabilities_from_framework"):
            target_folder_id = perimeter_dict.get_folder_uuid_from_perimeter_id(perimeter_id) if perimeter_dict and perimeter_id else None
            if not target_folder_id:
                target_folder_id = self.get_or_create_folder()
            if target_folder_id:
                vuln_dict.provision_vulnerabilities_from_framework(framework_file, target_folder_id)
                vuln_dict.provision_vulnerabilities_from_framework(
                    framework_file,
                    target_folder_id,
                    asset_id=asset_id,
                    asset_name=app_name,
                )
        if threat_dict and framework_file and hasattr(threat_dict, "provision_threats_from_framework"):
            threat_dict.provision_threats_from_framework(framework_file)

        total_existing_linked = 0
        total_planned_linked = 0
        total_vulnerabilities_linked = 0
        total_threats_linked = 0
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

            # Resolve vulnerabilities and threats from framework scenario definition
            vuln_dict = data.get("vulnerability_dict")
            threat_dict = data.get("threat_dict")
            scenario_vuln_urns = sc_def.get("vulnerabilities", [])
            scenario_threat_urns = sc_def.get("threats", [])
            if not scenario_vuln_urns and matching_ra:
                req_json = matching_ra.get_requirement_json()
                req_obj = req_json.get("requirement", {}) if isinstance(req_json, dict) else {}
                scenario_vuln_urns = req_obj.get("vulnerabilities", []) or []

            if vuln_dict and scenario_vuln_urns:
                v_ids = []
                for vu in scenario_vuln_urns:
                    vid = vuln_dict.get_id_by_urn(vu) or vuln_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                    vid = None
                    if hasattr(vuln_dict, "get_vulnerability_id_for_asset"):
                        vid = vuln_dict.get_vulnerability_id_for_asset(vu, asset_id=asset_id, asset_name=app_name)
                    if not vid:
                        vid = vuln_dict.get_id_by_urn(vu) or vuln_dict.get_id_by_ref_id(vu.rsplit(":", 1)[-1])
                    if not vid and hasattr(vuln_dict, "resolve_vulnerability_id"):
                        vid = vuln_dict.resolve_vulnerability_id(vu)
                    if vid and vid not in v_ids:
                        v_ids.append(vid)
                if v_ids:
                    patch_payload["vulnerabilities"] = v_ids
                    total_vulnerabilities_linked += len(v_ids)

            if threat_dict and scenario_threat_urns:
                t_ids = []
                for tu in scenario_threat_urns:
                    tid = threat_dict.get_id_by_urn(tu) or threat_dict.get_id_by_ref_id(tu.rsplit(":", 1)[-1])
                    if not tid and hasattr(threat_dict, "resolve_threat_id"):
                        tid = threat_dict.resolve_threat_id(tu)
                    if tid and tid not in t_ids:
                        t_ids.append(tid)
                if t_ids:
                    patch_payload["threats"] = t_ids
                    total_threats_linked += len(t_ids)

            utils.log(f"Updating scenario '{sc_name}' on {app_name}: existing={existing}, planned={planned}")
            res = utils.get_return(f"/api/risk-scenarios/{matching_sc.get_id()}/", method="PATCH", payload=patch_payload)
            if isinstance(res, dict) and not res.get("error"):
                matching_sc.json_object = res
                scenarios_updated += 1
                total_existing_linked += len(existing)
                total_planned_linked += len(planned)

            # Update priority on planned controls from scenario risk level
            req_urn = matching_ra.get_urn() if matching_ra else lh_urn
            for cid in planned:
                ctrl = app_controls.get(cid)
                if ctrl and req_urn:
                    applied_control_dict.update_priority_for_requirement_assessment(
                        ctrl.get_name(),
                        ca_id,
                        req_urn,
                        compliance_assessment_dict=compliance_dict,
                        framework_file=framework_file,
                    )

        # Synchronize findings with newly provisioned vulnerabilities/threats if findings exist
        try:
            self.create_findings_for_application(app_name)
        except Exception as e:
            utils.log(f"Could not refresh findings during link_controls for {app_name}: {e}", level=logging.DEBUG)

        return {
            "app_name": app_name,
            "scenarios_updated": scenarios_updated,
            "existing_controls": total_existing_linked,
            "planned_controls": total_planned_linked,
            "vulnerabilities_linked": total_vulnerabilities_linked,
            "threats_linked": total_threats_linked,
        }

    def link_all_controls_to_risk_scenarios(self) -> list[dict[str, Any]]:
        """Link existing and planned controls across all example applications."""
        results = []
        for app in self.get_example_applications():
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
        app_spec = self.find_example_application(app_id_or_name)
        app_name = app_spec["name"] if app_spec else app_id_or_name
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
        user_dict: UserDict | None = data.get("user_dict")
        findings_fa_dict = data.get("findings_assessment_dict")
        finding_dict = data.get("finding_dict")
        vuln_dict = data.get("vulnerability_dict")
        task_template_dict: TaskTemplateDict | None = data.get("task_template_dict")

        perimeter_id = perimeter_dict.get_id_from_name(app_name)
        entity_id = entity_dict.get_id_from_name(app_name)
        asset_id = asset_dict.get_asset_id_from_perimeter_name(app_name)

        deleted = {
            "app_name": app_name,
            "entity_assessments_deleted": 0,
            "entity_representatives_deleted": 0,
            "entities_deleted": 0,
            "users_deleted": 0,
            "findings_deleted": 0,
            "findings_assessments_deleted": 0,
            "scenarios_deleted": 0,
            "risk_assessments_deleted": 0,
            "task_templates_deleted": 0,
            "applied_controls_deleted": 0,
            "vulnerabilities_deleted": 0,
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
        rep_user_ids = []
        if entity_id:
            if hasattr(entity_rep_dict, "get_representatives_for_entity"):
                rep_objs = entity_rep_dict.get_representatives_for_entity(entity_id) or []
                rep_user_ids = [r.get_user_id() for r in rep_objs if hasattr(r, "get_user_id")]
            deleted["entity_representatives_deleted"] += entity_rep_dict.delete_representatives_for_entity(entity_id)
            if entity_dict.delete_entity(entity_id):
                deleted["entities_deleted"] += 1

        # 0c. Delete Associated Third-Party User
        user_email = app_spec.get("user", {}).get("email") if app_spec else None
        if user_dict:
            if user_email:
                u_id = user_dict.get_id_from_email(user_email)
                if u_id:
                    if not (hasattr(user_dict, "is_protected_user") and user_dict.is_protected_user(user_id=u_id) is True):
                        if user_dict.delete_user_by_id(u_id):
                            deleted["users_deleted"] += 1
            elif rep_user_ids:
                for r_uid in rep_user_ids:
                    if hasattr(user_dict, "is_protected_user") and user_dict.is_protected_user(user_id=r_uid) is True:
                        continue
                    if hasattr(entity_rep_dict, "get_entity_ids_for_user"):
                        other_entities = [eid for eid in entity_rep_dict.get_entity_ids_for_user(r_uid) if eid != entity_id]
                        if other_entities:
                            continue
                    if user_dict.delete_user_by_id(r_uid):
                        deleted["users_deleted"] += 1

        # 0d. Delete Findings and Findings Assessments
        if findings_fa_dict and finding_dict:
            for fa in list(findings_fa_dict.get_findings_assessments().values()):
                if (perimeter_id and fa.get_perimeter_id() == perimeter_id) or app_name in fa.get_name():
                    f_count = finding_dict.delete_findings_for_assessment(fa.get_id())
                    deleted["findings_deleted"] += f_count
                    if findings_fa_dict.delete_findings_assessment(fa.get_id()):
                        deleted["findings_assessments_deleted"] += 1

        # 1. Delete Risk Assessment and Risk Scenarios
        for ra in list(risk_dict.get_risk_assessments().values()):
            ra_perimeter = ra.json_object.get("perimeter")
            if (perimeter_id and ra_perimeter == perimeter_id) or app_name in ra.get_name():
                ra_id = ra.get_id()
                count = risk_scenario_dict.delete_scenarios_for_risk_assessment(ra_id)
                deleted["scenarios_deleted"] += count
                if risk_dict.delete_risk_assessment(ra_id):
                    deleted["risk_assessments_deleted"] += 1

        # 1c. Delete Task Templates linked to Applied Controls
        if task_template_dict and hasattr(task_template_dict, "delete_templates_for_applied_control"):
            for ctrl in list(applied_ctrl_dict.get_controls().values()):
                ctrl_name = ctrl.get_name()
                if f"on {app_name}" in ctrl_name:
                    count = task_template_dict.delete_templates_for_applied_control(ctrl.get_id())
                    deleted["task_templates_deleted"] += count

        # 2. Delete Applied Controls
        for ctrl in list(applied_ctrl_dict.get_controls().values()):
            ctrl_name = ctrl.get_name()
            if f"on {app_name}" in ctrl_name:
                if applied_ctrl_dict.delete_applied_control(ctrl.get_id()):
                    deleted["applied_controls_deleted"] += 1

        # 2b. Delete Asset-Scoped Vulnerabilities
        if vuln_dict:
            for v in list(vuln_dict.get_vulnerabilities().values()):
                v_name = v.get_name()
                v_assets = v.get_asset_ids() if hasattr(v, "get_asset_ids") else []
                if f"on {app_name}" in v_name or (asset_id and asset_id in v_assets):
                    if vuln_dict.delete_vulnerability(v.get_id()):
                        deleted["vulnerabilities_deleted"] += 1

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

    def create_all_examples(self, domain_name: str | None = None) -> list[dict[str, Any]]:
        """Create all example applications in CISO Assistant.

        Args:
            domain_name: Optional target domain/folder name or UUID (default: self.folder_name).
        """
        results = []
        for app in self.get_example_applications():
            res = self.create_example_application(app["id"], domain_name=domain_name)
            results.append(res)
        return results

    def remove_all_examples(self) -> list[dict[str, Any]]:
        """Remove all example applications that currently exist in CISO Assistant."""
        results = []
        status_list = self.get_status()
        existing_ids = {s["id"] for s in status_list if s.get("exists")}
        for app in self.get_example_applications():
            if app["id"] in existing_ids:
                res = self.remove_example_application(app["id"])
                results.append(res)
        return results

    def create_database_dump(
        self,
        output_dir: str | Path | None = None,
        filename: str | None = None,
    ) -> Path | None:
        """Create a full database dump via CISO Assistant Serdes API (/api/serdes/dump-db/).

        Args:
            output_dir: Target directory (default: 'backups').
            filename: Custom filename.

        Returns:
            Path to downloaded dump file, or None on failure.
        """
        return self.backup_manager.create_database_dump(output_dir=output_dir, filename=filename)

    def restore_database_dump(self, dump_path: str | Path) -> dict[str, Any] | bool | None:
        """Restore database from dump file via CISO Assistant Serdes API (/api/serdes/load-backup/).

        Args:
            dump_path: Path to database dump file on disk.

        Returns:
            API response or True on success, error dict or None on failure.
        """
        res = self.backup_manager.restore_database_dump(dump_path)
        self._init_data(force_reload=True)
        return res

    def create_workspace_snapshot(
        self,
        output_dir: str | Path | None = None,
        filename: str | None = None,
    ) -> Path:
        """Export current workspace resources to a structured JSON snapshot file.

        Args:
            output_dir: Target directory (default: 'backups').
            filename: Custom filename.

        Returns:
            Path to created snapshot file.
        """
        data = self._init_data()
        return self.backup_manager.create_workspace_snapshot(
            output_dir=output_dir,
            filename=filename,
            folder_name=self.folder_name,
            data=data,
        )

    def restore_workspace_snapshot(self, snapshot_path: str | Path) -> dict[str, Any]:
        """Restore workspace resources from a JSON snapshot file.

        Args:
            snapshot_path: Path to snapshot file.

        Returns:
            Dict summary of restored items.
        """
        return self.backup_manager.restore_workspace_snapshot(snapshot_path, manager=self)

    def list_backups(self, backup_dir: str | Path | None = None) -> list[dict[str, Any]]:
        """List all discovered backups and snapshots.

        Args:
            backup_dir: Directory to scan (default: 'backups').

        Returns:
            List of backup summary dictionaries sorted newest first.
        """
        return self.backup_manager.list_backups(backup_dir=backup_dir)

    def inspect_backup(self, backup_path: str | Path) -> dict[str, Any]:
        """Inspect metadata, checksum, and contents of a specific backup file.

        Args:
            backup_path: Path to backup file on disk.

        Returns:
            Inspection metadata dictionary.
        """
        return self.backup_manager.inspect_backup(backup_path)

