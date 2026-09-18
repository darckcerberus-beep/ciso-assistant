"""Risk assessment, scenario modeling, risk matrix, and vulnerability models.

This module provides the core data structures and API synchronization mechanisms for
CISO Assistant's risk engine:
1. RiskAssessment & RiskAssessmentDict: High-level risk containers associated with perimeters.
2. RiskScenario & RiskScenarioDict: Specific threat/vulnerability realizations with calculated
   likelihood, impact, and associated mitigating controls.
3. RiskMatrix & RiskMatrixDict: 4x4 or custom probability/impact matrix structures.
4. Vulnerability & VulnerabilityDict: Technical or organizational weaknesses linked to threats.
"""

import logging
import pprint
from typing import Any

from .. import utils


class RiskAssessment:
    """Represents a single risk assessment object."""

    def __init__(self, json_risk):
        """Initialize risk assessment from API payload or fetch if needed.

        Args:
            json_risk (dict or str): Dictionary payload containing risk assessment data or its UUID.
        """
        if isinstance(json_risk, dict) and "name" in json_risk:
            self.json_object = json_risk
        else:
            risk_id = json_risk.get('id', '') if isinstance(json_risk, dict) else str(json_risk)
            self.json_object = utils.get_return(f"/api/risk-assessments/{risk_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the risk assessment name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')

    def get_risk_id(self):
        """Return the associated risk identifier."""
        return self.json_object.get('risk', '')

    def get_status(self):
        """Return the assessment lifecycle status."""
        return self.json_object.get('status', '')

    def get_perimeter_id(self):
        """Return the perimeter UUID associated with this risk assessment."""
        p = self.json_object.get('perimeter')
        if isinstance(p, dict):
            return p.get('id', '')
        return p or ''

    def print_name(self):
        """Log the risk assessment name."""
        utils.log(f"Risk Assessment Name: {self.get_name()}")

    def print_id(self):
        """Log the risk assessment UUID."""
        utils.log(f"Risk Assessment ID: {self.get_id()}")


class RiskAssessmentDict:
    """Handles a collection of risk assessments loaded from the API."""

    def __init__(self):
        """Initialize and fetch all risk assessments from the API."""
        self.reload()

    def reload(self):
        """Reload the dictionary of risk assessments from the API."""
        self.risk_assessments = {}
        for ra in utils.get_all_results("/api/risk-assessments/", force_reload=True):
            self.risk_assessments[ra.get('id')] = RiskAssessment(ra)

    def get_risk_assessments(self):
        """Return dictionary of risk assessments keyed by UUID."""
        return self.risk_assessments

    def print_risk_assessments(self):
        """Print names and IDs for all risk assessments."""
        for ra in self.risk_assessments.values():
            ra.print_name()
            ra.print_id()

    def create_risk_assessments(self, name, domain, perimeter, risk_matrix):
        """Create a risk assessment if it does not already exist.

        Args:
            name (str): Unique name for the risk assessment.
            domain (str): Associated domain or framework identifier.
            perimeter (str): Organizational perimeter UUID.
            risk_matrix (str): Risk matrix UUID to bind for probability/impact scoring.

        Returns:
            dict: Raw API JSON dictionary of the existing or newly created risk assessment.
        """
        for ra in self.risk_assessments.values():
            if ra.get_name() == name:
                return ra.get_json()

        payload = {
            "name": name,
            "domain": domain,
            "perimeter": perimeter,
            "risk_matrix": risk_matrix,
        }
        created = utils.get_return("/api/risk-assessments/", method="POST", payload=payload)
        if isinstance(created, dict) and created.get("id"):
            self.risk_assessments[created.get("id")] = RiskAssessment(created)
        return created

    def delete_risk_assessment(self, risk_assessment_id):
        """Delete a risk assessment by UUID."""
        utils.log(f"Deleting risk assessment ID: {risk_assessment_id}", level=logging.INFO)
        response = utils.get_return(f"/api/risk-assessments/{risk_assessment_id}/", method="DELETE")
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.risk_assessments.pop(risk_assessment_id, None)
            utils.log(f"Successfully deleted risk assessment ID: {risk_assessment_id}", level=logging.INFO)
            return True
        utils.log(f"Failed to delete risk assessment ID {risk_assessment_id}: {response}", level=logging.ERROR)
        return False


class RiskScenario:
    """Represents a single risk scenario object."""

    def __init__(self, json_scenario):
        """Initialize risk scenario from API payload or fetch if needed.

        Args:
            json_scenario (dict or str): Dictionary payload or UUID of the scenario.
        """
        if isinstance(json_scenario, dict) and "name" in json_scenario:
            self.json_object = json_scenario
        else:
            scenario_id = json_scenario.get('id', '') if isinstance(json_scenario, dict) else str(json_scenario)
            self.json_object = utils.get_return(f"/api/risk-scenarios/{scenario_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the risk scenario name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')

    def get_related_ids(self, field_name):
        """Return IDs from a many-to-many scenario field.

        Args:
            field_name (str): Field name containing list of object dicts or IDs.

        Returns:
            list[str]: Clean list of string UUIDs.
        """
        related_objects = self.json_object.get(field_name, [])
        if not isinstance(related_objects, list):
            return []
        return [
            related_object.get('id', '') if isinstance(related_object, dict) else related_object
            for related_object in related_objects
        ]

    def get_vulnerability_ids(self) -> list[str]:
        """Return list of linked vulnerability UUIDs."""
        return self.get_related_ids("vulnerabilities")

    def get_threat_ids(self) -> list[str]:
        """Return list of linked threat UUIDs."""
        return self.get_related_ids("threats")

    def update_relationships(
        self,
        existing_control_ids,
        planned_control_ids,
        asset_ids,
        owner_ids,
        vulnerability_ids=None,
        threat_ids=None,
    ):
        """Add controls, assets, owners, vulnerabilities, and threats without removing existing links.

        Performs an idempotent PATCH only when relationships have changed.

        Args:
            existing_control_ids (list[str]): Implemented / active applied control UUIDs.
            planned_control_ids (list[str]): To-do / planned applied control UUIDs.
            asset_ids (list[str]): Linked perimeter asset UUIDs.
            owner_ids (list[str]): Asset owner user UUIDs.
            vulnerability_ids (list[str], optional): Linked vulnerability UUIDs.
            threat_ids (list[str], optional): Linked threat UUIDs.

        Returns:
            dict: API response payload.
        """
        relationship_updates = {
            "existing_applied_controls": existing_control_ids,
            "applied_controls": planned_control_ids,
            "assets": asset_ids,
            "owner": owner_ids,
        }
        if vulnerability_ids is not None:
            relationship_updates["vulnerabilities"] = vulnerability_ids
        if threat_ids is not None:
            relationship_updates["threats"] = threat_ids

        payload = {}
        for field_name, related_ids in relationship_updates.items():
            merged_ids = list(dict.fromkeys(self.get_related_ids(field_name) + related_ids))
            if merged_ids != self.get_related_ids(field_name):
                payload[field_name] = merged_ids

        if not payload:
            return self.json_object

        response = utils.get_return(
            f"/api/risk-scenarios/{self.get_id()}/",
            method="PATCH",
            payload=payload,
        )
        if isinstance(response, dict) and not response.get("error"):
            self.json_object = response
        return response


class RiskScenarioDict:
    """Handles a collection of risk scenarios and evaluation logic."""

    def __init__(self):
        """Initialize and fetch all risk scenarios from the API."""
        self.reload()

    def reload(self):
        """Reload all risk scenarios from the API."""
        self.risk_scenarios = {}
        for rs in utils.get_all_results("/api/risk-scenarios/", force_reload=True):
            self.risk_scenarios[rs.get('id')] = RiskScenario(rs)

    def get_risk_scenarios(self):
        """Return dictionary of risk scenarios keyed by UUID."""
        return self.risk_scenarios

    def print_risk_scenarios(self):
        """Log names and IDs of all scenarios."""
        for rs in self.risk_scenarios.values():
            utils.log(f"Scenario Name: {rs.get_name()}, ID: {rs.get_id()}")

    def print_risk_scenario_json(self):
        """Log raw JSON payload for all scenarios."""
        for rs in self.risk_scenarios.values():
            utils.log(f"Risk Scenario JSON:\n{pprint.pformat(rs.get_json())}")

    def delete_risk_scenario(self, name, risk_assessment_id):
        """Delete the matching scenario when its prerequisite is no longer applicable.

        Args:
            name (str): Scenario name.
            risk_assessment_id (str): Parent risk assessment UUID.

        Returns:
            bool or dict: API response result.
        """
        for scenario in list(self.risk_scenarios.values()):
            scenario_json = scenario.get_json()
            scenario_risk_assessment = scenario_json.get("risk_assessment")
            if isinstance(scenario_risk_assessment, dict):
                scenario_risk_assessment = scenario_risk_assessment.get("id")
            if scenario.get_name() != name or scenario_risk_assessment != risk_assessment_id:
                continue

            response = utils.get_return(
                f"/api/risk-scenarios/{scenario.get_id()}/",
                method="DELETE",
            )
            if response is True:
                self.risk_scenarios.pop(scenario.get_id(), None)
                utils.log(f"Deleted no-longer-applicable risk scenario: {name}")
            return response
        return True

    def delete_scenarios_for_risk_assessment(self, risk_assessment_id):
        """Delete all risk scenarios belonging to a specific risk assessment."""
        deleted_count = 0
        for scenario in list(self.risk_scenarios.values()):
            scenario_json = scenario.get_json()
            scenario_risk_assessment = scenario_json.get("risk_assessment")
            if isinstance(scenario_risk_assessment, dict):
                scenario_risk_assessment = scenario_risk_assessment.get("id")
            if scenario_risk_assessment == risk_assessment_id:
                response = utils.get_return(
                    f"/api/risk-scenarios/{scenario.get_id()}/",
                    method="DELETE",
                )
                if response is True or (isinstance(response, dict) and not response.get("error")):
                    self.risk_scenarios.pop(scenario.get_id(), None)
                    deleted_count += 1
        utils.log(f"Deleted {deleted_count} scenario(s) for risk assessment {risk_assessment_id}", level=logging.INFO)
        return deleted_count

    def create_risk_scenario(
        self,
        name,
        description,
        risk_assessment_id,
        current_proba,
        current_impact,
        residual_proba,
        residual_impact,
        existing_applied_controls=None,
        applied_controls=None,
        assets=None,
        owners=None,
        vulnerabilities=None,
        threats=None,
    ):
        """Create or update a risk scenario payload for the API.

        Note:
            The CISO Assistant API expects 0-based index values (0 to 3 for a 4x4 matrix),
            while callers pass 1-based domain scores (1 to 4). This method performs the
            `value - 1` conversion automatically.

        Args:
            name (str): Scenario title.
            description (str): Detailed scenario description.
            risk_assessment_id (str): Parent risk assessment UUID.
            current_proba (int): 1-based current probability level (1 to 4).
            current_impact (int): 1-based current impact level (1 to 4).
            residual_proba (int): 1-based residual probability level (1 to 4).
            residual_impact (int): 1-based residual impact level (1 to 4).
            existing_applied_controls (list[str], optional): UUIDs of implemented controls.
            applied_controls (list[str], optional): UUIDs of planned controls.
            assets (list[str], optional): UUIDs of linked perimeter assets.
            owners (list[str], optional): UUIDs of asset owners.
            vulnerabilities (list[str], optional): UUIDs of exploited vulnerabilities.
            threats (list[str], optional): UUIDs of relevant threats.

        Returns:
            dict: Created or updated API object.
        """
        if existing_applied_controls is None:
            existing_applied_controls = []
        if applied_controls is None:
            applied_controls = []
        if assets is None:
            assets = []
        if owners is None:
            owners = []
        if vulnerabilities is None:
            vulnerabilities = []
        if threats is None:
            threats = []

        payload = {
            "name": name,
            "description": description,
            "risk_assessment": risk_assessment_id,
            "current_proba": current_proba - 1,
            "current_impact": current_impact - 1,
            "residual_proba": residual_proba - 1,
            "residual_impact": residual_impact - 1,
            "existing_applied_controls": existing_applied_controls,
            "applied_controls": applied_controls,
            "assets": assets,
            "owner": owners,
            "vulnerabilities": vulnerabilities,
            "threats": threats,
        }

        # Check if an existing scenario with the same name exists under this risk assessment
        for scenario in self.risk_scenarios.values():
            scenario_json = scenario.get_json()
            risk_assessment = scenario_json.get("risk_assessment")
            if isinstance(risk_assessment, dict):
                risk_assessment = risk_assessment.get("id")
            if (
                scenario.get_name() == name
                and risk_assessment == risk_assessment_id
            ):
                update_payload = {
                    key: value for key, value in payload.items()
                    if value not in (None, [], {})
                }
                scenario_response = utils.get_return(
                    f"/api/risk-scenarios/{scenario.get_id()}/",
                    method="PATCH",
                    payload=update_payload,
                )
                if isinstance(scenario_response, dict) and not scenario_response.get("error"):
                    scenario.json_object = scenario_response
                    self.risk_scenarios[scenario.get_id()] = scenario
                return scenario_response

        utils.log(f"Creating risk scenario with payload: {payload}", level=logging.DEBUG)
        created = utils.get_return("/api/risk-scenarios/", method="POST", payload=payload)
        if isinstance(created, dict) and created.get("id"):
            self.risk_scenarios[created.get("id")] = RiskScenario(created)
        return created


class RiskMatrix:
    """Represents a single risk matrix object."""

    def __init__(self, json_matrix):
        """Initialize risk matrix from API payload or fetch if needed.

        Args:
            json_matrix (dict or str): Dictionary payload or UUID of the matrix.
        """
        if isinstance(json_matrix, dict) and "name" in json_matrix:
            self.json_object = json_matrix
        else:
            matrix_id = json_matrix.get('id', '') if isinstance(json_matrix, dict) else str(json_matrix)
            self.json_object = utils.get_return(f"/api/risk-matrices/{matrix_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object


class RiskMatrixDict:
    """Handles a collection of risk matrices loaded from the API."""

    def __init__(self):
        """Initialize and fetch all risk matrices from the API."""
        self.reload()

    def reload(self):
        """Reload all risk matrices from the API."""
        self.risk_matrices = {}
        for rm in utils.get_all_results("/api/risk-matrices/", force_reload=True):
            self.risk_matrices[rm.get('id')] = RiskMatrix(rm)

    def get_risk_matrices(self):
        """Return dictionary of risk matrices keyed by UUID."""
        return self.risk_matrices

    def print_risk_matrices(self):
        """Log raw JSON representation of each risk matrix."""
        for rm in self.risk_matrices.values():
            utils.log(pprint.pformat(rm.get_json()))

    def get_risk_matrix_id_by_library_id(self, library_id):
        """Return the matrix ID matching a given library ID.

        Args:
            library_id (str): Library UUID.

        Returns:
            str or None: Matrix UUID if found, None otherwise.
        """
        for rm in self.risk_matrices.values():
            library = rm.get_json().get('library') or {}
            if library.get('id') == library_id:
                return rm.get_json().get('id')
        return None


class Vulnerability:
    """Represents a single vulnerability object."""

    def __init__(self, json_vulnerability):
        """Initialize vulnerability from API payload or fetch if needed.

        Args:
            json_vulnerability (dict or str): Dictionary payload or UUID of the vulnerability.
        """
        if isinstance(json_vulnerability, dict) and "name" in json_vulnerability:
            self.json_object = json_vulnerability
        else:
            vuln_id = json_vulnerability.get('id', '') if isinstance(json_vulnerability, dict) else str(json_vulnerability)
            self.json_object = utils.get_return(f"/api/vulnerabilities/{vuln_id}/")

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the vulnerability name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')

    def get_urn(self):
        """Return the URN identifier if defined."""
        return self.json_object.get('urn', '')

    def get_ref_id(self):
        """Return the ref_id if defined."""
        return self.json_object.get('ref_id', '')

    def get_folder(self):
        """Return the folder UUID."""
        folder = self.json_object.get('folder', '')
        if isinstance(folder, dict):
            return folder.get('id', '')
        return str(folder) if folder else ''

    def get_asset_ids(self) -> list[str]:
        """Return list of linked asset UUIDs."""
        assets = self.json_object.get("assets", [])
        return [
            a.get("id", "") if isinstance(a, dict) else str(a)
            for a in assets
            if a
        ]

    def get_assets(self) -> list[Any]:
        """Return raw list of assets from JSON payload."""
        return self.json_object.get("assets", [])


class VulnerabilityDict:
    """Handles a collection of vulnerabilities."""

    def __init__(self):
        """Initialize and fetch all vulnerabilities from the API."""
        self.reload()

    def reload(self):
        """Reload all vulnerabilities from the API."""
        self.vulnerabilities = {}
        for v in utils.get_all_results("/api/vulnerabilities/", force_reload=True):
            if isinstance(v, dict) and v.get('id'):
                self.vulnerabilities[v['id']] = Vulnerability(v)

    def get_vulnerabilities(self):
        """Return dictionary of vulnerabilities keyed by UUID."""
        return self.vulnerabilities

    def get_id_by_name(self, name: str) -> str | None:
        """Find vulnerability UUID by name."""
        if not name:
            return None
        norm = name.strip().lower()
        for v in self.vulnerabilities.values():
            if v.get_name().strip().lower() == norm:
                return v.get_id()
        return None

    def get_id_by_urn(self, urn: str) -> str | None:
        """Find vulnerability UUID by URN or fallback to terminal ref_id."""
        if not urn:
            return None
        for v in self.vulnerabilities.values():
            if v.get_urn() == urn:
                return v.get_id()
        # In CISO Assistant API, vulnerabilities do not persist a URN field.
        # Fall back to ref_id matching the terminal token of the URN.
        ref_id = urn.rsplit(":", 1)[-1]
        return self.get_id_by_ref_id(ref_id)

    def get_id_by_ref_id(self, ref_id: str) -> str | None:
        """Find vulnerability UUID by ref_id."""
        if not ref_id:
            return None
        for v in self.vulnerabilities.values():
            if v.get_ref_id() == ref_id:
                return v.get_id()
        return None

    def resolve_vulnerability_id(self, identifier: str) -> str | None:
        """Find vulnerability UUID by direct UUID, URN, ref_id, or name."""
        if not identifier:
            return None
        if identifier in self.vulnerabilities:
            return identifier
        return (
            self.get_id_by_urn(identifier)
            or self.get_id_by_ref_id(identifier)
            or self.get_id_by_name(identifier)
        )

    def create_vulnerability(
        self,
        name: str,
        folder_id: str,
        description: str = "",
        ref_id: str = "",
        severity: int = 2,
        status: str = "potential",
        applied_controls: list[str] | None = None,
        assets: list[str] | None = None,
        findings: list[str] | None = None,
    ) -> dict:
        """Create a vulnerability in the API and register in cache.

        Args:
            name: Vulnerability name/title.
            folder_id: Folder UUID where the vulnerability belongs.
            description: Detailed vulnerability explanation.
            ref_id: Short reference identifier.
            severity: Severity integer (-1=undef, 0=info, 1=low, 2=medium, 3=high, 4=critical).
            status: Status string ('potential', 'exploitable', 'mitigated', etc.).
            applied_controls: Optional list of applied control UUIDs.
            assets: Optional list of asset UUIDs.
            findings: Optional list of finding UUIDs.

        Returns:
            dict: API response payload.
        """
        payload = {
            "name": name,
            "folder": folder_id,
            "status": status,
            "severity": severity,
        }
        if description:
            payload["description"] = description
        if ref_id:
            payload["ref_id"] = ref_id
        if applied_controls:
            payload["applied_controls"] = applied_controls
        if assets:
            payload["assets"] = assets
        if findings:
            payload["findings"] = findings

        utils.log(f"Creating vulnerability '{name}' (ref_id={ref_id}) in folder {folder_id}...", level=logging.INFO)
        result = utils.get_return("/api/vulnerabilities/", method="POST", payload=payload)
        if isinstance(result, dict) and result.get("id"):
            self.vulnerabilities[result["id"]] = Vulnerability(result)
            utils.log(f"Vulnerability '{name}' created with ID: {result['id']}", level=logging.INFO)
            return result
        utils.log(f"Failed to create vulnerability '{name}': {result}", level=logging.WARNING)
        return result or {}

    def ensure_assets_for_vulnerability(self, vulnerability_id_or_name: str, asset_ids: list[str]) -> dict | None:
        """Ensure a vulnerability has its asset(s) linked via PATCH if missing."""
        if not asset_ids:
            return None
        vuln = None
        if vulnerability_id_or_name in self.vulnerabilities:
            vuln = self.vulnerabilities[vulnerability_id_or_name]
        else:
            for v in self.vulnerabilities.values():
                if v.get_name() == vulnerability_id_or_name:
                    vuln = v
                    break
        if not vuln:
            return None
        current_assets = vuln.get_asset_ids()
        merged_assets = list(dict.fromkeys(current_assets + [a for a in asset_ids if a]))
        if merged_assets != current_assets:
            response = utils.get_return(
                f"/api/vulnerabilities/{vuln.get_id()}/",
                method="PATCH",
                payload={"assets": merged_assets},
            )
            if isinstance(response, dict) and not response.get("error"):
                vuln.json_object = response
            return response
        return vuln.get_json()

    def get_vulnerability_id_for_asset(
        self,
        identifier: str,
        asset_id: str | None = None,
        asset_name: str | None = None,
    ) -> str | None:
        """Find vulnerability UUID scoped to a specific asset or perimeter.

        Matches by exact scoped name ("<Base Name> on <Asset Name>"), by asset ID containment,
        or falls back to URN, ref_id, and name resolution.
        """
        if not identifier:
            return None

        # 1. Direct UUID match
        if identifier in self.vulnerabilities:
            return identifier

        # 2. Match by scoped name if asset_name provided
        if asset_name:
            target_name = f"{identifier} on {asset_name}".lower()
            for v in self.vulnerabilities.values():
                if v.get_name().strip().lower() == target_name:
                    return v.get_id()

        # 3. Match within vulnerabilities linked to this asset_id
        if asset_id:
            for v in self.vulnerabilities.values():
                if asset_id not in v.get_asset_ids():
                    continue
                if v.get_urn() == identifier:
                    return v.get_id()
                if v.get_ref_id() == identifier:
                    return v.get_id()
                # Scoped ref_id check, e.g. lack_of_encryption_app_secure_core
                if v.get_ref_id().startswith(f"{identifier}_"):
                    return v.get_id()
                # Check base name prefix
                v_name_lower = v.get_name().lower()
                id_lower = identifier.lower()
                if v_name_lower == id_lower or v_name_lower.startswith(f"{id_lower} on "):
                    return v.get_id()
                # Terminal ref_id from URN
                if ":" in identifier:
                    base_ref = identifier.rsplit(":", 1)[-1]
                    if v.get_ref_id() == base_ref or v.get_ref_id().startswith(f"{base_ref}_"):
                        return v.get_id()

        # 4. If asset_name provided, match any vulnerability whose name matches base token and ends with on {asset_name}
        if asset_name:
            suffix = f"on {asset_name}".lower()
            for v in self.vulnerabilities.values():
                v_name = v.get_name().lower()
                if v_name.endswith(suffix):
                    if ":" in identifier:
                        base_ref = identifier.rsplit(":", 1)[-1].replace("_", " ").lower()
                        if base_ref in v_name:
                            return v.get_id()
                    elif identifier.lower() in v_name:
                        return v.get_id()

        # 5. Fallback to general resolution
        return self.resolve_vulnerability_id(identifier)

    def create_vulnerability_if_missing(
        self,
        name: str,
        folder_id: str,
        description: str = "",
        ref_id: str = "",
        severity: int = 2,
        status: str = "potential",
        assets: list[str] | None = None,
    ) -> dict:
        """Return existing vulnerability or create one if not found by ref_id or name."""
        existing_id = None
        if ref_id:
            existing_id = self.get_id_by_ref_id(ref_id)
            if existing_id:
                return self.vulnerabilities[existing_id].get_json()
        if not existing_id:
            existing_id = self.get_id_by_name(name)

        existing_id = self.get_id_by_name(name)
        if existing_id:
            if assets:
                self.ensure_assets_for_vulnerability(existing_id, assets)
            return self.vulnerabilities[existing_id].get_json()

        return self.create_vulnerability(
            name=name,
            folder_id=folder_id,
            description=description,
            ref_id=ref_id,
            severity=severity,
            status=status,
            assets=assets,
        )

    def provision_vulnerabilities_from_framework(
        self,
        framework_file,
        folder_id: str,
        asset_id: str | None = None,
        asset_name: str | None = None,
    ) -> dict[str, str]:
        """Provision all vulnerabilities declared in the framework file into CISO Assistant.

        Vulnerabilities are linked to the given asset_id and named according to the asset_name
        ('<Vulnerability Name> on <Asset Name>').

        Args:
            framework_file: FrameworkFile or LibraryFile instance.
            folder_id: Folder UUID where vulnerabilities should be anchored.
            asset_id: Optional Asset UUID to link the vulnerabilities to.
            asset_name: Optional Asset/Application Name to suffix to vulnerability names.

        Returns:
            dict mapping ref_id / URN -> vulnerability UUID.
        """
        if not folder_id:
            utils.log("Cannot provision vulnerabilities: folder_id is missing.", level=logging.WARNING)
            return {}

        vuln_defs = []
        if hasattr(framework_file, "get_vulnerabilities"):
            vuln_defs = framework_file.get_vulnerabilities()
        elif hasattr(framework_file, "json_object"):
            vuln_defs = framework_file.json_object.get("objects", {}).get("vulnerabilities", [])

        if not vuln_defs:
            utils.log("No vulnerabilities found in framework definition.", level=logging.DEBUG)
            return {}

        resolved = {}
        assets_list = [asset_id] if asset_id else None

        for v in vuln_defs:
            name = v.get("name", "")
            ref_id = v.get("ref_id") or v.get("urn", "").rsplit(":", 1)[-1]
            base_name = v.get("name", "")
            base_ref_id = v.get("ref_id") or v.get("urn", "").rsplit(":", 1)[-1]
            desc = v.get("description", "")
            if not name:
            if not base_name:
                continue

            if asset_name and not base_name.endswith(f" on {asset_name}"):
                vuln_name = f"{base_name} on {asset_name}"
                asset_slug = asset_name.lower().replace("-", "_").replace(" ", "_")
                ref_id = f"{base_ref_id}_{asset_slug}"[:100]
            else:
                vuln_name = base_name
                ref_id = base_ref_id

            created_or_found = self.create_vulnerability_if_missing(
                name=name,
                name=vuln_name,
                folder_id=folder_id,
                description=desc,
                ref_id=ref_id,
                severity=2,
                status="potential",
                assets=assets_list,
            )
            vid = created_or_found.get("id") if isinstance(created_or_found, dict) else None
            if vid:
                resolved[ref_id] = vid
                resolved[base_ref_id] = vid
                if ref_id != base_ref_id:
                    resolved[ref_id] = vid
                if v.get("urn"):
                    resolved[v["urn"]] = vid

        return resolved

    def delete_vulnerability(self, vulnerability_id: str) -> bool:
        """Delete a vulnerability by UUID."""
        utils.log(f"Deleting vulnerability ID: {vulnerability_id}", level=logging.INFO)
        response = utils.get_return(f"/api/vulnerabilities/{vulnerability_id}/", method="DELETE")
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.vulnerabilities.pop(vulnerability_id, None)
            return True
        return False

    def print_vulnerabilities(self):
        """Log names and IDs of all vulnerabilities."""
        for v in self.vulnerabilities.values():
            utils.log(f"Vulnerability: {v.get_name()}, ID: {v.get_id()}")

    def print_vulnerability_json(self):
        """Log raw JSON payload for all vulnerabilities."""
        for v in self.vulnerabilities.values():
            utils.log(f"Vulnerability JSON:\n{pprint.pformat(v.get_json())}")


class Threat:
    """Represents a single threat object."""

    def __init__(self, json_threat):
        """Initialize threat from API payload or fetch if needed.

        Args:
            json_threat (dict or str): Dictionary payload or UUID of the threat.
        """
        if isinstance(json_threat, dict) and "name" in json_threat:
            self.json_object = json_threat
        else:
            t_id = json_threat.get('id', '') if isinstance(json_threat, dict) else str(json_threat)
            self.json_object = utils.get_return(f"/api/threats/{t_id}/") or {}

    def get_json(self):
        """Return the raw JSON dictionary payload."""
        return self.json_object

    def get_name(self):
        """Return the threat name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the unique UUID identifier."""
        return self.json_object.get('id', '')

    def get_urn(self):
        """Return the URN identifier if defined."""
        return self.json_object.get('urn', '')

    def get_ref_id(self):
        """Return the ref_id if defined."""
        return self.json_object.get('ref_id', '')


class ThreatDict:
    """Handles a collection of threats loaded from the API."""

    def __init__(self):
        """Initialize and fetch all threats from the API."""
        self.reload()

    def reload(self):
        """Reload all threats from the API."""
        self.threats = {}
        for t in utils.get_all_results("/api/threats/", force_reload=True):
            if isinstance(t, dict) and t.get('id'):
                self.threats[t['id']] = Threat(t)

    def get_threats(self):
        """Return dictionary of threats keyed by UUID."""
        return self.threats

    def get_id_by_name(self, name: str) -> str | None:
        """Find threat UUID by name."""
        if not name:
            return None
        norm = name.strip().lower()
        for t in self.threats.values():
            if t.get_name().strip().lower() == norm:
                return t.get_id()
        return None

    def get_id_by_urn(self, urn: str) -> str | None:
        """Find threat UUID by URN or fallback to terminal ref_id."""
        if not urn:
            return None
        for t in self.threats.values():
            if t.get_urn() == urn:
                return t.get_id()
        ref_id = urn.rsplit(":", 1)[-1]
        return self.get_id_by_ref_id(ref_id)

    def get_id_by_ref_id(self, ref_id: str) -> str | None:
        """Find threat UUID by ref_id."""
        if not ref_id:
            return None
        for t in self.threats.values():
            if t.get_ref_id() == ref_id:
                return t.get_id()
        return None

    def resolve_threat_id(self, identifier: str) -> str | None:
        """Find threat UUID by direct UUID, URN, ref_id, or name."""
        if not identifier:
            return None
        if identifier in self.threats:
            return identifier
        return (
            self.get_id_by_urn(identifier)
            or self.get_id_by_ref_id(identifier)
            or self.get_id_by_name(identifier)
        )

    def create_threat(
        self,
        name: str,
        description: str = "",
        ref_id: str = "",
        urn: str = "",
        provider: str = "custom",
    ) -> dict:
        """Create a threat in the API and register in cache."""
        payload = {
            "name": name,
            "provider": provider,
        }
        if description:
            payload["description"] = description
        if ref_id:
            payload["ref_id"] = ref_id
        if urn:
            payload["urn"] = urn

        utils.log(f"Creating threat '{name}' (ref_id={ref_id})...", level=logging.INFO)
        result = utils.get_return("/api/threats/", method="POST", payload=payload)
        if isinstance(result, dict) and result.get("id"):
            self.threats[result["id"]] = Threat(result)
            return result
        return result or {}

    def create_threat_if_missing(
        self,
        name: str,
        description: str = "",
        ref_id: str = "",
        urn: str = "",
        provider: str = "custom",
    ) -> dict:
        """Return existing threat or create one if not found."""
        if urn:
            existing_id = self.get_id_by_urn(urn)
            if existing_id:
                return self.threats[existing_id].get_json()
        if ref_id:
            existing_id = self.get_id_by_ref_id(ref_id)
            if existing_id:
                return self.threats[existing_id].get_json()
        existing_id = self.get_id_by_name(name)
        if existing_id:
            return self.threats[existing_id].get_json()

        return self.create_threat(
            name=name,
            description=description,
            ref_id=ref_id,
            urn=urn,
            provider=provider,
        )

    def provision_threats_from_framework(self, framework_file) -> dict[str, str]:
        """Provision all threats declared in the framework file into CISO Assistant."""
        threat_defs = []
        if hasattr(framework_file, "get_threats"):
            threat_defs = framework_file.get_threats()
        elif hasattr(framework_file, "json_object"):
            threat_defs = framework_file.json_object.get("objects", {}).get("threats", [])

        if not threat_defs:
            return {}

        resolved = {}
        for t in threat_defs:
            name = t.get("name", "")
            ref_id = t.get("ref_id") or t.get("urn", "").rsplit(":", 1)[-1]
            desc = t.get("description", "")
            urn = t.get("urn", "")
            provider = t.get("provider", "custom")
            if not name:
                continue

            created_or_found = self.create_threat_if_missing(
                name=name,
                description=desc,
                ref_id=ref_id,
                urn=urn,
                provider=provider,
            )
            tid = created_or_found.get("id") if isinstance(created_or_found, dict) else None
            if tid:
                resolved[ref_id] = tid
                if urn:
                    resolved[urn] = tid

        return resolved

    def print_threats(self):
        """Log names and IDs of all threats."""
        for t in self.threats.values():
            utils.log(f"Threat: {t.get_name()}, ID: {t.get_id()}")

