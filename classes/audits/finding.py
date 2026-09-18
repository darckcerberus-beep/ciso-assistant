"""Finding and findings assessment models and collection helpers."""

import logging
import pprint
from typing import Any

from .. import utils

LOGGER = logging.getLogger(__name__)


class FindingsAssessment:
    """Represents a single findings assessment container."""

    def __init__(self, json_findings_assessment: dict[str, Any] | str):
        """Initialize from API JSON dict or fetch via UUID string."""
        if isinstance(json_findings_assessment, dict) and "name" in json_findings_assessment:
            self.json_object = json_findings_assessment
        else:
            fa_id = (
                json_findings_assessment.get("id", "")
                if isinstance(json_findings_assessment, dict)
                else str(json_findings_assessment)
            )
            self.json_object = utils.get_return(f"/api/findings-assessments/{fa_id}/") or {}

    def get_json(self) -> dict[str, Any]:
        """Return the raw JSON payload."""
        return self.json_object

    def get_id(self) -> str:
        """Return unique UUID of the findings assessment."""
        return self.json_object.get("id", "")

    def get_name(self) -> str:
        """Return the findings assessment name."""
        return self.json_object.get("name", "")

    def get_folder_id(self) -> str:
        """Return the folder UUID."""
        folder = self.json_object.get("folder")
        if isinstance(folder, dict):
            return folder.get("id", "")
        return str(folder) if folder else ""

    def get_perimeter_id(self) -> str:
        """Return the perimeter UUID if configured."""
        perimeter = self.json_object.get("perimeter")
        if isinstance(perimeter, dict):
            return perimeter.get("id", "")
        return str(perimeter) if perimeter else ""

    def get_category(self) -> str:
        """Return the category (e.g. 'audit')."""
        return self.json_object.get("category", "")

    def get_status(self) -> str:
        """Return the current assessment status."""
        return self.json_object.get("status", "")

    def get_findings_count(self) -> int:
        """Return the count of findings under this assessment."""
        return self.json_object.get("findings_count", 0)


class FindingsAssessmentDict:
    """Manages collection of findings assessments loaded from the API."""

    def __init__(self):
        self.findings_assessments: dict[str, FindingsAssessment] = {}
        self.reload()

    def reload(self):
        """Reload all findings assessments from the API."""
        self.findings_assessments = {}
        for fa in utils.get_all_results("/api/findings-assessments/", force_reload=True):
            if isinstance(fa, dict) and fa.get("id"):
                self.findings_assessments[fa["id"]] = FindingsAssessment(fa)

    def get_findings_assessments(self) -> dict[str, FindingsAssessment]:
        """Return all findings assessments keyed by ID."""
        return self.findings_assessments

    def get_id_from_name(self, name: str) -> str | None:
        """Find findings assessment ID by name."""
        for fa in self.findings_assessments.values():
            if fa.get_name() == name:
                return fa.get_id()
        return None

    def create_findings_assessment(
        self,
        name: str,
        folder_id: str,
        perimeter_id: str | None = None,
        category: str = "audit",
        status: str = "in_progress",
        description: str | None = None,
        authors: list[str] | None = None,
        reviewers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Idempotently create or update a findings assessment container.

        Args:
            name: Assessment name.
            folder_id: Folder/domain UUID.
            perimeter_id: Optional perimeter UUID.
            category: Category string ('audit', 'pentest', etc.).
            status: Status ('planned', 'in_progress', 'done').
            description: Optional summary text.
            authors: Optional list of author user/actor UUIDs.
            reviewers: Optional list of reviewer UUIDs.

        Returns:
            API dictionary of created or existing record.
        """
        payload: dict[str, Any] = {
            "name": name,
            "category": category,
            "status": status,
        }
        if folder_id:
            payload["folder"] = folder_id
        if perimeter_id:
            payload["perimeter"] = perimeter_id
        if description:
            payload["description"] = description
        if authors:
            payload["authors"] = authors
        if reviewers:
            payload["reviewers"] = reviewers

        # Check existing by name and perimeter/folder
        for fa in self.findings_assessments.values():
            if fa.get_name() == name:
                fa_id = fa.get_id()
                update_payload = {
                    k: v for k, v in payload.items() if v not in (None, [], {})
                }
                res = utils.get_return(
                    f"/api/findings-assessments/{fa_id}/",
                    method="PATCH",
                    payload=update_payload,
                    log_errors=False,
                )
                if isinstance(res, dict) and not res.get("error"):
                    fa.json_object = res
                    self.findings_assessments[fa_id] = fa
                    return res
                return fa.get_json()

        utils.log(f"Creating findings assessment '{name}'...", level=logging.INFO)
        created = utils.get_return("/api/findings-assessments/", method="POST", payload=payload)
        if isinstance(created, dict) and created.get("id"):
            self.findings_assessments[created["id"]] = FindingsAssessment(created)
        return created or {}

    def delete_findings_assessment(self, findings_assessment_id: str) -> bool:
        """Delete a findings assessment by UUID."""
        utils.log(f"Deleting findings assessment ID: {findings_assessment_id}", level=logging.INFO)
        response = utils.get_return(f"/api/findings-assessments/{findings_assessment_id}/", method="DELETE")
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.findings_assessments.pop(findings_assessment_id, None)
            return True
        utils.log(f"Failed to delete findings assessment ID {findings_assessment_id}: {response}", level=logging.ERROR)
        return False


class Finding:
    """Represents a single finding record."""

    def __init__(self, json_finding: dict[str, Any] | str):
        """Initialize from API JSON dict or fetch via UUID string."""
        if isinstance(json_finding, dict) and "name" in json_finding:
            self.json_object = json_finding
        else:
            f_id = json_finding.get("id", "") if isinstance(json_finding, dict) else str(json_finding)
            self.json_object = utils.get_return(f"/api/findings/{f_id}/") or {}

    def get_json(self) -> dict[str, Any]:
        """Return the raw JSON payload."""
        return self.json_object

    def get_id(self) -> str:
        """Return unique UUID."""
        return self.json_object.get("id", "")

    def get_name(self) -> str:
        """Return finding name."""
        return self.json_object.get("name", "")

    def get_findings_assessment_id(self) -> str:
        """Return parent findings assessment UUID."""
        fa = self.json_object.get("findings_assessment")
        if isinstance(fa, dict):
            return fa.get("id", "")
        return str(fa) if fa else ""

    def get_severity(self) -> int:
        """Return severity integer (0-4)."""
        return self.json_object.get("severity", -1)

    def get_priority(self) -> int | None:
        """Return priority integer (1-4) or None."""
        return self.json_object.get("priority")

    def get_status(self) -> str:
        """Return status string."""
        return self.json_object.get("status", "")

    def get_requirement_node_id(self) -> str | None:
        """Return linked requirement node UUID."""
        rn = self.json_object.get("requirement_node")
        if isinstance(rn, dict):
            return rn.get("id")
        return str(rn) if rn else None

    def get_asset_id(self) -> str | None:
        """Return linked asset UUID."""
        asset = self.json_object.get("asset")
        if isinstance(asset, dict):
            return asset.get("id")
        return str(asset) if asset else None


class FindingDict:
    """Manages collection of findings loaded from the API."""

    def __init__(self):
        self.findings: dict[str, Finding] = {}
        self.reload()

    def reload(self):
        """Reload all findings from the API."""
        self.findings = {}
        for f in utils.get_all_results("/api/findings/", force_reload=True):
            if isinstance(f, dict) and f.get("id"):
                self.findings[f["id"]] = Finding(f)

    def get_findings(self) -> dict[str, Finding]:
        """Return all findings keyed by UUID."""
        return self.findings

    def get_findings_for_assessment(self, findings_assessment_id: str) -> list[Finding]:
        """Return list of findings belonging to a specific findings assessment."""
        return [
            f for f in self.findings.values()
            if f.get_findings_assessment_id() == findings_assessment_id
        ]

    def create_finding(
        self,
        findings_assessment_id: str,
        name: str,
        description: str | None = None,
        observation: str | None = None,
        severity: int = 2,
        priority: int = 3,
        status: str = "identified",
        requirement_node: str | None = None,
        asset: str | None = None,
        threats: list[str] | None = None,
        vulnerabilities: list[str] | None = None,
        reference_controls: list[str] | None = None,
        applied_controls: list[str] | None = None,
        owner: list[str] | None = None,
        ref_id: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a finding idempotently.

        Args:
            findings_assessment_id: Parent findings assessment UUID.
            name: Finding title.
            description: Detailed description of the gap.
            observation: Auditor/respondent observation text.
            severity: Severity (0=info, 1=low, 2=medium, 3=high, 4=critical).
            priority: Priority (1=P1, 2=P2, 3=P3, 4=P4).
            status: Status string ('identified', 'confirmed', 'in_progress', etc.).
            requirement_node: Optional requirement node UUID.
            asset: Optional asset UUID.
            threats: Optional list of threat UUIDs.
            vulnerabilities: Optional list of vulnerability UUIDs.
            reference_controls: Optional list of reference control UUIDs.
            applied_controls: Optional list of applied control UUIDs.
            owner: Optional list of owner UUIDs.
            ref_id: Optional reference identifier.

        Returns:
            API dictionary of created or updated finding.
        """
        payload: dict[str, Any] = {
            "findings_assessment": findings_assessment_id,
            "name": name,
            "severity": severity,
            "priority": priority,
            "status": status,
            "threats": threats or [],
            "vulnerabilities": vulnerabilities or [],
            "reference_controls": reference_controls or [],
            "applied_controls": applied_controls or [],
            "owner": owner or [],
        }
        if description:
            payload["description"] = description
        if observation:
            payload["observation"] = observation
        if requirement_node:
            payload["requirement_node"] = requirement_node
        if asset:
            payload["asset"] = asset
        if ref_id:
            payload["ref_id"] = ref_id

        # Check existing finding with same name in same findings assessment
        for f in self.findings.values():
            if (
                f.get_name() == name
                and f.get_findings_assessment_id() == findings_assessment_id
            ):
                f_id = f.get_id()
                update_payload = {
                    k: v for k, v in payload.items() if v not in (None, [], {})
                }
                res = utils.get_return(
                    f"/api/findings/{f_id}/",
                    method="PATCH",
                    payload=update_payload,
                    log_errors=False,
                )
                if isinstance(res, dict) and not res.get("error"):
                    f.json_object = res
                    self.findings[f_id] = f
                    return res
                return f.get_json()

        utils.log(f"Creating finding '{name}' under assessment {findings_assessment_id}...", level=logging.DEBUG)
        created = utils.get_return("/api/findings/", method="POST", payload=payload)
        if isinstance(created, dict) and created.get("id"):
            self.findings[created["id"]] = Finding(created)
        return created or {}

    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding by UUID."""
        utils.log(f"Deleting finding ID: {finding_id}", level=logging.DEBUG)
        response = utils.get_return(f"/api/findings/{finding_id}/", method="DELETE")
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.findings.pop(finding_id, None)
            return True
        return False

    def delete_findings_for_assessment(self, findings_assessment_id: str) -> int:
        """Delete all findings under a given findings assessment UUID.

        Returns:
            Count of findings successfully deleted.
        """
        deleted_count = 0
        matching = [
            f.get_id() for f in self.findings.values()
            if f.get_findings_assessment_id() == findings_assessment_id
        ]
        for f_id in matching:
            if self.delete_finding(f_id):
                deleted_count += 1
        return deleted_count

