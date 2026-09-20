"""Security Exception models and collection helpers.

A Security Exception in CISO Assistant represents an authorized or pending deviation
from standard security policies, baseline controls, or compliance requirements.
"""

import logging
from typing import Any

from .. import utils

LOGGER = logging.getLogger(__name__)

SEVERITY_MAPPING = {
    -1: "undefined",
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

STATUS_CHOICES = {
    "draft",
    "in_review",
    "approved",
    "rejected",
    "resolved",
    "expired",
    "deprecated",
}


class SecurityException:
    """Represents a single Security Exception in CISO Assistant."""

    def __init__(self, json_exception: dict[str, Any] | str):
        """Initialize from API JSON dict or fetch via UUID string."""
        if isinstance(json_exception, dict) and "name" in json_exception:
            self.json_object = json_exception
        else:
            e_id = (
                json_exception.get("id", "")
                if isinstance(json_exception, dict)
                else str(json_exception)
            )
            self.json_object = utils.get_return(f"/api/security-exceptions/{e_id}/") or {}

    def get_json(self) -> dict[str, Any]:
        """Return the raw JSON payload."""
        return self.json_object

    def get_id(self) -> str:
        """Return unique UUID."""
        return self.json_object.get("id", "")

    def get_name(self) -> str:
        """Return security exception name."""
        return self.json_object.get("name", "")

    def get_ref_id(self) -> str | None:
        """Return reference identifier (e.g. 'EXC-2026-001')."""
        return self.json_object.get("ref_id")

    def get_description(self) -> str | None:
        """Return detailed description of the exception."""
        return self.json_object.get("description")

    def get_severity(self) -> int:
        """Return severity level (-1: undefined, 0: info, 1: low, 2: medium, 3: high, 4: critical)."""
        return self.json_object.get("severity", -1)

    def get_severity_label(self) -> str:
        """Return human-readable severity label."""
        return SEVERITY_MAPPING.get(self.get_severity(), "undefined")

    def get_status(self) -> str:
        """Return current lifecycle status ('draft', 'in_review', 'approved', 'rejected', etc.)."""
        return self.json_object.get("status", "draft")

    def get_expiration_date(self) -> str | None:
        """Return expiration date string (YYYY-MM-DD) or None."""
        return self.json_object.get("expiration_date")

    def is_published(self) -> bool:
        """Return whether the security exception is published."""
        return bool(self.json_object.get("is_published", False))

    def get_observation(self) -> str | None:
        """Return observation notes or compensating controls."""
        return self.json_object.get("observation")

    def get_link(self) -> str | None:
        """Return external tracking URI link if set."""
        return self.json_object.get("link")

    def get_folder_id(self) -> str:
        """Return folder UUID."""
        folder = self.json_object.get("folder")
        if isinstance(folder, dict):
            return folder.get("id", "")
        return str(folder) if folder else ""

    def get_asset_ids(self) -> list[str]:
        """Return list of associated asset UUIDs."""
        raw = self.json_object.get("assets", [])
        if not isinstance(raw, list):
            return []
        return [a.get("id", "") if isinstance(a, dict) else str(a) for a in raw]

    def get_applied_control_ids(self) -> list[str]:
        """Return list of associated applied control UUIDs."""
        raw = self.json_object.get("applied_controls", [])
        if not isinstance(raw, list):
            return []
        return [c.get("id", "") if isinstance(c, dict) else str(c) for c in raw]

    def get_requirement_assessment_ids(self) -> list[str]:
        """Return list of associated requirement assessment UUIDs."""
        raw = self.json_object.get("requirement_assessments", [])
        if not isinstance(raw, list):
            return []
        return [r.get("id", "") if isinstance(r, dict) else str(r) for r in raw]

    def get_owners(self) -> list[str]:
        """Return list of owner user UUIDs."""
        raw = self.json_object.get("owners", [])
        if not isinstance(raw, list):
            return []
        return [o.get("id", "") if isinstance(o, dict) else str(o) for o in raw]


class SecurityExceptionDict:
    """Manages collection of Security Exceptions loaded from the API."""

    def __init__(self):
        self.security_exceptions: dict[str, SecurityException] = {}
        self.reload()

    def reload(self):
        """Reload all security exceptions from the API."""
        self.security_exceptions = {}
        for item in utils.get_all_results("/api/security-exceptions/", force_reload=True):
            if isinstance(item, dict) and item.get("id"):
                self.security_exceptions[item["id"]] = SecurityException(item)

    def get_security_exceptions(self) -> dict[str, SecurityException]:
        """Return all security exceptions keyed by UUID."""
        return self.security_exceptions

    def get_exception_by_id(self, exception_id: str) -> SecurityException | None:
        """Find a security exception by UUID."""
        return self.security_exceptions.get(exception_id)

    def get_id_from_name(self, name: str) -> str | None:
        """Find a security exception UUID by exact name."""
        for exc in self.security_exceptions.values():
            if exc.get_name() == name:
                return exc.get_id()
        return None

    def get_exceptions_for_asset(self, asset_id: str) -> list[SecurityException]:
        """Return all security exceptions linked to a specific asset UUID."""
        return [
            exc for exc in self.security_exceptions.values()
            if asset_id in exc.get_asset_ids()
        ]

    def get_exceptions_for_applied_control(self, control_id: str) -> list[SecurityException]:
        """Return all security exceptions linked to a specific applied control UUID."""
        return [
            exc for exc in self.security_exceptions.values()
            if control_id in exc.get_applied_control_ids()
        ]

    def create_security_exception(
        self,
        name: str,
        folder_id: str,
        description: str | None = None,
        ref_id: str | None = None,
        severity: int = 2,
        status: str = "approved",
        expiration_date: str | None = None,
        is_published: bool = True,
        observation: str | None = None,
        link: str | None = None,
        assets: list[str] | None = None,
        applied_controls: list[str] | None = None,
        requirement_assessments: list[str] | None = None,
        owners: list[str] | None = None,
        evidences: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create or update a security exception idempotently.

        Args:
            name: Title of the exception.
            folder_id: Folder/domain UUID.
            description: Detailed business and technical rationale.
            ref_id: Optional reference identifier (e.g. 'EXC-2026-001').
            severity: Severity integer (0=info, 1=low, 2=medium, 3=high, 4=critical).
            status: Lifecycle status ('draft', 'in_review', 'approved', 'rejected', etc.).
            expiration_date: Expiration date string ('YYYY-MM-DD').
            is_published: Whether the exception is published.
            observation: Auditor/risk observation notes and compensating controls.
            link: External tracking URI (Jira, ticketing system, documentation).
            assets: Optional list of asset UUIDs.
            applied_controls: Optional list of applied control UUIDs.
            requirement_assessments: Optional list of requirement assessment UUIDs.
            owners: Optional list of owner user UUIDs.
            evidences: Optional list of evidence UUIDs.

        Returns:
            API dictionary of the created or updated security exception.
        """
        payload: dict[str, Any] = {
            "name": name,
            "severity": severity,
            "status": status,
            "is_published": is_published,
            "assets": assets or [],
            "applied_controls": applied_controls or [],
            "requirement_assessments": requirement_assessments or [],
            "owners": owners or [],
            "evidences": evidences or [],
        }
        if folder_id:
            payload["folder"] = folder_id
        if description:
            payload["description"] = description
        if ref_id:
            payload["ref_id"] = ref_id
        if expiration_date:
            payload["expiration_date"] = expiration_date
        if observation:
            payload["observation"] = observation
        if link:
            payload["link"] = link

        # Check existing by name and folder
        for exc in self.security_exceptions.values():
            if exc.get_name() == name and (not folder_id or exc.get_folder_id() == folder_id):
                exc_id = exc.get_id()
                update_payload = {
                    k: v for k, v in payload.items() if v not in (None, [], {})
                }
                res = utils.get_return(
                    f"/api/security-exceptions/{exc_id}/",
                    method="PATCH",
                    payload=update_payload,
                    log_errors=False,
                )
                if isinstance(res, dict) and res.get("error") and "owners" in str(res.get("details", "")):
                    update_payload["owners"] = []
                    res = utils.get_return(
                        f"/api/security-exceptions/{exc_id}/",
                        method="PATCH",
                        payload=update_payload,
                        log_errors=False,
                    )
                if isinstance(res, dict) and not res.get("error"):
                    exc.json_object = res
                    self.security_exceptions[exc_id] = exc
                    return res
                return exc.get_json()

        utils.log(f"Creating security exception '{name}'...", level=logging.INFO)
        created = utils.get_return("/api/security-exceptions/", method="POST", payload=payload)
        # Defensive fallback: if owners PK was rejected (e.g. User UUID instead of Actor UUID), retry without owners
        if isinstance(created, dict) and created.get("error") and "owners" in str(created.get("details", "")):
            utils.log(
                f"Retrying security exception '{name}' creation without owners due to: {created.get('details')}",
                level=logging.WARNING,
            )
            payload["owners"] = []
            created = utils.get_return("/api/security-exceptions/", method="POST", payload=payload)

        if isinstance(created, dict) and created.get("id"):
            self.security_exceptions[created["id"]] = SecurityException(created)
        return created or {}

    def delete_security_exception(self, exception_id: str) -> bool:
        """Delete a security exception by UUID."""
        utils.log(f"Deleting security exception ID: {exception_id}", level=logging.INFO)
        response = utils.get_return(f"/api/security-exceptions/{exception_id}/", method="DELETE")
        if response is True or (isinstance(response, dict) and not response.get("error")):
            self.security_exceptions.pop(exception_id, None)
            return True
        return False

    def delete_exceptions_for_asset(self, asset_id: str) -> int:
        """Delete all security exceptions linked to a specific asset UUID.

        Returns:
            Count of security exceptions deleted.
        """
        deleted_count = 0
        matching = [
            exc.get_id() for exc in self.security_exceptions.values()
            if asset_id in exc.get_asset_ids()
        ]
        for e_id in matching:
            if self.delete_security_exception(e_id):
                deleted_count += 1
        return deleted_count

