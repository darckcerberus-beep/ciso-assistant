"""Unit tests for Security Exception models, collection, and ExamplesManager integration."""

import unittest
from unittest.mock import MagicMock, patch

from classes.controls.security_exception import (
    SEVERITY_MAPPING,
    SecurityException,
    SecurityExceptionDict,
)
from classes.examples_manager import (
    EXAMPLE_APPLICATIONS,
    ExamplesManager,
)


class TestSecurityExceptionModel(unittest.TestCase):
    """Test suite for SecurityException data class."""

    def test_security_exception_getters(self):
        """Verify SecurityException getters return correct fields from API payload."""
        sample_json = {
            "id": "exc-uuid-1",
            "name": "Exception: Emergency Break-Glass Local Console MFA Bypass",
            "ref_id": "EXC-SEC-001",
            "description": "Physical air-gapped server console emergency account exempt from remote MFA.",
            "severity": 1,
            "status": "approved",
            "expiration_date": "2027-12-31",
            "is_published": True,
            "observation": "Compensating control: Console locked in physical vault.",
            "link": "https://wiki.example.com/sec-001",
            "folder": {"id": "folder-uuid-1", "name": "Folder 1"},
            "assets": ["asset-uuid-1"],
            "applied_controls": ["ctrl-uuid-1"],
            "requirement_assessments": ["ra-uuid-1"],
            "owners": ["user-uuid-1"],
        }
        exc = SecurityException(sample_json)
        self.assertEqual(exc.get_id(), "exc-uuid-1")
        self.assertEqual(exc.get_name(), "Exception: Emergency Break-Glass Local Console MFA Bypass")
        self.assertEqual(exc.get_ref_id(), "EXC-SEC-001")
        self.assertEqual(exc.get_description(), "Physical air-gapped server console emergency account exempt from remote MFA.")
        self.assertEqual(exc.get_severity(), 1)
        self.assertEqual(exc.get_severity_label(), "low")
        self.assertEqual(exc.get_status(), "approved")
        self.assertEqual(exc.get_expiration_date(), "2027-12-31")
        self.assertTrue(exc.is_published())
        self.assertEqual(exc.get_observation(), "Compensating control: Console locked in physical vault.")
        self.assertEqual(exc.get_link(), "https://wiki.example.com/sec-001")
        self.assertEqual(exc.get_folder_id(), "folder-uuid-1")
        self.assertEqual(exc.get_asset_ids(), ["asset-uuid-1"])
        self.assertEqual(exc.get_applied_control_ids(), ["ctrl-uuid-1"])
        self.assertEqual(exc.get_requirement_assessment_ids(), ["ra-uuid-1"])
        self.assertEqual(exc.get_owners(), ["user-uuid-1"])
        self.assertEqual(exc.get_json(), sample_json)

    @patch("classes.utils.get_return")
    def test_security_exception_fetch_by_uuid(self, mock_get_return):
        """Verify SecurityException fetches payload via GET when initialized with UUID."""
        mock_get_return.return_value = {
            "id": "exc-uuid-99",
            "name": "Fetched Exception",
            "severity": 3,
        }
        exc = SecurityException("exc-uuid-99")
        self.assertEqual(exc.get_id(), "exc-uuid-99")
        self.assertEqual(exc.get_name(), "Fetched Exception")
        self.assertEqual(exc.get_severity(), 3)
        self.assertEqual(exc.get_severity_label(), "high")
        mock_get_return.assert_called_with("/api/security-exceptions/exc-uuid-99/")


class TestSecurityExceptionDict(unittest.TestCase):
    """Test suite for SecurityExceptionDict collection manager."""

    @patch("classes.utils.get_all_results")
    def test_reload_and_getters(self, mock_get_all):
        """Verify reloading and lookup by ID, name, asset, and control."""
        mock_get_all.return_value = [
            {
                "id": "exc-1",
                "name": "Exception A",
                "folder": "folder-1",
                "assets": ["asset-1"],
                "applied_controls": ["ctrl-1"],
            },
            {
                "id": "exc-2",
                "name": "Exception B",
                "folder": "folder-1",
                "assets": ["asset-2"],
                "applied_controls": [],
            },
        ]
        sec_dict = SecurityExceptionDict()
        self.assertEqual(len(sec_dict.get_security_exceptions()), 2)
        self.assertIsNotNone(sec_dict.get_exception_by_id("exc-1"))
        self.assertIsNone(sec_dict.get_exception_by_id("exc-999"))
        self.assertEqual(sec_dict.get_id_from_name("Exception A"), "exc-1")
        self.assertIsNone(sec_dict.get_id_from_name("NonExistent"))

        # Asset filtering
        for_asset1 = sec_dict.get_exceptions_for_asset("asset-1")
        self.assertEqual(len(for_asset1), 1)
        self.assertEqual(for_asset1[0].get_id(), "exc-1")

        # Control filtering
        for_ctrl1 = sec_dict.get_exceptions_for_applied_control("ctrl-1")
        self.assertEqual(len(for_ctrl1), 1)
        self.assertEqual(for_ctrl1[0].get_id(), "exc-1")

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_create_security_exception_post(self, mock_get_all, mock_get_return):
        """Verify creating a new security exception via POST."""
        mock_get_all.return_value = []
        sec_dict = SecurityExceptionDict()

        mock_get_return.return_value = {
            "id": "exc-new",
            "name": "New Waiver",
            "folder": "folder-1",
            "severity": 2,
            "status": "approved",
        }
        created = sec_dict.create_security_exception(
            name="New Waiver",
            folder_id="folder-1",
            description="Testing exception creation",
            ref_id="EXC-TEST-001",
            severity=2,
            status="approved",
            assets=["asset-1"],
        )
        self.assertEqual(created["id"], "exc-new")
        self.assertIn("exc-new", sec_dict.get_security_exceptions())

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_create_security_exception_patch(self, mock_get_all, mock_get_return):
        """Verify updating an existing security exception via PATCH (idempotence)."""
        mock_get_all.return_value = [
            {
                "id": "exc-existing",
                "name": "Existing Waiver",
                "folder": "folder-1",
                "severity": 1,
                "status": "draft",
            }
        ]
        sec_dict = SecurityExceptionDict()

        mock_get_return.return_value = {
            "id": "exc-existing",
            "name": "Existing Waiver",
            "folder": "folder-1",
            "severity": 2,
            "status": "approved",
        }
        updated = sec_dict.create_security_exception(
            name="Existing Waiver",
            folder_id="folder-1",
            severity=2,
            status="approved",
        )
        self.assertEqual(updated["id"], "exc-existing")
        self.assertEqual(updated["status"], "approved")

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_delete_security_exception(self, mock_get_all, mock_get_return):
        """Verify deleting a security exception by UUID."""
        mock_get_all.return_value = [
            {"id": "exc-del", "name": "To Delete", "folder": "f-1", "assets": ["asset-1"]}
        ]
        sec_dict = SecurityExceptionDict()
        self.assertIn("exc-del", sec_dict.get_security_exceptions())

        mock_get_return.return_value = True
        res = sec_dict.delete_security_exception("exc-del")
        self.assertTrue(res)
        self.assertNotIn("exc-del", sec_dict.get_security_exceptions())

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_delete_exceptions_for_asset(self, mock_get_all, mock_get_return):
        """Verify deleting all security exceptions linked to an asset."""
        mock_get_all.return_value = [
            {"id": "exc-1", "name": "Exc 1", "folder": "f-1", "assets": ["asset-tgt"]},
            {"id": "exc-2", "name": "Exc 2", "folder": "f-1", "assets": ["asset-tgt"]},
            {"id": "exc-3", "name": "Exc 3", "folder": "f-1", "assets": ["other"]},
        ]
        sec_dict = SecurityExceptionDict()
        mock_get_return.return_value = True

        deleted_count = sec_dict.delete_exceptions_for_asset("asset-tgt")
        self.assertEqual(deleted_count, 2)
        self.assertNotIn("exc-1", sec_dict.get_security_exceptions())
        self.assertNotIn("exc-2", sec_dict.get_security_exceptions())
        self.assertIn("exc-3", sec_dict.get_security_exceptions())


class TestExamplesManagerExceptions(unittest.TestCase):
    """Test suite for ExamplesManager security exceptions provisioning and lifecycle."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_example_applications_define_exceptions(self):
        """Verify all 8 example applications define realistic security exceptions."""
        for app in EXAMPLE_APPLICATIONS:
            self.assertIn("exceptions", app, f"Application {app['name']} missing 'exceptions' key")
            self.assertGreater(len(app["exceptions"]), 0, f"Application {app['name']} has empty exceptions")
            for exc in app["exceptions"]:
                self.assertIn("name", exc)
                self.assertIn("severity", exc)
                self.assertIn("status", exc)
                self.assertIn("expiration_date", exc)

    def test_create_security_exceptions_for_application(self):
        """Verify provisioning security exceptions for an example application."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "user_dict": MagicMock(),
            "security_exception_dict": MagicMock(),
        }
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid"
        mock_data["user_dict"].get_id_from_email.return_value = "user-uuid"
        mock_data["security_exception_dict"].create_security_exception.return_value = {
            "id": "exc-created-1",
            "name": "Exception: Emergency Break-Glass Local Console MFA Bypass (App-Secure-Core)",
            "severity": 1,
            "status": "approved",
        }

        self.manager.data = mock_data
        with patch.object(self.manager, "get_or_create_folder", return_value="folder-uuid"), \
             patch.object(self.manager, "_init_data", return_value=mock_data):
            results = self.manager.create_security_exceptions_for_application("app_secure_core")
            self.assertGreater(len(results), 0)
            mock_data["security_exception_dict"].create_security_exception.assert_called()

    def test_get_status_reports_security_exceptions(self):
        """Verify get_status populates security_exceptions_count and security_exceptions."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "user_dict": MagicMock(),
            "findings_assessment_dict": MagicMock(),
            "finding_dict": MagicMock(),
            "security_exception_dict": MagicMock(),
        }
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {}
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["risk_scenario_dict"].get_risk_scenarios.return_value = {}
        mock_data["applied_control_dict"].get_controls.return_value = {}
        mock_data["entity_dict"].get_id_from_name.return_value = None
        mock_data["entity_assessment_dict"].get_entity_assessments.return_value = []
        mock_data["user_dict"].get_id_from_email.return_value = None
        mock_data["findings_assessment_dict"].get_findings_assessments.return_value = {}
        mock_data["finding_dict"].get_findings_for_assessment.return_value = []

        mock_exc = MagicMock()
        mock_exc.get_asset_ids.return_value = ["asset-uuid-1"]
        mock_exc.get_name.return_value = "Exception: Emergency Break-Glass (App-Secure-Core)"
        mock_exc.get_json.return_value = {"id": "exc-uuid-1", "name": "Exception: Emergency Break-Glass"}
        mock_data["security_exception_dict"].get_security_exceptions.return_value = {"exc-uuid-1": mock_exc}

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            status = self.manager.get_status()
            app_status = next(s for s in status if s["name"] == "App-Secure-Core")
            self.assertEqual(app_status["security_exceptions_count"], 1)
            self.assertEqual(len(app_status["security_exceptions"]), 1)

    def test_remove_application_cleans_up_security_exceptions(self):
        """Verify removing an application deletes its security exceptions."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "user_dict": MagicMock(),
            "findings_assessment_dict": MagicMock(),
            "finding_dict": MagicMock(),
            "security_exception_dict": MagicMock(),
            "vulnerability_dict": MagicMock(),
        }
        app_name = "App-Secure-Core"
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid"
        mock_data["entity_dict"].get_id_from_name.return_value = None
        mock_data["entity_assessment_dict"].get_entity_assessments.return_value = []
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["applied_control_dict"].get_controls.return_value = {}
        mock_data["findings_assessment_dict"].get_findings_assessments.return_value = {}
        mock_data["vulnerability_dict"].get_vulnerabilities.return_value = {}

        mock_exc = MagicMock()
        mock_exc.get_id.return_value = "exc-to-delete"
        mock_exc.get_asset_ids.return_value = ["asset-uuid"]
        mock_exc.get_name.return_value = f"Exception on {app_name}"
        mock_data["security_exception_dict"].get_security_exceptions.return_value = {"exc-to-delete": mock_exc}
        mock_data["security_exception_dict"].delete_security_exception.return_value = True

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            del_res = self.manager.remove_example_application("app_secure_core")
            self.assertEqual(del_res["security_exceptions_deleted"], 1)
            mock_data["security_exception_dict"].delete_security_exception.assert_called_with("exc-to-delete")

    @patch("classes.utils.get_all_results")
    def test_resolve_actor_id(self, mock_get_all):
        """Verify resolve_actor_id resolves by user ID, email, or default assignee fallback."""
        mock_get_all.return_value = [
            {"id": "actor-1", "str": "admin@example.com", "specific": {"id": "user-uuid-1"}},
            {"id": "actor-2", "str": "user@example.com", "specific": {"id": "user-uuid-2"}},
        ]
        with patch.object(self.manager, "get_default_assignee_id", return_value="default-actor"):
            self.assertEqual(self.manager.resolve_actor_id(user_id="user-uuid-1"), "actor-1")
            self.assertEqual(self.manager.resolve_actor_id(user_email="user@example.com"), "actor-2")
            self.assertEqual(self.manager.resolve_actor_id(user_id="unknown-uuid"), "default-actor")

    def test_create_all_security_exceptions(self):
        """Verify create_all_security_exceptions iterates over deployed apps."""
        with patch.object(self.manager, "get_status", return_value=[
            {"name": "App-Secure-Core", "exists": True},
            {"name": "App-Missing", "exists": False},
        ]), patch.object(self.manager, "create_security_exceptions_for_application", return_value=[{"id": "exc-1"}]):
            res = self.manager.create_all_security_exceptions()
            self.assertEqual(res, {"App-Secure-Core": 1})


if __name__ == "__main__":
    unittest.main()

