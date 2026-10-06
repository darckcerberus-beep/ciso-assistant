"""Unit tests for the ExamplesManager class and example application simulation."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from classes.examples_manager import (
    EXAMPLE_APPLICATIONS,
    ExamplesManager,
    load_example_applications,
)


class TestExamplesManager(unittest.TestCase):
    """Test suite for ExamplesManager operations, creation, and removal workflows."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_example_applications_definitions(self):
        """Verify the 15 expected example applications (8 DPP + 4 VDD + 3 AppSec) are defined with valid YAML files."""
        self.assertEqual(len(EXAMPLE_APPLICATIONS), 15)
        apps = self.manager.get_example_applications()
        self.assertEqual(len(apps), 15)
        app_names = [a["name"] for a in apps]
        self.assertIn("App-Secure-Core", app_names)
        self.assertIn("App-Vulnerable-Portal", app_names)
        self.assertIn("App-Internal-Tool", app_names)
        self.assertIn("App-Public-Blog", app_names)
        self.assertIn("App-HR-People-System", app_names)
        self.assertIn("App-Customer-Payment-API", app_names)
        self.assertIn("App-Legacy-ERP-Production", app_names)
        self.assertIn("App-AI-Analytics-Workbench", app_names)
        self.assertIn("Vendor-Cloud-CRM", app_names)
        self.assertIn("Vendor-Shadow-Payroll", app_names)
        self.assertIn("Vendor-AI-Transcription", app_names)
        self.assertIn("Vendor-Marketing-Widget", app_names)
        self.assertIn("App-AppSec-Secure-API", app_names)
        self.assertIn("App-AppSec-Vulnerable-Legacy", app_names)
        self.assertIn("App-AppSec-Hybrid-SaaS", app_names)

        for app in apps:
            self.assertTrue(app["yaml_path"].endswith((".yml", ".yaml")))
            self.assertTrue(Path(app["yaml_path"]).exists(), f"{app['yaml_path']} does not exist")
            self.assertIn("user", app)
            self.assertIn("email", app["user"])
            self.assertIn("tprm", app)
            self.assertIn("criticality", app["tprm"])
            self.assertIn("description", app)
            self.assertIn("classification", app)

        csv_files = list(Path("test_data").glob("*.csv"))
        self.assertEqual(csv_files, [], f"No CSV files should remain in test_data: {csv_files}")

    def test_find_example_application(self):
        """Verify searching for applications by ID or name case-insensitively."""
        app = self.manager.find_example_application("app_secure_core")
        self.assertIsNotNone(app)
        self.assertEqual(app["name"], "App-Secure-Core")

        app_by_name = self.manager.find_example_application("app-secure-core")
        self.assertIsNotNone(app_by_name)
        self.assertEqual(app_by_name["id"], "app_secure_core")

        unknown = self.manager.find_example_application("non-existent-app")
        self.assertIsNone(unknown)

    def test_load_example_applications_dynamic_from_directory(self):
        """Verify dynamic discovery of example applications from an isolated directory."""
        import tempfile
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            test_app_yaml = {
                "application": {
                    "id": "app_custom_test",
                    "name": "App-Custom-Test",
                    "label": "App-Custom-Test (Test / Dynamic)",
                    "description": "Dynamic test app loaded from file",
                    "classification": "Internal",
                    "user": {"email": "test@custom.com"},
                    "tprm": {"criticality": 2, "conclusion": "ok"},
                }
            }
            file_path = Path(tmpdir) / "app_custom_test.yml"
            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(test_app_yaml, f)

            loaded = load_example_applications(tmpdir)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["id"], "app_custom_test")
            self.assertEqual(loaded[0]["name"], "App-Custom-Test")
            self.assertEqual(loaded[0]["user"]["email"], "test@custom.com")

    @patch("classes.utils.get_return")
    def test_test_connection_success(self, mock_get_return):
        """Test API connection verification when successful."""
        mock_get_return.return_value = [{"id": "user-1", "username": "admin"}]
        ok, msg = self.manager.test_connection()
        self.assertTrue(ok)
        self.assertIn("Connected successfully", msg)

    @patch("classes.utils.get_return")
    def test_test_connection_failure(self, mock_get_return):
        """Test API connection verification when failed."""
        mock_get_return.return_value = None
        ok, msg = self.manager.test_connection()
        self.assertFalse(ok)
        self.assertIn("Connection failed", msg)

    def test_get_status_with_mocked_data(self):
        """Verify status reporting when no applications exist vs when deployed."""
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
        }
        mock_data["perimeter_dict"].get_id_from_name.return_value = None
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = None
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {}
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["risk_scenario_dict"].get_risk_scenarios.return_value = {}
        mock_data["applied_control_dict"].get_controls.return_value = {}
        mock_data["entity_dict"].get_id_from_name.return_value = None
        mock_data["entity_assessment_dict"].get_entity_assessments.return_value = []
        mock_data["user_dict"].get_id_from_email.return_value = None
        mock_data["findings_assessment_dict"].get_findings_assessments.return_value = {}
        mock_data["finding_dict"].get_findings_for_assessment.return_value = []

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            status = self.manager.get_status()
            self.assertEqual(len(status), len(EXAMPLE_APPLICATIONS))
            for item in status:
                self.assertFalse(item["exists"])
                self.assertIn("user_email", item)
                self.assertIn("entity_id", item)
                self.assertIn("entity_assessment_id", item)
                self.assertIn("findings_assessment_id", item)
                self.assertIn("findings_count", item)

    def test_remove_example_application_ordering(self):
        """Verify deletion runs in reverse dependency order: TPRM -> Risk -> Controls -> Compliance -> Asset -> Perimeter."""
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
        }

        app_name = "App-Secure-Core"
        perimeter_id = "perm-uuid-1"
        asset_id = "asset-uuid-1"
        ca_id = "ca-uuid-1"
        ra_id = "ra-uuid-1"
        fa_id = "fa-uuid-1"
        ctrl_id = "ctrl-uuid-1"
        entity_id = "entity-uuid-1"
        ea_id = "ea-uuid-1"
        user_id = "user-uuid-1"

        mock_data["perimeter_dict"].get_id_from_name.return_value = perimeter_id
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = asset_id
        mock_data["entity_dict"].get_id_from_name.return_value = entity_id
        mock_data["user_dict"].get_id_from_email.return_value = user_id

        # Mock Entity Assessment
        mock_ea = MagicMock()
        mock_ea.get_id.return_value = ea_id
        mock_ea.get_entity_id.return_value = entity_id
        mock_ea.get_name.return_value = f"Third-party assessment for {app_name}"
        mock_data["entity_assessment_dict"].get_entity_assessments.return_value = [mock_ea]
        mock_data["entity_assessment_dict"].delete_entity_assessment.return_value = True

        # Mock Entity Representatives, Entity, and User deletes
        mock_data["entity_representative_dict"].delete_representatives_for_entity.return_value = 1
        mock_data["entity_dict"].delete_entity.return_value = True
        mock_data["user_dict"].delete_user_by_id.return_value = True

        # Mock Findings Assessment and Findings deletes
        mock_fa = MagicMock()
        mock_fa.get_id.return_value = fa_id
        mock_fa.get_name.return_value = f"Findings Assessment for {app_name}"
        mock_fa.get_perimeter_id.return_value = perimeter_id
        mock_data["findings_assessment_dict"].get_findings_assessments.return_value = {fa_id: mock_fa}
        mock_data["findings_assessment_dict"].delete_findings_assessment.return_value = True
        mock_data["finding_dict"].delete_findings_for_assessment.return_value = 3

        # Mock Risk Assessment
        mock_ra = MagicMock()
        mock_ra.get_id.return_value = ra_id
        mock_ra.get_name.return_value = f"{app_name} Risk Assessment"
        mock_ra.json_object = {"perimeter": perimeter_id}
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {ra_id: mock_ra}
        mock_data["risk_assessment_dict"].delete_risk_assessment.return_value = True
        mock_data["risk_scenario_dict"].delete_scenarios_for_risk_assessment.return_value = 7

        # Mock Control
        mock_ctrl = MagicMock()
        mock_ctrl.get_id.return_value = ctrl_id
        mock_ctrl.get_name.return_value = f"Encryption on {app_name}"
        mock_data["applied_control_dict"].get_controls.return_value = {ctrl_id: mock_ctrl}
        mock_data["applied_control_dict"].delete_applied_control.return_value = True

        # Mock Compliance Assessment
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = ca_id
        mock_ca.get_name.return_value = f"Assessment of DPP in {app_name}"
        mock_ca.get_perimeter_id.return_value = perimeter_id
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {ca_id: mock_ca}
        mock_data["compliance_assessment_dict"].delete_compliance_assessment.return_value = True

        # Mock Asset and Perimeter deletes
        mock_data["asset_dict"].delete_asset.return_value = True
        mock_data["perimeter_dict"].delete_perimeter.return_value = True

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            del_summary = self.manager.remove_example_application("app_secure_core")

            self.assertEqual(del_summary["app_name"], app_name)
            self.assertEqual(del_summary["entity_assessments_deleted"], 1)
            self.assertEqual(del_summary["entity_representatives_deleted"], 1)
            self.assertEqual(del_summary["entities_deleted"], 1)
            self.assertEqual(del_summary["users_deleted"], 1)
            self.assertEqual(del_summary["findings_deleted"], 3)
            self.assertEqual(del_summary["findings_assessments_deleted"], 1)
            self.assertEqual(del_summary["risk_assessments_deleted"], 1)
            self.assertEqual(del_summary["scenarios_deleted"], 7)
            self.assertEqual(del_summary["applied_controls_deleted"], 1)
            self.assertEqual(del_summary["compliance_assessments_deleted"], 1)
            self.assertEqual(del_summary["assets_deleted"], 1)
            self.assertEqual(del_summary["perimeters_deleted"], 1)

            # Verify call order
            mock_data["entity_assessment_dict"].delete_entity_assessment.assert_called_once_with(ea_id)
            mock_data["entity_representative_dict"].delete_representatives_for_entity.assert_called_once_with(entity_id)
            mock_data["entity_dict"].delete_entity.assert_called_once_with(entity_id)
            mock_data["user_dict"].delete_user_by_id.assert_called_once_with(user_id)
            mock_data["finding_dict"].delete_findings_for_assessment.assert_called_once_with(fa_id)
            mock_data["findings_assessment_dict"].delete_findings_assessment.assert_called_once_with(fa_id)
            mock_data["risk_scenario_dict"].delete_scenarios_for_risk_assessment.assert_called_once_with(ra_id)
            mock_data["risk_assessment_dict"].delete_risk_assessment.assert_called_once_with(ra_id)
            mock_data["applied_control_dict"].delete_applied_control.assert_called_once_with(ctrl_id)
            mock_data["compliance_assessment_dict"].delete_compliance_assessment.assert_called_once_with(ca_id)
            mock_data["asset_dict"].delete_asset.assert_called_once_with(asset_id)
            mock_data["perimeter_dict"].delete_perimeter.assert_called_once_with(perimeter_id)

    @patch("classes.utils.get_return")
    def test_link_controls_for_application(self, mock_get_return):
        """Verify linking active and planned controls to risk scenarios."""
        mock_get_return.return_value = {"id": "sc-uuid-1", "existing_applied_controls": ["ctrl-active-1"], "applied_controls": []}

        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        app_name = "App-Secure-Core"
        perimeter_id = "perm-uuid-1"
        asset_id = "asset-uuid-1"
        ca_id = "ca-uuid-1"
        ra_id = "ra-uuid-1"

        mock_data["perimeter_dict"].get_id_from_name.return_value = perimeter_id
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = asset_id
        mock_data["perimeter_dict"].get_owner_id_from_perimeter_id.return_value = "owner-1"

        # Mock Compliance Assessment
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = ca_id
        mock_ca.get_perimeter_id.return_value = perimeter_id
        mock_ca.get_name.return_value = f"Assessment in {app_name}"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {ca_id: mock_ca}

        # Mock Requirement Assessment
        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = ca_id
        mock_ra.get_urn.return_value = "data_in_transit"
        mock_ra.get_applied_control_ids.return_value = ["ctrl-active-1"]
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        # Mock Applied Control
        mock_ctrl = MagicMock()
        mock_ctrl.get_id.return_value = "ctrl-active-1"
        mock_ctrl.get_name.return_value = f"Control on {app_name}"
        mock_ctrl.get_status.return_value = "active"
        mock_data["applied_control_dict"].get_controls.return_value = {"ctrl-active-1": mock_ctrl}

        # Mock Risk Assessment
        mock_risk_assessment = MagicMock()
        mock_risk_assessment.get_id.return_value = ra_id
        mock_risk_assessment.get_perimeter_id.return_value = perimeter_id
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {ra_id: mock_risk_assessment}

        # Mock Scenario
        mock_sc = MagicMock()
        mock_sc.get_id.return_value = "sc-uuid-1"
        mock_sc.get_name.return_value = "Exposure of unencrypted data in transit"
        mock_sc.get_json.return_value = {"risk_assessment": ra_id}
        mock_data["risk_scenario_dict"].get_risk_scenarios.return_value = {"sc-uuid-1": mock_sc}

        # Mock Framework
        mock_data["framework_file"].get_risk_scenarios.return_value = [
            {"name": "Exposure of unencrypted data in transit", "likelihood": "data_in_transit"}
        ]

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            res = self.manager.link_controls_for_application("app_secure_core")
            self.assertEqual(res["app_name"], app_name)
            self.assertEqual(res["scenarios_updated"], 1)
            self.assertEqual(res["existing_controls"], 1)
            self.assertEqual(res["planned_controls"], 0)
            mock_get_return.assert_called_once()
            call_args = mock_get_return.call_args
            self.assertIn("/api/risk-scenarios/sc-uuid-1/", call_args[0][0])
            self.assertEqual(call_args[1]["payload"]["existing_applied_controls"], ["ctrl-active-1"])
            self.assertEqual(call_args[1]["payload"]["assets"], [asset_id])


    @patch("classes.integrations.answers_import.import_compliance_answers")
    @patch("tests.test_application_scenarios.ApplicationRiskSimulator")
    def test_create_example_application_tprm_and_user(self, mock_sim_cls, mock_import_answers):
        """Verify that create_example_application provisions TPRM user, entity, and entity assessment."""
        mock_import_answers.return_value = {"updated": 10}
        mock_sim = MagicMock()
        mock_sim.evaluate_application.return_value = {
            "impact_level": 4,
            "scenarios": {},
            "requirement_scores": {},
        }
        mock_sim_cls.return_value = mock_sim

        mock_data = {
            "user_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "risk_matrix_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        # Mock user & TPRM
        mock_data["user_dict"].create_user_if_missing.return_value = {"id": "user-uuid-1"}
        mock_data["entity_dict"].create_entity.return_value = {"id": "entity-uuid-1"}
        mock_data["entity_representative_dict"].upsert_entity_representative.return_value = {"id": "rep-uuid-1"}
        mock_data["entity_assessment_dict"].create_entity_assessment.return_value = {"id": "ea-uuid-1"}

        # Mock perimeter & asset
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-1"
        mock_asset = MagicMock()
        mock_asset.get_id.return_value = "asset-uuid-1"
        mock_data["asset_dict"].get_assets.return_value = [mock_asset]

        # Mock framework
        mock_fw = MagicMock()
        mock_fw.get_id.return_value = "fw-uuid-1"
        mock_fw.get_name.return_value = "Multi-level DPP"

        # Mock compliance assessment
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-1"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Secure-Core"
        mock_ca.get_perimeter_id.return_value = "perm-uuid-1"
        mock_ca.get_framework_id.return_value = "fw-uuid-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-1": mock_ca}

        # Mock risk assessment & matrix
        mock_data["risk_assessment_dict"].create_risk_assessments.return_value = {"id": "ra-uuid-1"}
        mock_data["framework_file"].get_risk_scenarios.return_value = []

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_or_create_folder", return_value="folder-uuid-1"), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-uuid-1"), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch.object(self.manager, "find_target_risk_matrix", return_value="matrix-uuid-1"), \
             patch.object(self.manager, "link_controls_for_application", return_value={"existing_controls": 2, "planned_controls": 1}), \
             patch("time.sleep"):

            res = self.manager.create_example_application("app_secure_core")

            self.assertEqual(res["app_name"], "App-Secure-Core")
            self.assertEqual(res["user_email"], "alice.secure@example-core.com")
            self.assertEqual(res["user_id"], "user-uuid-1")
            self.assertEqual(res["entity_id"], "entity-uuid-1")
            self.assertEqual(res["entity_assessment_id"], "ea-uuid-1")
            self.assertEqual(res["perimeter_id"], "perm-uuid-1")
            self.assertEqual(res["compliance_assessment_id"], "ca-uuid-1")

            mock_data["user_dict"].create_user_if_missing.assert_called_once_with(
                email="alice.secure@example-core.com",
                first_name="Alice",
                last_name="Secure",
                is_third_party=True,
            )
            mock_data["entity_dict"].create_entity.assert_called_once_with(
                name="App-Secure-Core",
                folder_id="folder-uuid-1",
                description="High classification (Secret) + Full compliance (100%) -> Low Risk",
            )
            mock_data["entity_representative_dict"].upsert_entity_representative.assert_called_once_with(
                entity_id="entity-uuid-1",
                user_id="user-uuid-1",
                role="representative",
            )
            mock_data["entity_assessment_dict"].create_entity_assessment.assert_called_once_with(
                name="Third-party assessment for App-Secure-Core",
                entity_id="entity-uuid-1",
                compliance_assessment_id="ca-uuid-1",
                representative_ids=["user-uuid-1"],
                criticality=4,
                maturity=4,
                trust=4,
                conclusion="ok",
            )

    @patch("classes.utils.get_return")
    def test_create_application_for_audit_new_user(self, mock_get_return):
        """Verify create_application_for_audit provisions uncompleted audit and creates user when missing."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "user_dict": MagicMock(),
            "domain_dict": MagicMock(),
        }

        mock_data["user_dict"].get_id_from_email.side_effect = [None, "new-user-123"]
        mock_data["user_dict"].create_user_if_missing.return_value = {"id": "new-user-123"}
        mock_data["entity_dict"].create_entity.return_value = {"id": "entity-uuid-audit"}
        mock_data["entity_dict"].get_id_from_name.return_value = "entity-uuid-audit"
        mock_data["perimeter_dict"].create_perimeter.return_value = {"id": "perm-uuid-audit"}
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-audit"
        mock_data["asset_dict"].create_asset.return_value = {"id": "asset-uuid-audit"}
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-audit"
        mock_data["asset_dict"].get_assets.return_value = []

        mock_fw = MagicMock()
        mock_fw.get_id.return_value = "fw-uuid-1"
        mock_fw.get_name.return_value = "Multi-level DPP"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-audit"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Audit-Demo"
        mock_ca.get_status.return_value = "in_progress"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-audit": mock_ca}
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id.return_value = ["ra-1", "ra-2"]
        mock_data["compliance_assessment_dict"].requirement_assignments.get_requirement_assignment_id_list_from_compliance_assessment_id.return_value = ["assign-1"]

        mock_data["entity_assessment_dict"].create_entity_assessment.return_value = {"id": "ea-uuid-audit"}

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_or_create_folder", return_value="folder-uuid-1"), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-uuid-1"), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch("time.sleep"):

            res = self.manager.create_application_for_audit(
                app_name="App-Audit-Demo",
                user_email="auditor@example.com",
                first_name="Auditor",
                last_name="Test",
                is_third_party=True,
            )

            self.assertEqual(res["app_name"], "App-Audit-Demo")
            self.assertEqual(res["user_email"], "auditor@example.com")
            self.assertEqual(res["user_id"], "new-user-123")
            self.assertTrue(res["user_created"])
            self.assertEqual(res["entity_id"], "entity-uuid-audit")
            self.assertEqual(res["entity_assessment_id"], "ea-uuid-audit")
            self.assertEqual(res["compliance_assessment_id"], "ca-uuid-audit")
            self.assertEqual(res["compliance_status"], "in_progress")
            self.assertEqual(res["requirement_assessments_count"], 2)
            self.assertEqual(res["assignment_id"], "assign-1")

            mock_data["user_dict"].create_user_if_missing.assert_called_once_with(
                email="auditor@example.com",
                first_name="Auditor",
                last_name="Test",
                is_third_party=True,
            )
            mock_data["entity_dict"].create_entity.assert_called_once_with(
                name="App-Audit-Demo",
                folder_id="folder-uuid-1",
                description="External entity for App-Audit-Demo (audit demonstration)",
            )
            mock_data["entity_representative_dict"].upsert_entity_representative.assert_called_once_with(
                entity_id="entity-uuid-audit",
                user_id="new-user-123",
                role="representative",
            )
            mock_data["entity_assessment_dict"].create_entity_assessment.assert_called_once_with(
                name="Third-party assessment for App-Audit-Demo",
                entity_id="entity-uuid-audit",
                compliance_assessment_id="ca-uuid-audit",
                representative_ids=["new-user-123"],
                status="in_progress",
            )

    @patch("classes.utils.get_return")
    def test_create_application_for_audit_existing_user(self, mock_get_return):
        """Verify create_application_for_audit reuses user when already existing."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "user_dict": MagicMock(),
            "domain_dict": MagicMock(),
        }

        mock_data["user_dict"].get_id_from_email.return_value = "existing-user-uuid"
        mock_data["entity_dict"].create_entity.return_value = {"id": "entity-uuid-2"}
        mock_data["entity_dict"].get_id_from_name.return_value = "entity-uuid-2"
        mock_data["perimeter_dict"].create_perimeter.return_value = {"id": "perm-uuid-2"}
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-2"
        mock_data["asset_dict"].create_asset.return_value = {"id": "asset-uuid-2"}
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-2"
        mock_data["asset_dict"].get_assets.return_value = []

        mock_fw = MagicMock()
        mock_fw.get_id.return_value = "fw-uuid-1"
        mock_fw.get_name.return_value = "Multi-level DPP"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-2"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Audit-Existing"
        mock_ca.get_status.return_value = "in_progress"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-2": mock_ca}
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id.return_value = ["ra-1"]
        mock_data["compliance_assessment_dict"].requirement_assignments.get_requirement_assignment_id_list_from_compliance_assessment_id.return_value = ["assign-2"]

        mock_data["entity_assessment_dict"].create_entity_assessment.return_value = {"id": "ea-uuid-2"}

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_or_create_folder", return_value="folder-uuid-1"), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-uuid-1"), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch("time.sleep"):

            res = self.manager.create_application_for_audit(
                app_name="App-Audit-Existing",
                user_email="existing@example.com",
            )

            self.assertEqual(res["app_name"], "App-Audit-Existing")
            self.assertEqual(res["user_email"], "existing@example.com")
            self.assertEqual(res["user_id"], "existing-user-uuid")
            self.assertFalse(res["user_created"])
            mock_data["user_dict"].create_user_if_missing.assert_not_called()

    @patch("classes.integrations.answers_import.import_compliance_answers")
    @patch("tests.test_application_scenarios.ApplicationRiskSimulator")
    def test_generate_controls_and_risks_with_answers_file(self, mock_sim_cls, mock_import_answers):
        """Verify generating controls and risks using a YAML/profile answers file."""
        mock_import_answers.return_value = {"updated": 10}
        mock_sim = MagicMock()
        mock_sim.evaluate_application.return_value = {
            "impact_level": 4,
            "scenarios": {
                "Exposure of unencrypted data in transit": {
                    "scaled_likelihood": 1,
                    "scaled_impact": 4,
                }
            },
            "requirement_scores": {"data_in_transit": 100},
        }
        mock_sim_cls.return_value = mock_sim

        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "framework_file": MagicMock(),
            "domain_dict": MagicMock(),
        }

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-1"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-1"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Audit-Demo"
        mock_ca.get_framework_id.return_value = "fw-uuid-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-1": mock_ca}

        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-uuid-1"
        mock_ra.get_urn.return_value = "data_in_transit"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_applied_control_ids.return_value = ["ctrl-uuid-1"]
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        mock_ctrl = MagicMock()
        mock_ctrl.get_id.return_value = "ctrl-uuid-1"
        mock_ctrl.get_name.return_value = "Control on App-Audit-Demo"
        mock_ctrl.get_status.return_value = "active"
        mock_data["applied_control_dict"].get_controls.return_value = {"ctrl-uuid-1": mock_ctrl}

        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["risk_assessment_dict"].create_risk_assessments.return_value = {"id": "ra-uuid-1"}

        mock_data["framework_file"].get_risk_scenarios.return_value = [
            {
                "name": "Exposure of unencrypted data in transit",
                "description": "Desc",
                "likelihood": "data_in_transit",
            }
        ]

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "find_target_risk_matrix", return_value="matrix-uuid-1"), \
             patch.object(self.manager, "link_controls_for_application", return_value={"existing_controls": 1, "planned_controls": 0}), \
             patch("time.sleep"):

            res = self.manager.generate_controls_and_risks_for_application(
                app_id_or_name="App-Audit-Demo",
                yaml_path="test_data/app_secure_core.yml",
            )

            self.assertEqual(res["app_name"], "App-Audit-Demo")
            self.assertEqual(res["compliance_assessment_id"], "ca-uuid-1")
            self.assertEqual(res["risk_assessment_id"], "ra-uuid-1")
            self.assertEqual(res["answers_updated"], 10)
            self.assertEqual(res["scenarios_created"], 1)
            self.assertEqual(res["existing_controls_linked"], 1)
            mock_import_answers.assert_called_once()
            mock_data["risk_scenario_dict"].create_risk_scenario.assert_called_once()

    @patch("tests.test_application_scenarios.ApplicationRiskSimulator")
    def test_generate_controls_and_risks_from_live_ui_answers(self, mock_sim_cls):
        """Verify generating controls and risks using live answers from CISO Assistant UI."""
        mock_sim = MagicMock()
        mock_sim.evaluate_application.return_value = {
            "impact_level": 4,
            "scenarios": {
                "Exposure of unencrypted data in transit": {
                    "scaled_likelihood": 2,
                    "scaled_impact": 4,
                }
            },
            "requirement_scores": {"data_in_transit": 75},
        }
        mock_sim_cls.return_value = mock_sim

        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "framework_file": MagicMock(),
            "domain_dict": MagicMock(),
        }

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-1"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-1"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Audit-Demo"
        mock_ca.get_framework_id.return_value = "fw-uuid-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-1": mock_ca}

        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-uuid-1"
        mock_ra.get_urn.return_value = "data_in_transit"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_applied_control_ids.return_value = ["ctrl-uuid-1"]
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        mock_ctrl = MagicMock()
        mock_ctrl.get_id.return_value = "ctrl-uuid-1"
        mock_ctrl.get_name.return_value = "Control on App-Audit-Demo"
        mock_ctrl.get_status.return_value = "active"
        mock_data["applied_control_dict"].get_controls.return_value = {"ctrl-uuid-1": mock_ctrl}

        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["risk_assessment_dict"].create_risk_assessments.return_value = {"id": "ra-uuid-1"}

        mock_data["framework_file"].get_risk_scenarios.return_value = [
            {
                "name": "Exposure of unencrypted data in transit",
                "description": "Desc",
                "likelihood": "data_in_transit",
            }
        ]

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "find_target_risk_matrix", return_value="matrix-uuid-1"), \
             patch.object(self.manager, "link_controls_for_application", return_value={"existing_controls": 1, "planned_controls": 0}), \
             patch("time.sleep"):

            res = self.manager.generate_controls_and_risks_for_application(
                app_id_or_name="App-Audit-Demo",
                yaml_path=None,
            )

            self.assertEqual(res["app_name"], "App-Audit-Demo")
            self.assertEqual(res["answers_updated"], 0)
            self.assertEqual(res["scenarios_created"], 1)
            # Ensure polymorphic evaluate_application was called with requirement assessments
            mock_sim.evaluate_application.assert_called_once()
            call_arg = mock_sim.evaluate_application.call_args[0][0]
            self.assertIsInstance(call_arg, list)
            self.assertIn(mock_ra, call_arg)

    def test_generate_controls_and_risks_unanswered_raises_error(self):
        """Verify that attempting to generate risks for an unanswered audit raises ValueError."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-1"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-1"
        mock_ca.get_name.return_value = "Assessment in App-Unanswered"
        mock_ca.get_framework_id.return_value = "fw-uuid-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-1": mock_ca}

        # Mock unanswered RA
        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-uuid-1"
        mock_ra.has_selected_answer.return_value = False
        mock_ra.is_unassessed_result.return_value = True
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-uuid-1"):
            with self.assertRaises(ValueError) as ctx:
                self.manager.generate_controls_and_risks_for_application("App-Unanswered")
            self.assertIn("0 answered requirements", str(ctx.exception))

    def test_generate_controls_and_risks_missing_ca_raises_error(self):
        """Verify that an unknown application raises ValueError."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "framework_file": MagicMock(),
        }
        mock_data["perimeter_dict"].get_id_from_name.return_value = None
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {}

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-uuid-1"):
            with self.assertRaises(ValueError) as ctx:
                self.manager.generate_controls_and_risks_for_application("NonExistentApp")
            self.assertIn("No compliance assessment found", str(ctx.exception))

    @patch("classes.integrations.answers_import.import_compliance_answers")
    @patch("tests.test_application_scenarios.ApplicationRiskSimulator")
    def test_create_example_application_links_vulnerabilities_and_threats_to_scenarios(self, mock_sim_cls, mock_import_answers):
        """Verify that create_example_application resolves and links vulnerabilities and threats to risk scenarios."""
        mock_import_answers.return_value = {"updated": 1}
        mock_sim = MagicMock()
        mock_sim.evaluate_application.return_value = {
            "impact_level": 4,
            "scenarios": {
                "Exposure of unencrypted data in transit": {
                    "scaled_likelihood": 4,
                    "scaled_impact": 4,
                }
            },
            "requirement_scores": {},
        }
        mock_sim_cls.return_value = mock_sim

        mock_data = {
            "user_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "risk_matrix_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "vulnerability_dict": MagicMock(),
            "threat_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        mock_data["user_dict"].create_user_if_missing.return_value = {"id": "u-1"}
        mock_data["entity_dict"].create_entity.return_value = {"id": "e-1"}
        mock_data["entity_representative_dict"].upsert_entity_representative.return_value = {"id": "rep-1"}
        mock_data["entity_assessment_dict"].create_entity_assessment.return_value = {"id": "ea-1"}

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-1"
        mock_asset = MagicMock()
        mock_asset.get_id.return_value = "asset-1"
        mock_data["asset_dict"].get_assets.return_value = [mock_asset]

        mock_fw = MagicMock()
        mock_fw.get_id.return_value = "fw-1"
        mock_fw.get_name.return_value = "Multi-level DPP"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-1"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Secure-Core"
        mock_ca.get_perimeter_id.return_value = "perm-1"
        mock_ca.get_framework_id.return_value = "fw-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-1": mock_ca}

        # Mock requirement assessment with answer
        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-1"
        mock_ra.get_urn.return_value = "urn:dpp:transit"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_applied_control_ids.return_value = []
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        # Mock scenario definition in framework YAML with vulnerabilities and threats
        mock_data["framework_file"].get_risk_scenarios.return_value = [
            {
                "name": "Exposure of unencrypted data in transit",
                "description": "Sensitive data exposed",
                "likelihood": "urn:dpp:transit",
                "vulnerabilities": ["urn:dpp:vuln:no_enc"],
                "threats": ["urn:dpp:threat:leak"],
            }
        ]

        mock_data["vulnerability_dict"].get_id_by_urn.return_value = "vuln-uuid-99"
        mock_data["vulnerability_dict"].get_vulnerability_id_for_asset.return_value = "vuln-uuid-99"
        mock_data["threat_dict"].get_id_by_urn.return_value = "threat-uuid-99"
        mock_data["risk_assessment_dict"].create_risk_assessments.return_value = {"id": "ra-1"}

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_or_create_folder", return_value="folder-1"), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-1"), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch.object(self.manager, "find_target_risk_matrix", return_value="matrix-1"), \
             patch.object(self.manager, "link_controls_for_application", return_value={}), \
             patch.object(self.manager, "create_findings_for_application", return_value={}), \
             patch("time.sleep"):

            self.manager.create_example_application("app_secure_core")

            mock_data["risk_scenario_dict"].create_risk_scenario.assert_called_once_with(
                "Exposure of unencrypted data in transit",
                "Sensitive data exposed",
                "ra-1",
                4,
                4,
                1,
                4,
                [],
                [],
                ["asset-1"],
                ["assignee-1"],
                vulnerabilities=["vuln-uuid-99"],
                threats=["threat-uuid-99"],
            )

    @patch("classes.integrations.answers_import.import_compliance_answers")
    @patch("tests.test_application_scenarios.ApplicationRiskSimulator")
    def test_create_example_application_order_scenarios_before_applied_controls(self, mock_sim_cls, mock_import_answers):
        """Verify that create_example_application creates risk scenarios BEFORE creating applied controls."""
        mock_import_answers.return_value = {"updated": 1}
        mock_sim = MagicMock()
        mock_sim.evaluate_application.return_value = {
            "impact_level": 4,
            "scenarios": {
                "Exposure of unencrypted data in transit": {
                    "scaled_likelihood": 4,
                    "scaled_impact": 4,
                }
            },
            "requirement_scores": {},
        }
        mock_sim_cls.return_value = mock_sim

        mock_data = {
            "user_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "risk_matrix_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        mock_data["user_dict"].create_user_if_missing.return_value = {"id": "u-1"}
        mock_data["entity_dict"].create_entity.return_value = {"id": "e-1"}
        mock_data["entity_representative_dict"].upsert_entity_representative.return_value = {"id": "rep-1"}
        mock_data["entity_assessment_dict"].create_entity_assessment.return_value = {"id": "ea-1"}

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-1"
        mock_asset = MagicMock()
        mock_asset.get_id.return_value = "asset-1"
        mock_data["asset_dict"].get_assets.return_value = [mock_asset]

        mock_fw = MagicMock()
        mock_fw.get_id.return_value = "fw-1"
        mock_fw.get_name.return_value = "Multi-level DPP"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-1"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Secure-Core"
        mock_ca.get_perimeter_id.return_value = "perm-1"
        mock_ca.get_framework_id.return_value = "fw-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-1": mock_ca}

        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-1"
        mock_ra.get_urn.return_value = "urn:dpp:transit"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_applied_control_ids.return_value = []
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        mock_data["framework_file"].get_risk_scenarios.return_value = [
            {
                "name": "Exposure of unencrypted data in transit",
                "description": "Sensitive data exposed",
                "likelihood": "urn:dpp:transit",
            }
        ]
        mock_data["risk_assessment_dict"].create_risk_assessments.return_value = {"id": "ra-1"}

        call_order = []
        mock_data["risk_scenario_dict"].create_risk_scenario.side_effect = lambda *a, **kw: call_order.append("create_risk_scenario")
        mock_data["compliance_assessment_dict"].create_missing_applied_controls.side_effect = lambda *a, **kw: call_order.append("create_missing_applied_controls")

        def mock_link(app_name):
            call_order.append("link_controls_for_application")
            return {"existing_controls": 0, "planned_controls": 0}

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_or_create_folder", return_value="folder-1"), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-1"), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch.object(self.manager, "find_target_risk_matrix", return_value="matrix-1"), \
             patch.object(self.manager, "link_controls_for_application", side_effect=mock_link), \
             patch.object(self.manager, "create_findings_for_application", return_value={}), \
             patch("time.sleep"):

            self.manager.create_example_application("app_secure_core")

            self.assertEqual(
                call_order,
                ["create_risk_scenario", "create_missing_applied_controls", "link_controls_for_application"],
            )

    @patch("classes.integrations.answers_import.import_compliance_answers")
    @patch("tests.test_application_scenarios.ApplicationRiskSimulator")
    def test_generate_controls_and_risks_order_scenarios_before_applied_controls(self, mock_sim_cls, mock_import_answers):
        """Verify that generate_controls_and_risks_for_application creates risk scenarios BEFORE creating applied controls."""
        mock_import_answers.return_value = {"updated": 10}
        mock_sim = MagicMock()
        mock_sim.evaluate_application.return_value = {
            "impact_level": 4,
            "scenarios": {
                "Exposure of unencrypted data in transit": {
                    "scaled_likelihood": 1,
                    "scaled_impact": 4,
                }
            },
            "requirement_scores": {"data_in_transit": 100},
        }
        mock_sim_cls.return_value = mock_sim

        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "reference_control_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "framework_file": MagicMock(),
            "domain_dict": MagicMock(),
        }

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-uuid-1"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-uuid-1"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-uuid-1"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Audit-Demo"
        mock_ca.get_framework_id.return_value = "fw-uuid-1"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-uuid-1": mock_ca}

        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-uuid-1"
        mock_ra.get_urn.return_value = "data_in_transit"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_applied_control_ids.return_value = []
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments.return_value = {
            "ra-1": mock_ra
        }

        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["risk_assessment_dict"].create_risk_assessments.return_value = {"id": "ra-uuid-1"}

        mock_data["framework_file"].get_risk_scenarios.return_value = [
            {
                "name": "Exposure of unencrypted data in transit",
                "description": "Desc",
                "likelihood": "data_in_transit",
            }
        ]

        call_order = []
        mock_data["risk_scenario_dict"].create_risk_scenario.side_effect = lambda *a, **kw: call_order.append("create_risk_scenario")
        mock_data["compliance_assessment_dict"].create_missing_applied_controls.side_effect = lambda *a, **kw: call_order.append("create_missing_applied_controls")

        def mock_link(app_name):
            call_order.append("link_controls_for_application")
            return {"existing_controls": 0, "planned_controls": 0}

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "find_target_risk_matrix", return_value="matrix-uuid-1"), \
             patch.object(self.manager, "link_controls_for_application", side_effect=mock_link), \
             patch.object(self.manager, "create_findings_for_application", return_value={}), \
             patch("time.sleep"):

            res = self.manager.generate_controls_and_risks_for_application(
                app_id_or_name="App-Audit-Demo",
                yaml_path="test_data/app_secure_core.yml",
            )

            self.assertEqual(
                call_order,
                ["create_risk_scenario", "create_missing_applied_controls", "link_controls_for_application"],
            )


class TestMainCLI(unittest.TestCase):
    """Test CLI flags and interactive entrypoints in main.py."""

    @patch("main.generate_controls_and_risks_ui")
    @patch("main.ExamplesManager")
    def test_cli_generate_risks_explicit(self, mock_mgr_cls, mock_gen_ui):
        """Verify --generate-risks APP --answers FILE calls generate_controls_and_risks_ui."""
        from main import main
        test_args = ["main.py", "--generate-risks", "Custom-App", "--answers", "test_data/app_secure_core.yml"]
        with patch("sys.argv", test_args):
            main()
            mock_gen_ui.assert_called_once_with(
                mock_mgr_cls.return_value,
                app_name="Custom-App",
                answers_source="test_data/app_secure_core.yml",
                interactive=False,
            )

    @patch("main.generate_controls_and_risks_ui")
    @patch("main.ExamplesManager")
    def test_cli_generate_risks_default_name(self, mock_mgr_cls, mock_gen_ui):
        """Verify --generate-risks without argument defaults to App-Audit-Demo."""
        from main import main
        test_args = ["main.py", "--generate-risks"]
        with patch("sys.argv", test_args):
            main()
            mock_gen_ui.assert_called_once_with(
                mock_mgr_cls.return_value,
                app_name="App-Audit-Demo",
                answers_source=None,
                interactive=False,
            )

    @patch("main.create_audit_demo_ui")
    @patch("main.ExamplesManager")
    def test_cli_create_audit_with_framework(self, mock_mgr_cls, mock_audit_ui):
        """Verify --create-audit APP --framework VENDOR calls create_audit_demo_ui with framework."""
        from main import main
        test_args = ["main.py", "--create-audit", "Vendor-Test", "--user", "user@example.com", "--framework", "vendor-due-diligence"]
        with patch("sys.argv", test_args):
            main()
            mock_audit_ui.assert_called_once_with(
                mock_mgr_cls.return_value,
                app_name="Vendor-Test",
                user_email="user@example.com",
                framework_ref_or_name="vendor-due-diligence",
            )

    @patch("main.create_examples_ui")
    @patch("main.ExamplesManager")
    def test_cli_create_with_framework(self, mock_mgr_cls, mock_create_ui):
        """Verify --create APP --framework VENDOR calls create_examples_ui with framework."""
        from main import main
        test_args = ["main.py", "--create", "app_secure_core", "--framework", "vendor-due-diligence"]
        with patch("sys.argv", test_args):
            main()
            mock_create_ui.assert_called_once_with(
                mock_mgr_cls.return_value,
                target="app_secure_core",
                framework_ref_or_name="vendor-due-diligence",
            )


class TestFrameworkSelection(unittest.TestCase):
    """Test suite for multi-framework catalog, resolution, and selection workflows."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_example_applications_framework_references(self):
        """Verify each example application contains framework reference metadata."""
        from pathlib import Path
        for app in EXAMPLE_APPLICATIONS:
            self.assertIn("framework_ref", app)
            self.assertIn("framework_name", app)
            self.assertIn("framework_yaml", app)
            if app["framework_ref"] == "mls":
                self.assertEqual(app["framework_name"], "Multi-level DPP")
            elif app["framework_ref"] == "vendor-due-diligence":
                self.assertEqual(app["framework_name"], "Vendor Due Diligence (VDD) - simple")
            elif app["framework_ref"] == "appsec":
                self.assertEqual(app["framework_name"], "Application Security Assessment Framework (AppSec)")
            else:
                self.fail(f"Unknown framework_ref: {app['framework_ref']}")
            self.assertTrue(Path(app["framework_yaml"]).exists())

    def test_test_data_yaml_profiles_contain_framework(self):
        """Verify YAML application profiles in test_data contain framework references."""
        from pathlib import Path
        import yaml
        test_data_dir = Path("test_data")
        for yml_file in test_data_dir.glob("*.yml"):
            with open(yml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            app_block = data.get("application", {})
            self.assertIn("framework_ref", app_block, f"Missing framework_ref in {yml_file.name}")
            self.assertIn("framework_name", app_block, f"Missing framework_name in {yml_file.name}")
            self.assertIn(app_block["framework_ref"], ["mls", "vendor-due-diligence", "appsec"])

    def test_get_available_frameworks_catalog(self):
        """Verify catalog returns both DPP and Vendor Due Diligence frameworks."""
        mock_fw_dict = MagicMock()
        mock_fw_dict.get_frameworks.return_value = []
        with patch.object(self.manager, "_init_data", return_value={"framework_dict": mock_fw_dict}):
            fws = self.manager.get_available_frameworks()
            self.assertGreaterEqual(len(fws), 2)
            ref_ids = [fw["ref_id"] for fw in fws]
            names = [fw["name"] for fw in fws]
            self.assertIn("mls", ref_ids)
            self.assertIn("vendor-due-diligence", ref_ids)
            self.assertIn("Multi-level DPP", names)
            self.assertIn("Vendor Due Diligence (VDD) - simple", names)

    def test_get_installed_frameworks_only_in_ciso_assistant(self):
        """Verify get_installed_frameworks only returns frameworks verified in CISO Assistant."""
        mock_fw_dpp = MagicMock()
        mock_fw_dpp.get_id.return_value = "fw-dpp-id"
        mock_fw_dpp.get_name.return_value = "Data protection policy of ACME Corp"
        mock_fw_dpp.json_object = {"ref_id": "mls", "urn": "urn:dpp"}

        mock_fw_dict = MagicMock()
        mock_fw_dict.get_frameworks.return_value = [mock_fw_dpp]

        with patch.object(self.manager, "_init_data", return_value={"framework_dict": mock_fw_dict}):
            installed = self.manager.get_installed_frameworks()
            self.assertEqual(len(installed), 1)
            self.assertEqual(installed[0]["id"], "fw-dpp-id")
            self.assertEqual(installed[0]["ref_id"], "mls")
            self.assertTrue(installed[0]["installed"])
            self.assertTrue(installed[0]["in_ciso_assistant"])

            # Verify uninstalled catalog frameworks are NOT in installed list
            ref_ids = [fw["ref_id"] for fw in installed]
            self.assertNotIn("vendor-due-diligence", ref_ids)

    def test_is_framework_in_ciso_assistant(self):
        """Verify is_framework_in_ciso_assistant checks framework existence in CISO Assistant."""
        mock_fw_dpp = MagicMock()
        mock_fw_dpp.get_id.return_value = "fw-dpp-id"
        mock_fw_dpp.get_name.return_value = "Multi-level DPP"
        mock_fw_dpp.json_object = {"ref_id": "mls", "urn": "urn:dpp"}

        mock_fw_dict = MagicMock()
        mock_fw_dict.get_frameworks.return_value = [mock_fw_dpp]
        mock_fw_dict.get_framework_by_identifier.side_effect = lambda ident: (
            mock_fw_dpp if ident in ("mls", "Multi-level DPP", "fw-dpp-id") else None
        )

        with patch.object(self.manager, "_init_data", return_value={"framework_dict": mock_fw_dict}):
            self.assertTrue(self.manager.is_framework_in_ciso_assistant("mls"))
            self.assertTrue(self.manager.is_framework_in_ciso_assistant("Multi-level DPP"))
            self.assertFalse(self.manager.is_framework_in_ciso_assistant("vendor-due-diligence"))
            self.assertFalse(self.manager.is_framework_in_ciso_assistant("non-existent"))
            self.assertFalse(self.manager.is_framework_in_ciso_assistant(None))

    def test_find_target_framework_rejects_uninstalled(self):
        """Verify find_target_framework returns None for uninstalled framework instead of falling back."""
        mock_fw_dpp = MagicMock()
        mock_fw_dpp.get_id.return_value = "fw-dpp-id"
        mock_fw_dpp.get_name.return_value = "Multi-level DPP"
        mock_fw_dpp.json_object = {"ref_id": "mls", "urn": "urn:dpp"}

        mock_fw_dict = MagicMock()
        mock_fw_dict.get_frameworks.return_value = [mock_fw_dpp]
        mock_fw_dict.get_framework_by_identifier.side_effect = lambda ident: (
            mock_fw_dpp if ident in ("mls", "Multi-level DPP", "fw-dpp-id") else None
        )

        with patch.object(self.manager, "_init_data", return_value={"framework_dict": mock_fw_dict}):
            # Explicit target that does not exist in CISO Assistant must return None
            result = self.manager.find_target_framework("vendor-due-diligence")
            self.assertIsNone(result)

            # Default (no target) should still return default
            result_def = self.manager.find_target_framework(None)
            self.assertEqual(result_def, mock_fw_dpp)

    def test_resolve_framework_yaml_path(self):
        """Verify framework YAML resolution for ref_id, name, and default."""
        from pathlib import Path
        # By ref_id
        path_mls = self.manager.resolve_framework_yaml_path("mls")
        self.assertEqual(path_mls, Path("YML/newDPP.yml"))
        path_vdd = self.manager.resolve_framework_yaml_path("vendor-due-diligence")
        self.assertEqual(path_vdd, Path("YML/vendor-due-diligence.yaml"))

        # By name
        path_dpp_name = self.manager.resolve_framework_yaml_path("Multi-level DPP")
        self.assertEqual(path_dpp_name, Path("YML/newDPP.yml"))
        path_vdd_name = self.manager.resolve_framework_yaml_path("Vendor Due Diligence (VDD) - simple")
        self.assertEqual(path_vdd_name, Path("YML/vendor-due-diligence.yaml"))

        # Default fallback
        path_def = self.manager.resolve_framework_yaml_path(None)
        self.assertEqual(path_def, Path("YML/newDPP.yml"))

    def test_find_target_framework_selection(self):
        """Verify find_target_framework matches by ref_id and name."""
        mock_fw_dpp = MagicMock()
        mock_fw_dpp.get_id.return_value = "fw-dpp-id"
        mock_fw_dpp.get_name.return_value = "Multi-level DPP"
        mock_fw_dpp.json_object = {"ref_id": "mls", "urn": "urn:dpp"}

        mock_fw_vdd = MagicMock()
        mock_fw_vdd.get_id.return_value = "fw-vdd-id"
        mock_fw_vdd.get_name.return_value = "Vendor Due Diligence (VDD) - simple"
        mock_fw_vdd.json_object = {"ref_id": "vendor-due-diligence", "urn": "urn:vdd"}

        mock_fw_dict = MagicMock()
        mock_fw_dict.get_frameworks.return_value = [mock_fw_dpp, mock_fw_vdd]
        mock_fw_dict.get_framework_by_identifier.side_effect = lambda ident: (
            mock_fw_vdd if ident in ("vendor-due-diligence", "Vendor Due Diligence (VDD) - simple", "fw-vdd-id")
            else (mock_fw_dpp if ident in ("mls", "Multi-level DPP", "fw-dpp-id") else None)
        )

        mock_data = {"framework_dict": mock_fw_dict}
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            # Select VDD by ref_id
            selected_vdd = self.manager.find_target_framework("vendor-due-diligence")
            self.assertEqual(selected_vdd, mock_fw_vdd)

            # Select DPP by ref_id
            selected_dpp = self.manager.find_target_framework("mls")
            self.assertEqual(selected_dpp, mock_fw_dpp)

            # Default
            selected_def = self.manager.find_target_framework()
            self.assertEqual(selected_def, mock_fw_dpp)

    @patch("classes.utils.get_return")
    def test_create_application_for_audit_with_framework_selection(self, mock_get_return):
        """Verify create_application_for_audit uses the selected framework and returns its info."""
        mock_fw_vdd = MagicMock()
        mock_fw_vdd.get_id.return_value = "fw-vdd-id"
        mock_fw_vdd.get_name.return_value = "Vendor Due Diligence (VDD) - simple"
        mock_fw_vdd.json_object = {"ref_id": "vendor-due-diligence"}

        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "user_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "framework_dict": MagicMock(),
            "framework_file": MagicMock(),
        }
        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-test"
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "asset-test"
        mock_data["user_dict"].get_id_from_email.return_value = "user-test"
        mock_data["entity_dict"].get_id_from_name.return_value = "entity-test"
        mock_data["entity_dict"].create_entity.return_value = {"id": "entity-test"}
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {}
        mock_data["compliance_assessment_dict"].requirement_assignments.get_requirement_assignment_id_list_from_compliance_assessment_id.return_value = ["assign-1"]
        mock_data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id.return_value = ["ra-1"]

        mock_ca_created = MagicMock()
        mock_ca_created.get_id.return_value = "ca-test"
        mock_ca_created.get_name.return_value = "Assessment of Vendor Due Diligence (VDD) - simple in App-Vendor-Demo"
        mock_ca_created.get_status.return_value = "in_progress"

        mock_get_return.return_value = {"id": "ca-test"}

        def reload_ca():
            mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-test": mock_ca_created}
        mock_data["compliance_assessment_dict"].reload.side_effect = reload_ca

        with patch.object(self.manager, "_init_data", return_value=mock_data), \
             patch.object(self.manager, "get_or_create_folder", return_value="folder-1"), \
             patch.object(self.manager, "get_default_assignee_id", return_value="assignee-1"), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw_vdd):

            res = self.manager.create_application_for_audit(
                app_name="App-Vendor-Demo",
                user_email="vendor@example.com",
                framework_ref_or_name="vendor-due-diligence",
            )
            self.assertEqual(res["framework_id"], "fw-vdd-id")
            self.assertEqual(res["framework_name"], "Vendor Due Diligence (VDD) - simple")
            self.assertEqual(res["framework_ref"], "vendor-due-diligence")
            self.assertEqual(res["compliance_assessment_id"], "ca-test")

    def test_create_examples_ui_uses_associated_framework(self):
        """Verify create_examples_ui provisions an example using its associated framework."""
        from main import create_examples_ui
        mock_fw = MagicMock()
        mock_fw.get_name.return_value = "Multi-level DPP"
        with patch.object(self.manager, "test_connection", return_value=(True, "OK")), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch.object(self.manager, "create_example_application", return_value={"perimeter_id": "p1", "compliance_assessment_name": "ca1", "answers_updated": 5, "scenarios_created": 3}) as mock_create, \
             patch("main.show_status"):
            create_examples_ui(self.manager, target="app_secure_core")
            mock_create.assert_called_once_with("app_secure_core", framework_ref_or_name="mls")

    def test_create_examples_ui_vendor_uses_associated_framework(self):
        """Verify create_examples_ui provisions vendor example using vendor-due-diligence."""
        from main import create_examples_ui
        mock_fw = MagicMock()
        mock_fw.get_name.return_value = "Vendor Due Diligence"
        with patch.object(self.manager, "test_connection", return_value=(True, "OK")), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch.object(self.manager, "create_example_application", return_value={"perimeter_id": "p1", "compliance_assessment_name": "ca1", "answers_updated": 5, "scenarios_created": 3}) as mock_create, \
             patch("main.show_status"):
            create_examples_ui(self.manager, target="vendor_cloud_crm")
            mock_create.assert_called_once_with("vendor_cloud_crm", framework_ref_or_name="vendor-due-diligence")

    def test_create_examples_ui_all_uses_each_apps_associated_framework(self):
        """Verify create_examples_ui with target='all' provisions each app with its own associated framework."""
        from main import create_examples_ui
        mock_fw = MagicMock()
        mock_fw.get_name.return_value = "Mock Framework"
        with patch.object(self.manager, "test_connection", return_value=(True, "OK")), \
             patch.object(self.manager, "find_target_framework", return_value=mock_fw), \
             patch.object(self.manager, "create_example_application", return_value={"perimeter_id": "p1", "compliance_assessment_name": "ca1", "answers_updated": 5, "scenarios_created": 3}) as mock_create, \
             patch("main.show_status"), \
             patch("time.sleep"):
            create_examples_ui(self.manager, target="all")
            self.assertEqual(mock_create.call_count, len(EXAMPLE_APPLICATIONS))
            # Verify DPP apps were called with 'mls', vendor apps with 'vendor-due-diligence', and appsec apps with 'appsec'
            for call_args in mock_create.call_args_list:
                app_id, kwargs = call_args[0][0], call_args[1]
                if "vendor" in app_id:
                    expected_fw = "vendor-due-diligence"
                elif "appsec" in app_id:
                    expected_fw = "appsec"
                else:
                    expected_fw = "mls"
                self.assertEqual(kwargs.get("framework_ref_or_name"), expected_fw)

    def test_create_examples_ui_skips_when_associated_framework_uninstalled(self):
        """Verify create_examples_ui skips applications whose associated framework is missing."""
        from main import create_examples_ui
        # MLS is installed, VDD and AppSec are not installed
        def mock_find_fw(target):
            if target in ("mls", "Multi-level DPP"):
                m = MagicMock()
                m.get_name.return_value = "Multi-level DPP"
                return m
            return None

        with patch.object(self.manager, "test_connection", return_value=(True, "OK")), \
             patch.object(self.manager, "find_target_framework", side_effect=mock_find_fw), \
             patch.object(self.manager, "create_example_application", return_value={"perimeter_id": "p1", "compliance_assessment_name": "ca1", "answers_updated": 5, "scenarios_created": 3}) as mock_create, \
             patch("main.show_status"), \
             patch("time.sleep"):
            create_examples_ui(self.manager, target="all")
            # Only the 8 DPP apps should be created; the 4 VDD and 3 AppSec apps skipped
            self.assertEqual(mock_create.call_count, 8)
            for call_args in mock_create.call_args_list:
                app_id = call_args[0][0]
                self.assertNotIn("vendor", app_id)
                self.assertNotIn("appsec", app_id)

    def test_interactive_menu_choice_3_offers_only_associated_framework(self):
        """Verify interactive menu Choice 3 offers only the associated framework for an example."""
        import io
        from main import interactive_menu
        mock_installed = [
            {"id": "fw-1", "name": "Multi-level DPP", "ref_id": "mls"},
            {"id": "fw-2", "name": "Vendor Due Diligence", "ref_id": "vendor-due-diligence"},
            {"id": "fw-3", "name": "ISO 27001:2022", "ref_id": "iso-27001"},
        ]
        # User selects choice 3, selects app 1 (App-Secure-Core), confirms creation with 'y', presses enter, then exits (0)
        simulated_inputs = ["3", "1", "y", "", "0"]
        stdout_buf = io.StringIO()

        mock_input = MagicMock(side_effect=simulated_inputs)
        with patch("builtins.input", mock_input), \
             patch.object(self.manager, "get_installed_frameworks", return_value=mock_installed), \
             patch.object(self.manager, "find_target_framework", return_value=MagicMock(get_name=MagicMock(return_value="Multi-level DPP"))), \
             patch("main.create_examples_ui") as mock_create_ui, \
             patch("sys.stdout", stdout_buf):
            interactive_menu(self.manager)

        output = stdout_buf.getvalue()
        # Verify it displayed the associated framework
        self.assertIn("Associated Framework:  Multi-level DPP (mls)", output)
        # Verify the confirmation prompt offered only the associated framework
        confirm_call_prompt = mock_input.call_args_list[2][0][0]
        self.assertIn("Create 'App-Secure-Core' with associated framework 'Multi-level DPP'?", confirm_call_prompt)
        # Verify it did NOT offer a numbered list of all frameworks
        self.assertNotIn("Select Framework for App-Secure-Core", output)
        # Verify create_examples_ui was called with the associated framework
        mock_create_ui.assert_called_once_with(self.manager, target="app_secure_core", framework_ref_or_name="mls")

    def test_interactive_menu_choice_3_blocks_when_associated_framework_uninstalled(self):
        """Verify Choice 3 refuses creation when the associated framework is not in CISO Assistant."""
        import io
        from main import interactive_menu
        # Only MLS installed, VDD is not
        mock_installed = [{"id": "fw-1", "name": "Multi-level DPP", "ref_id": "mls"}]
        # User selects choice 3, selects Vendor-Cloud-CRM (index 9), then exits (0)
        simulated_inputs = ["3", "9", "0"]
        stdout_buf = io.StringIO()

        def mock_find_fw(target):
            if target in ("mls", "Multi-level DPP"):
                return MagicMock()
            return None

        with patch("builtins.input", side_effect=simulated_inputs), \
             patch.object(self.manager, "get_installed_frameworks", return_value=mock_installed), \
             patch.object(self.manager, "find_target_framework", side_effect=mock_find_fw), \
             patch("main.create_examples_ui") as mock_create_ui, \
             patch("sys.stdout", stdout_buf):
            interactive_menu(self.manager)

        output = stdout_buf.getvalue()
        self.assertIn("Associated framework 'Vendor Due Diligence (VDD) - simple' (vendor-due-diligence) is not installed in CISO Assistant", output)
        mock_create_ui.assert_not_called()

    def test_vdd_conditional_requirements_vendor_cloud_crm(self):
        """Verify Vendor-Cloud-CRM dynamically triggers SaaS, AI, sub-processor, and confidential requirements, skipping Secret-only controls."""
        import yaml
        from classes.examples_manager import ExamplesManager
        with open("YML/vendor-due-diligence.yaml") as f:
            vdd = yaml.safe_load(f)
        assessable = [n for n in vdd["objects"]["framework"]["requirement_nodes"] if n.get("assessable")]

        mock_ras = []
        for n in assessable:
            ref = n.get("ref_id")
            ra = MagicMock()
            ra.get_requirement_ref_id.return_value = ref
            ra.get_urn.return_value = n.get("urn")
            # Mark all as unassessed initially so triggered logic determines active count
            ra.has_selected_answer.return_value = False
            ra.is_unassessed_result.return_value = True
            ra.get_answers.return_value = {}
            mock_ras.append(ra)

        ans_count, trig_count = ExamplesManager._resolve_triggered_requirements(
            mock_ras, yaml_path="test_data/vendor_cloud_crm.yml"
        )
        # 74 active requirements out of 80 total in framework (6 Secret-only controls skipped)
        self.assertEqual(trig_count, 74)

        # Now simulate all 74 active requirements answered in the assessment
        with open("test_data/vendor_cloud_crm.yml") as f:
            crm_answers = yaml.safe_load(f).get("answers", [])
        answered_refs = {a["requirement"] for a in crm_answers}
        for ra in mock_ras:
            if ra.get_requirement_ref_id() in answered_refs:
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = False

        ans_count2, trig_count2 = ExamplesManager._resolve_triggered_requirements(
            mock_ras, yaml_path="test_data/vendor_cloud_crm.yml"
        )
        self.assertEqual(ans_count2, 74)
        self.assertEqual(trig_count2, 74)

        # Build status dict and verify status is FULLY CONFIGURED, NOT AUDIT PARTIAL
        status = ExamplesManager._build_status_dict(
            app_id="vendor_cloud_crm",
            app_name="Vendor-Cloud-CRM",
            label="Vendor-Cloud-CRM (Tier 2 Confidential / 100% Compliant)",
            yaml_path="test_data/vendor_cloud_crm.yml",
            ca_obj=MagicMock(get_id=MagicMock(return_value="ca-crm"), get_status=MagicMock(return_value="in_progress")),
            ra_obj=MagicMock(get_id=MagicMock(return_value="ra-crm")),
            ra_scenarios_count=10,
            ctrl_count=5,
            existing_ctrls_linked=5,
            req_by_ca={"ca-crm": mock_ras},
        )
        self.assertEqual(status["lifecycle_status"], "FULLY CONFIGURED")
        self.assertEqual(status["audit_completion_pct"], 100)
        self.assertNotIn("PARTIAL", status["lifecycle_status"])

    def test_vdd_conditional_requirements_vendor_marketing_widget(self):
        """Verify Vendor-Marketing-Widget triggers only baseline and basic SaaS, skipping AI, subproc, SDLC, and confidential groups."""
        import yaml
        from classes.examples_manager import ExamplesManager
        with open("YML/vendor-due-diligence.yaml") as f:
            vdd = yaml.safe_load(f)
        assessable = [n for n in vdd["objects"]["framework"]["requirement_nodes"] if n.get("assessable")]

        mock_ras = []
        for n in assessable:
            ref = n.get("ref_id")
            ra = MagicMock()
            ra.get_requirement_ref_id.return_value = ref
            ra.get_urn.return_value = n.get("urn")
            ra.has_selected_answer.return_value = False
            ra.is_unassessed_result.return_value = True
            ra.get_answers.return_value = {}
            mock_ras.append(ra)

        ans_count, trig_count = ExamplesManager._resolve_triggered_requirements(
            mock_ras, yaml_path="test_data/vendor_marketing_widget.yml"
        )
        # Only 43 active requirements triggered out of 80
        self.assertEqual(trig_count, 43)

    def test_vdd_framework_service_and_classification_questions(self):
        """Verify VDD framework structure: PROF.00 is first with service delivery questions and PROF.01 sets implementation groups."""
        import yaml
        with open("YML/vendor-due-diligence.yaml") as f:
            vdd = yaml.safe_load(f)

        framework = vdd["objects"]["framework"]
        # Verify implementation_groups_definition exists and defines expected groups
        ig_defs = {ig["ref_id"]: ig for ig in framework.get("implementation_groups_definition", [])}
        self.assertIn("info", ig_defs)
        self.assertIn("saas_app", ig_defs)
        self.assertIn("ai_service", ig_defs)
        self.assertIn("subprocessors_used", ig_defs)
        self.assertIn("confidential_vendor", ig_defs)
        self.assertIn("secret_vendor", ig_defs)
        self.assertTrue(ig_defs["info"].get("default_selected"))

        req_nodes = framework["requirement_nodes"]
        assessable = [n for n in req_nodes if n.get("assessable")]
        first_assessable = assessable[0]

        # First question is PROF.00: service delivery model
        self.assertEqual(first_assessable.get("ref_id"), "PROF.00")
        self.assertEqual(first_assessable.get("name"), "Vendor service type and delivery model")
        q1 = first_assessable["questions"]["urn:intuitem:risk:req_node:vendor-due-diligence:service_type:q1"]
        self.assertIn("primary service delivery model", q1["text"])
        saas_choice = next(c for c in q1["choices"] if "SaaS" in c["value"])
        self.assertIn("saas_app", saas_choice.get("select_implementation_groups", []))

        # PROF.01: data classification sets implementation groups like newDPP
        prof_01 = next(n for n in assessable if n.get("ref_id") == "PROF.01")
        q_conf = prof_01["questions"]["urn:intuitem:risk:req_node:vendor-due-diligence:vendor_classification:q1"]
        c_conf = next(c for c in q_conf["choices"] if "Confidential" in c["value"])
        self.assertIn("confidential_vendor", c_conf.get("select_implementation_groups", []))
        c_sec = next(c for c in q_conf["choices"] if "Secret" in c["value"])
        self.assertIn("secret_vendor", c_sec.get("select_implementation_groups", []))

    def test_vdd_coverage_for_user_requested_vendor_types(self):
        """Verify conditional scoping for the 4 user-requested vendor types:
        1. Marketplace software maker (SaaS, sub-processors, SDLC, Confidential)
        2. Transport provider (Physical logistics, sub-contracted carriers, Internal)
        3. Ex-subsidiary writing software (Custom SDLC, workstation controls, Confidential)
        4. Online project management SaaS augmented with AI (SaaS, AI, sub-processors, Confidential)
        """
        import yaml
        from classes.examples_manager import ExamplesManager
        with open("YML/vendor-due-diligence.yaml") as f:
            vdd = yaml.safe_load(f)
        assessable = [n for n in vdd["objects"]["framework"]["requirement_nodes"] if n.get("assessable")]

        def _make_mock_ras(prof00_answers, prof01_answer):
            ras = []
            for n in assessable:
                ref = n.get("ref_id")
                ra = MagicMock()
                ra.get_requirement_ref_id.return_value = ref
                ra.get_urn.return_value = n.get("urn")
                ra.has_selected_answer.return_value = False
                ra.is_unassessed_result.return_value = True
                answers = {}
                if ref in ("PROF.00", "service_type"):
                    answers = prof00_answers
                elif ref in ("PROF.01", "vendor_classification"):
                    answers = {"q1": prof01_answer}
                ra.get_answers.return_value = answers
                ras.append(ra)
            return ras

        # 1. Marketplace software maker
        marketplace_ras = _make_mock_ras(
            prof00_answers={
                "q1": "SaaS / Cloud Software Platform (e.g., marketplace engine, CRM, collaboration tool)",
                "q2": "No - Does not use Artificial Intelligence",
                "q3": "Yes - Relies on sub-processors or hosting subcontractors",
                "q4": "Yes - Active software development lifecycle and code updates",
            },
            prof01_answer="Tier 2 / Confidential - High Criticality",
        )
        _, trig_mkt = ExamplesManager._resolve_triggered_requirements(marketplace_ras)
        # Triggers baseline, SaaS, cloud infra, sub-processors, SDLC, confidential (skips AI and Secret)
        self.assertEqual(trig_mkt, 70)

        # 2. Transport provider
        transport_ras = _make_mock_ras(
            prof00_answers={
                "q1": "Physical Logistics, Fleet & Freight Transport Services",
                "q2": "No - Does not use Artificial Intelligence",
                "q3": "Yes - Relies on sub-processors or hosting subcontractors",
                "q4": "No - Standard off-the-shelf service without custom software development",
            },
            prof01_answer="Tier 3 / Internal - Moderate Criticality",
        )
        _, trig_trans = ExamplesManager._resolve_triggered_requirements(transport_ras)
        # Triggers baseline info + sub-contracted carriers (21 requirements, skipping SaaS web app controls & custom SDLC)
        self.assertEqual(trig_trans, 21)

        # 3. Ex-subsidiary writing software for client
        ex_sub_ras = _make_mock_ras(
            prof00_answers={
                "q1": "Custom Software Development & Dedicated Engineering Team (e.g., outsourced developers, captive / ex-subsidiary)",
                "q2": "No - Does not use Artificial Intelligence",
                "q3": "No - Direct self-contained service without sub-processors",
                "q4": "Yes - Active software development lifecycle and code updates",
            },
            prof01_answer="Tier 2 / Confidential - High Criticality",
        )
        _, trig_ex_sub = ExamplesManager._resolve_triggered_requirements(ex_sub_ras)
        # Triggers SDLC, developer workstation security, confidential data/IP protection, baseline
        self.assertEqual(trig_ex_sub, 65)

        # 4. Online project management SaaS augmented with AI
        pm_ai_ras = _make_mock_ras(
            prof00_answers={
                "q1": "SaaS / Cloud Software Platform (e.g., marketplace engine, CRM, collaboration tool)",
                "q2": "Yes - Incorporates AI or LLM features",
                "q3": "Yes - Relies on sub-processors or hosting subcontractors",
                "q4": "No - Standard off-the-shelf service without custom software development",
            },
            prof01_answer="Tier 2 / Confidential - High Criticality",
        )
        _, trig_pm_ai = ExamplesManager._resolve_triggered_requirements(pm_ai_ras)
        # Triggers baseline, SaaS, cloud infra, AI model controls, sub-processors, confidential (skips custom SDLC and Secret)
        self.assertEqual(trig_pm_ai, 64)


if __name__ == "__main__":
    unittest.main()

