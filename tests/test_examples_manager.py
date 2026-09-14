"""Unit tests for the ExamplesManager class and example application simulation."""

import unittest
from unittest.mock import MagicMock, patch

from classes.examples_manager import (
    EXAMPLE_APPLICATIONS,
    ExamplesManager,
)


class TestExamplesManager(unittest.TestCase):
    """Test suite for ExamplesManager operations, creation, and removal workflows."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_example_applications_definitions(self):
        """Verify the 8 expected example applications are defined with valid CSV files."""
        self.assertEqual(len(EXAMPLE_APPLICATIONS), 8)
        app_names = [a["name"] for a in EXAMPLE_APPLICATIONS]
        self.assertIn("App-Secure-Core", app_names)
        self.assertIn("App-Vulnerable-Portal", app_names)
        self.assertIn("App-Internal-Tool", app_names)
        self.assertIn("App-Public-Blog", app_names)
        self.assertIn("App-HR-People-System", app_names)
        self.assertIn("App-Customer-Payment-API", app_names)
        self.assertIn("App-Legacy-ERP-Production", app_names)
        self.assertIn("App-AI-Analytics-Workbench", app_names)

        for app in EXAMPLE_APPLICATIONS:
            self.assertTrue(app["csv_path"].endswith(".csv"))

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

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            status = self.manager.get_status()
            self.assertEqual(len(status), len(EXAMPLE_APPLICATIONS))
            for item in status:
                self.assertFalse(item["exists"])
                self.assertIn("user_email", item)
                self.assertIn("entity_id", item)
                self.assertIn("entity_assessment_id", item)

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
        }

        app_name = "App-Secure-Core"
        perimeter_id = "perm-uuid-1"
        asset_id = "asset-uuid-1"
        ca_id = "ca-uuid-1"
        ra_id = "ra-uuid-1"
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
            mock_data["risk_scenario_dict"].delete_scenarios_for_risk_assessment.assert_called_once_with(ra_id)
            mock_data["risk_assessment_dict"].delete_risk_assessment.assert_called_once_with(ra_id)
            mock_data["applied_control_dict"].delete_applied_control.assert_called_once_with(ctrl_id)
            mock_data["compliance_assessment_dict"].delete_compliance_assessment.assert_called_once_with(ca_id)
            mock_data["asset_dict"].delete_asset.assert_called_once_with(asset_id)
            mock_data["perimeter_dict"].delete_perimeter.assert_called_once_with(perimeter_id)
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


    @patch("classes.integrations.csv_import.import_compliance_answers")
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


if __name__ == "__main__":
    unittest.main()

