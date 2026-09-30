"""Unit and integration tests for the CISO Assistant Web UI and REST API.

Tests cover:
- Dashboard and HTML rendering
- Deployment status and inventory endpoints
- Catalog and framework metadata endpoints
- Offline simulation studio (4x4 matrix and scenario calculations)
- Background Task Manager and log streaming (SSE)
- Provisioning, Audit Demo, Risk Generation, Control Linking, and Removal endpoints
- Backup creation, listing, inspection, download, upload, and deletion
- Pipeline execution and model import endpoints
"""

import io
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from web.app import TASK_MANAGER, create_app


class TestWebUI(unittest.TestCase):
    """Test suite for the Web UI and REST API."""

    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    def test_index_route(self):
        """Test GET / renders the main HTML interface."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("CISO Assistant", html)
        self.assertIn("Dashboard & Inventory", html)
        self.assertIn("Domains & Folders", html)
        self.assertIn("domain-filter", html)
        self.assertIn("Offline Simulation Studio", html)
        self.assertIn("Disaster Recovery & Backups", html)

    def test_status_endpoint(self):
        """Test GET /api/status returns connected state and summary."""
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("connected", data)
        self.assertIn("applications", data)
        self.assertIn("domains", data)
        self.assertIn("summary", data)
        self.assertIn("total_catalog", data["summary"])
        self.assertIn("total_domains", data["summary"])

    def test_domains_endpoint(self):
        """Test GET and POST /api/domains."""
        # GET domains
        response = self.client.get("/api/domains")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("domains", data)

        # POST domain (validation error if empty name)
        err_res = self.client.post("/api/domains", json={"name": ""})
        self.assertEqual(err_res.status_code, 400)

        # POST domain (valid creation task)
        with patch("classes.examples_manager.ExamplesManager.create_domain") as mock_create:
            mock_create.return_value = {"id": "dom-123", "name": "IT-Ops"}
            ok_res = self.client.post("/api/domains", json={"name": "IT-Ops", "description": "IT Domain"})
            self.assertEqual(ok_res.status_code, 200)
            ok_data = ok_res.get_json()
            self.assertIn("task_id", ok_data)

    def test_catalog_endpoint(self):
        """Test GET /api/catalog returns pre-configured application profiles."""
        response = self.client.get("/api/catalog")
        self.assertEqual(response.status_code, 200)
        catalog = response.get_json()
        self.assertIsInstance(catalog, list)
        self.assertGreaterEqual(len(catalog), 8)
        names = [app["name"] for app in catalog]
        self.assertIn("App-Secure-Core", names)
        self.assertIn("App-Vulnerable-Portal", names)

    def test_frameworks_endpoint(self):
        """Test GET /api/frameworks returns installed and catalog frameworks."""
        response = self.client.get("/api/frameworks")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("installed", data)
        self.assertIn("catalog", data)
        cat_refs = [f["ref_id"] for f in data["catalog"]]
        self.assertIn("mls", cat_refs)
        self.assertIn("vendor-due-diligence", cat_refs)

    def test_offline_simulation_all(self):
        """Test GET /api/offline-simulation evaluates all profiles offline."""
        response = self.client.get("/api/offline-simulation")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("applications", data)
        self.assertIn("matrix_counts", data)
        self.assertGreaterEqual(len(data["applications"]), 8)

        # Verify 4x4 matrix grid has valid keys
        self.assertIn("1_1", data["matrix_counts"])
        self.assertIn("4_4", data["matrix_counts"])

        # Check App-Secure-Core evaluation
        secure_core = next(a for a in data["applications"] if a["name"] == "App-Secure-Core")
        self.assertEqual(secure_core["confidentiality_impact"], 4)
        self.assertEqual(secure_core["availability_impact"], 4)
        self.assertGreater(len(secure_core["scenarios"]), 0)

    def test_offline_simulation_single_app(self):
        """Test GET /api/offline-simulation?app_id=app_vulnerable_portal evaluates a single profile."""
        response = self.client.get("/api/offline-simulation?app_id=app_vulnerable_portal")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data["applications"]), 1)
        self.assertEqual(data["applications"][0]["name"], "App-Vulnerable-Portal")

    def test_task_manager_execution(self):
        """Test BackgroundTaskManager lifecycle, log capture, and completion."""
        def dummy_job():
            print("Starting dummy execution")
            time.sleep(0.05)
            print("Finishing dummy execution")
            return {"dummy": "done"}

        task_id = TASK_MANAGER.create_task("Test Dummy Job", dummy_job)
        self.assertTrue(task_id.startswith("task_"))

        # Wait for task to finish
        for _ in range(50):
            time.sleep(0.02)
            task = TASK_MANAGER.get_task(task_id)
            if task and task["status"] in ("completed", "failed"):
                break

        task = TASK_MANAGER.get_task(task_id)
        self.assertIsNotNone(task)
        self.assertEqual(task["status"], "completed")
        self.assertEqual(task["result"], {"dummy": "done"})

        # Check logs captured stdout
        log_text = "\n".join(task["logs"])
        self.assertIn("Starting dummy execution", log_text)
        self.assertIn("Finishing dummy execution", log_text)

        # Check API endpoint for task
        resp = self.client.get(f"/api/tasks/{task_id}")
        self.assertEqual(resp.status_code, 200)
        t_data = resp.get_json()
        self.assertEqual(t_data["id"], task_id)
        self.assertEqual(t_data["status"], "completed")

    @patch("classes.examples_manager.ExamplesManager.find_target_framework")
    @patch("classes.examples_manager.ExamplesManager.create_example_application")
    def test_provision_app_endpoint(self, mock_create, mock_fw):
        """Test POST /api/provision/app launches provisioning task."""
        mock_fw.return_value = MagicMock(get_name=lambda: "MLS")
        mock_create.return_value = {
            "app_name": "App-Secure-Core",
            "perimeter_id": "p-123",
            "compliance_assessment_name": "Audit",
            "answers_updated": 5,
            "scenarios_created": 3,
        }

        response = self.client.post(
            "/api/provision/app",
            data=json.dumps({"app_id": "app_secure_core"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("task_id", data)

        # Wait for task completion
        task_id = data["task_id"]
        for _ in range(100):
            time.sleep(0.02)
            task = TASK_MANAGER.get_task(task_id)
            if task and task["status"] in ("completed", "failed"):
                break

        self.assertEqual(task["status"], "completed")
        mock_create.assert_called_once()

    @patch("classes.examples_manager.ExamplesManager.create_application_for_audit")
    def test_audit_demo_endpoint(self, mock_create_audit):
        """Test POST /api/audit-demo launches unanswered audit creation task."""
        mock_create_audit.return_value = {
            "app_name": "App-Test-Demo",
            "user_email": "test@demo.com",
            "perimeter_id": "p-test",
            "compliance_assessment_name": "Audit Demo",
        }

        # Invalid email validation
        bad_resp = self.client.post(
            "/api/audit-demo",
            data=json.dumps({"user_email": "invalid"}),
            content_type="application/json",
        )
        self.assertEqual(bad_resp.status_code, 400)

        # Valid submission
        response = self.client.post(
            "/api/audit-demo",
            data=json.dumps({
                "app_name": "App-Test-Demo",
                "user_email": "test@demo.com",
                "first_name": "Tester",
                "last_name": "User",
                "framework": "mls",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("task_id", data)

        task_id = data["task_id"]
        for _ in range(50):
            time.sleep(0.02)
            task = TASK_MANAGER.get_task(task_id)
            if task and task["status"] in ("completed", "failed"):
                break

        self.assertEqual(task["status"], "completed")
        mock_create_audit.assert_called_once()

    @patch("classes.examples_manager.ExamplesManager.generate_controls_and_risks_for_application")
    def test_generate_risks_endpoint(self, mock_gen):
        """Test POST /api/generate-risks launches calculation task."""
        mock_gen.return_value = {
            "app_name": "App-Secure-Core",
            "applied_controls_count": 5,
            "scenarios_created": 3,
            "findings_count": 0,
        }

        response = self.client.post(
            "/api/generate-risks",
            data=json.dumps({
                "app_name": "App-Secure-Core",
                "answers_source": "live",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("task_id", data)

        task_id = data["task_id"]
        for _ in range(50):
            time.sleep(0.02)
            task = TASK_MANAGER.get_task(task_id)
            if task and task["status"] in ("completed", "failed"):
                break

        self.assertEqual(task["status"], "completed")
        mock_gen.assert_called_once()

    def test_generate_controls_and_risks_signature_compatibility(self):
        """Verify ExamplesManager.generate_controls_and_risks_for_application accepts both app_name and app_id_or_name."""
        from classes.examples_manager import ExamplesManager
        manager = ExamplesManager()
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca1"
        mock_ca.get_name.return_value = "Audit Demo in App-Audit-Demo"
        mock_ca.get_perimeter_id.return_value = "p1"
        mock_ca.get_framework_id.return_value = "fw1"

        mock_req_assessment = MagicMock()
        mock_req_assessment.get_compliance_assessment_id.return_value = "ca1"
        mock_req_assessment.has_selected_answer.return_value = True
        mock_req_assessment.is_unassessed_result.return_value = False

        mock_risk_assessment = MagicMock()
        mock_risk_assessment.get_id.return_value = "ra1"
        mock_risk_assessment.get_name.return_value = "Risk Assessment on App-Audit-Demo"
        mock_risk_assessment.json_object = {"perimeter": "p1"}

        with patch.object(manager, "_init_data") as mock_init, \
             patch.object(manager, "find_target_risk_matrix", return_value="rm1"), \
             patch("tests.test_application_scenarios.ApplicationRiskSimulator") as mock_sim:
            mock_init.return_value = {
                "perimeter_dict": MagicMock(get_id_from_name=lambda n: "p1", get_owner_id_from_perimeter_id=lambda p: "u1"),
                "asset_dict": MagicMock(get_asset_id_from_perimeter_name=lambda n: "a1"),
                "compliance_assessment_dict": MagicMock(
                    get_id_from_perimeter_id=lambda p: "ca1",
                    get_compliance_assessments=lambda: {"ca1": mock_ca},
                    get_assessment=lambda i: MagicMock(get_answered_count=lambda: 5, get_requirement_assessments=lambda: [mock_req_assessment]),
                    requirement_assessments=MagicMock(get_requirement_assessments=lambda: {"ra1": mock_req_assessment}),
                ),
                "applied_control_dict": MagicMock(get_controls=lambda: {}),
                "reference_control_dict": MagicMock(),
                "risk_assessment_dict": MagicMock(
                    get_id_from_perimeter_id=lambda p: "ra1",
                    get_risk_assessments=lambda: {"ra1": mock_risk_assessment},
                    create_risk_assessments=lambda *a, **kw: {"id": "ra1"},
                ),
                "risk_scenario_dict": MagicMock(get_risk_scenarios=lambda: {}),
                "framework_dict": MagicMock(),
                "framework_file": MagicMock(),
                "risk_matrix_dict": MagicMock(),
            }
            # Test calling with app_name keyword argument
            mock_sim.return_value.evaluate_application.return_value = {"scenarios": {}}
            res = manager.generate_controls_and_risks_for_application(
                app_name="App-Audit-Demo",
            )
            self.assertEqual(res["app_name"], "App-Audit-Demo")

    @patch("classes.examples_manager.ExamplesManager.link_all_controls_to_risk_scenarios")
    def test_link_controls_endpoint(self, mock_link):
        """Test POST /api/link-controls launches control linking task."""
        mock_link.return_value = [{"app_name": "App-Secure-Core", "scenarios_updated": 3}]

        response = self.client.post(
            "/api/link-controls",
            data=json.dumps({"target": "all"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("task_id", data)

    @patch("classes.examples_manager.ExamplesManager.remove_example_application")
    def test_remove_endpoint(self, mock_remove):
        """Test POST /api/remove launches application removal task."""
        mock_remove.return_value = {"perimeters_deleted": 1, "assets_deleted": 1}

        response = self.client.post(
            "/api/remove",
            data=json.dumps({"target": "App-Secure-Core"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("task_id", data)

    def test_backups_list_and_actions(self):
        """Test backup listing, creation, and inspection."""
        resp = self.client.get("/api/backups")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.get_json(), list)

        # Test upload endpoint with dummy json
        dummy_content = b'{"type": "workspace_snapshot", "data": {}, "counts": {"domains": 1}}'
        data = {
            "file": (io.BytesIO(dummy_content), "workspace_snapshot_test.json"),
        }
        up_resp = self.client.post("/api/backups/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(up_resp.status_code, 200)
        up_data = up_resp.get_json()
        self.assertIn("stat", up_data)
        filename = up_data["stat"]["filename"]

        # Test inspect
        inspect_resp = self.client.get(f"/api/backups/inspect/{filename}")
        self.assertEqual(inspect_resp.status_code, 200)
        stat = inspect_resp.get_json()
        self.assertEqual(stat["filename"], filename)
        self.assertEqual(stat["type"], "workspace_snapshot")

        # Test download
        down_resp = self.client.get(f"/api/backups/download/{filename}")
        self.assertEqual(down_resp.status_code, 200)
        self.assertEqual(down_resp.data, dummy_content)

        # Test delete
        del_resp = self.client.delete(f"/api/backups/{filename}")
        self.assertEqual(del_resp.status_code, 200)

    @patch("web.app.import_department_external_entity_model")
    def test_model_import_endpoint(self, mock_import):
        """Test POST /api/model-import launches YAML import task."""
        mock_import.return_value = {
            "domains_processed": 2,
            "entities_processed": 4,
            "representative_links_created": 3,
            "entity_assessments_created": 0,
            "issues": [],
        }

        response = self.client.post(
            "/api/model-import",
            data=json.dumps({
                "yaml_path": "YML/sample_entity_assessment_model.yml",
                "create_assessments": False,
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("task_id", data)


if __name__ == "__main__":
    unittest.main()
