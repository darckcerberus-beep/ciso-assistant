"""Unit and integration tests for FrameworkLoader and automated pre-operation backup."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import yaml

from classes.examples_manager import ExamplesManager
from classes.integrations.backup import BackupManager
from classes.integrations.framework_loader import FrameworkLoader


class TestFrameworkLoader(unittest.TestCase):
    """Test suite for FrameworkLoader pre-operation backup and loading workflows."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name) / "backups"
        self.backup_manager = BackupManager(backup_dir=self.backup_dir)
        self.loader = FrameworkLoader(backup_manager=self.backup_manager)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_framework_loader_init(self):
        """Verify proper initialization with default and custom components."""
        loader_default = FrameworkLoader()
        self.assertIsNotNone(loader_default.backup_manager)
        self.assertIsNone(loader_default.manager)

        mgr_mock = MagicMock()
        loader_custom = FrameworkLoader(backup_manager=self.backup_manager, manager=mgr_mock)
        self.assertEqual(loader_custom.backup_manager, self.backup_manager)
        self.assertEqual(loader_custom.manager, mgr_mock)

    def test_backup_existing_data_none(self):
        """Verify that backup_type='none' safely skips backup creation."""
        res = self.loader.backup_existing_data(backup_type="none")
        self.assertFalse(res["backup_created"])
        self.assertEqual(res["backup_type"], "none")

        res_skip = self.loader.backup_existing_data(backup_type="skip")
        self.assertFalse(res_skip["backup_created"])

    def test_backup_existing_data_snapshot(self):
        """Verify workspace snapshot creation before loading a framework."""
        mock_data = {
            "perimeter_dict": MagicMock(get_perimeters=MagicMock(return_value=[])),
            "asset_dict": MagicMock(get_assets=MagicMock(return_value=[])),
            "compliance_assessment_dict": MagicMock(get_compliance_assessments=MagicMock(return_value=[])),
            "applied_control_dict": MagicMock(get_controls=MagicMock(return_value=[])),
            "risk_assessment_dict": MagicMock(get_risk_assessments=MagicMock(return_value=[])),
            "risk_scenario_dict": MagicMock(get_risk_scenarios=MagicMock(return_value=[])),
            "findings_assessment_dict": MagicMock(get_findings_assessments=MagicMock(return_value=[])),
            "finding_dict": MagicMock(get_findings=MagicMock(return_value=[])),
        }
        mock_manager = MagicMock()
        mock_manager.folder_name = "TestDomain"
        mock_manager._init_data = MagicMock(return_value=mock_data)

        loader = FrameworkLoader(backup_manager=self.backup_manager, manager=mock_manager)
        res = loader.backup_existing_data(backup_type="snapshot", output_dir=self.backup_dir)

        self.assertTrue(res["backup_created"])
        self.assertEqual(res["backup_type"], "snapshot")
        self.assertTrue(Path(res["backup_path"]).exists())
        self.assertIn("workspace_snapshot", res["filename"])
        self.assertIsNotNone(res["checksum"])
        self.assertEqual(len(res["checksum"]), 64)

    def test_backup_existing_data_dump(self):
        """Verify database dump pre-load backup workflow."""
        fake_dump = self.backup_dir / "test.dump"
        fake_dump.parent.mkdir(parents=True, exist_ok=True)
        fake_dump.write_bytes(b"PGDUMP_BINARY_DATA")

        with patch.object(self.backup_manager, "create_database_dump", return_value=fake_dump):
            res = self.loader.backup_existing_data(backup_type="dump")
            self.assertTrue(res["backup_created"])
            self.assertEqual(res["backup_type"], "dump")
            self.assertEqual(res["filename"], "test.dump")
            self.assertEqual(res["file_size"], len(b"PGDUMP_BINARY_DATA"))

    def test_backup_existing_data_failure_raises(self):
        """Verify that pre-load backup failure raises RuntimeError to protect against unbacked changes."""
        with patch.object(self.backup_manager, "create_workspace_snapshot", side_effect=Exception("Disk full")):
            with self.assertRaises(RuntimeError) as ctx:
                self.loader.backup_existing_data(backup_type="snapshot")
            self.assertIn("Pre-load backup failed", str(ctx.exception))

    def test_prepare_framework_payload_yaml(self):
        """Verify reading, merging, and preparing a standard YAML framework."""
        fw_dict = {
            "name": "Custom Test Framework",
            "ref_id": "custom_fw",
            "urn": "urn:intuitem:risk:library:custom_fw",
            "version": 2,
            "objects": {
                "framework": {"name": "Custom Test Framework"}
            },
        }
        fw_path = Path(self.temp_dir.name) / "custom_fw.yaml"
        fw_path.write_text(yaml.dump(fw_dict), encoding="utf-8")

        content_bytes, filename, content_type, metadata = self.loader.prepare_framework_payload(fw_path)

        self.assertEqual(filename, "custom_fw.yaml")
        self.assertEqual(content_type, "application/yaml")
        self.assertEqual(metadata["name"], "Custom Test Framework")
        self.assertEqual(metadata["ref_id"], "custom_fw")
        self.assertEqual(metadata["version"], 2)

        # Verify decoded content is valid YAML
        parsed = yaml.safe_load(content_bytes.decode("utf-8"))
        self.assertEqual(parsed["name"], "Custom Test Framework")

    def test_prepare_framework_payload_version_override(self):
        """Verify custom_version parameter overrides version in payload."""
        fw_dict = {
            "name": "Versioned Framework",
            "ref_id": "ver_fw",
            "version": 1,
            "objects": {"framework": {}},
        }
        fw_path = Path(self.temp_dir.name) / "ver_fw.yaml"
        fw_path.write_text(yaml.dump(fw_dict), encoding="utf-8")

        content_bytes, _, _, metadata = self.loader.prepare_framework_payload(fw_path, custom_version=99)
        self.assertEqual(metadata["version"], 99)
        parsed = yaml.safe_load(content_bytes.decode("utf-8"))
        self.assertEqual(parsed["version"], 99)

    def test_prepare_framework_payload_appsec_manual(self):
        """Verify special dependency handling for appsec_manual."""
        manual_dict = {
            "name": "AppSec Manual",
            "ref_id": "appsec_manual",
            "objects": {
                "framework": {"name": "AppSec Manual IG"},
                "reference_controls": [{"urn": "c1"}],
            },
        }
        fw_path = Path(self.temp_dir.name) / "appsec_manual.yml"
        fw_path.write_text(yaml.dump(manual_dict), encoding="utf-8")

        content_bytes, _, _, _ = self.loader.prepare_framework_payload(fw_path)
        parsed = yaml.safe_load(content_bytes.decode("utf-8"))

        self.assertEqual(parsed["dependencies"], ["urn:intuitem:risk:library:appsec"])
        self.assertEqual(list(parsed["objects"].keys()), ["framework"])

    def test_prepare_framework_payload_not_found(self):
        """Verify FileNotFoundError on non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.loader.prepare_framework_payload("/non/existent/framework.yaml")

    def test_prepare_framework_payload_unsupported_format(self):
        """Verify ValueError on unsupported file extensions."""
        bad_path = Path(self.temp_dir.name) / "framework.txt"
        bad_path.write_text("Hello world", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            self.loader.prepare_framework_payload(bad_path)
        self.assertIn("Unsupported framework file format", str(ctx.exception))

    @patch("classes.utils.get_all_results")
    def test_list_stored_libraries_filtering(self, mock_get_results):
        """Verify query and loaded status filtering for stored libraries."""
        mock_libs = [
            {"id": "id-1", "ref_id": "ISO-27001", "name": "ISO/IEC 27001:2022", "is_loaded": True, "version": 1},
            {"id": "id-2", "ref_id": "NIST-CSF", "name": "NIST Cybersecurity Framework", "is_loaded": False, "version": 2},
            {"id": "id-3", "ref_id": "NIS2", "name": "European NIS 2 Directive", "is_loaded": False, "version": 1},
        ]
        mock_get_results.return_value = mock_libs

        # Unfiltered
        all_res = self.loader.list_stored_libraries()
        self.assertEqual(len(all_res), 3)

        # Loaded only
        loaded_res = self.loader.list_stored_libraries(loaded_only=True)
        self.assertEqual(len(loaded_res), 1)
        self.assertEqual(loaded_res[0]["ref_id"], "ISO-27001")

        # Unloaded only
        unloaded_res = self.loader.list_stored_libraries(unloaded_only=True)
        self.assertEqual(len(unloaded_res), 2)

        # Query filter
        query_res = self.loader.list_stored_libraries(query="NIST")
        self.assertEqual(len(query_res), 1)
        self.assertEqual(query_res[0]["ref_id"], "NIST-CSF")

    @patch("classes.utils.get_all_results")
    def test_find_stored_library(self, mock_get_results):
        """Verify finding stored libraries by ID, ref_id, or name."""
        mock_libs = [
            {"id": "uuid-123", "ref_id": "NIS-1", "name": "NIS Directive FR", "urn": "urn:nis:1"},
            {"id": "uuid-456", "ref_id": "CIS-v8", "name": "CIS Controls v8", "urn": "urn:cis:8"},
        ]
        mock_get_results.return_value = mock_libs

        # By exact ID
        self.assertEqual(self.loader.find_stored_library("uuid-123")["ref_id"], "NIS-1")
        # By ref_id
        self.assertEqual(self.loader.find_stored_library("cis-v8")["id"], "uuid-456")
        # By URN
        self.assertEqual(self.loader.find_stored_library("urn:nis:1")["id"], "uuid-123")
        # By name substring
        self.assertEqual(self.loader.find_stored_library("controls v8")["id"], "uuid-456")
        # Non-existent
        self.assertIsNone(self.loader.find_stored_library("non-existent"))

    @patch("classes.utils.get_all_results")
    def test_get_framework_status(self, mock_get_results):
        """Verify framework status inspection."""
        mock_stored = [{"id": "uuid-1", "ref_id": "appsec", "name": "AppSec", "is_loaded": True, "version": 31}]
        mock_fws = [{"id": "fw-1", "ref_id": "appsec", "name": "AppSec"}]

        def side_effect(endpoint, **kwargs):
            if "stored-libraries" in endpoint:
                return mock_stored
            elif "frameworks" in endpoint:
                return mock_fws
            return []

        mock_get_results.side_effect = side_effect

        status = self.loader.get_framework_status("appsec")
        self.assertTrue(status["is_stored"])
        self.assertTrue(status["is_loaded"])
        self.assertEqual(status["framework_name"], "AppSec")
        self.assertEqual(status["stored_version"], 31)

    @patch("requests.post")
    def test_import_stored_library_success(self, mock_post):
        """Verify import of a stored library with pre-load backup."""
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"status": "success"})

        with patch.object(self.loader, "find_stored_library") as mock_find:
            mock_find.return_value = {
                "id": "uuid-test-lib",
                "name": "Test Stored Framework",
                "ref_id": "test_fw",
                "urn": "urn:test:fw",
                "is_loaded": False,
                "version": 1,
            }
            with patch.object(self.loader, "backup_existing_data") as mock_backup:
                mock_backup.return_value = {"backup_created": True, "backup_type": "snapshot", "filename": "snap.json"}
                with patch.object(self.loader, "_sync_cache"):
                    res = self.loader.import_stored_library("test_fw", backup_first=True, backup_type="snapshot")

                    mock_backup.assert_called_once()
                    self.assertTrue(res["success"])
                    self.assertEqual(res["action"], "imported")
                    self.assertEqual(res["framework_name"], "Test Stored Framework")
                    self.assertTrue(res["backup"]["backup_created"])

    @patch("requests.post")
    def test_unload_framework_success(self, mock_post):
        """Verify framework unload with pre-operation backup."""
        mock_post.return_value = MagicMock(status_code=200, text="success")

        with patch.object(self.loader, "get_framework_status") as mock_status:
            mock_status.return_value = {
                "stored_id": "uuid-unload-me",
                "framework_name": "Framework to Unload",
                "is_loaded": True,
            }
            with patch.object(self.loader, "backup_existing_data") as mock_backup:
                mock_backup.return_value = {"backup_created": True, "backup_type": "snapshot", "filename": "pre_unload.json"}
                with patch.object(self.loader, "_sync_cache"):
                    res = self.loader.unload_framework("Framework to Unload", backup_first=True)

                    mock_backup.assert_called_once()
                    self.assertTrue(res["success"])
                    self.assertEqual(res["action"], "unloaded")
                    self.assertEqual(res["stored_id"], "uuid-unload-me")


class TestExamplesManagerFrameworkMethods(unittest.TestCase):
    """Test suite for ExamplesManager delegation methods for framework loading."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_examples_manager_has_framework_loader(self):
        """Verify ExamplesManager initializes framework_loader with its own backup_manager."""
        self.assertIsNotNone(self.manager.framework_loader)
        self.assertEqual(self.manager.framework_loader.backup_manager, self.manager.backup_manager)
        self.assertEqual(self.manager.framework_loader.manager, self.manager)

    @patch.object(FrameworkLoader, "load_framework")
    def test_manager_load_framework_delegation(self, mock_load):
        """Verify manager.load_framework delegates cleanly and refreshes cache."""
        mock_load.return_value = {"success": True, "action": "imported", "framework_name": "Demo"}
        with patch.object(self.manager, "_init_data") as mock_init:
            res = self.manager.load_framework("demo_fw", backup_first=True, backup_type="snapshot")
            mock_load.assert_called_once_with(
                target="demo_fw",
                backup_first=True,
                backup_type="snapshot",
                force_reload=False,
            )
            mock_init.assert_called_with(force_reload=True)
            self.assertTrue(res["success"])

    @patch.object(FrameworkLoader, "unload_framework")
    def test_manager_unload_framework_delegation(self, mock_unload):
        """Verify manager.unload_framework delegates cleanly and refreshes cache."""
        mock_unload.return_value = {"success": True, "action": "unloaded"}
        with patch.object(self.manager, "_init_data") as mock_init:
            res = self.manager.unload_framework("demo_fw", backup_first=False)
            mock_unload.assert_called_once_with(
                identifier="demo_fw",
                backup_first=False,
                backup_type="snapshot",
            )
            mock_init.assert_called_with(force_reload=True)
            self.assertTrue(res["success"])

    @patch.object(FrameworkLoader, "list_stored_libraries")
    def test_manager_list_stored_libraries_delegation(self, mock_list):
        """Verify manager.list_stored_libraries delegates to framework_loader."""
        mock_list.return_value = [{"name": "Lib 1"}]
        res = self.manager.list_stored_libraries(query="test", loaded_only=True)
        mock_list.assert_called_once_with(query="test", loaded_only=True, unloaded_only=False)
        self.assertEqual(len(res), 1)

    @patch.object(FrameworkLoader, "load_framework")
    def test_manager_backup_and_load_framework_convenience(self, mock_load):
        """Verify backup_and_load_framework forces backup_first=True."""
        mock_load.return_value = {"success": True, "backup": {"backup_created": True}}
        with patch.object(self.manager, "_init_data"):
            res = self.manager.backup_and_load_framework("custom.yaml", backup_type="dump")
            mock_load.assert_called_once_with(
                target="custom.yaml",
                backup_first=True,
                backup_type="dump",
                force_reload=False,
            )
            self.assertTrue(res["success"])


try:
    from web.app import HAS_FLASK, create_app
except ImportError:
    HAS_FLASK = False
    create_app = None


@unittest.skipUnless(HAS_FLASK, "Flask and Werkzeug are required for Web UI endpoint tests")
class TestWebFrameworkEndpoints(unittest.TestCase):
    """Test suite for Web UI framework endpoints."""

    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    @patch.object(ExamplesManager, "list_stored_libraries")
    def test_api_frameworks_stored(self, mock_list):
        """Test GET /api/frameworks/stored."""
        mock_list.return_value = [{"name": "ISO 27001", "ref_id": "iso-27001", "is_loaded": True}]
        res = self.client.get("/api/frameworks/stored?query=27001&loaded_only=true")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["ref_id"], "iso-27001")

    def test_api_framework_load_missing_target(self):
        """Test POST /api/frameworks/load with missing target returns 400."""
        res = self.client.post("/api/frameworks/load", json={})
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertIn("Missing 'target'", data["error"])

    def test_api_framework_unload_missing_target(self):
        """Test POST /api/frameworks/unload with missing target returns 400."""
        res = self.client.post("/api/frameworks/unload", json={})
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertIn("Missing 'target'", data["error"])


if __name__ == "__main__":
    unittest.main()
