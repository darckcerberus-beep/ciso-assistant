"""Unit tests for Backup and Restore management, Serdes API integration, and snapshot lifecycle."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from classes import utils
from classes.examples_manager import ExamplesManager
from classes.integrations.backup import BackupManager


class TestUtilsFileTransfer(unittest.TestCase):
    """Test suite for download_file and upload_file network helpers in classes/utils.py."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("requests.get")
    def test_download_file_success(self, mock_get):
        """Verify download_file streams bytes and writes to disk."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_content.return_value = [b"chunk1_", b"chunk2"]
        mock_get.return_value = mock_resp

        target_file = self.test_dir / "test_download.bin"
        success = utils.download_file("/api/serdes/dump-db/", target_file)

        self.assertTrue(success)
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.read_bytes(), b"chunk1_chunk2")

    @patch("requests.get")
    def test_download_file_failure(self, mock_get):
        """Verify download_file returns False on HTTP failure."""
        mock_get.side_effect = Exception("Connection error")
        target_file = self.test_dir / "failed.bin"
        success = utils.download_file("/api/serdes/dump-db/", target_file)
        self.assertFalse(success)
        self.assertFalse(target_file.exists())

    @patch("requests.post")
    def test_upload_file_success(self, mock_post):
        """Verify upload_file posts multipart form data."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "restored"}
        mock_post.return_value = mock_resp

        source_file = self.test_dir / "upload.dump"
        source_file.write_bytes(b"sample dump data")

        res = utils.upload_file("/api/serdes/load-backup/", source_file, field_name="backup")
        self.assertEqual(res, {"status": "restored"})
        mock_post.assert_called_once()

    def test_upload_file_missing(self):
        """Verify upload_file returns 404 error dict when source file is missing."""
        missing = self.test_dir / "missing.dump"
        res = utils.upload_file("/api/serdes/load-backup/", missing)
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("error"), 404)


class TestBackupManager(unittest.TestCase):
    """Test suite for BackupManager database dumps, snapshots, discovery, and inspection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name) / "backups"
        self.manager = BackupManager(backup_dir=self.backup_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("classes.utils.download_file")
    def test_create_database_dump_success(self, mock_download):
        """Verify create_database_dump requests /api/serdes/dump-db/ and returns file path."""
        def fake_download(endpoint, target_path, params=None):
            Path(target_path).write_bytes(b"binary_db_dump_content")
            return True

        mock_download.side_effect = fake_download
        dump_path = self.manager.create_database_dump(filename="custom_dump.dump")

        self.assertIsNotNone(dump_path)
        self.assertTrue(dump_path.exists())
        self.assertEqual(dump_path.name, "custom_dump.dump")
        mock_download.assert_called_once()

    @patch("classes.utils.upload_file")
    def test_restore_database_dump_success(self, mock_upload):
        """Verify restore_database_dump uploads dump file to /api/serdes/load-backup/."""
        dump_file = self.backup_dir / "test.dump"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        dump_file.write_bytes(b"dump content")

        mock_upload.return_value = {"status": "ok"}
        res = self.manager.restore_database_dump(dump_file)
        self.assertEqual(res, {"status": "ok"})
        mock_upload.assert_called_with("/api/serdes/load-backup/", dump_file, field_name="backup")

    def test_restore_database_dump_missing_file(self):
        """Verify restore_database_dump handles missing file gracefully."""
        res = self.manager.restore_database_dump(self.backup_dir / "non_existent.dump")
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("error"), 404)

    def test_create_workspace_snapshot(self):
        """Verify create_workspace_snapshot creates structured JSON with metadata and counts."""
        mock_perimeter = MagicMock()
        mock_perimeter.get_json.return_value = {"id": "perm-1", "name": "Perimeter 1"}

        mock_asset = MagicMock()
        mock_asset.get_json.return_value = {"id": "asset-1", "name": "Asset 1"}

        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "findings_assessment_dict": MagicMock(),
            "finding_dict": MagicMock(),
        }
        mock_data["perimeter_dict"].get_perimeters.return_value = {"perm-1": mock_perimeter}
        mock_data["asset_dict"].get_assets.return_value = {"asset-1": mock_asset}
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {}
        mock_data["applied_control_dict"].get_controls.return_value = {}
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["risk_scenario_dict"].get_risk_scenarios.return_value = {}
        mock_data["findings_assessment_dict"].get_findings_assessments.return_value = {}
        mock_data["finding_dict"].get_findings.return_value = {}

        snapshot_path = self.manager.create_workspace_snapshot(
            filename="snap_test.json",
            folder_name="Test Folder",
            data=mock_data,
        )

        self.assertTrue(snapshot_path.exists())
        with open(snapshot_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        self.assertEqual(content.get("type"), "workspace_snapshot")
        self.assertEqual(content.get("version"), "1.0")
        self.assertEqual(content.get("folder_name"), "Test Folder")
        self.assertEqual(content.get("counts", {}).get("perimeters"), 1)
        self.assertEqual(content.get("counts", {}).get("assets"), 1)
        self.assertEqual(len(content.get("data", {}).get("perimeters", [])), 1)

    def test_restore_workspace_snapshot(self):
        """Verify restore_workspace_snapshot validates and parses snapshot JSON."""
        snap_content = {
            "version": "1.0",
            "type": "workspace_snapshot",
            "created_at": "2026-09-22T12:00:00Z",
            "source_url": "https://example.com",
            "counts": {"assets": 2},
            "data": {"assets": [{"id": "a-1"}, {"id": "a-2"}]},
        }
        snap_file = self.backup_dir / "valid_snap.json"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        snap_file.write_text(json.dumps(snap_content), encoding="utf-8")

        mock_mgr = MagicMock()
        res = self.manager.restore_workspace_snapshot(snap_file, manager=mock_mgr)

        self.assertEqual(res.get("status"), "success")
        self.assertEqual(res.get("expected_counts"), {"assets": 2})
        self.assertEqual(res.get("restored_counts"), {"assets": 2})
        mock_mgr._init_data.assert_called_with(force_reload=True)

    def test_restore_workspace_snapshot_invalid_schema(self):
        """Verify restore_workspace_snapshot rejects corrupted or unrecognized JSON."""
        invalid_file = self.backup_dir / "invalid.json"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        invalid_file.write_text(json.dumps({"some_key": "some_value"}), encoding="utf-8")

        res = self.manager.restore_workspace_snapshot(invalid_file)
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("error"), 400)

    def test_list_and_inspect_backups(self):
        """Verify list_backups discovers dumps and snapshots, and inspect_backup computes sha256."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # 1. Create a dummy dump file
        dump_file = self.backup_dir / "db_dump_20260922_100000.dump"
        dump_file.write_bytes(b"database dump data")

        # 2. Create a dummy snapshot file
        snap_file = self.backup_dir / "workspace_snapshot_20260922_110000.json"
        snap_data = {
            "type": "workspace_snapshot",
            "version": "1.0",
            "created_at": "2026-09-22T11:00:00Z",
            "counts": {"perimeters": 3},
            "data": {"perimeters": [1, 2, 3]},
        }
        snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

        backups = self.manager.list_backups()
        self.assertEqual(len(backups), 2)

        types = {b["type"] for b in backups}
        self.assertIn("database_dump", types)
        self.assertIn("workspace_snapshot", types)

        # Inspect dump
        dump_info = self.manager.inspect_backup(dump_file)
        self.assertEqual(dump_info["type"], "database_dump")
        self.assertIn("sha256", dump_info)
        self.assertGreater(len(dump_info["sha256"]), 0)

        # Inspect snapshot
        snap_info = self.manager.inspect_backup(snap_file)
        self.assertEqual(snap_info["type"], "workspace_snapshot")
        self.assertEqual(snap_info.get("counts", {}).get("perimeters"), 3)


class TestExamplesManagerBackupIntegration(unittest.TestCase):
    """Test suite for ExamplesManager backup convenience methods."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ex_mgr = ExamplesManager()
        self.ex_mgr.backup_manager = BackupManager(backup_dir=self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_manager_delegates_to_backup_manager(self):
        """Verify ExamplesManager delegates backup methods properly."""
        with patch.object(self.ex_mgr.backup_manager, "create_database_dump", return_value=Path("/tmp/dump.dump")) as m_dump:
            res = self.ex_mgr.create_database_dump()
            self.assertEqual(res, Path("/tmp/dump.dump"))
            m_dump.assert_called_once()

        with patch.object(self.ex_mgr.backup_manager, "restore_database_dump", return_value=True) as m_rest, \
             patch.object(self.ex_mgr, "_init_data") as m_init:
            res = self.ex_mgr.restore_database_dump("/tmp/dump.dump")
            self.assertTrue(res)
            m_rest.assert_called_with("/tmp/dump.dump")
            m_init.assert_called_with(force_reload=True)

        with patch.object(self.ex_mgr.backup_manager, "list_backups", return_value=[{"type": "database_dump"}]) as m_list:
            res = self.ex_mgr.list_backups()
            self.assertEqual(len(res), 1)
            m_list.assert_called_once()


if __name__ == "__main__":
    unittest.main()

