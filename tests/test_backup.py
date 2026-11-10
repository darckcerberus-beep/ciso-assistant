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
        self.backup_dir.mkdir(parents=True, exist_ok=True)
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


class TestFrameworkAnswersSnapshot(unittest.TestCase):
    """Test suite for framework versioning, questionnaire answer snapshots, remapping, and diffing."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name) / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.manager = BackupManager(backup_dir=self.backup_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_create_framework_snapshot_success(self, mock_get_all, mock_get_return):
        """Verify create_framework_snapshot captures framework metadata, catalog, and enriched answers."""
        # 1. Framework mock
        mock_get_all.side_effect = [
            # /api/frameworks/
            [
                {
                    "id": "fw-1",
                    "name": "AppSec Framework",
                    "ref_id": "appsec",
                    "library": {"id": "lib-1", "name": "AppSec Lib", "urn": "urn:appsec"},
                }
            ],
            # /api/requirement-nodes/?framework=fw-1
            [
                {
                    "id": "node-1",
                    "ref_id": "stakeholders",
                    "urn": "urn:req:stakeholders",
                    "name": "Stakeholders",
                    "questions": {
                        "urn:req:stakeholders:q1": {
                            "text": "Is there a business contact?",
                            "type": "unique_choice",
                            "choices": [
                                {"urn": "urn:req:stakeholders:q1:c1", "value": "Yes"},
                                {"urn": "urn:req:stakeholders:q1:c2", "value": "No"},
                            ],
                        }
                    },
                }
            ],
            # /api/compliance-assessments/
            [
                {
                    "id": "ca-1",
                    "name": "Audit App 1",
                    "framework": {"id": "fw-1"},
                    "perimeter": {"id": "p-1", "name": "App 1"},
                    "status": "in_progress",
                }
            ],
            # /api/requirement-assessments/?compliance_assessment=ca-1
            [
                {
                    "id": "ra-1",
                    "requirement": {
                        "id": "node-1",
                        "ref_id": "stakeholders",
                        "urn": "urn:req:stakeholders",
                        "name": "Stakeholders",
                        "questions": {
                            "urn:req:stakeholders:q1": {
                                "text": "Is there a business contact?",
                                "type": "unique_choice",
                                "choices": [
                                    {"urn": "urn:req:stakeholders:q1:c1", "value": "Yes"},
                                    {"urn": "urn:req:stakeholders:q1:c2", "value": "No"},
                                ],
                            }
                        },
                    },
                    "answers": {"urn:req:stakeholders:q1": "urn:req:stakeholders:q1:c1"},
                    "result": "compliant",
                    "observation": "Primary contact verified",
                    "status": "done",
                    "score": 100,
                }
            ],
        ]
        # Loaded library mock
        mock_get_return.return_value = {"id": "lib-1", "version": 35, "name": "AppSec Lib"}

        snap_path = self.manager.create_framework_snapshot(
            framework_id_or_ref="appsec",
            notes="Pre-update v35 snapshot",
        )

        self.assertTrue(snap_path.exists())
        with open(snap_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        self.assertEqual(content.get("type"), "framework_answers_snapshot")
        self.assertEqual(content.get("version"), "1.0")
        self.assertEqual(content.get("notes"), "Pre-update v35 snapshot")

        fw = content.get("framework", {})
        self.assertEqual(fw.get("id"), "fw-1")
        self.assertEqual(fw.get("library_version"), 35)
        self.assertIn("stakeholders", fw.get("requirements", {}))

        counts = content.get("counts", {})
        self.assertEqual(counts.get("compliance_assessments_count"), 1)
        self.assertEqual(counts.get("total_answers"), 1)

        cas = content.get("compliance_assessments", [])
        self.assertEqual(len(cas), 1)
        ra = cas[0]["assessments"][0]
        self.assertEqual(ra["requirement_ref_id"], "stakeholders")
        self.assertEqual(ra["result"], "compliant")
        self.assertEqual(ra["observation"], "Primary contact verified")

        # Verify enriched answer
        enriched = ra["answers_enriched"][0]
        self.assertEqual(enriched["question_urn"], "urn:req:stakeholders:q1")
        self.assertEqual(enriched["selected_text"], "Yes")

    def test_create_framework_snapshot_missing_framework(self):
        """Verify create_framework_snapshot raises ValueError if framework is not found."""
        with patch("classes.utils.get_all_results", return_value=[]):
            with self.assertRaises(ValueError):
                self.manager.create_framework_snapshot(framework_id_or_ref="non_existent_fw")

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_restore_framework_snapshot_exact_match(self, mock_get_all, mock_get_return):
        """Verify restore_framework_snapshot restores answers via exact URN match."""
        snap_data = {
            "type": "framework_answers_snapshot",
            "framework": {"name": "AppSec", "library_version": 35},
            "compliance_assessments": [
                {
                    "id": "ca-1",
                    "name": "Audit App 1",
                    "assessments": [
                        {
                            "requirement_ref_id": "stakeholders",
                            "requirement_urn": "urn:req:stakeholders",
                            "raw_answers": {"urn:req:stakeholders:q1": "urn:req:stakeholders:q1:c1"},
                            "answers_enriched": [
                                {
                                    "question_urn": "urn:req:stakeholders:q1",
                                    "question_text": "Is there a business contact?",
                                    "selected_text": "Yes",
                                }
                            ],
                            "result": "compliant",
                            "observation": "Documented in catalog",
                        }
                    ],
                }
            ],
        }
        snap_file = self.backup_dir / "framework_snapshots" / "snap_test.json"
        snap_file.parent.mkdir(parents=True, exist_ok=True)
        snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

        # Mock live state: CA exists, but live RA currently has no answer
        mock_get_all.side_effect = [
            # live compliance assessments
            [{"id": "ca-1", "name": "Audit App 1"}],
            # live requirement assessments for ca-1
            [
                {
                    "id": "ra-1",
                    "requirement": {
                        "ref_id": "stakeholders",
                        "urn": "urn:req:stakeholders",
                        "questions": {
                            "urn:req:stakeholders:q1": {
                                "type": "unique_choice",
                                "choices": [
                                    {"urn": "urn:req:stakeholders:q1:c1", "value": "Yes"},
                                    {"urn": "urn:req:stakeholders:q1:c2", "value": "No"},
                                ],
                            }
                        },
                    },
                    "answers": {"urn:req:stakeholders:q1": None},
                    "result": "not_assessed",
                    "observation": None,
                }
            ],
        ]
        mock_get_return.return_value = {"id": "ra-1", "result": "compliant"}

        res = self.manager.restore_framework_snapshot(snap_file, dry_run=False)

        self.assertEqual(res.get("status"), "success")
        self.assertEqual(res.get("total_requirements_updated"), 1)
        self.assertEqual(res.get("total_answers_restored"), 1)

        # Verify PATCH call was made to update ra-1
        mock_get_return.assert_called_once_with(
            "/api/requirement-assessments/ra-1/",
            method="PATCH",
            payload={
                "answers": {"urn:req:stakeholders:q1": "urn:req:stakeholders:q1:c1"},
                "result": "compliant",
                "observation": "Documented in catalog",
            },
        )

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_restore_framework_snapshot_cross_version_semantic_remap(self, mock_get_all, mock_get_return):
        """Verify restore_framework_snapshot remaps answers when question and choice URNs shifted in updated version."""
        # Snapshot has old question URN ':old_q1' with choice text 'Confidential'
        snap_data = {
            "type": "framework_answers_snapshot",
            "framework": {"name": "AppSec", "library_version": 35},
            "compliance_assessments": [
                {
                    "id": "ca-1",
                    "name": "Audit App 1",
                    "assessments": [
                        {
                            "requirement_ref_id": "data_classification",
                            "requirement_urn": "urn:req:data_classification",
                            "raw_answers": {"urn:req:data_classification:old_q1": "urn:choice:c3"},
                            "answers_enriched": [
                                {
                                    "question_urn": "urn:req:data_classification:old_q1",
                                    "question_text": "What is the primary confidentiality level?",
                                    "selected_text": "Confidential",
                                }
                            ],
                            "result": "compliant",
                            "observation": "Contains confidential business records",
                        }
                    ],
                }
            ],
        }
        snap_file = self.backup_dir / "framework_snapshots" / "snap_remap.json"
        snap_file.parent.mkdir(parents=True, exist_ok=True)
        snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

        # Live state in updated framework v36 has a new question URN ':new_v36_q1' with new choice URN ':v36_c2'
        mock_get_all.side_effect = [
            [{"id": "ca-1", "name": "Audit App 1"}],
            [
                {
                    "id": "ra-1",
                    "requirement": {
                        "ref_id": "data_classification",
                        "urn": "urn:req:data_classification",
                        "questions": {
                            "urn:req:data_classification:new_v36_q1": {
                                "text": "What is the primary confidentiality level?",
                                "type": "unique_choice",
                                "choices": [
                                    {"urn": "urn:choice:v36_c1", "value": "Public"},
                                    {"urn": "urn:choice:v36_c2", "value": "Confidential"},
                                ],
                            }
                        },
                    },
                    "answers": {"urn:req:data_classification:new_v36_q1": None},
                    "result": "not_assessed",
                    "observation": "",
                }
            ],
        ]
        mock_get_return.return_value = {"id": "ra-1"}

        res = self.manager.restore_framework_snapshot(snap_file, dry_run=False)

        self.assertEqual(res.get("status"), "success")
        self.assertEqual(res.get("total_requirements_updated"), 1)
        self.assertEqual(res.get("total_answers_restored"), 1)
        self.assertEqual(res.get("remapped_answers_count"), 1)

        # Verify it mapped ':old_q1' -> ':new_v36_q1' and ':choice:c3' ('Confidential') -> ':choice:v36_c2'
        mock_get_return.assert_called_once_with(
            "/api/requirement-assessments/ra-1/",
            method="PATCH",
            payload={
                "answers": {"urn:req:data_classification:new_v36_q1": "urn:choice:v36_c2"},
                "result": "compliant",
                "observation": "Contains confidential business records",
            },
        )

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_restore_framework_snapshot_dry_run(self, mock_get_all, mock_get_return):
        """Verify restore_framework_snapshot performs preview without sending PATCH requests."""
        snap_data = {
            "type": "framework_answers_snapshot",
            "framework": {"name": "AppSec", "library_version": 35},
            "compliance_assessments": [
                {
                    "id": "ca-1",
                    "name": "Audit App 1",
                    "assessments": [
                        {
                            "requirement_ref_id": "stakeholders",
                            "raw_answers": {"urn:q1": "urn:c1"},
                            "answers_enriched": [{"question_urn": "urn:q1", "selected_text": "Yes"}],
                            "result": "compliant",
                        }
                    ],
                }
            ],
        }
        snap_file = self.backup_dir / "snap_dry.json"
        snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

        mock_get_all.side_effect = [
            [{"id": "ca-1", "name": "Audit App 1"}],
            [
                {
                    "id": "ra-1",
                    "requirement": {
                        "ref_id": "stakeholders",
                        "questions": {
                            "urn:q1": {
                                "type": "unique_choice",
                                "choices": [{"urn": "urn:c1", "value": "Yes"}],
                            }
                        },
                    },
                    "answers": {"urn:q1": None},
                    "result": "not_assessed",
                    "observation": None,
                }
            ],
        ]

        res = self.manager.restore_framework_snapshot(snap_file, dry_run=True)

        self.assertEqual(res.get("status"), "success")
        self.assertTrue(res.get("dry_run"))
        self.assertEqual(res.get("total_requirements_updated"), 1)
        mock_get_return.assert_not_called()

    def test_restore_framework_snapshot_missing_file(self):
        """Verify restore_framework_snapshot returns 404 when file is missing."""
        res = self.manager.restore_framework_snapshot(self.backup_dir / "missing.json")
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("error"), 404)

    def test_restore_framework_snapshot_invalid_schema(self):
        """Verify restore_framework_snapshot returns 400 on unrecognized JSON schema."""
        bad_file = self.backup_dir / "bad.json"
        bad_file.write_text(json.dumps({"some_key": 123}), encoding="utf-8")
        res = self.manager.restore_framework_snapshot(bad_file)
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("error"), 400)

    def test_diff_framework_snapshots_two_files(self):
        """Verify diff_framework_snapshots detects schema changes and answer drift between snapshots."""
        snap_a = {
            "type": "framework_answers_snapshot",
            "framework": {
                "name": "AppSec",
                "library_version": 35,
                "requirements": {
                    "data_classification": {
                        "name": "Data Classification",
                        "questions": {
                            "q1": {"text": "Max classification"},
                            "q2": {"text": "Aggregation & Scope"},
                        },
                    }
                },
            },
            "compliance_assessments": [
                {
                    "id": "ca-1",
                    "name": "Audit App 1",
                    "assessments": [
                        {
                            "requirement_ref_id": "data_classification",
                            "raw_answers": {"q1": "c_secret", "q2": "c_scope"},
                            "result": "compliant",
                            "observation": "High impact",
                        }
                    ],
                }
            ],
        }

        snap_b = {
            "type": "framework_answers_snapshot",
            "framework": {
                "name": "AppSec",
                "library_version": 36,
                "requirements": {
                    "data_classification": {
                        "name": "Data Classification",
                        "questions": {
                            "q1": {"text": "Max classification"},
                            # q2 Aggregation & Scope removed
                            "q3": {"text": "Personal data GDPR"},
                        },
                    }
                },
            },
            "compliance_assessments": [
                {
                    "id": "ca-1",
                    "name": "Audit App 1",
                    "assessments": [
                        {
                            "requirement_ref_id": "data_classification",
                            "raw_answers": {"q1": "c_secret", "q3": "c_gdpr"},
                            "result": "compliant",
                            "observation": "High impact updated",
                        }
                    ],
                }
            ],
        }

        file_a = self.backup_dir / "snap_a.json"
        file_b = self.backup_dir / "snap_b.json"
        file_a.write_text(json.dumps(snap_a), encoding="utf-8")
        file_b.write_text(json.dumps(snap_b), encoding="utf-8")

        diff = self.manager.diff_framework_snapshots(file_a, file_b)

        self.assertTrue(diff.get("has_differences"))
        self.assertEqual(diff.get("version_transition"), "v35 -> v36")

        schema = diff.get("schema_diff", {})
        self.assertEqual(schema.get("requirements_modified_count"), 1)
        mod = schema["modified_requirements"][0]
        self.assertEqual(mod["requirement"], "data_classification")
        self.assertEqual(len(mod["added_questions"]), 1)
        self.assertEqual(mod["added_questions"][0]["urn"], "q3")
        self.assertEqual(len(mod["removed_questions"]), 1)
        self.assertEqual(mod["removed_questions"][0]["urn"], "q2")

        apps = diff.get("applications_diff", [])
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["compliance_assessment"], "Audit App 1")

    def test_list_and_inspect_framework_snapshots(self):
        """Verify list_backups and inspect_backup discover and extract framework snapshot details."""
        fw_dir = self.backup_dir / "framework_snapshots"
        fw_dir.mkdir(parents=True, exist_ok=True)
        snap_file = fw_dir / "framework_appsec_v35_test.json"

        snap_data = {
            "type": "framework_answers_snapshot",
            "notes": "Pre-update test",
            "framework": {
                "name": "AppSec",
                "ref_id": "appsec",
                "library_version": 35,
                "library_urn": "urn:appsec",
                "requirements_count": 60,
            },
            "counts": {
                "compliance_assessments_count": 5,
                "total_answers": 80,
            },
            "compliance_assessments": [
                {
                    "name": "Demo Audit",
                    "perimeter_name": "Demo Perimeter",
                    "answered_requirements": 19,
                    "total_requirements": 60,
                }
            ],
        }
        snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

        backups = self.manager.list_backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["type"], "framework_snapshot")
        self.assertEqual(backups[0]["details"]["framework_version"], 35)
        self.assertEqual(backups[0]["details"]["total_answers"], 80)

        info = self.manager.inspect_backup(snap_file)
        self.assertEqual(info["type"], "framework_snapshot")
        self.assertEqual(info["framework"]["name"], "AppSec")
        self.assertEqual(info["counts"]["total_answers"], 80)
        self.assertEqual(len(info["compliance_assessments"]), 1)


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

        with patch.object(self.ex_mgr.backup_manager, "create_framework_snapshot", return_value=Path("/tmp/fw.json")) as m_fw_snap:
            res = self.ex_mgr.create_framework_snapshot(framework_id_or_ref="appsec", notes="note")
            self.assertEqual(res, Path("/tmp/fw.json"))
            m_fw_snap.assert_called_once_with(
                framework_id_or_ref="appsec",
                compliance_assessment_ids=None,
                output_dir=None,
                filename=None,
                notes="note",
                manager=self.ex_mgr,
            )

        with patch.object(self.ex_mgr.backup_manager, "restore_framework_snapshot", return_value={"status": "success"}) as m_fw_rest:
            res = self.ex_mgr.restore_framework_snapshot("/tmp/fw.json", dry_run=True)
            self.assertEqual(res.get("status"), "success")
            m_fw_rest.assert_called_once_with(
                snapshot_path="/tmp/fw.json",
                compliance_assessment_id=None,
                dry_run=True,
                remap_rules=None,
                manager=self.ex_mgr,
            )

        with patch.object(self.ex_mgr.backup_manager, "diff_framework_snapshots", return_value={"has_differences": False}) as m_fw_diff:
            res = self.ex_mgr.diff_framework_snapshots("/tmp/a.json", "/tmp/b.json")
            self.assertFalse(res.get("has_differences"))
            m_fw_diff.assert_called_once_with(
                snapshot_a="/tmp/a.json",
                snapshot_b_or_live="/tmp/b.json",
            )


if __name__ == "__main__":
    unittest.main()

