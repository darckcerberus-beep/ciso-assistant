"""Unit tests for recurrent controls and task templates."""

import unittest
from pathlib import Path
import yaml

from classes.core.task import Task, TaskTemplate


class TestTasks(unittest.TestCase):
    """Test suite for task configurations and task template data structures."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.base_dir = Path(__file__).resolve().parent.parent

        with open(cls.base_dir / "YML/newDPP.yml", "r", encoding="utf-8") as f:
            cls.dpp_data = yaml.safe_load(f)

        with open(cls.base_dir / "YML/vendor-due-diligence.yaml", "r", encoding="utf-8") as f:
            cls.vdd_data = yaml.safe_load(f)

    def test_newdpp_tasks_exist_and_valid(self):
        """Verify that all reference controls in newDPP have valid recurring tasks."""
        ref_controls = self.dpp_data.get("objects", {}).get("reference_controls", [])
        self.assertGreater(len(ref_controls), 0)

        valid_cadences = {"daily", "weekly", "biweekly", "monthly", "quarterly", "biannually", "semiannually", "annually", "yearly"}
        valid_frequencies = {"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}

        for ctrl in ref_controls:
            urn = ctrl.get("urn", "")
            self.assertTrue(ctrl.get("is_recurrent"), f"Control {urn} should be marked is_recurrent")
            cadence = ctrl.get("cadence")
            self.assertIn(cadence, valid_cadences, f"Invalid cadence {cadence} for {urn}")

            task = ctrl.get("task")
            self.assertIsInstance(task, dict, f"Task should be a dict for {urn}")
            self.assertTrue(task.get("name"), f"Task name missing for {urn}")
            self.assertTrue(task.get("description"), f"Task description missing for {urn}")
            self.assertIn(task.get("frequency"), valid_frequencies, f"Invalid frequency for {urn}")
            self.assertGreaterEqual(task.get("interval", 0), 1, f"Invalid interval for {urn}")

    def test_vendor_due_diligence_tasks_exist_and_valid(self):
        """Verify that all reference controls in vendor-due-diligence have valid recurring tasks."""
        ref_controls = self.vdd_data.get("objects", {}).get("reference_controls", [])
        self.assertGreater(len(ref_controls), 0)

        valid_cadences = {"daily", "weekly", "biweekly", "monthly", "quarterly", "biannually", "semiannually", "annually", "yearly"}
        valid_frequencies = {"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}

        for ctrl in ref_controls:
            urn = ctrl.get("urn", "")
            self.assertTrue(ctrl.get("is_recurrent"), f"Control {urn} should be marked is_recurrent")
            cadence = ctrl.get("cadence")
            self.assertIn(cadence, valid_cadences, f"Invalid cadence {cadence} for {urn}")

            task = ctrl.get("task")
            self.assertIsInstance(task, dict, f"Task should be a dict for {urn}")
            self.assertTrue(task.get("name"), f"Task name missing for {urn}")
            self.assertTrue(task.get("description"), f"Task description missing for {urn}")
            self.assertIn(task.get("frequency"), valid_frequencies, f"Invalid frequency for {urn}")
            self.assertGreaterEqual(task.get("interval", 0), 1, f"Invalid interval for {urn}")

    def test_task_model_wrapper(self):
        """Test Task wrapper class methods."""
        data = {"id": "t-1", "name": "Review Access"}
        task = Task(data)
        self.assertEqual(task.get_id(), "t-1")
        self.assertEqual(task.get_name(), "Review Access")
        self.assertEqual(task.get_json(), data)

    def test_task_template_model_wrapper(self):
        """Test TaskTemplate wrapper class methods."""
        data = {"id": "tt-1", "name": "Quarterly Audit", "is_recurrent": True}
        template = TaskTemplate(data)
        self.assertEqual(template.get_id(), "tt-1")
        self.assertEqual(template.get_name(), "Quarterly Audit")
        self.assertTrue(template.get_is_reccurring())
        self.assertEqual(template.get_json(), data)

    def test_task_template_dict_delete_templates(self):
        """Verify delete_templates_for_applied_control removes matching templates."""
        from unittest.mock import patch
        from classes.core.task import TaskTemplateDict

        with patch("classes.utils.get_all_results", return_value=[
            {"id": "tt-1", "name": "Task 1", "applied_controls": ["ctrl-100"]},
            {"id": "tt-2", "name": "Task 2", "applied_controls": ["ctrl-200"]},
        ]), patch("classes.utils.get_return", return_value=True) as mock_delete:
            tt_dict = TaskTemplateDict()
            self.assertEqual(len(tt_dict.get_task_templates()), 2)

            with patch.object(tt_dict, "reload"):
                count = tt_dict.delete_templates_for_applied_control("ctrl-100")
                self.assertEqual(count, 1)
                mock_delete.assert_called_with("/api/task-templates/tt-1/", method="DELETE")

    def test_applied_control_create_tasks_for_applied_controls(self):
        """Verify create_tasks_for_applied_controls creates task templates for recurrent controls."""
        from unittest.mock import MagicMock, patch
        from classes.controls.applied import AppliedControl, AppliedControlDict

        with patch("classes.utils.get_all_results", return_value=[]):
            applied_dict = AppliedControlDict()

        ctrl_data = {
            "id": "c-1",
            "name": "Access Review on ApSec",
            "reference_control": "ref-1",
            "folder": "f-1",
        }
        applied_dict.controls = {"c-1": AppliedControl(ctrl_data)}

        ref_ctrl = MagicMock()
        ref_ctrl.get_json.return_value = {
            "urn": "urn:test:ref1",
            "is_recurrent": True,
            "task": {
                "name": "Periodic Access Review",
                "description": "Review entitlements",
                "frequency": "MONTHLY",
                "interval": 1,
            },
        }

        ref_dict = MagicMock()
        ref_dict.get_control_from_id.return_value = ref_ctrl

        with patch("classes.utils.get_return", return_value={"id": "tt-new"}) as mock_post:
            created = applied_dict.create_tasks_for_applied_controls(ref_dict, user_id="u-1")
            self.assertEqual(len(created), 1)
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args[1]
            self.assertEqual(call_kwargs["method"], "POST")
            self.assertEqual(call_kwargs["payload"]["name"], "Periodic Access Review on ApSec")
            self.assertEqual(call_kwargs["payload"]["applied_controls"], ["c-1"])
            self.assertEqual(call_kwargs["payload"]["assigned_to"], ["u-1"])

    def test_ensure_requirement_assessment_for_control(self):
        """Verify ensure_requirement_assessment_for_control merges new RA IDs into applied control."""
        from unittest.mock import patch
        from classes.controls.applied import AppliedControl, AppliedControlDict

        with patch("classes.utils.get_all_results", return_value=[]):
            applied_dict = AppliedControlDict()

        ctrl_data = {
            "id": "c-1",
            "name": "MFA on ApSec",
            "requirement_assessments": ["ra-1"],
            "compliance_assessments": ["ca-1"],
        }
        applied_dict.controls = {"c-1": AppliedControl(ctrl_data)}

        with patch("classes.utils.get_return", return_value={"id": "c-1", "requirement_assessments": ["ra-1", "ra-2"]}) as mock_patch:
            applied_dict.ensure_requirement_assessment_for_control("MFA on ApSec", "ra-2", "ca-1")
            mock_patch.assert_called_once()
            call_kwargs = mock_patch.call_args[1]
            self.assertEqual(call_kwargs["method"], "PATCH")
            self.assertEqual(call_kwargs["payload"]["requirement_assessments"], ["ra-1", "ra-2"])

    def test_create_missing_applied_controls_shared_reference_control(self):
        """Verify that multiple requirement assessments sharing a reference control create 1 control and link both."""
        from unittest.mock import MagicMock, patch
        from classes.controls.applied import AppliedControlDict

        with patch("classes.utils.get_all_results", return_value=[]):
            applied_dict = AppliedControlDict()

        # Mock requirement assessments
        ra1 = MagicMock()
        ra1.get_id.return_value = "ra-1"
        ra1.get_compliance_assessment_id.return_value = "ca-1"
        ra1.get_perimeter_id.return_value = "p-1"
        ra1.has_selected_answer.return_value = True
        ra1.is_unassessed_result.return_value = False
        ra1.is_score_compliant.return_value = True
        ra1.get_associated_reference_control_ids.return_value = ["ref-mfa"]

        ra2 = MagicMock()
        ra2.get_id.return_value = "ra-2"
        ra2.get_compliance_assessment_id.return_value = "ca-1"
        ra2.get_perimeter_id.return_value = "p-1"
        ra2.has_selected_answer.return_value = True
        ra2.is_unassessed_result.return_value = False
        ra2.is_score_compliant.return_value = True
        ra2.get_associated_reference_control_ids.return_value = ["ref-mfa"]

        ra_dict = MagicMock()
        ra_dict.get_requirement_assessments.return_value = {"ra-1": ra1, "ra-2": ra2}

        # Mock perimeter
        perimeter_dict = MagicMock()
        perimeter_dict.get_name_from_id.return_value = "ApSec"
        perimeter_dict.get_folder_uuid_from_perimeter_id.return_value = "folder-1"
        perimeter_dict.get_owner_id_from_perimeter_id.return_value = "owner-1"

        # Mock reference control
        ref_dict = MagicMock()
        ref_dict.get_name_from_id.return_value = "Enforce Multi-Factor Authentication"

        # Mock compliance assessment dict
        ca_dict = MagicMock()
        ca_dict.get_asset_id_list_from_compliance_assessment_id.return_value = ["asset-1"]

        # Track POST and PATCH calls
        post_calls = []
        patch_calls = []

        def mock_get_return(endpoint, method="GET", payload=None):
            if method == "POST" and endpoint == "/api/applied-controls/":
                post_calls.append(payload)
                return {
                    "id": "new-ctrl-1",
                    "name": payload["name"],
                    "reference_control": payload["reference_control"],
                    "requirement_assessments": payload["requirement_assessments"],
                    "compliance_assessments": payload["compliance_assessments"],
                    "folder": payload["folder"],
                    "assets": payload["assets"],
                    "status": payload["status"],
                }
            if method == "PATCH" and "/api/applied-controls/" in endpoint:
                patch_calls.append((endpoint, payload))
                return {"id": "new-ctrl-1", **payload}
            return None

        with patch("classes.utils.get_all_results", return_value=[]), \
             patch("classes.utils.get_return", side_effect=mock_get_return), \
             patch("classes.core.framework.FrameworkFile"):
            applied_dict.create_missing_applied_controls(
                perimeter_dict=perimeter_dict,
                requirement_assessment=ra_dict,
                reference_control_dict=ref_dict,
                compliance_assessment_dict=ca_dict,
            )

        # POST should only be called ONCE
        self.assertEqual(len(post_calls), 1)
        self.assertEqual(post_calls[0]["name"], "Enforce Multi-Factor Authentication on ApSec")
        self.assertEqual(post_calls[0]["requirement_assessments"], ["ra-1"])

        # PATCH should be called to link ra-2 without 400 error!
        self.assertEqual(len(patch_calls), 1)
        self.assertEqual(patch_calls[0][1]["requirement_assessments"], ["ra-1", "ra-2"])


if __name__ == "__main__":
    unittest.main()
