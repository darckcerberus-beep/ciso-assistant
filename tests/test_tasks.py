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


if __name__ == "__main__":
    unittest.main()
