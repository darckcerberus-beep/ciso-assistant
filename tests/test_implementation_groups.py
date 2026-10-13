"""Unit tests for compliance audit implementation groups support.

Tests cover:
- classes.audits.implementation_groups helper functions (get, default, resolve, set)
- ComplianceAssessment model methods (get, set, add selected implementation groups)
- ComplianceAssessmentDict integration (create, update, add)
- ExamplesManager orchestration (get, select, add audit implementation groups)
"""

import unittest
from unittest.mock import MagicMock, patch

from classes.audits.compliance import ComplianceAssessment, ComplianceAssessmentDict
from classes.audits.implementation_groups import (
    add_default_implementation_groups,
    get_default_implementation_groups,
    get_framework_implementation_groups,
    resolve_implementation_groups,
    set_implementation_groups,
)
from classes.examples_manager import ExamplesManager


class TestImplementationGroups(unittest.TestCase):
    """Test suite for implementation groups resolution and management."""

    def setUp(self):
        self.sample_defs = [
            {
                "name": "Application information",
                "ref_id": "baseline",
                "urn": "urn:intuitem:risk:ig:mls:baseline",
                "default_selected": True,
            },
            {
                "name": "Custom applications",
                "ref_id": "custom_app",
                "urn": "urn:intuitem:risk:ig:mls:custom_app",
                "default_selected": False,
            },
            {
                "name": "SaaS & Cloud Application",
                "ref_id": "saas_app",
                "urn": "urn:intuitem:risk:ig:mls:saas_app",
                "default_selected": False,
            },
        ]

    def test_get_framework_implementation_groups_from_dict(self):
        """Verify extraction of definitions directly from a framework dictionary."""
        fw_dict = {"implementation_groups_definition": self.sample_defs}
        res = get_framework_implementation_groups(fw_dict)
        self.assertEqual(len(res), 3)
        self.assertEqual(res[0]["ref_id"], "baseline")

    def test_get_framework_implementation_groups_from_object(self):
        """Verify extraction from a framework object with getter or json_object."""
        mock_fw = MagicMock()
        mock_fw.get_implementation_groups_definition.return_value = self.sample_defs
        res = get_framework_implementation_groups(mock_fw)
        self.assertEqual(len(res), 3)

        mock_fw2 = MagicMock()
        mock_fw2.get_implementation_groups_definition.return_value = []
        mock_fw2.json_object = {"implementation_groups_definition": self.sample_defs}
        res2 = get_framework_implementation_groups(mock_fw2)
        self.assertEqual(len(res2), 3)

    @patch("classes.utils.get_return")
    def test_get_framework_implementation_groups_from_api(self, mock_get_return):
        """Verify API fallback when framework ID is passed as string."""
        mock_get_return.return_value = {"implementation_groups_definition": self.sample_defs}
        res = get_framework_implementation_groups("fw-uuid-1")
        self.assertEqual(len(res), 3)
        mock_get_return.assert_called_once_with("/api/frameworks/fw-uuid-1/")

    def test_get_default_implementation_groups(self):
        """Verify only default_selected=True groups are returned."""
        fw_dict = {"implementation_groups_definition": self.sample_defs}
        defaults = get_default_implementation_groups(fw_dict)
        self.assertEqual(defaults, ["Application information"])

    def test_resolve_implementation_groups_canonical_mapping(self):
        """Verify ref_id, urn, and name are mapped to canonical framework definition names."""
        fw_dict = {"implementation_groups_definition": self.sample_defs}

        # Resolve via ref_id
        resolved = resolve_implementation_groups(["baseline", "saas_app"], fw_dict)
        self.assertEqual(resolved, ["Application information", "SaaS & Cloud Application"])

        # Resolve via URN
        resolved_urn = resolve_implementation_groups(["urn:intuitem:risk:ig:mls:custom_app"], fw_dict)
        self.assertEqual(resolved_urn, ["Custom applications"])

        # Resolve via exact canonical name
        resolved_name = resolve_implementation_groups(["Application information"], fw_dict)
        self.assertEqual(resolved_name, ["Application information"])

        # Deduplication and unknown group retention
        resolved_mixed = resolve_implementation_groups(
            ["baseline", "Application information", "saas_app", "Extra Custom Group"],
            fw_dict,
        )
        self.assertEqual(
            resolved_mixed,
            ["Application information", "SaaS & Cloud Application", "Extra Custom Group"],
        )

    def test_set_and_add_default_implementation_groups(self):
        """Verify payload manipulation helpers."""
        fw_dict = {"implementation_groups_definition": self.sample_defs}

        # set with explicit groups
        payload = {}
        set_implementation_groups(payload, fw_dict, groups=["custom_app"])
        self.assertEqual(payload["selected_implementation_groups"], ["Custom applications"])

        # set with None defaults
        payload2 = {}
        set_implementation_groups(payload2, fw_dict, groups=None)
        self.assertEqual(payload2["selected_implementation_groups"], ["Application information"])

        # add_default when already present does not overwrite
        payload3 = {"selected_implementation_groups": ["Existing Group"]}
        add_default_implementation_groups(payload3, fw_dict)
        self.assertEqual(payload3["selected_implementation_groups"], ["Existing Group"])


class TestComplianceAssessmentModel(unittest.TestCase):
    """Test suite for ComplianceAssessment implementation group methods."""

    def test_compliance_assessment_get_selected_implementation_groups(self):
        """Verify getter returns selected_implementation_groups list."""
        ca = ComplianceAssessment.__new__(ComplianceAssessment)
        ca.compliance_assessment_json = {
            "id": "ca-1",
            "name": "Audit",
            "selected_implementation_groups": ["Application information", "Custom applications"],
        }
        groups = ca.get_selected_implementation_groups()
        self.assertEqual(groups, ["Application information", "Custom applications"])

    @patch("classes.utils.get_return")
    def test_compliance_assessment_set_selected_implementation_groups(self, mock_get_return):
        """Verify set_selected_implementation_groups executes PATCH and updates local state."""
        mock_get_return.return_value = {
            "id": "ca-1",
            "selected_implementation_groups": ["Custom applications"],
        }
        ca = ComplianceAssessment.__new__(ComplianceAssessment)
        ca.id = "ca-1"
        ca.compliance_assessment_json = {
            "id": "ca-1",
            "framework": "fw-1",
            "selected_implementation_groups": ["Application information"],
        }

        with patch("classes.audits.compliance.resolve_implementation_groups", return_value=["Custom applications"]):
            updated = ca.set_selected_implementation_groups(["custom_app"])

        self.assertEqual(updated["selected_implementation_groups"], ["Custom applications"])
        self.assertEqual(ca.compliance_assessment_json["selected_implementation_groups"], ["Custom applications"])
        mock_get_return.assert_called_once_with(
            "/api/compliance-assessments/ca-1/",
            method="PATCH",
            payload={"selected_implementation_groups": ["Custom applications"]},
        )

    @patch("classes.utils.get_return")
    def test_compliance_assessment_add_selected_implementation_groups(self, mock_get_return):
        """Verify add_selected_implementation_groups merges new groups with existing."""
        mock_get_return.return_value = {
            "id": "ca-1",
            "selected_implementation_groups": ["Application information", "Custom applications"],
        }
        ca = ComplianceAssessment.__new__(ComplianceAssessment)
        ca.id = "ca-1"
        ca.compliance_assessment_json = {
            "id": "ca-1",
            "framework": "fw-1",
            "selected_implementation_groups": ["Application information"],
        }

        with patch("classes.audits.compliance.resolve_implementation_groups", side_effect=lambda g, fw: g):
            updated = ca.add_selected_implementation_groups(["Custom applications"])

        self.assertEqual(updated["selected_implementation_groups"], ["Application information", "Custom applications"])
        mock_get_return.assert_called_once_with(
            "/api/compliance-assessments/ca-1/",
            method="PATCH",
            payload={"selected_implementation_groups": ["Application information", "Custom applications"]},
        )


class TestExamplesManagerImplementationGroups(unittest.TestCase):
    """Test suite for ExamplesManager audit implementation groups orchestration."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_get_audit_implementation_groups(self):
        """Verify retrieving selected and available implementation groups for an audit."""
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-1"
        mock_ca.get_name.return_value = "Assessment of MLS in App-Audit"
        mock_ca.get_perimeter_id.return_value = "perm-1"
        mock_ca.get_framework_id.return_value = "fw-1"
        mock_ca.get_selected_implementation_groups.return_value = ["Application information"]

        mock_fw = MagicMock()
        mock_fw.get_name.return_value = "Multi-level DPP"
        ig_defs = [
            {"name": "Application information", "ref_id": "baseline", "default_selected": True},
            {"name": "Custom applications", "ref_id": "custom_app", "default_selected": False},
        ]
        mock_fw.get_implementation_groups_definition.return_value = ig_defs
        mock_fw.json_object = {
            "ref_id": "mls",
            "implementation_groups_definition": ig_defs,
        }

        mock_data = {
            "compliance_assessment_dict": MagicMock(
                get_compliance_assessments=MagicMock(return_value={"ca-1": mock_ca}),
            ),
            "perimeter_dict": MagicMock(
                get_id_from_name=MagicMock(return_value="perm-1"),
                get_name_from_id=MagicMock(return_value="App-Audit"),
            ),
        }

        with (
            patch.object(self.manager, "_init_data", return_value=mock_data),
            patch.object(self.manager, "find_target_framework", return_value=mock_fw),
        ):
            res = self.manager.get_audit_implementation_groups("App-Audit")

            self.assertEqual(res["app_name"], "App-Audit")
            self.assertEqual(res["compliance_assessment_id"], "ca-1")
            self.assertEqual(res["framework_name"], "Multi-level DPP")
            self.assertEqual(res["framework_ref"], "mls")
            self.assertEqual(res["selected_implementation_groups"], ["Application information"])
            self.assertEqual(len(res["available_implementation_groups"]), 2)

    def test_select_and_add_audit_implementation_groups(self):
        """Verify selecting and adding implementation groups via ExamplesManager."""
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-1"
        mock_ca.get_name.return_value = "Assessment of MLS in App-Audit"
        mock_ca.get_perimeter_id.return_value = "perm-1"
        mock_ca.get_framework_id.return_value = "fw-1"
        mock_ca.get_selected_implementation_groups.return_value = ["Application information"]
        mock_ca.set_selected_implementation_groups.return_value = ["Custom applications"]
        mock_ca.add_selected_implementation_groups.return_value = [
            "Application information",
            "Custom applications",
        ]

        mock_compliance_dict = MagicMock()
        mock_compliance_dict.get_compliance_assessments.return_value = {"ca-1": mock_ca}

        mock_data = {
            "compliance_assessment_dict": mock_compliance_dict,
            "perimeter_dict": MagicMock(
                get_id_from_name=MagicMock(return_value="perm-1"),
                get_name_from_id=MagicMock(return_value="App-Audit"),
            ),
        }

        mock_info = {
            "app_name": "App-Audit",
            "compliance_assessment_id": "ca-1",
            "selected_implementation_groups": ["Custom applications"],
            "available_implementation_groups": [],
        }

        with (
            patch.object(self.manager, "_init_data", return_value=mock_data),
            patch.object(self.manager, "get_audit_implementation_groups", return_value=mock_info),
        ):
            # Test replace mode
            res_replace = self.manager.select_audit_implementation_groups(
                "App-Audit",
                ["custom_app"],
                mode="replace",
            )
            mock_ca.set_selected_implementation_groups.assert_called_once_with(["custom_app"])
            self.assertEqual(res_replace["selected_implementation_groups"], ["Custom applications"])

            # Test add mode
            res_add = self.manager.add_audit_implementation_groups(
                "App-Audit",
                ["custom_app"],
            )
            mock_ca.add_selected_implementation_groups.assert_called_once_with(["custom_app"])


if __name__ == "__main__":
    unittest.main()
