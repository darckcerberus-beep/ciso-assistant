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
    determine_implementation_groups_triggered_by_others,
    get_default_implementation_groups,
    get_framework_implementation_groups,
    get_implementation_groups_triggered_by_others,
    get_initial_implementation_groups,
    get_visible_implementation_groups,
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

    def test_get_framework_implementation_groups_annotations(self):
        """Verify is_triggered, is_initial, and triggered_by_questions annotations."""
        defs = [
            {"name": "Application information", "ref_id": "info", "default_selected": True},
            {"name": "Custom applications", "ref_id": "custom_app", "default_selected": False},
        ]
        mock_map = {"custom_app": ["Does the app use custom software?"]}
        with patch("classes.audits.implementation_groups.get_framework_triggered_implementation_groups_map", return_value=mock_map):
            annotated = get_framework_implementation_groups({"implementation_groups_definition": defs})
            self.assertEqual(len(annotated), 2)
            # Default group info
            self.assertFalse(annotated[0]["is_triggered"])
            self.assertTrue(annotated[0]["is_initial"])
            self.assertEqual(annotated[0]["triggered_by_questions"], [])
            # Triggered custom_app
            self.assertTrue(annotated[1]["is_triggered"])
            self.assertFalse(annotated[1]["is_initial"])
            self.assertEqual(annotated[1]["triggered_by_questions"], ["Does the app use custom software?"])

    def test_get_initial_implementation_groups(self):
        """Verify get_initial_implementation_groups only returns groups that are default or not triggered."""
        defs = [
            {"name": "Application information", "ref_id": "info", "default_selected": True},
            {"name": "General Controls", "ref_id": "general", "default_selected": False},
            {"name": "Custom applications", "ref_id": "custom_app", "default_selected": False},
        ]
        mock_map = {"custom_app": ["Does the app use custom software?"]}
        with patch("classes.audits.implementation_groups.get_framework_triggered_implementation_groups_map", return_value=mock_map):
            initial = get_initial_implementation_groups({"implementation_groups_definition": defs})
            names = [g["name"] for g in initial]
            self.assertIn("Application information", names)
            self.assertIn("General Controls", names)
            self.assertNotIn("Custom applications", names)


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
            self.assertIn("always_selectable_groups", res)
            self.assertIn("hidden_implementation_groups", res)
            self.assertIn("visible_implementation_groups", res)
            self.assertIn("groups_triggered_by_others_map", res)

    def test_examples_manager_determine_implementation_groups(self):
        """Verify ExamplesManager delegation to determine_implementation_groups_triggered_by_others."""
        mock_fw = MagicMock()
        mock_fw.get_id.return_value = "test_fw"
        mock_fw.get_name.return_value = "Test FW"
        mock_fw.json_object = {
            "ref_id": "test_fw",
            "implementation_groups_definition": [
                {"name": "Info", "ref_id": "info", "default_selected": True},
            ],
            "requirement_nodes": [],
        }
        with patch.object(self.manager, "find_target_framework", return_value=mock_fw):
            res = self.manager.determine_implementation_groups_triggered_by_others("test_fw")
            self.assertEqual(len(res["always_selectable_groups"]), 1)
            self.assertEqual(res["always_selectable_groups"][0]["name"], "Info")
            alias_res = self.manager.get_implementation_groups_triggered_by_others("test_fw")
            self.assertEqual(alias_res["framework_id"], "test_fw")

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

    def test_assign_audit_implementation_groups(self):
        """Verify multi-step assignment of triggered implementation groups."""
        mock_info = {
            "app_name": "App-Audit",
            "compliance_assessment_id": "ca-1",
            "framework_id": "fw-1",
            "selected_implementation_groups": ["Application information"],
            "available_implementation_groups": [
                {"name": "Application information", "ref_id": "info", "default_selected": True, "is_triggered": False, "is_initial": True},
                {"name": "Custom applications", "ref_id": "custom_app", "default_selected": False, "is_triggered": True, "is_initial": False},
            ],
            "app_owner_email": "owner@company.local",
            "existing_assignments": [
                {"id": "asgn-1", "name": "Step 1 Profiling", "status": "completed", "requirements_count": 3}
            ],
        }

        mock_ra1 = MagicMock(get_id=MagicMock(return_value="ra-1"), json_object={"implementation_groups": ["info"]})
        mock_ra2 = MagicMock(get_id=MagicMock(return_value="ra-2"), json_object={"implementation_groups": ["custom_app"]})

        mock_req_assessments = MagicMock()
        mock_req_assessments.get_requirement_assessment_id_list_from_compliance_assessment_id.return_value = ["ra-1", "ra-2"]
        mock_req_assessments.get_requirement_assessments.return_value = {"ra-1": mock_ra1, "ra-2": mock_ra2}

        mock_req_assignments = MagicMock()
        mock_asgn_existing = MagicMock(
            get_compliance_assessment_id=MagicMock(return_value="ca-1"),
            get_requirement_assessment_id_list=MagicMock(return_value=["ra-1"]),
        )
        mock_req_assignments.get_requirement_assignments.return_value = [mock_asgn_existing]

        mock_user = MagicMock(get_id=MagicMock(return_value="u-100"), get_email=MagicMock(return_value="dev@company.local"))
        mock_user_dict = MagicMock()
        mock_user_dict.get_id_from_email.return_value = "u-100"
        mock_user_dict.get_users.return_value = {"u-100": mock_user}

        mock_ca = MagicMock(get_id=MagicMock(return_value="ca-1"), get_name=MagicMock(return_value="Assessment ca-1"))
        mock_compliance_dict = MagicMock()
        mock_compliance_dict.get_compliance_assessments.return_value = {"ca-1": mock_ca}
        mock_compliance_dict.requirement_assessments = mock_req_assessments
        mock_compliance_dict.requirement_assignments = mock_req_assignments

        mock_data = {
            "compliance_assessment_dict": mock_compliance_dict,
            "user_dict": mock_user_dict,
            "perimeter_dict": MagicMock(get_id_from_name=MagicMock(return_value="p-1")),
        }

        with (
            patch.object(self.manager, "_init_data", return_value=mock_data),
            patch.object(self.manager, "get_audit_implementation_groups", return_value=mock_info),
            patch.object(self.manager, "resolve_actor_id", return_value="u-100"),
            patch("classes.audits.requirement_assessment.create_requirement_assignment", return_value={"id": "asgn-2", "status": "draft"}) as mock_create_asgn,
            patch("classes.audits.requirement_assignment.start_requirement_assignment", return_value={"id": "asgn-2", "status": "in_progress"}) as mock_start_asgn,
        ):
            res = self.manager.assign_audit_implementation_groups(
                "App-Audit",
                groups=["custom_app"],
                user_email="dev@company.local",
                start=True,
            )
            mock_ca.add_selected_implementation_groups.assert_called_once()
            mock_create_asgn.assert_called_once()
            payload_passed = mock_create_asgn.call_args[0][0]
            self.assertEqual(payload_passed["compliance_assessment"], "ca-1")
            self.assertEqual(payload_passed["actor"], ["u-100"])
            self.assertEqual(payload_passed["requirement_assessments"], ["ra-2"])
            mock_start_asgn.assert_called_once_with("asgn-2")
            self.assertEqual(res["assignment_id"], "asgn-2")
            self.assertEqual(res["assignment_status"], "in_progress")
            self.assertEqual(res["assigned_requirements_count"], 1)


class TestImplementationGroupsTriggeredByOthers(unittest.TestCase):
    """Test suite for determine_implementation_groups_triggered_by_others logic."""

    def setUp(self):
        self.mock_fw = {
            "ref_id": "test_fw",
            "name": "Test Framework",
            "implementation_groups_definition": [
                {
                    "name": "Application information",
                    "ref_id": "info",
                    "default_selected": True,
                },
                {
                    "name": "Custom Software Track",
                    "ref_id": "custom_app",
                    "default_selected": False,
                },
                {
                    "name": "COTS Software Track",
                    "ref_id": "cots_app",
                    "default_selected": False,
                },
                {
                    "name": "Internet Facing Track",
                    "ref_id": "internet_facing",
                    "default_selected": False,
                },
            ],
            "requirement_nodes": [
                {
                    "ref_id": "node_hosting",
                    "name": "Hosting Model",
                    "implementation_groups": ["info"],
                    "questions": {
                        "q1": {
                            "text": "What is the hosting model?",
                            "choices": [
                                {
                                    "ref_id": "c_custom",
                                    "value": "Custom Development",
                                    "select_implementation_groups": ["custom_app"],
                                },
                                {
                                    "ref_id": "c_cots",
                                    "value": "Bought Software",
                                    "select_implementation_groups": ["cots_app"],
                                },
                            ],
                        }
                    },
                },
                {
                    "ref_id": "node_exposure",
                    "name": "Exposure",
                    "implementation_groups": ["custom_app", "cots_app"],
                    "questions": {
                        "q2": {
                            "text": "Is it exposed to the Internet?",
                            "choices": [
                                {
                                    "ref_id": "c_pub",
                                    "value": "Public Internet",
                                    "select_implementation_groups": ["internet_facing"],
                                }
                            ],
                        }
                    },
                },
            ],
        }

    def test_determine_implementation_groups_triggered_by_others_initial(self):
        """Verify initial state: only always_selectable (untriggered) are shown; others are hidden."""
        res = determine_implementation_groups_triggered_by_others(self.mock_fw)

        always_selectable_names = [g["name"] for g in res["always_selectable_groups"]]
        hidden_names = [g["name"] for g in res["hidden_groups"]]
        triggered_names = [g["name"] for g in res["triggered_groups"]]
        visible_names = [g["name"] for g in res["visible_groups"]]

        # 'Application information' does not need to be triggered
        self.assertIn("Application information", always_selectable_names)
        self.assertIn("Application information", visible_names)

        # 'Custom Software Track', 'COTS Software Track', 'Internet Facing Track' must be triggered but haven't
        self.assertIn("Custom Software Track", hidden_names)
        self.assertIn("COTS Software Track", hidden_names)
        self.assertIn("Internet Facing Track", hidden_names)
        self.assertEqual(len(triggered_names), 0)
        self.assertEqual(len(visible_names), 1)

        # Check dependency mapping (triggered by other groups)
        dep_map = res["dependency_map"]
        self.assertIn("Application information", dep_map["Custom Software Track"]["triggered_by_groups"])
        self.assertIn("Custom Software Track", dep_map["Internet Facing Track"]["triggered_by_groups"])
        self.assertIn("COTS Software Track", dep_map["Internet Facing Track"]["triggered_by_groups"])

    def test_determine_implementation_groups_with_answers(self):
        """Verify that answering the trigger question makes the group triggered and visible."""
        answers = {
            "node_hosting": {
                "q1": "Custom Development",
            }
        }
        res = determine_implementation_groups_triggered_by_others(self.mock_fw, answers=answers)

        always_selectable_names = [g["name"] for g in res["always_selectable_groups"]]
        hidden_names = [g["name"] for g in res["hidden_groups"]]
        triggered_names = [g["name"] for g in res["triggered_groups"]]
        visible_names = [g["name"] for g in res["visible_groups"]]

        self.assertIn("Application information", always_selectable_names)
        self.assertIn("Custom Software Track", triggered_names)
        self.assertIn("Custom Software Track", visible_names)
        self.assertIn("Application information", visible_names)

        # COTS and Internet facing remain hidden because their triggers haven't matched
        self.assertIn("COTS Software Track", hidden_names)
        self.assertIn("Internet Facing Track", hidden_names)

    def test_determine_implementation_groups_with_active_groups(self):
        """Verify groups active in audit are recognized as triggered and visible."""
        res = determine_implementation_groups_triggered_by_others(
            self.mock_fw, active_groups=["custom_app"]
        )
        visible_names = [g["name"] for g in res["visible_groups"]]
        triggered_names = [g["name"] for g in res["triggered_groups"]]

        self.assertIn("Custom Software Track", visible_names)
        self.assertIn("Custom Software Track", triggered_names)

    def test_determine_implementation_groups_with_ca_reqs(self):
        """Verify evaluating triggers from requirement assessment objects."""
        mock_ra = MagicMock()
        mock_ra.get_ref_id.return_value = "node_exposure"
        mock_ra.get_urn.return_value = "urn:node_exposure"
        mock_ra.get_answers.return_value = {"q2": "Public Internet"}

        res = determine_implementation_groups_triggered_by_others(
            self.mock_fw, ca_reqs=[mock_ra]
        )
        triggered_names = [g["name"] for g in res["triggered_groups"]]
        self.assertIn("Internet Facing Track", triggered_names)

    def test_get_visible_implementation_groups_and_alias(self):
        """Verify get_visible_implementation_groups and get_implementation_groups_triggered_by_others alias."""
        visible = get_visible_implementation_groups(self.mock_fw, active_groups=["cots_app"])
        visible_names = [g["name"] for g in visible]
        self.assertIn("Application information", visible_names)
        self.assertIn("COTS Software Track", visible_names)
        self.assertNotIn("Internet Facing Track", visible_names)

        alias_res = get_implementation_groups_triggered_by_others(self.mock_fw)
        self.assertEqual(len(alias_res["all_groups"]), 4)

    def test_appsec_real_framework_dependencies(self):
        """Verify dependency analysis on the real AppSec framework definition."""
        res = determine_implementation_groups_triggered_by_others("appsec")
        self.assertGreater(len(res["all_groups"]), 0)

        always_selectable = [g["ref_id"] for g in res["always_selectable_groups"]]
        hidden = [g["ref_id"] for g in res["hidden_groups"]]

        self.assertEqual(always_selectable, ["info"])
        self.assertIn("baseline", hidden)
        self.assertIn("custom_app", hidden)
        self.assertIn("cots_app", hidden)
        self.assertIn("infra", hidden)
        self.assertIn("saas_app", hidden)
        self.assertIn("saas_uncertified", hidden)
        self.assertIn("internet_facing", hidden)

        # 1. Custom software (hosting:q1:c1) triggers custom_app, infra, and baseline
        res_custom = determine_implementation_groups_triggered_by_others(
            "appsec",
            answers={"hosting": {"q1": "Custom software created and deployed by my teams (In-house development)"}},
        )
        triggered_custom = [g["ref_id"] for g in res_custom["triggered_groups"]]
        self.assertIn("custom_app", triggered_custom)
        self.assertIn("infra", triggered_custom)
        self.assertIn("baseline", triggered_custom)
        self.assertNotIn("cots_app", triggered_custom)
        self.assertNotIn("saas_app", triggered_custom)

        # 2. COTS software (hosting:q1:c2) triggers cots_app, infra, and baseline
        res_cots = determine_implementation_groups_triggered_by_others(
            "appsec",
            answers={"hosting": {"q1": "Bought software deployed by my teams (COTS / Vendor package)"}},
        )
        triggered_cots = [g["ref_id"] for g in res_cots["triggered_groups"]]
        self.assertIn("cots_app", triggered_cots)
        self.assertIn("infra", triggered_cots)
        self.assertIn("baseline", triggered_cots)
        self.assertNotIn("custom_app", triggered_cots)
        self.assertNotIn("saas_app", triggered_cots)

        # 3. SaaS software (hosting:q1:c3) triggers saas_app and baseline, and does NOT trigger infra
        res_saas = determine_implementation_groups_triggered_by_others(
            "appsec",
            answers={"hosting": {"q1": "SaaS (Third-party software hosted and operated by a vendor)"}},
        )
        triggered_saas = [g["ref_id"] for g in res_saas["triggered_groups"]]
        self.assertIn("saas_app", triggered_saas)
        self.assertIn("baseline", triggered_saas)
        self.assertNotIn("infra", triggered_saas)
        self.assertNotIn("custom_app", triggered_saas)
        self.assertNotIn("cots_app", triggered_saas)

    def test_appsec_manual_triggered_implementation_groups_orchestration(self):
        """Verify that the manual AppSec framework hides non-relevant tracks and enables orchestrator-driven dynamic triggering."""
        # 1. Initial State: Only 'info' (basic profiling) is always selectable; all dependent tracks are hidden
        res_initial = determine_implementation_groups_triggered_by_others("appsec_manual")
        self.assertGreater(len(res_initial["all_groups"]), 0)

        always_selectable = [g["ref_id"] for g in res_initial["always_selectable_groups"]]
        hidden = [g["ref_id"] for g in res_initial["hidden_groups"]]
        triggered = [g["ref_id"] for g in res_initial["triggered_groups"]]
        visible = [g["ref_id"] for g in res_initial["visible_groups"]]

        self.assertEqual(always_selectable, ["info"])
        self.assertEqual(visible, ["info"])
        self.assertEqual(len(triggered), 0)
        self.assertIn("custom_app", hidden)
        self.assertIn("cots_app", hidden)
        self.assertIn("infra", hidden)
        self.assertIn("saas_app", hidden)
        self.assertIn("saas_uncertified", hidden)
        self.assertIn("baseline", hidden)
        self.assertIn("internet_facing", hidden)

        # Triggered map defines prompts for orchestrator
        from classes.audits.implementation_groups import get_framework_triggered_implementation_groups_map
        trig_map = get_framework_triggered_implementation_groups_map("appsec_manual")
        self.assertIn("custom_app", trig_map)
        self.assertIn("cots_app", trig_map)
        self.assertIn("infra", trig_map)
        self.assertIn("saas_app", trig_map)
        self.assertIn("saas_uncertified", trig_map)
        self.assertIn("internet_facing", trig_map)

        # 2. Answers Provided: Custom Software + Internet-Facing
        custom_answers = {
            "hosting": {
                "q1": "Custom software created and deployed by my teams (In-house development)",
                "q2": "Internet-facing (Public Web / Mobile API)",
            },
        }
        res_custom = determine_implementation_groups_triggered_by_others("appsec_manual", answers=custom_answers)

        triggered_custom = [g["ref_id"] for g in res_custom["triggered_groups"]]
        visible_custom = [g["ref_id"] for g in res_custom["visible_groups"]]
        hidden_custom = [g["ref_id"] for g in res_custom["hidden_groups"]]
        pending_custom = [d["target_implementation_group"] for d in res_custom["pending_dependencies"]]

        # Custom, Infra & Internet-Facing (and baseline) are now triggered & visible
        self.assertIn("custom_app", triggered_custom)
        self.assertIn("infra", triggered_custom)
        self.assertIn("internet_facing", triggered_custom)
        self.assertIn("baseline", triggered_custom)
        self.assertIn("info", visible_custom)
        self.assertIn("custom_app", visible_custom)
        self.assertIn("infra", visible_custom)
        self.assertIn("internet_facing", visible_custom)
        self.assertIn("custom_app", pending_custom)
        self.assertIn("infra", pending_custom)
        self.assertIn("internet_facing", pending_custom)

        # Non-relevant tracks (COTS, SaaS) remain hidden and non-selectable
        self.assertIn("cots_app", hidden_custom)
        self.assertIn("saas_app", hidden_custom)
        self.assertNotIn("cots_app", visible_custom)
        self.assertNotIn("saas_app", visible_custom)

        # 3. Answers Provided: COTS Software + Internal Network
        cots_answers = {
            "hosting": {
                "q1": "Bought software deployed by my teams (COTS / Vendor package)",
                "q2": "Internal / Restricted Network only",
            },
        }
        res_cots = determine_implementation_groups_triggered_by_others("appsec_manual", answers=cots_answers)
        triggered_cots = [g["ref_id"] for g in res_cots["triggered_groups"]]
        hidden_cots = [g["ref_id"] for g in res_cots["hidden_groups"]]

        self.assertIn("cots_app", triggered_cots)
        self.assertIn("infra", triggered_cots)
        self.assertIn("custom_app", hidden_cots)
        self.assertIn("saas_app", hidden_cots)
        self.assertIn("internet_facing", hidden_cots)

        # 4. Answers Provided: Certified SaaS Software -> Triggers saas_app and baseline; saas_uncertified & internet_facing remain hidden
        saas_answers = {
            "hosting": {
                "q1": "SaaS (Third-party software hosted and operated by a vendor)",
                "q3": "Yes - The SaaS vendor holds an active ISO/IEC 27001 certification or SOC 2 Type II report",
            },
        }
        res_saas = determine_implementation_groups_triggered_by_others("appsec_manual", answers=saas_answers)
        triggered_saas = [g["ref_id"] for g in res_saas["triggered_groups"]]
        hidden_saas = [g["ref_id"] for g in res_saas["hidden_groups"]]
        visible_saas = [g["ref_id"] for g in res_saas["visible_groups"]]

        self.assertIn("saas_app", triggered_saas)
        self.assertIn("baseline", triggered_saas)
        self.assertIn("saas_app", visible_saas)
        self.assertIn("baseline", visible_saas)
        self.assertIn("info", visible_saas)

        # Non-relevant tracks (Custom, COTS, Infra, Internet-Facing, Uncertified SaaS) remain hidden
        self.assertIn("custom_app", hidden_saas)
        self.assertIn("cots_app", hidden_saas)
        self.assertIn("infra", hidden_saas)
        self.assertIn("internet_facing", hidden_saas)
        self.assertIn("saas_uncertified", hidden_saas)
        self.assertNotIn("internet_facing", visible_saas)
        self.assertNotIn("internet_facing", triggered_saas)
        self.assertNotIn("saas_uncertified", visible_saas)
        self.assertNotIn("saas_uncertified", triggered_saas)

        # 5. Answers Provided: Uncertified SaaS Software -> Triggers saas_app, saas_uncertified, and baseline
        saas_uncert_answers = {
            "hosting": {
                "q1": "SaaS (Third-party software hosted and operated by a vendor)",
                "q3": "No - The SaaS vendor is not ISO/IEC 27001 or SOC 2 Type II certified",
            },
        }
        res_saas_uncert = determine_implementation_groups_triggered_by_others("appsec_manual", answers=saas_uncert_answers)
        triggered_saas_uncert = [g["ref_id"] for g in res_saas_uncert["triggered_groups"]]
        hidden_saas_uncert = [g["ref_id"] for g in res_saas_uncert["hidden_groups"]]
        visible_saas_uncert = [g["ref_id"] for g in res_saas_uncert["visible_groups"]]

        self.assertIn("saas_app", triggered_saas_uncert)
        self.assertIn("saas_uncertified", triggered_saas_uncert)
        self.assertIn("baseline", triggered_saas_uncert)
        self.assertIn("saas_app", visible_saas_uncert)
        self.assertIn("saas_uncertified", visible_saas_uncert)
        self.assertIn("custom_app", hidden_saas_uncert)
        self.assertIn("cots_app", hidden_saas_uncert)
        self.assertIn("infra", hidden_saas_uncert)
        self.assertIn("internet_facing", hidden_saas_uncert)

    def test_appsec_manual_example_suite_all_6_combinations(self):
        """Verify the comprehensive application example suite testing all 6 conditional IG combinations."""
        from pathlib import Path
        import yaml
        from tests.test_application_scenarios import ApplicationRiskSimulator

        with open("YML/appsec_manual.yml", "r", encoding="utf-8") as f:
            fw_doc = yaml.safe_load(f)
        fw = fw_doc["objects"]["framework"]
        nodes_by_ref = {n["ref_id"]: n for n in fw["requirement_nodes"] if n.get("assessable")}
        simulator = ApplicationRiskSimulator("YML/appsec_manual.yml")

        expected_cases = {
            "test_data/app_manual_custom_internal.yml": {
                "name": "App-Manual-Custom-Internal",
                "visible_igs": {"info", "baseline", "custom_app", "infra"},
                "hidden_igs": {"cots_app", "internet_facing", "saas_app", "saas_uncertified"},
                "node_count": 22,
                "scenario_count": 19,
                "excluded_scenario_count": 25,
            },
            "test_data/app_manual_custom_internet.yml": {
                "name": "App-Manual-Custom-Internet",
                "visible_igs": {"info", "baseline", "custom_app", "infra", "internet_facing"},
                "hidden_igs": {"cots_app", "saas_app", "saas_uncertified"},
                "node_count": 24,
                "scenario_count": 21,
                "excluded_scenario_count": 23,
            },
            "test_data/app_manual_cots_internal.yml": {
                "name": "App-Manual-COTS-Internal",
                "visible_igs": {"info", "baseline", "cots_app", "infra"},
                "hidden_igs": {"custom_app", "internet_facing", "saas_app", "saas_uncertified"},
                "node_count": 18,
                "scenario_count": 15,
                "excluded_scenario_count": 29,
            },
            "test_data/app_manual_cots_internet.yml": {
                "name": "App-Manual-COTS-Internet",
                "visible_igs": {"info", "baseline", "cots_app", "infra", "internet_facing"},
                "hidden_igs": {"custom_app", "saas_app", "saas_uncertified"},
                "node_count": 20,
                "scenario_count": 17,
                "excluded_scenario_count": 27,
            },
            "test_data/app_manual_saas_certified.yml": {
                "name": "App-Manual-SaaS-Certified",
                "visible_igs": {"info", "baseline", "saas_app"},
                "hidden_igs": {"custom_app", "cots_app", "infra", "internet_facing", "saas_uncertified"},
                "node_count": 13,
                "scenario_count": 10,
                "excluded_scenario_count": 34,
            },
            "test_data/app_manual_saas_uncertified.yml": {
                "name": "App-Manual-SaaS-Uncertified",
                "visible_igs": {"info", "baseline", "saas_app", "saas_uncertified"},
                "hidden_igs": {"custom_app", "cots_app", "infra", "internet_facing"},
                "node_count": 27,
                "scenario_count": 24,
                "excluded_scenario_count": 20,
            },
        }

        for file_path, exp in expected_cases.items():
            with self.subTest(file=file_path, case=exp["name"]):
                yaml_p = Path(file_path)
                self.assertTrue(yaml_p.exists(), f"File {file_path} missing")
                with open(yaml_p, "r", encoding="utf-8") as f:
                    app_doc = yaml.safe_load(f)

                # 1. Implementation Group Scoping
                dep_info = determine_implementation_groups_triggered_by_others(
                    "appsec_manual",
                    yaml_path=file_path,
                )
                vis_refs = {g["ref_id"] for g in dep_info["visible_groups"]}
                hid_refs = {g["ref_id"] for g in dep_info["hidden_groups"]}
                self.assertEqual(vis_refs, exp["visible_igs"], f"Visible IG mismatch in {file_path}")
                self.assertEqual(hid_refs, exp["hidden_igs"], f"Hidden IG mismatch in {file_path}")

                # 2. Requirement Node Coverage & Absence of Out-of-Scope Requirements
                answers = app_doc.get("answers", [])
                answered_req_refs = {a["requirement"] for a in answers}
                self.assertEqual(len(answered_req_refs), exp["node_count"], f"Node count mismatch in {file_path}")

                for req_ref in answered_req_refs:
                    node = nodes_by_ref.get(req_ref)
                    self.assertIsNotNone(node, f"Unknown requirement '{req_ref}' in {file_path}")
                    node_igs = set(node.get("implementation_groups", []))
                    self.assertTrue(
                        bool(node_igs & exp["visible_igs"]),
                        f"Requirement '{req_ref}' belongs to {node_igs}, none of which are visible in {file_path}",
                    )

                # 3. Risk Scenarios Evaluation
                eval_results = simulator.evaluate_application(file_path)
                scenarios = eval_results["scenarios"]
                self.assertEqual(len(scenarios), exp["scenario_count"], f"Scenario count mismatch in {file_path}")
                excluded = app_doc.get("expected_evaluation", {}).get("excluded_scenarios", [])
                self.assertEqual(len(excluded), exp["excluded_scenario_count"], f"Excluded scenario count mismatch in {file_path}")

                # Every evaluated scenario belongs to in-scope requirements
                for sc_name, sc_data in scenarios.items():
                    sc_def = next(s for s in simulator.risk_scenarios if s["name"] == sc_name)
                    lh_node_ref = sc_def["likelihood"].rsplit(":", 1)[-1]
                    self.assertIn(
                        lh_node_ref, answered_req_refs,
                        f"Scenario '{sc_name}' evaluated but its likelihood requirement '{lh_node_ref}' is not answered in {file_path}",
                    )

    def test_appsec_example_suite_all_6_combinations(self):
        """Verify the comprehensive application example suite testing all 6 conditional IG combinations for appsec."""
        from pathlib import Path
        import yaml
        from tests.test_application_scenarios import ApplicationRiskSimulator

        with open("YML/appsec.yml", "r", encoding="utf-8") as f:
            fw_doc = yaml.safe_load(f)
        fw = fw_doc["objects"]["framework"]
        nodes_by_ref = {n["ref_id"]: n for n in fw["requirement_nodes"] if n.get("assessable")}
        simulator = ApplicationRiskSimulator("YML/appsec.yml")

        expected_cases = {
            "test_data/app_appsec_custom_internal.yml": {
                "name": "App-AppSec-Custom-Internal",
                "visible_igs": {"info", "baseline", "custom_app", "infra"},
                "hidden_igs": {"cots_app", "internet_facing", "saas_app", "saas_uncertified"},
                "node_count": 22,
                "scenario_count": 19,
                "excluded_scenario_count": 25,
            },
            "test_data/app_appsec_custom_internet.yml": {
                "name": "App-AppSec-Custom-Internet",
                "visible_igs": {"info", "baseline", "custom_app", "infra", "internet_facing"},
                "hidden_igs": {"cots_app", "saas_app", "saas_uncertified"},
                "node_count": 24,
                "scenario_count": 21,
                "excluded_scenario_count": 23,
            },
            "test_data/app_appsec_cots_internal.yml": {
                "name": "App-AppSec-COTS-Internal",
                "visible_igs": {"info", "baseline", "cots_app", "infra"},
                "hidden_igs": {"custom_app", "internet_facing", "saas_app", "saas_uncertified"},
                "node_count": 18,
                "scenario_count": 15,
                "excluded_scenario_count": 29,
            },
            "test_data/app_appsec_cots_internet.yml": {
                "name": "App-AppSec-COTS-Internet",
                "visible_igs": {"info", "baseline", "cots_app", "infra", "internet_facing"},
                "hidden_igs": {"custom_app", "saas_app", "saas_uncertified"},
                "node_count": 20,
                "scenario_count": 17,
                "excluded_scenario_count": 27,
            },
            "test_data/app_appsec_saas_certified.yml": {
                "name": "App-AppSec-SaaS-Certified",
                "visible_igs": {"info", "baseline", "saas_app"},
                "hidden_igs": {"custom_app", "cots_app", "infra", "internet_facing", "saas_uncertified"},
                "node_count": 13,
                "scenario_count": 10,
                "excluded_scenario_count": 34,
            },
            "test_data/app_appsec_saas_uncertified.yml": {
                "name": "App-AppSec-SaaS-Uncertified",
                "visible_igs": {"info", "baseline", "saas_app", "saas_uncertified"},
                "hidden_igs": {"custom_app", "cots_app", "infra", "internet_facing"},
                "node_count": 27,
                "scenario_count": 24,
                "excluded_scenario_count": 20,
            },
        }

        for file_path, exp in expected_cases.items():
            with self.subTest(file=file_path, case=exp["name"]):
                yaml_p = Path(file_path)
                self.assertTrue(yaml_p.exists(), f"File {file_path} missing")
                with open(yaml_p, "r", encoding="utf-8") as f:
                    app_doc = yaml.safe_load(f)

                # 1. Implementation Group Scoping
                dep_info = determine_implementation_groups_triggered_by_others(
                    "appsec",
                    yaml_path=file_path,
                )
                vis_refs = {g["ref_id"] for g in dep_info["visible_groups"]}
                hid_refs = {g["ref_id"] for g in dep_info["hidden_groups"]}
                self.assertEqual(vis_refs, exp["visible_igs"], f"Visible IG mismatch in {file_path}")
                self.assertEqual(hid_refs, exp["hidden_igs"], f"Hidden IG mismatch in {file_path}")

                # 2. Requirement Node Coverage & Absence of Out-of-Scope Requirements
                answers = app_doc.get("answers", [])
                answered_req_refs = {a["requirement"] for a in answers}
                self.assertEqual(len(answered_req_refs), exp["node_count"], f"Node count mismatch in {file_path}")

                for req_ref in answered_req_refs:
                    node = nodes_by_ref.get(req_ref)
                    self.assertIsNotNone(node, f"Unknown requirement '{req_ref}' in {file_path}")
                    node_igs = set(node.get("implementation_groups", []))
                    self.assertTrue(
                        bool(node_igs & exp["visible_igs"]),
                        f"Requirement '{req_ref}' belongs to {node_igs}, none of which are visible in {file_path}",
                    )

                # 3. Risk Scenarios Evaluation
                eval_results = simulator.evaluate_application(file_path)
                scenarios = eval_results["scenarios"]
                self.assertEqual(len(scenarios), exp["scenario_count"], f"Scenario count mismatch in {file_path}")
                excluded = app_doc.get("expected_evaluation", {}).get("excluded_scenarios", [])
                self.assertEqual(len(excluded), exp["excluded_scenario_count"], f"Excluded scenario count mismatch in {file_path}")

                # Every evaluated scenario belongs to in-scope requirements
                for sc_name, sc_data in scenarios.items():
                    sc_def = next(s for s in simulator.risk_scenarios if s["name"] == sc_name)
                    lh_node_ref = sc_def["likelihood"].rsplit(":", 1)[-1]
                    self.assertIn(
                        lh_node_ref, answered_req_refs,
                        f"Scenario '{sc_name}' evaluated but its likelihood requirement '{lh_node_ref}' is not answered in {file_path}",
                    )

if __name__ == "__main__":
    unittest.main()

