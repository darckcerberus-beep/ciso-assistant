"""Unit tests for status reporting table and lifecycle states in main.py and ExamplesManager."""

import io
import unittest
from unittest.mock import MagicMock, patch

from classes.examples_manager import ExamplesManager
from main import print_status_table, remove_examples_ui


class TestMainStatus(unittest.TestCase):
    """Test suite for deployment status table and lifecycle state evaluation."""

    def test_print_status_table_renders_all_status_columns(self):
        """Verify that print_status_table prints headers and rows for all lifecycle statuses."""
        mock_status_list = [
            {
                "id": "app_secure_core",
                "name": "App-Secure-Core",
                "exists": True,
                "app_created": True,
                "audit_created": True,
                "audit_answered": True,
                "total_requirements_count": 12,
                "answered_requirements_count": 12,
                "audit_completion_pct": 100,
                "risks_created": True,
                "controls_created": True,
                "controls_linked": True,
                "lifecycle_status": "CONFIGURED",
                "perimeter_id": "perm-1",
                "asset_id": "asset-1",
                "compliance_assessment_id": "ca-1",
                "compliance_assessment_name": "Compliance in App-Secure-Core",
                "risk_assessment_id": "ra-1",
                "risk_scenarios_count": 4,
                "applied_controls_count": 11,
                "existing_controls_linked": 11,
                "planned_controls_linked": 0,
                "vulnerabilities_linked": 4,
                "threats_linked": 4,
                "findings_assessment_id": "fa-1",
                "findings_count": 0,
                "entity_id": "ent-1",
                "entity_assessment_id": "ea-1",
                "user_email": "alice@example.com",
                "user_id": "usr-1",
                "tprm_conclusion": "ok",
            },
            {
                "id": "app_audit_demo",
                "name": "App-Audit-Demo",
                "exists": True,
                "app_created": True,
                "audit_created": True,
                "audit_answered": False,
                "total_requirements_count": 12,
                "answered_requirements_count": 0,
                "audit_completion_pct": 0,
                "risks_created": False,
                "controls_created": False,
                "controls_linked": False,
                "lifecycle_status": "AUDIT PENDING",
                "perimeter_id": "perm-2",
                "asset_id": "asset-2",
                "compliance_assessment_id": "ca-2",
                "compliance_assessment_name": "Compliance in App-Audit-Demo",
                "risk_assessment_id": None,
                "risk_scenarios_count": 0,
                "applied_controls_count": 0,
                "existing_controls_linked": 0,
                "planned_controls_linked": 0,
                "findings_assessment_id": None,
                "findings_count": 0,
                "entity_id": "ent-2",
                "entity_assessment_id": "ea-2",
                "user_email": "respondent@example.com",
                "user_id": "usr-2",
                "tprm_conclusion": None,
            },
            {
                "id": "app_partial_demo",
                "name": "App-Partial-Demo",
                "exists": True,
                "app_created": True,
                "audit_created": True,
                "audit_answered": True,
                "total_requirements_count": 12,
                "answered_requirements_count": 6,
                "audit_completion_pct": 50,
                "risks_created": False,
                "controls_created": False,
                "controls_linked": False,
                "lifecycle_status": "RISKS PENDING",
                "perimeter_id": "perm-3",
                "asset_id": "asset-3",
                "compliance_assessment_id": "ca-3",
                "compliance_assessment_name": "Compliance in App-Partial-Demo",
                "risk_assessment_id": None,
                "risk_scenarios_count": 0,
                "applied_controls_count": 0,
                "existing_controls_linked": 0,
                "planned_controls_linked": 0,
                "findings_assessment_id": None,
                "findings_count": 0,
                "entity_id": "ent-3",
                "entity_assessment_id": "ea-3",
                "user_email": "partial@example.com",
                "user_id": "usr-3",
                "tprm_conclusion": None,
            },
            {
                "id": "app_vulnerable_portal",
                "name": "App-Vulnerable-Portal",
                "exists": False,
                "app_created": False,
                "audit_created": False,
                "audit_answered": False,
                "total_requirements_count": 0,
                "answered_requirements_count": 0,
                "audit_completion_pct": 0,
                "risks_created": False,
                "controls_created": False,
                "controls_linked": False,
                "lifecycle_status": "NOT CREATED",
                "perimeter_id": None,
                "asset_id": None,
                "compliance_assessment_id": None,
                "compliance_assessment_name": None,
                "risk_assessment_id": None,
                "risk_scenarios_count": 0,
                "applied_controls_count": 0,
                "existing_controls_linked": 0,
                "planned_controls_linked": 0,
                "findings_assessment_id": None,
                "findings_count": 0,
                "entity_id": None,
                "entity_assessment_id": None,
                "user_email": "victor@example.com",
                "user_id": None,
                "tprm_conclusion": None,
            },
        ]

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_status_table(mock_status_list)

        output = buf.getvalue()

        # Check Table Headers
        self.assertIn("Application Name", output)
        self.assertIn("Status", output)
        self.assertIn("App Created", output)
        self.assertIn("Audit Answered", output)
        self.assertIn("Risks Created", output)
        self.assertIn("Controls", output)
        self.assertIn("Linked", output)

        # Check Row Values
        # App-Secure-Core: CONFIGURED | App: YES | Audit: YES (12/12) | Risks: YES (4)
        self.assertIn("CONFIGURED", output)
        self.assertIn("YES (12/12)", output)
        self.assertIn("YES (4)", output)

        # App-Audit-Demo: AUDIT PENDING | App: YES | Audit: NO (0/12) | Risks: NO
        self.assertIn("AUDIT PENDING", output)
        self.assertIn("NO (0/12)", output)

        # App-Partial-Demo: RISKS PENDING | App: YES | Audit: PARTIAL (6/12) | Risks: NO
        self.assertIn("RISKS PENDING", output)
        self.assertIn("PARTIAL (6/12)", output)

        # App-Vulnerable-Portal: NOT CREATED | App: NO | Audit: - | Risks: -
        self.assertIn("NOT CREATED", output)

        # Check Detailed view breakdown
        self.assertIn("Lifecycle Status:", output)
        self.assertIn("App Created:", output)
        self.assertIn("Audit Answered:", output)
        self.assertIn("Risks Created:", output)
        self.assertIn("12/12 requirements answered, 100% complete", output)
        self.assertIn("0/12 requirements answered, 0% complete", output)

    def test_build_status_dict_states(self):
        """Verify lifecycle_status and flags for all application states."""
        # State 1: Not Created
        s1 = ExamplesManager._build_status_dict(
            app_id="app_1",
            app_name="App-1",
            label="App 1",
            yaml_path="",
            perimeter_id=None,
            asset_id=None,
            ca_obj=None,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id=None,
            ea_obj=None,
            user_email=None,
            user_id=None,
            req_by_ca={},
        )
        self.assertFalse(s1["exists"])
        self.assertFalse(s1["app_created"])
        self.assertFalse(s1["audit_created"])
        self.assertFalse(s1["audit_answered"])
        self.assertFalse(s1["risks_created"])
        self.assertEqual(s1["lifecycle_status"], "NOT CREATED")
        self.assertEqual(s1["status"], "NOT CREATED")

        # State 2: App Only (Perimeter & Asset created, no CA)
        s2 = ExamplesManager._build_status_dict(
            app_id="app_2",
            app_name="App-2",
            label="App 2",
            yaml_path="",
            perimeter_id="perm-2",
            asset_id="asset-2",
            ca_obj=None,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-2",
            ea_obj=None,
            user_email="user@example.com",
            user_id="u-2",
            req_by_ca={},
        )
        self.assertTrue(s2["exists"])
        self.assertTrue(s2["app_created"])
        self.assertFalse(s2["audit_created"])
        self.assertFalse(s2["audit_answered"])
        self.assertEqual(s2["lifecycle_status"], "APP ONLY (NO AUDIT)")

        # State 3: Audit Pending (CA created with 2 requirements, 0 answered)
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-3"
        mock_ca.get_name.return_value = "CA-3"
        mock_ca.get_status.return_value = "in_progress"

        mock_ra1 = MagicMock()
        mock_ra1.get_compliance_assessment_id.return_value = "ca-3"
        mock_ra1.has_selected_answer.return_value = False
        mock_ra1.is_unassessed_result.return_value = True

        mock_ra2 = MagicMock()
        mock_ra2.get_compliance_assessment_id.return_value = "ca-3"
        mock_ra2.has_selected_answer.return_value = False
        mock_ra2.is_unassessed_result.return_value = True

        s3 = ExamplesManager._build_status_dict(
            app_id="app_3",
            app_name="App-3",
            label="App 3",
            yaml_path="",
            perimeter_id="perm-3",
            asset_id="asset-3",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-3",
            ea_obj=MagicMock(),
            user_email="user@example.com",
            user_id="u-3",
            req_by_ca={"ca-3": [mock_ra1, mock_ra2]},
        )
        self.assertTrue(s3["exists"])
        self.assertTrue(s3["app_created"])
        self.assertTrue(s3["audit_created"])
        self.assertFalse(s3["audit_answered"])
        self.assertEqual(s3["total_requirements_count"], 2)
        self.assertEqual(s3["answered_requirements_count"], 0)
        self.assertEqual(s3["lifecycle_status"], "AUDIT PENDING (0/2)")

        # State 4: Risks Pending (Audit answered, but 0 scenarios)
        mock_ra_ans = MagicMock()
        mock_ra_ans.get_compliance_assessment_id.return_value = "ca-4"
        mock_ra_ans.has_selected_answer.return_value = True
        mock_ra_ans.is_unassessed_result.return_value = False

        s4 = ExamplesManager._build_status_dict(
            app_id="app_4",
            app_name="App-4",
            label="App 4",
            yaml_path="",
            perimeter_id="perm-4",
            asset_id="asset-4",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-4",
            ea_obj=MagicMock(),
            user_email="user@example.com",
            user_id="u-4",
            req_by_ca={"ca-3": [mock_ra_ans]},
        )
        self.assertTrue(s4["app_created"])
        self.assertTrue(s4["audit_answered"])
        self.assertFalse(s4["risks_created"])
        self.assertEqual(s4["lifecycle_status"], "RISKS PENDING")

        # State 5: Configured (Audit answered, scenarios evaluated, controls linked)
        mock_ra_obj = MagicMock()
        mock_ra_obj.get_id.return_value = "ra-5"

        s5 = ExamplesManager._build_status_dict(
            app_id="app_5",
            app_name="App-5",
            label="App 5",
            yaml_path="",
            perimeter_id="perm-5",
            asset_id="asset-5",
            ca_obj=mock_ca,
            ra_obj=mock_ra_obj,
            ra_scenarios_count=4,
            ctrl_count=11,
            existing_ctrls_linked=11,
            planned_ctrls_linked=0,
            vulns_linked=4,
            threats_linked=4,
            fa_id="fa-5",
            findings_count=0,
            entity_id="ent-5",
            ea_obj=MagicMock(),
            user_email="user@example.com",
            user_id="u-5",
            req_by_ca={"ca-3": [mock_ra_ans]},
        )
        self.assertTrue(s5["app_created"])
        self.assertTrue(s5["audit_answered"])
        self.assertTrue(s5["risks_created"])
        self.assertTrue(s5["controls_created"])
        self.assertTrue(s5["controls_linked"])
        self.assertEqual(s5["lifecycle_status"], "FULLY CONFIGURED")

        # State 6: Audit Partial (1 of 2 answered)
        s6 = ExamplesManager._build_status_dict(
            app_id="app_6",
            app_name="App-6",
            label="App 6",
            yaml_path="",
            perimeter_id="perm-6",
            asset_id="asset-6",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-6",
            ea_obj=MagicMock(),
            user_email="user@example.com",
            user_id="u-6",
            req_by_ca={"ca-3": [mock_ra_ans, mock_ra1]},
        )
        self.assertEqual(s6["lifecycle_status"], "AUDIT PARTIAL (1/2)")

        # State 7: Controls Pending (Scenarios created, 0 controls created)
        s7 = ExamplesManager._build_status_dict(
            app_id="app_7",
            app_name="App-7",
            label="App 7",
            yaml_path="",
            perimeter_id="perm-7",
            asset_id="asset-7",
            ca_obj=mock_ca,
            ra_obj=mock_ra_obj,
            ra_scenarios_count=3,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-7",
            ea_obj=MagicMock(),
            user_email="user@example.com",
            user_id="u-7",
            req_by_ca={"ca-3": [mock_ra_ans]},
        )
        self.assertEqual(s7["lifecycle_status"], "CONTROLS PENDING")

        # State 8: Linking Pending (Controls created, 0 linked)
        s8 = ExamplesManager._build_status_dict(
            app_id="app_8",
            app_name="App-8",
            label="App 8",
            yaml_path="",
            perimeter_id="perm-8",
            asset_id="asset-8",
            ca_obj=mock_ca,
            ra_obj=mock_ra_obj,
            ra_scenarios_count=3,
            ctrl_count=5,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-8",
            ea_obj=MagicMock(),
            user_email="user@example.com",
            user_id="u-8",
            req_by_ca={"ca-3": [mock_ra_ans]},
        )
        self.assertEqual(s8["lifecycle_status"], "LINKING PENDING")

    def test_triggered_requirements_resolution_public_app(self):
        """Verify that Public SaaS applications with 4/4 triggered requirements answered are NOT marked AUDIT PARTIAL."""
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-pub"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Public-Blog"
        mock_ca.get_status.return_value = "in_progress"

        req_refs = [
            "stakeholder_identification", "data_classification", "hosting", "saas_contract_compliance",
            "data_in_transit", "data_at_rest", "non_prod_data", "data_exchange", "data_destruction",
        ]
        mock_ras = []
        for ref in req_refs:
            ra = MagicMock()
            ra.get_requirement_ref_id.return_value = ref
            ra.get_urn.return_value = f"urn:intuitem:risk:req_node:mls:{ref}"
            if ref in ("stakeholder_identification", "data_classification", "hosting", "saas_contract_compliance"):
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = False
                if ref == "data_classification":
                    ra.get_answers.return_value = {"q1": "Public"}
                elif ref == "hosting":
                    ra.get_answers.return_value = {"q1": "SaaS"}
                else:
                    ra.get_answers.return_value = {"q1": "Yes"}
            else:
                ra.has_selected_answer.return_value = False
                ra.is_unassessed_result.return_value = True
                ra.get_answers.return_value = {}
            mock_ras.append(ra)

        status = ExamplesManager._build_status_dict(
            app_id="app_public_blog",
            app_name="App-Public-Blog",
            label="App-Public-Blog",
            yaml_path="test_data/app_public_blog.yml",
            perimeter_id="perm-pub",
            asset_id="asset-pub",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-pub",
            ea_obj=MagicMock(),
            user_email="paula@example.com",
            user_id="usr-pub",
            req_by_ca={"ca-pub": mock_ras},
        )

        # Triggered requirements: 4 (Chapter 2 encryption requirements are NOT triggered)
        self.assertEqual(status["total_requirements_count"], 4)
        self.assertEqual(status["answered_requirements_count"], 4)
        self.assertEqual(status["audit_completion_pct"], 100)
        self.assertTrue(status["audit_answered"])
        # Should NOT be classified as AUDIT PARTIAL
        self.assertNotEqual(status["lifecycle_status"], "AUDIT PARTIAL (4/12)")
        self.assertNotEqual(status["lifecycle_status"], "AUDIT PARTIAL (4/9)")
        self.assertEqual(status["lifecycle_status"], "RISKS PENDING")

        # Table formatting check
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_status_table([status])
        output = buf.getvalue()
        self.assertIn("YES (4/4)", output)
        self.assertNotIn("PARTIAL", output)

    def test_triggered_requirements_resolution_internal_onprem_app(self):
        """Verify that Internal On-Prem apps (e.g. ERP) have 3 triggered requirements and evaluate as complete."""
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-erp"
        mock_ca.get_name.return_value = "Assessment in App-Legacy-ERP-Production"
        mock_ca.get_status.return_value = "in_progress"

        req_refs = [
            "stakeholder_identification", "data_classification", "hosting", "saas_contract_compliance",
            "data_in_transit", "data_at_rest", "non_prod_data", "data_exchange", "data_destruction",
        ]
        mock_ras = []
        for ref in req_refs:
            ra = MagicMock()
            ra.get_requirement_ref_id.return_value = ref
            ra.get_urn.return_value = f"urn:intuitem:risk:req_node:mls:{ref}"
            if ref in ("stakeholder_identification", "data_classification", "hosting"):
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = False
                if ref == "data_classification":
                    ra.get_answers.return_value = {"q1": "Internal"}
                elif ref == "hosting":
                    ra.get_answers.return_value = {"q1": "In-house"}
                else:
                    ra.get_answers.return_value = {"q1": "Yes"}
            else:
                ra.has_selected_answer.return_value = False
                ra.is_unassessed_result.return_value = True
                ra.get_answers.return_value = {}
            mock_ras.append(ra)

        status = ExamplesManager._build_status_dict(
            app_id="app_legacy_erp_production",
            app_name="App-Legacy-ERP-Production",
            label="App-Legacy-ERP-Production",
            yaml_path="test_data/app_legacy_erp_production.yml",
            perimeter_id="perm-erp",
            asset_id="asset-erp",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-erp",
            ea_obj=MagicMock(),
            user_email="larry@example.com",
            user_id="usr-erp",
            req_by_ca={"ca-erp": mock_ras},
        )

        self.assertEqual(status["total_requirements_count"], 3)
        self.assertEqual(status["answered_requirements_count"], 3)
        self.assertEqual(status["audit_completion_pct"], 100)
        self.assertEqual(status["lifecycle_status"], "RISKS PENDING")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_status_table([status])
        output = buf.getvalue()
        self.assertIn("YES (3/3)", output)
        self.assertNotIn("PARTIAL", output)

    def test_partial_audit_only_when_triggered_requirements_unanswered(self):
        """Verify that AUDIT PARTIAL is only assigned when triggered questions are missing answers."""
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-partial-blog"
        mock_ca.get_name.return_value = "Assessment in App-Public-Blog"
        mock_ca.get_status.return_value = "in_progress"

        req_refs = [
            "stakeholder_identification", "data_classification", "hosting", "saas_contract_compliance",
            "data_in_transit", "data_at_rest", "non_prod_data", "data_exchange", "data_destruction",
        ]
        mock_ras = []
        for ref in req_refs:
            ra = MagicMock()
            ra.get_requirement_ref_id.return_value = ref
            ra.get_urn.return_value = f"urn:intuitem:risk:req_node:mls:{ref}"
            # Only answer 2 out of the 4 triggered requirements
            if ref in ("stakeholder_identification", "data_classification"):
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = False
                if ref == "data_classification":
                    ra.get_answers.return_value = {"q1": "Public"}
                else:
                    ra.get_answers.return_value = {"q1": "Yes"}
            else:
                ra.has_selected_answer.return_value = False
                ra.is_unassessed_result.return_value = True
                ra.get_answers.return_value = {}
            mock_ras.append(ra)

        status = ExamplesManager._build_status_dict(
            app_id="app_public_blog",
            app_name="App-Public-Blog",
            label="App-Public-Blog",
            yaml_path="test_data/app_public_blog.yml",
            perimeter_id="perm-pb",
            asset_id="asset-pb",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-pb",
            ea_obj=MagicMock(),
            user_email="paula@example.com",
            user_id="usr-pb",
            req_by_ca={"ca-partial-blog": mock_ras},
        )

        self.assertEqual(status["total_requirements_count"], 4)
        self.assertEqual(status["answered_requirements_count"], 2)
        self.assertEqual(status["audit_completion_pct"], 50)
        self.assertEqual(status["lifecycle_status"], "AUDIT PARTIAL (2/4)")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_status_table([status])
        output = buf.getvalue()
        self.assertIn("PARTIAL (2/4)", output)
        self.assertIn("AUDIT PARTIAL (2/4)", output)

    def test_unassessed_result_with_selected_answers_counts_as_answered(self):
        """Verify that questions with result=not_assessed (like data_classification and hosting) are counted as answered when choices are selected."""
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-rom"
        mock_ca.get_name.return_value = "Assessment of DPP in App-Rom"
        mock_ca.get_status.return_value = "planned"

        req_refs = [
            "stakeholder_identification", "data_classification", "hosting", "saas_contract_compliance",
            "data_in_transit", "data_at_rest", "non_prod_data", "data_exchange", "data_destruction",
        ]
        mock_ras = []
        for ref in req_refs:
            ra = MagicMock()
            ra.get_requirement_ref_id.return_value = ref
            ra.get_urn.return_value = f"urn:intuitem:risk:req_node:mls:{ref}"
            if ref == "stakeholder_identification":
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = False
                ra.get_answers.return_value = {"q1": "choice:2"}
            elif ref == "data_classification":
                # In live CISO Assistant, classification has selected answers but result remains not_assessed
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = True
                ra.get_answers.return_value = {"q1": "urn:intuitem:risk:req_node:mls:data_classification:q1:c2"}
            elif ref == "hosting":
                # In live CISO Assistant, hosting has selected answers but result remains not_assessed
                ra.has_selected_answer.return_value = True
                ra.is_unassessed_result.return_value = True
                ra.get_answers.return_value = {"q1": "urn:intuitem:risk:req_node:mls:hosting:q1:c1"}
            else:
                ra.has_selected_answer.return_value = False
                ra.is_unassessed_result.return_value = True
                ra.get_answers.return_value = {}
            mock_ras.append(ra)

        status = ExamplesManager._build_status_dict(
            app_id="custom_app-rom",
            app_name="App-Rom",
            label="App-Rom (Custom Audit Demo)",
            yaml_path="-",
            perimeter_id="perm-rom",
            asset_id="asset-rom",
            ca_obj=mock_ca,
            ra_obj=None,
            ra_scenarios_count=0,
            ctrl_count=0,
            existing_ctrls_linked=0,
            planned_ctrls_linked=0,
            vulns_linked=0,
            threats_linked=0,
            fa_id=None,
            findings_count=0,
            entity_id="ent-rom",
            ea_obj=MagicMock(),
            user_email="lucie@redoute.fr",
            user_id="usr-rom",
            req_by_ca={"ca-rom": mock_ras},
        )

        self.assertEqual(status["total_requirements_count"], 3)
        self.assertEqual(status["answered_requirements_count"], 3)
        self.assertEqual(status["audit_completion_pct"], 100)
        self.assertEqual(status["lifecycle_status"], "RISKS PENDING")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_status_table([status])
        output = buf.getvalue()
        self.assertIn("YES (3/3)", output)
        self.assertNotIn("PARTIAL", output)

    @patch("main.create_audit_demo_ui")
    def test_create_audit_demo_ui_called_from_cli(self, mock_create_audit_demo_ui):
        """Verify CLI --create-audit dispatches to create_audit_demo_ui."""
        from main import main
        with patch("sys.argv", ["main.py", "--create-audit", "App-Cli-Demo", "--user", "cli@example.com", "--framework", "mls"]):
            main()
            mock_create_audit_demo_ui.assert_called_once()
            _args, kwargs = mock_create_audit_demo_ui.call_args
            self.assertEqual(kwargs.get("app_name"), "App-Cli-Demo")
            self.assertEqual(kwargs.get("user_email"), "cli@example.com")
            self.assertEqual(kwargs.get("framework_ref_or_name"), "mls")

    def test_create_audit_demo_ui_aborts_when_no_frameworks_in_ciso_assistant(self):
        """Verify create_audit_demo_ui checks CISO Assistant and aborts if no frameworks are installed."""
        from main import create_audit_demo_ui
        mock_manager = MagicMock()
        mock_manager.test_connection.return_value = (True, "OK")
        mock_manager.get_installed_frameworks.return_value = []

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            create_audit_demo_ui(mock_manager, app_name="App-Demo", user_email="test@example.com")

        output = buf.getvalue()
        self.assertIn("No frameworks found in CISO Assistant", output)
        mock_manager.create_application_for_audit.assert_not_called()

    def test_create_audit_demo_ui_aborts_when_specified_framework_not_in_ciso_assistant(self):
        """Verify create_audit_demo_ui checks CISO Assistant and rejects uninstalled framework."""
        from main import create_audit_demo_ui
        mock_manager = MagicMock()
        mock_manager.test_connection.return_value = (True, "OK")
        mock_manager.get_installed_frameworks.return_value = [
            {"id": "fw-1", "name": "Data protection policy of ACME Corp", "ref_id": "mls"}
        ]
        mock_manager.find_target_framework.return_value = None

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            create_audit_demo_ui(
                mock_manager,
                app_name="App-Demo",
                user_email="test@example.com",
                framework_ref_or_name="vendor-due-diligence",
            )

        output = buf.getvalue()
        self.assertIn("Framework 'vendor-due-diligence' is not installed in CISO Assistant", output)
        self.assertIn("Data protection policy of ACME Corp (mls)", output)
        mock_manager.create_application_for_audit.assert_not_called()

    def test_create_audit_demo_ui_only_offers_installed_frameworks_in_selection(self):
        """Verify create_audit_demo_ui only offers frameworks verified in CISO Assistant."""
        from main import create_audit_demo_ui
        mock_manager = MagicMock()
        mock_manager.test_connection.return_value = (True, "OK")
        mock_manager.get_installed_frameworks.return_value = [
            {"id": "fw-1", "name": "Data protection policy of ACME Corp", "ref_id": "mls"}
        ]
        mock_manager._init_data.return_value = {"user_dict": MagicMock(get_id_from_email=MagicMock(return_value="user-1"))}
        mock_manager.create_application_for_audit.return_value = {
            "app_name": "App-Audit-Demo",
            "user_email": "auditor@example.com",
            "user_id": "u-1",
            "entity_id": "e-1",
            "entity_assessment_name": "EA-1",
            "entity_assessment_id": "ea-1",
            "compliance_assessment_name": "CA-1",
            "compliance_assessment_id": "ca-1",
            "framework_name": "Data protection policy of ACME Corp",
            "framework_ref": "mls",
        }

        buf = io.StringIO()
        # Feed selection '1' for framework choice
        with (
            patch("sys.stdout", buf),
            patch("builtins.input", side_effect=["1"]),
            patch("time.sleep"),
            patch("main.show_status"),
        ):
            create_audit_demo_ui(
                mock_manager,
                app_name="App-Audit-Demo",
                user_email="auditor@example.com",
            )

        output = buf.getvalue()
        self.assertIn("Select Framework for Assessment (verified in CISO Assistant):", output)
        self.assertIn("1) Data protection policy of ACME Corp (mls)", output)
        # Should NOT offer option 2) for Vendor Due Diligence as an installed choice
        self.assertNotIn("2) Vendor Due Diligence", output)
        mock_manager.create_application_for_audit.assert_called_once()

    def test_remove_examples_ui_when_no_examples_exist(self):
        """Verify remove_examples_ui detects that no examples exist and exits without attempting deletion."""
        mock_manager = MagicMock(spec=ExamplesManager)
        mock_manager.test_connection.return_value = (True, "OK")
        mock_manager.get_status.return_value = [
            {"id": "app_secure_core", "name": "App-Secure-Core", "exists": False},
            {"id": "vendor_cloud_crm", "name": "Vendor-Cloud-CRM", "exists": False},
        ]

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            remove_examples_ui(mock_manager, target="all")

        output = buf.getvalue()
        self.assertIn("No example applications currently exist in CISO Assistant. Nothing to remove.", output)
        mock_manager.remove_example_application.assert_not_called()

    def test_remove_examples_ui_only_removes_created_examples(self):
        """Verify remove_examples_ui lists and deletes ONLY the examples that have actually been created."""
        mock_manager = MagicMock(spec=ExamplesManager)
        mock_manager.test_connection.return_value = (True, "OK")
        mock_manager.get_status.return_value = [
            {"id": "app_secure_core", "name": "App-Secure-Core", "exists": True, "status": "FULLY CONFIGURED"},
            {"id": "app_vulnerable_portal", "name": "App-Vulnerable-Portal", "exists": False},
            {"id": "vendor_cloud_crm", "name": "Vendor-Cloud-CRM", "exists": True, "status": "FULLY CONFIGURED"},
            {"id": "vendor_shadow_payroll", "name": "Vendor-Shadow-Payroll", "exists": False},
        ]
        mock_manager.remove_example_application.return_value = {"perimeters_deleted": 1}

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            remove_examples_ui(mock_manager, target="all", auto_confirm=True)

        output = buf.getvalue()
        self.assertIn("Found 2 example application(s) currently created in CISO Assistant:", output)
        self.assertIn("- App-Secure-Core (FULLY CONFIGURED)", output)
        self.assertIn("- Vendor-Cloud-CRM (FULLY CONFIGURED)", output)
        self.assertNotIn("- App-Vulnerable-Portal", output)
        self.assertNotIn("- Vendor-Shadow-Payroll", output)

        # Ensure remove_example_application was called ONLY for the 2 created apps
        self.assertEqual(mock_manager.remove_example_application.call_count, 2)
        mock_manager.remove_example_application.assert_any_call("app_secure_core")
        mock_manager.remove_example_application.assert_any_call("vendor_cloud_crm")

    def test_remove_examples_ui_specific_app_not_created(self):
        """Verify removing a specific app that was not created is blocked with an informative message."""
        mock_manager = MagicMock(spec=ExamplesManager)
        mock_manager.test_connection.return_value = (True, "OK")
        mock_manager.get_status.return_value = [
            {"id": "app_secure_core", "name": "App-Secure-Core", "exists": False},
            {"id": "app_vulnerable_portal", "name": "App-Vulnerable-Portal", "exists": False},
        ]

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            remove_examples_ui(mock_manager, target="app_vulnerable_portal", auto_confirm=True)

        output = buf.getvalue()
        self.assertIn("Application 'App-Vulnerable-Portal' is not currently created in CISO Assistant. Nothing to remove.", output)
        mock_manager.remove_example_application.assert_not_called()

    def test_manager_remove_all_examples_only_removes_created(self):
        """Verify ExamplesManager.remove_all_examples checks get_status and only removes created applications."""
        manager = ExamplesManager()
        mock_status = [
            {"id": "app_secure_core", "name": "App-Secure-Core", "exists": True},
            {"id": "app_vulnerable_portal", "name": "App-Vulnerable-Portal", "exists": False},
            {"id": "app_internal_tool", "name": "App-Internal-Tool", "exists": False},
        ]
        with (
            patch.object(manager, "get_status", return_value=mock_status),
            patch.object(manager, "remove_example_application", return_value={"perimeters_deleted": 1}) as mock_remove,
        ):
            results = manager.remove_all_examples()

            self.assertEqual(len(results), 1)
            mock_remove.assert_called_once_with("app_secure_core")


if __name__ == "__main__":
    unittest.main()


