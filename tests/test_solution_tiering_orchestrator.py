"""Unit tests for the AppSec Solution Tiering Orchestrator logic.

Tests coverage:
- Implementation group scoping and pruning by tier (filter_implementation_groups_by_tier)
- Tier governance policies, pentest gates, and SLAs (get_tier_governance_policy)
- Tiering questionnaire to hosting question translation (map_tiering_answers_to_hosting_answers)
- Inherent scoring & knock-out rule evaluations in assess_appsec_solution_tier
- Tier resolution helper methods
"""

import unittest
from unittest.mock import MagicMock, patch

from classes.audits.implementation_groups import (
    evaluate_security_by_design_knockouts,
    filter_implementation_groups_by_tier,
    get_tier_governance_policy,
    map_tiering_answers_to_hosting_answers,
    map_tiering_answers_to_audit_answers,
)
from classes.examples_manager import ExamplesManager


class TestSolutionTieringGovernance(unittest.TestCase):
    """Test governance policies and SLAs derived from criticality tiers."""

    def test_critical_tier_policy(self):
        policy = get_tier_governance_policy("critical")
        self.assertEqual(policy["tier"], "critical")
        self.assertEqual(policy["audit_depth"], "comprehensive")
        self.assertTrue(policy["pentest_required"])
        self.assertEqual(policy["remediation_sla_critical_days"], 7)
        self.assertEqual(policy["remediation_sla_high_days"], 14)
        self.assertEqual(policy["cicd_blocking_threshold"], "high")
        self.assertEqual(policy["reassessment_frequency_months"], 12)

    def test_important_tier_policy(self):
        policy = get_tier_governance_policy("important")
        self.assertEqual(policy["tier"], "important")
        self.assertEqual(policy["audit_depth"], "standard")
        self.assertTrue(policy["pentest_required"])
        self.assertEqual(policy["remediation_sla_critical_days"], 14)
        self.assertEqual(policy["remediation_sla_high_days"], 30)

    def test_standard_tier_policy(self):
        policy = get_tier_governance_policy("standard")
        self.assertEqual(policy["tier"], "standard")
        self.assertEqual(policy["audit_depth"], "targeted")
        self.assertFalse(policy["pentest_required"])
        self.assertEqual(policy["remediation_sla_critical_days"], 30)

    def test_low_impact_tier_policy(self):
        policy = get_tier_governance_policy("low-impact")
        self.assertEqual(policy["tier"], "low-impact")
        self.assertEqual(policy["audit_depth"], "lightweight")
        self.assertFalse(policy["pentest_required"])
        self.assertEqual(policy["remediation_sla_critical_days"], 30)
        self.assertEqual(policy["reassessment_frequency_months"], 36)

    def test_rank_based_lookup(self):
        policy = get_tier_governance_policy(4)
        self.assertEqual(policy["tier"], "critical")
        policy_low = get_tier_governance_policy(1)
        self.assertEqual(policy_low["tier"], "low-impact")

    def test_sbd_governance_policy_attributes(self):
        crit = get_tier_governance_policy("critical")
        self.assertEqual(crit["sbd_review_level"], "deep_sar")
        self.assertEqual(crit["sbd_gate_action"], "mandatory_pre_prod_approval")
        self.assertFalse(crit["sbd_fast_track_eligible"])

        imp = get_tier_governance_policy("important")
        self.assertEqual(imp["sbd_review_level"], "standard_sbd")
        self.assertEqual(imp["sbd_gate_action"], "standard_cab_sec_review")
        self.assertFalse(imp["sbd_fast_track_eligible"])

        std = get_tier_governance_policy("standard")
        self.assertEqual(std["sbd_review_level"], "automated_guardrails")
        self.assertEqual(std["sbd_gate_action"], "automated_guardrails_check")
        self.assertTrue(std["sbd_fast_track_eligible"])

        low = get_tier_governance_policy("low-impact")
        self.assertEqual(low["sbd_review_level"], "fast_track")
        self.assertEqual(low["sbd_gate_action"], "peer_review_only")
        self.assertTrue(low["sbd_fast_track_eligible"])


class TestImplementationGroupFiltering(unittest.TestCase):
    """Test implementation group scoping by criticality tier."""

    def setUp(self):
        self.candidates = [
            "baseline",
            "custom_app",
            "internet_facing",
            "saas_uncertified",
            "sensitive_data",
        ]

    def test_critical_tier_retains_all_tracks(self):
        scoped = filter_implementation_groups_by_tier("critical", self.candidates)
        self.assertEqual(scoped, self.candidates)

    def test_important_tier_retains_all_tracks(self):
        scoped = filter_implementation_groups_by_tier("important", self.candidates)
        self.assertEqual(scoped, self.candidates)

    def test_standard_tier_prunes_deep_engineering(self):
        scoped = filter_implementation_groups_by_tier("standard", self.candidates)
        self.assertIn("baseline", scoped)
        self.assertIn("internet_facing", scoped)
        self.assertNotIn("custom_app", scoped)

    def test_low_impact_prunes_to_baseline_only(self):
        scoped = filter_implementation_groups_by_tier("low-impact", self.candidates)
        self.assertIn("baseline", scoped)
        self.assertNotIn("custom_app", scoped)
        self.assertNotIn("internet_facing", scoped)
        self.assertNotIn("saas_uncertified", scoped)


class TestTieringToHostingMapping(unittest.TestCase):
    """Test questionnaire translation from tiering to hosting questions."""

    def test_saas_certified_mapping(self):
        answers = {
            "delivery": "saas",
            "saas_type": "certified",
            "exposure": "internet",
        }
        mapped = map_tiering_answers_to_hosting_answers(answers)
        self.assertEqual(mapped.get("hosting:q1"), "c3")
        self.assertEqual(mapped.get("hosting:q2"), "c2")

    def test_custom_app_mapping(self):
        answers = {
            "delivery": "custom",
            "exposure": "internal",
        }
        mapped = map_tiering_answers_to_hosting_answers(answers)
        self.assertEqual(mapped.get("hosting:q1"), "c1")
        self.assertEqual(mapped.get("hosting:q2"), "c1")

    def test_legacy_onprem_mapping(self):
        answers = {
            "delivery": "onprem",
            "exposure": "no",
        }
        mapped = map_tiering_answers_to_hosting_answers(answers)
        self.assertEqual(mapped.get("hosting:q1"), "c2")
        self.assertEqual(mapped.get("hosting:q2"), "c1")

    def test_data_classification_mapping(self):
        from classes.audits.implementation_groups import map_tiering_answers_to_audit_answers
        answers = {
            "delivery": "custom",
            "exposure": "internet",
            "d1": "secrets",
            "d2": "catastrophic",
            "d3": "large",
        }
        mapped = map_tiering_answers_to_audit_answers(answers)
        self.assertEqual(mapped.get("hosting:q1"), "c1")
        self.assertEqual(mapped.get("hosting:q2"), "c2")
        self.assertEqual(mapped.get("data_classification:q1"), "c4")
        self.assertEqual(mapped.get("data_classification:q2"), "c4")
        self.assertEqual(mapped.get("data_classification:q3"), "c4")
        self.assertEqual(mapped.get("data_classification:q4"), "c3")
        self.assertIn("urn:intuitem:risk:req_node:appsec:data_classification:q1", mapped)

    def test_data_classification_mapping_public_low(self):
        from classes.audits.implementation_groups import map_tiering_answers_to_audit_answers
        answers = {
            "d1": "public",
            "d2": "negligible",
            "d3": "none",
        }
        mapped = map_tiering_answers_to_audit_answers(answers)
        self.assertEqual(mapped.get("data_classification:q1"), "c1")
        self.assertEqual(mapped.get("data_classification:q2"), "c1")
        self.assertEqual(mapped.get("data_classification:q3"), "c1")
        self.assertIsNone(mapped.get("data_classification:q4"))

    def test_infra_delivery_model_mapping(self):
        answers = {
            "delivery": "infra",
            "exposure": "internal",
        }
        mapped = map_tiering_answers_to_audit_answers(answers)
        self.assertEqual(mapped.get("hosting:q1"), "c2")
        self.assertEqual(mapped.get("hosting:q2"), "c1")
        self.assertEqual(mapped.get("hosting:q7"), "c1")

    def test_track_readiness_and_delegation_mapping(self):
        from classes.audits.implementation_groups import map_tiering_answers_to_audit_answers
        answers = {
            "delivery_model": "custom",
            "exposure": "internet",
            "baseline_readiness": "self",
            "custom_readiness": "delegate",
            "custom_delegate": "lead-dev@example.com",
            "infra_readiness": "delegate",
            "infra_delegate": "devops-team@example.com",
            "internet_facing_readiness": "self",
        }
        mapped = map_tiering_answers_to_audit_answers(answers)
        self.assertEqual(mapped.get("hosting:q1"), "c1")
        self.assertEqual(mapped.get("hosting:q2"), "c2")
        self.assertEqual(mapped.get("hosting:q4"), "c1")
        self.assertEqual(mapped.get("hosting:q5"), "c2")
        self.assertEqual(mapped.get("hosting:q5_delegate"), "lead-dev@example.com")
        self.assertEqual(mapped.get("hosting:q7"), "c2")
        self.assertEqual(mapped.get("hosting:q7_delegate"), "devops-team@example.com")
        self.assertEqual(mapped.get("hosting:q8"), "c1")
        self.assertIn("urn:intuitem:risk:req_node:appsec:hosting:q5_delegate", mapped)


class TestAppSecSolutionTierAssessment(unittest.TestCase):
    """Test scoring calculation and knock-out logic in ExamplesManager."""

    def setUp(self):
        self.mgr = ExamplesManager()

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_knockout_regulated_function(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "minor",
            "b2": "no target",
            "b3": "commodity",
            "d1": "public",
            "d2": "negligible",
            "d3": "none",
            "d4": "none",
            "regulated": "yes",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=True)
        self.assertEqual(res["final_tier"], "critical")
        self.assertIn("regulated_function", res["knock_outs"])
        mock_set_tier.assert_called_once()

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_knockout_single_point_of_failure(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "stops business",
            "b2": "1 month",
            "b3": "sole provider - SPOF",
            "d1": "internal",
            "d2": "minor",
            "d3": "low",
            "d4": "standard",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=False)
        self.assertEqual(res["final_tier"], "critical")
        self.assertIn("single_point_of_failure", res["knock_outs"])
        mock_set_tier.assert_not_called()

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_knockout_cardholder_and_secrets(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "minor",
            "b2": "no target",
            "b3": "commodity",
            "d1": "secrets and PCI-DSS cardholder data",
            "d2": "minor",
            "d3": "low",
            "d4": "standard",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=False)
        self.assertEqual(res["final_tier"], "critical")
        self.assertIn("critical_secrets_or_payment", res["knock_outs"])

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_knockout_internet_facing_confidential(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "minor",
            "b2": "no target",
            "b3": "commodity",
            "d1": "confidential business data",
            "d2": "severe",
            "d3": "low",
            "d4": "standard",
            "exposure": "internet-facing",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=False)
        self.assertEqual(res["final_tier"], "important")
        self.assertIn("internet_facing_confidential", res["knock_outs"])

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_knockout_large_scale_gdpr(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "minor",
            "b2": "no target",
            "b3": "commodity",
            "d1": "internal",
            "d2": "minor",
            "d3": "large scale > 100,000 subjects",
            "d4": "standard",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=False)
        self.assertEqual(res["final_tier"], "important")
        self.assertIn("large_scale_gdpr", res["knock_outs"])

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_knockout_privileged_access(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "minor",
            "b2": "no target",
            "b3": "commodity",
            "d1": "internal",
            "d2": "minor",
            "d3": "low",
            "d4": "privileged root access",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=False)
        self.assertEqual(res["final_tier"], "important")
        self.assertIn("privileged_access", res["knock_outs"])

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_low_impact_baseline(self, mock_fw, mock_set_tier):
        answers = {
            "b1": "minor impact",
            "b2": "no target",
            "b3": "commodity market alternative",
            "d1": "public data",
            "d2": "negligible harm",
            "d3": "none",
            "d4": "none",
            "exposure": "internal",
            "regulated": "no",
        }
        res = self.mgr.assess_appsec_solution_tier("TestApp", answers, auto_sign_off=False)
        self.assertEqual(res["final_tier"], "low-impact")
        self.assertEqual(len(res["knock_outs"]), 0)


class TestAuditCreationWithTiering(unittest.TestCase):
    """Test audit creation form integration with the solution tiering system."""

    def setUp(self):
        self.mgr = ExamplesManager()

    @patch("classes.examples_manager.utils.get_return")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework")
    def test_create_audit_with_tier(self, mock_fw, mock_set_tier, mock_get_return):
        mock_fw_obj = MagicMock()
        mock_fw_obj.get_id.return_value = "fw-1"
        mock_fw_obj.get_name.return_value = "AppSec Framework"
        mock_fw_obj.json_object = {"ref_id": "appsec"}
        mock_fw.return_value = mock_fw_obj
        mock_set_tier.return_value = {"id": "sol-123", "name": "App-Tier-Demo", "tier": "critical"}
        mock_get_return.return_value = {"id": "ca-1"}

        mock_data = {
            "domain_dict": MagicMock(get_name_from_id=lambda _: "Examples"),
            "user_dict": MagicMock(get_id_from_email=lambda _: "u-1"),
            "entity_dict": MagicMock(create_entity=lambda **kw: {"id": "ent-1"}, get_id_from_name=lambda _: "ent-1"),
            "entity_representative_dict": MagicMock(),
            "perimeter_dict": MagicMock(create_perimeter=lambda *a: MagicMock(), get_id_from_name=lambda _: "per-1"),
            "asset_dict": MagicMock(create_asset=lambda *a, **kw: MagicMock(), get_asset_id_from_perimeter_name=lambda _: "ast-1", get_assets=lambda: []),
            "compliance_assessment_dict": MagicMock(
                get_compliance_assessments=lambda: {"ca-1": MagicMock(get_id=lambda: "ca-1", get_status=lambda: "in_progress", get_selected_implementation_groups=lambda: ["baseline", "custom_app"])},
                requirement_assessments=MagicMock(get_requirement_assessment_id_list_from_compliance_assessment_id=lambda _: ["ra-1"]),
                requirement_assignments=MagicMock(get_requirement_assignment_id_list_from_compliance_assessment_id=lambda _: ["asgn-1"]),
            ),
            "entity_assessment_dict": MagicMock(create_entity_assessment=lambda **kw: {"id": "ea-1"}),
        }

        with patch.object(self.mgr, "_init_data", return_value=mock_data), \
             patch.object(self.mgr, "get_or_create_folder", return_value="f-1"), \
             patch.object(self.mgr, "resolve_actor_id", return_value="act-1"):

            res = self.mgr.create_application_for_audit(
                app_name="App-Tier-Demo",
                user_email="sec@example.com",
                tier="critical",
                implementation_groups=["baseline", "custom_app"],
            )

            mock_set_tier.assert_called_once_with(
                "App-Tier-Demo",
                "critical",
                note="Assigned during audit intake for App-Tier-Demo",
            )
            self.assertEqual(res["solution_tier"], "critical")
            self.assertIsNotNone(res["governance_policy"])
            self.assertEqual(res["governance_policy"]["tier"], "critical")
            self.assertTrue(res["governance_policy"]["pentest_required"])
            self.assertEqual(res["governance_policy"]["remediation_sla_critical_days"], 7)

    @patch("main.create_audit_demo_ui")
    def test_cli_create_audit_with_app_tier_flag(self, mock_create_audit_ui):
        """Verify CLI --create-audit APP --app-tier TIER passes tier to create_audit_demo_ui."""
        from main import main
        import sys
        test_args = ["main.py", "--create-audit", "App-Cli-Demo", "--app-tier", "important", "--user", "auditor@example.com"]
        with patch.object(sys, "argv", test_args), patch("classes.examples_manager.ExamplesManager.test_connection", return_value=(True, "OK")):
            main()
            mock_create_audit_ui.assert_called_once()
            _, kwargs = mock_create_audit_ui.call_args
            self.assertEqual(kwargs.get("app_name"), "App-Cli-Demo")
            self.assertEqual(kwargs.get("tier"), "important")
            self.assertEqual(kwargs.get("user_email"), "auditor@example.com")

    @patch("main.assign_tiering_questionnaire_ui")
    def test_cli_assign_tiering_flag(self, mock_assign_ui):
        """Verify CLI --assign-tiering APP --user EMAIL invokes assign_tiering_questionnaire_ui."""
        from main import main
        import sys
        test_args = ["main.py", "--assign-tiering", "App-Tier-Target", "--user", "custodian@example.com", "--due-date", "2026-12-31"]
        with patch.object(sys, "argv", test_args), patch("classes.examples_manager.ExamplesManager.test_connection", return_value=(True, "OK")):
            main()
            mock_assign_ui.assert_called_once()
            _, kwargs = mock_assign_ui.call_args
            self.assertEqual(kwargs.get("app_name"), "App-Tier-Target")
            self.assertEqual(kwargs.get("user_email"), "custodian@example.com")
            self.assertEqual(kwargs.get("due_date"), "2026-12-31")


class TestTieringAssignmentManagerAndRoutes(unittest.TestCase):
    """Test manager tiering quick-form methods and web routes."""

    def setUp(self):
        self.mgr = ExamplesManager()

    @patch("classes.utils.get_all_results")
    def test_get_tiering_quick_forms(self, mock_get):
        mock_get.return_value = [
            {
                "id": "qf-1",
                "name": "AppSec Application Criticality Tiering",
                "ref_id": "appsec-solution-tiering",
                "on_accept": [{"target": "solution.tier"}],
            },
            {
                "id": "qf-2",
                "name": "Vendor Security Assessment",
                "ref_id": "tprm-vendor",
                "on_accept": [{"target": "entity.status"}],
            }
        ]
        forms = self.mgr.get_tiering_quick_forms()
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["id"], "qf-1")
        self.assertEqual(forms[0]["ref_id"], "appsec-solution-tiering")

    @patch("classes.utils.get_all_results")
    def test_get_tiering_responses(self, mock_get):
        mock_get.return_value = [
            {
                "id": "qfr-1",
                "ref_id": "AST.000001",
                "status": "submitted",
                "subject": {"id": "sol-1", "name": "App-One", "model": "solution", "str": "App-One"},
                "quick_form": {"id": "qf-1", "name": "AppSec Tiering", "ref_id": "appsec-solution-tiering"},
                "due_date": "2026-12-01T00:00:00Z",
                "respondents": ["Security Lead"],
            }
        ]
        responses = self.mgr.get_tiering_responses()
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["ref_id"], "AST.000001")
        self.assertEqual(responses[0]["status"], "submitted")

    @patch("classes.examples_manager.ExamplesManager.get_or_create_solution")
    @patch("classes.examples_manager.ExamplesManager.resolve_actor_id")
    @patch("classes.examples_manager.ExamplesManager.get_tiering_quick_forms")
    @patch("classes.utils.get_return")
    def test_assign_tiering_questionnaire(
        self,
        mock_get_return,
        mock_get_forms,
        mock_resolve_actor,
        mock_get_solution,
    ):
        mock_get_forms.return_value = [{"id": "qf-1", "name": "AppSec Tiering", "ref_id": "appsec-solution-tiering"}]
        mock_get_solution.return_value = {"id": "sol-123", "name": "App-Checkout"}
        mock_resolve_actor.return_value = "actor-456"

        def mock_return_impl(endpoint, *args, **kwargs):
            if "start" in str(endpoint):
                return {
                    "redirect": "/quick-form-responses/qfr-789",
                    "ref_id": "AST.000002",
                }
            if kwargs.get("method") == "PATCH":
                return {"id": "qfr-789", "status": "draft"}
            return {"results": []}

        mock_get_return.side_effect = mock_return_impl

        with patch.dict(self.mgr._init_data(), {"user_dict": MagicMock()}):
            res = self.mgr.assign_tiering_questionnaire(
                app_name="App-Checkout",
                user_email="checkout-owner@example.com",
                due_date="2026-12-15",
                form_id="qf-1",
            )
            self.assertEqual(res["response_id"], "qfr-789")
            self.assertEqual(res["ref_id"], "AST.000002")
            self.assertEqual(res["solution_id"], "sol-123")

    def test_web_tiering_routes(self):
        from web import create_app
        app = create_app()
        client = app.test_client()

        with patch("classes.examples_manager.ExamplesManager.get_tiering_quick_forms", return_value=[{"id": "f1", "name": "Form 1"}]):
            res = client.get("/api/tiering/forms")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(len(data["forms"]), 1)

        with patch("classes.examples_manager.ExamplesManager.get_tiering_responses", return_value=[{"id": "r1", "ref_id": "AST.1"}]):
            res = client.get("/api/tiering/responses")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(len(data["responses"]), 1)

        with patch("classes.examples_manager.ExamplesManager.assign_tiering_questionnaire", return_value={"response_id": "r1", "ref_id": "AST.1"}):
            res = client.post("/api/tiering/assign", json={
                "app_name": "App-Test",
                "user_email": "test@example.com",
            })
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["assignment"]["ref_id"], "AST.1")

    def test_map_audit_answers_to_tiering_answers(self):
        """Verify Chapter 1 audit answers map back to tiering scoring parameters."""
        from classes.audits.implementation_groups import map_audit_answers_to_tiering_answers
        audit_answers = {
            "hosting:q1": "c1",
            "hosting:q2": "c2",
            "data_classification:q1": "c4",
            "data_classification:q2": "c3",
            "data_classification:q4": "c3",
        }
        mapped = map_audit_answers_to_tiering_answers(audit_answers)
        self.assertEqual(mapped.get("delivery_model"), "custom")
        self.assertEqual(mapped.get("exposure"), "internet")
        self.assertEqual(mapped.get("d1"), "secrets")
        self.assertEqual(mapped.get("d2"), "severe")
        self.assertEqual(mapped.get("d3"), "large")

    def test_assess_tier_from_extracted_audit_answers(self):
        """Verify assess_appsec_solution_tier automatically extracts answers when tiering_answers is omitted."""
        mgr = ExamplesManager()
        mock_audit_answers = {
            "data_classification": {"q1": "c4", "q2": "c4"},
            "hosting": {"q1": "c1", "q2": "c2"},
        }
        with patch.object(mgr, "extract_tiering_answers_from_compliance_assessment") as mock_extract, \
             patch.object(mgr, "set_solution_tier") as mock_set:
            from classes.audits.implementation_groups import map_audit_answers_to_tiering_answers
            mock_extract.return_value = map_audit_answers_to_tiering_answers(mock_audit_answers)

            res = mgr.assess_appsec_solution_tier("App-Audit-Demo", tiering_answers=None, auto_sign_off=True)
            mock_extract.assert_called_once_with("App-Audit-Demo")
            self.assertEqual(res["final_tier"], "critical")
            self.assertIn("critical_secrets_or_payment", res["knock_outs"])
            mock_set.assert_called_once()
            self.assertEqual(mock_set.call_args[0][1], "critical")

    def test_tier_control_confirmation_schedule_scaling(self):
        """Verify tier-driven confirmation frequency scaling across all 4 tiers."""
        from classes.audits.implementation_groups import get_tier_control_confirmation_schedule

        # Critical: quarterly task tightens to monthly
        crit = get_tier_control_confirmation_schedule("critical", "MONTHLY", 3, "Quarterly TLS and Cipher Suite Audit")
        self.assertEqual(crit["tier"], "critical")
        self.assertEqual(crit["frequency"], "MONTHLY")
        self.assertEqual(crit["interval"], 1)
        self.assertIn("[Critical • Monthly]", crit["formatted_task_name"])

        # Important: quarterly task remains quarterly
        imp = get_tier_control_confirmation_schedule("important", "MONTHLY", 3, "Quarterly TLS and Cipher Suite Audit")
        self.assertEqual(imp["tier"], "important")
        self.assertEqual(imp["frequency"], "MONTHLY")
        self.assertEqual(imp["interval"], 3)
        self.assertIn("[Important • Quarterly]", imp["formatted_task_name"])

        # Standard: quarterly task relaxes to semi-annual
        std = get_tier_control_confirmation_schedule("standard", "MONTHLY", 3, "Quarterly TLS and Cipher Suite Audit")
        self.assertEqual(std["tier"], "standard")
        self.assertEqual(std["frequency"], "MONTHLY")
        self.assertEqual(std["interval"], 6)
        self.assertIn("[Standard • Semi-Annual]", std["formatted_task_name"])

        # Low-Impact: relaxes to annual or biennial
        low = get_tier_control_confirmation_schedule("low-impact", "MONTHLY", 1, "Monthly CI/CD Security Pipeline and Quality Gate Audit")
        self.assertEqual(low["tier"], "low-impact")
        self.assertEqual(low["frequency"], "YEARLY")
        self.assertEqual(low["interval"], 2)
        self.assertIn("[Low-Impact • Biennial]", low["formatted_task_name"])

    @patch("classes.utils.get_return")
    def test_create_tasks_with_tier_schedule(self, mock_get_return):
        """Verify AppliedControlDict.create_tasks_for_applied_controls creates task templates with tier schedule."""
        from unittest.mock import Mock
        from classes.controls.applied import AppliedControlDict, AppliedControl

        ctrl_dict = AppliedControlDict.__new__(AppliedControlDict)
        mock_applied_ctrl = Mock()
        mock_applied_ctrl.get_id.return_value = "ctrl-123"
        mock_applied_ctrl.get_name.return_value = "TLS Encryption on App-Audit-Demo"
        mock_applied_ctrl.get_reference_control_id.return_value = "encrypt_data_in_transit"
        mock_applied_ctrl.json_object = {"folder": "f-123"}
        ctrl_dict.controls = {"ctrl-123": mock_applied_ctrl}

        mock_ref_ctrl = Mock()
        mock_ref_ctrl.get_json.return_value = {
            "is_recurrent": True,
            "task": {
                "name": "Quarterly TLS and Cipher Suite Audit",
                "description": "Audit TLS ciphers",
                "frequency": "MONTHLY",
                "interval": 3,
            }
        }
        mock_ref_dict = Mock()
        mock_ref_dict.get_control_from_id.return_value = mock_ref_ctrl

        mock_get_return.return_value = {"id": "tt-123", "name": "[Critical • Monthly] TLS and Cipher Suite Audit on App-Audit-Demo"}

        created = ctrl_dict.create_tasks_for_applied_controls(
            reference_control_dict=mock_ref_dict,
            tier="critical",
            user_id="user-123",
        )
        self.assertEqual(len(created), 1)
        mock_get_return.assert_called_once()
        _, kwargs = mock_get_return.call_args
        payload = kwargs.get("payload") or mock_get_return.call_args[1].get("payload")
        self.assertIn("[Critical • Monthly]", payload["name"])
        self.assertEqual(payload["schedule"]["frequency"], "MONTHLY")
        self.assertEqual(payload["schedule"]["interval"], 1)
        self.assertEqual(payload["applied_controls"], ["ctrl-123"])


class TestSecurityByDesignIntake(unittest.TestCase):
    """Test Security by Design (SbD) intake knock-outs (KO-1 to KO-6) and triage decisions."""

    def test_knockout_ko1_public_exposure(self):
        res = evaluate_security_by_design_knockouts({"ko1": "yes"})
        self.assertTrue(res["requires_sbd"])
        self.assertEqual(res["review_level"], "standard_sbd")
        self.assertEqual(res["gate_action"], "standard_cab_sec_review")
        self.assertFalse(res["fast_track_eligible"])
        triggered_ids = [k["id"] for k in res["triggered_knockouts"]]
        self.assertIn("KO-1", triggered_ids)

    def test_knockout_ko2_core_iam(self):
        res = evaluate_security_by_design_knockouts({"core_iam": "yes"})
        self.assertTrue(res["requires_sbd"])
        self.assertEqual(res["review_level"], "deep_sar")
        self.assertEqual(res["gate_action"], "mandatory_pre_prod_approval")
        self.assertFalse(res["fast_track_eligible"])
        triggered_ids = [k["id"] for k in res["triggered_knockouts"]]
        self.assertIn("KO-2", triggered_ids)

    def test_knockout_ko3_network_boundary(self):
        res = evaluate_security_by_design_knockouts({"network_boundary": "yes"})
        self.assertTrue(res["requires_sbd"])
        self.assertEqual(res["review_level"], "standard_sbd")
        triggered_ids = [k["id"] for k in res["triggered_knockouts"]]
        self.assertIn("KO-3", triggered_ids)

    def test_knockout_ko4_sensitive_data(self):
        res = evaluate_security_by_design_knockouts({"d1": "secrets"})
        self.assertTrue(res["requires_sbd"])
        self.assertEqual(res["review_level"], "deep_sar")
        triggered_ids = [k["id"] for k in res["triggered_knockouts"]]
        self.assertIn("KO-4", triggered_ids)

    def test_knockout_ko5_third_party(self):
        res = evaluate_security_by_design_knockouts({"third_party": "yes"})
        self.assertTrue(res["requires_sbd"])
        self.assertEqual(res["review_level"], "standard_sbd")
        triggered_ids = [k["id"] for k in res["triggered_knockouts"]]
        self.assertIn("KO-5", triggered_ids)

    def test_knockout_ko6_spof(self):
        res = evaluate_security_by_design_knockouts({"b1": "stops", "b3": "sole"})
        self.assertTrue(res["requires_sbd"])
        self.assertEqual(res["review_level"], "standard_sbd")
        triggered_ids = [k["id"] for k in res["triggered_knockouts"]]
        self.assertIn("KO-6", triggered_ids)

    def test_fast_track_eligible_when_no_knockouts(self):
        res = evaluate_security_by_design_knockouts({
            "exposure": "internal",
            "d1": "public",
            "b1": "minor",
            "b3": "commodity",
        })
        self.assertFalse(res["requires_sbd"])
        self.assertEqual(res["review_level"], "fast_track")
        self.assertEqual(res["gate_action"], "peer_review_only")
        self.assertTrue(res["fast_track_eligible"])
        self.assertEqual(len(res["triggered_knockouts"]), 0)

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_assess_security_by_design_deep_sar(self, mock_fw, mock_set_tier):
        manager = ExamplesManager()
        result = manager.assess_security_by_design(
            "Test-IAM-Core",
            change_answers={"ko2": "yes", "delivery": "custom", "exposure": "internal"},
            auto_sign_off=False,
        )
        self.assertTrue(result["requires_sbd_check"])
        self.assertEqual(result["review_level"], "deep_sar")
        self.assertEqual(result["gate_action"], "mandatory_pre_prod_approval")
        self.assertIn("Deep Security Architecture Review", result["sbd_decision"])
        self.assertFalse(result["fast_track_eligible"])

    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    def test_assess_security_by_design_fast_track(self, mock_fw, mock_set_tier):
        manager = ExamplesManager()
        result = manager.assess_security_by_design(
            "Test-Internal-Tool",
            change_answers={
                "initiative_type": "change",
                "exposure": "internal",
                "d1": "public",
                "d2": "negligible",
                "d3": "none",
                "d4": "standard",
                "b1": "minor",
                "b2": "no target",
                "b3": "commodity",
            },
            auto_sign_off=False,
        )
        self.assertFalse(result["requires_sbd_check"])
        self.assertEqual(result["review_level"], "fast_track")
        self.assertEqual(result["gate_action"], "peer_review_only")
        self.assertTrue(result["fast_track_eligible"])
        self.assertEqual(result["evaluation_nature"], "change")
        self.assertIn("Fast-Track Standard Change", result["sbd_decision"])

    def test_initiative_type_mapping(self):
        answers = {
            "initiative_type": "new_app",
            "delivery": "custom",
            "exposure": "internal",
        }
        mapped = map_tiering_answers_to_audit_answers(answers)
        self.assertEqual(mapped.get("business_project_scope:q0"), "c1")
        self.assertEqual(mapped.get("initiative_type"), "c1")

    def test_map_audit_answers_to_tiering_sbd_knockouts(self):
        from classes.audits.implementation_groups import map_audit_answers_to_tiering_answers
        audit_answers = {
            "business_project_scope": {
                "urn:intuitem:risk:req_node:infra-sbd:business_project_scope:q0": "urn:intuitem:risk:req_node:infra-sbd:business_project_scope:q0:c1",
                "urn:intuitem:risk:req_node:infra-sbd:business_project_scope:q3": "urn:intuitem:risk:req_node:infra-sbd:business_project_scope:q3:c3",
            },
            "data_classification_profiling": {
                "urn:intuitem:risk:req_node:infra-sbd:data_classification_profiling:q1": "urn:intuitem:risk:req_node:infra-sbd:data_classification_profiling:q1:c4",
                "urn:intuitem:risk:req_node:infra-sbd:data_classification_profiling:q2": "urn:intuitem:risk:req_node:infra-sbd:data_classification_profiling:q2:c1",
            },
            "operational_criticality_intake": {
                "urn:intuitem:risk:req_node:infra-sbd:operational_criticality_intake:q1": "urn:intuitem:risk:req_node:infra-sbd:operational_criticality_intake:q1:c1",
            },
            "knockout_assessment": {
                "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q1": "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q1:c1",
                "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q2": "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q2:c2",
                "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q3": "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q3:c2",
                "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q4": "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q4:c1",
                "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q5": "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q5:c2",
                "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q6": "urn:intuitem:risk:req_node:infra-sbd:knockout_assessment:q6:c1",
            },
        }
        mapped = map_audit_answers_to_tiering_answers(audit_answers)
        self.assertEqual(mapped.get("initiative_type"), "new_app")
        self.assertEqual(mapped.get("delivery_model"), "saas")
        self.assertEqual(mapped.get("d1"), "secrets")
        self.assertEqual(mapped.get("d3"), "large")
        self.assertEqual(mapped.get("b1"), "stops")
        self.assertEqual(mapped.get("b3"), "sole")
        self.assertEqual(mapped.get("ko1"), "yes")
        self.assertEqual(mapped.get("ko2"), "no")
        self.assertEqual(mapped.get("ko3"), "no")
        self.assertEqual(mapped.get("ko4"), "yes")
        self.assertEqual(mapped.get("ko5"), "no")
        self.assertEqual(mapped.get("ko6"), "yes")

    def test_map_audit_answers_to_tiering_appsec_merged_sbd_knockouts(self):
        from classes.audits.implementation_groups import map_audit_answers_to_tiering_answers
        audit_answers = {
            "business_project_scope": {
                "urn:intuitem:risk:req_node:appsec:business_project_scope:q0": "urn:intuitem:risk:req_node:appsec:business_project_scope:q0:c2",
                "urn:intuitem:risk:req_node:appsec:business_project_scope:q3": "urn:intuitem:risk:req_node:appsec:business_project_scope:q3:c2",
            },
            "data_classification": {
                "urn:intuitem:risk:req_node:appsec:data_classification:q1": "urn:intuitem:risk:req_node:appsec:data_classification:q1:c4",
                "urn:intuitem:risk:req_node:appsec:data_classification:q2": "urn:intuitem:risk:req_node:appsec:data_classification:q2:c3",
                "urn:intuitem:risk:req_node:appsec:data_classification:q3": "urn:intuitem:risk:req_node:appsec:data_classification:q3:c3",
                "urn:intuitem:risk:req_node:appsec:data_classification:q4": "urn:intuitem:risk:req_node:appsec:data_classification:q4:c3",
            },
            "operational_criticality_intake": {
                "urn:intuitem:risk:req_node:appsec:operational_criticality_intake:q1": "urn:intuitem:risk:req_node:appsec:operational_criticality_intake:q1:c1",
            },
            "knockout_assessment": {
                "urn:intuitem:risk:req_node:appsec:knockout_assessment:q1": "urn:intuitem:risk:req_node:appsec:knockout_assessment:q1:c2",
                "urn:intuitem:risk:req_node:appsec:knockout_assessment:q2": "urn:intuitem:risk:req_node:appsec:knockout_assessment:q2:c1",
                "urn:intuitem:risk:req_node:appsec:knockout_assessment:q3": "urn:intuitem:risk:req_node:appsec:knockout_assessment:q3:c2",
                "urn:intuitem:risk:req_node:appsec:knockout_assessment:q4": "urn:intuitem:risk:req_node:appsec:knockout_assessment:q4:c2",
                "urn:intuitem:risk:req_node:appsec:knockout_assessment:q5": "urn:intuitem:risk:req_node:appsec:knockout_assessment:q5:c2",
                "urn:intuitem:risk:req_node:appsec:knockout_assessment:q6": "urn:intuitem:risk:req_node:appsec:knockout_assessment:q6:c2",
            },
        }
        mapped = map_audit_answers_to_tiering_answers(audit_answers)
        self.assertEqual(mapped.get("initiative_type"), "change")
        self.assertEqual(mapped.get("delivery_model"), "cots")
        self.assertEqual(mapped.get("d1"), "secrets")
        self.assertEqual(mapped.get("d2"), "severe")
        self.assertEqual(mapped.get("d3"), "large")
        self.assertEqual(mapped.get("b1"), "stops")
        self.assertEqual(mapped.get("b3"), "sole")
        self.assertEqual(mapped.get("ko1"), "no")
        self.assertEqual(mapped.get("ko2"), "yes")
        self.assertEqual(mapped.get("ko3"), "no")
        self.assertEqual(mapped.get("ko4"), "no")
        self.assertEqual(mapped.get("ko5"), "no")
        self.assertEqual(mapped.get("ko6"), "no")

    @patch.object(ExamplesManager, "create_application_for_audit")
    def test_create_sbd_assessment(self, mock_create):
        mock_create.return_value = {
            "app_name": "App-SbD-Test",
            "user_email": "biz@example.com",
            "compliance_assessment_id": "test-ca-123",
            "compliance_assessment_name": "Assessment of App-SbD-Test with SbD",
            "direct_url": "https://ciso-assistant.siege.red/",
        }
        manager = ExamplesManager()
        res = manager.create_sbd_assessment("App-SbD-Test", "biz@example.com")
        mock_create.assert_called_once_with(
            app_name="App-SbD-Test",
            user_email="biz@example.com",
            first_name="",
            last_name="",
            is_third_party=True,
            framework_ref_or_name="appsec",
            domain_name=None,
            implementation_groups=None,
        )
        self.assertIn("message", res)
        self.assertEqual(res["compliance_assessment_id"], "test-ca-123")

    @patch.object(ExamplesManager, "extract_tiering_answers_from_compliance_assessment", return_value={})
    @patch.object(ExamplesManager, "get_sbd_assessment_status")
    def test_assess_security_by_design_awaiting_submission(self, mock_status, mock_extract):
        mock_status.return_value = {
            "exists": True,
            "has_answers": False,
            "compliance_assessment_id": "ca-pending-123",
            "compliance_assessment_name": "Assessment of App-Pending with SbD",
        }
        manager = ExamplesManager()
        res = manager.assess_security_by_design("App-Pending")
        self.assertFalse(res["has_answers"])
        self.assertEqual(res["status"], "awaiting_submission")
        self.assertIn("Pending Submission", res["sbd_decision"])
        self.assertEqual(res["review_level"], "pending")

    @patch.object(ExamplesManager, "find_solution")
    @patch("classes.utils.get_return")
    def test_record_fast_track_clearance_zero_audit(self, mock_get_return, mock_find_solution):
        mock_find_solution.return_value = {
            "id": "sol-fast-1",
            "name": "App-Fast-Track",
            "tier_note": "Previous note",
        }
        mock_get_return.return_value = {"id": "sol-fast-1"}

        manager = ExamplesManager()
        res = manager.record_fast_track_clearance(
            "App-Fast-Track",
            gate_decision="Fast-Track Standard Change (Peer Review Only)",
            eval_nature="change",
        )
        self.assertEqual(res["clearance_status"], "FAST_TRACK_APPROVED")
        self.assertFalse(res["audit_created"])
        self.assertIn("SbD Fast-Track Clearance", res["note"])
        mock_get_return.assert_called_once_with(
            "api/solutions/sol-fast-1/",
            method="PATCH",
            payload={"tier_note": "Previous note | [SbD Fast-Track Clearance]: Fast-Track Standard Change (Peer Review Only) (Scope: change)"},
        )

    @patch.object(ExamplesManager, "get_sbd_assessment_status")
    @patch.object(ExamplesManager, "_init_data")
    @patch("classes.utils.get_return")
    def test_update_application_audit_delta(self, mock_get_return, mock_init_data, mock_sbd_status):
        mock_sbd_status.return_value = {
            "exists": True,
            "compliance_assessment_id": "ca-existing-99",
            "compliance_assessment_name": "Assessment of App-Core with AppSec",
        }
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-existing-99"
        mock_ca.get_name.return_value = "Assessment of App-Core with AppSec"
        mock_ca.get_selected_implementation_groups.return_value = ["info", "baseline", "custom_app"]

        mock_dict = MagicMock()
        mock_dict.get_compliance_assessments.return_value = {"ca-existing-99": mock_ca}
        mock_init_data.return_value = {"compliance_assessment_dict": mock_dict}
        mock_get_return.return_value = {"id": "ca-existing-99"}

        manager = ExamplesManager()
        res = manager.update_application_audit_delta(
            "App-Core",
            delta_implementation_groups=["deep_sar", "infra_sbd"],
        )
        self.assertTrue(res["updated"])
        self.assertEqual(res["compliance_assessment_id"], "ca-existing-99")
        self.assertEqual(res["previous_implementation_groups"], ["info", "baseline", "custom_app"])
        self.assertEqual(res["active_implementation_groups"], ["baseline", "custom_app", "deep_sar", "info", "infra_sbd"])
        mock_get_return.assert_called_once_with(
            "api/compliance-assessments/ca-existing-99/",
            method="PATCH",
            payload={"selected_implementation_groups": ["baseline", "custom_app", "deep_sar", "info", "infra_sbd"]},
        )

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "record_fast_track_clearance")
    def test_assess_security_by_design_fast_track_integration(self, mock_record_clr, mock_set_tier, mock_fw):
        mock_record_clr.return_value = {
            "clearance_status": "FAST_TRACK_APPROVED",
            "audit_created": False,
        }
        answers = {
            "initiative_type": "change",
            "ko1": "no",
            "ko2": "no",
            "ko3": "no",
            "ko4": "no",
            "ko5": "no",
            "ko6": "no",
            "d1": "internal",
            "b1": "minor",
        }
        manager = ExamplesManager()
        res = manager.assess_security_by_design("App-Clean-Change", change_answers=answers, auto_sign_off=True)
        self.assertTrue(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "fast_track")
        self.assertIsNotNone(res["clearance_record"])
        self.assertEqual(res["clearance_record"]["clearance_status"], "FAST_TRACK_APPROVED")
        mock_record_clr.assert_called_once()

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_assess_security_by_design_delta_integration(self, mock_delta_update, mock_set_tier, mock_fw):
        mock_delta_update.return_value = {
            "updated": True,
            "compliance_assessment_id": "ca-123",
            "delta_implementation_groups": ["deep_sar"],
        }
        answers = {
            "initiative_type": "change",
            "ko1": "no",
            "ko2": "yes",  # Core IAM knockout
            "ko3": "no",
            "ko4": "no",
            "ko5": "no",
            "ko6": "no",
        }
        manager = ExamplesManager()
        res = manager.assess_security_by_design("App-IAM-Change", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "deep_sar")
        self.assertIsNotNone(res["delta_update"])
        self.assertTrue(res["delta_update"]["updated"])
        mock_delta_update.assert_called_once()


class TestDecisionTreeMatrixConsistency(unittest.TestCase):
    """Test decision tree matrix exhaustively covering all intake, knock-out, and audit pathways."""

    def setUp(self):
        self.manager = ExamplesManager()

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "record_fast_track_clearance")
    def test_branch_c01_fast_track_standard_change(self, mock_clr, mock_tier, mock_fw):
        """Branch C-01: Zero knock-outs -> Fast-Track, zero audit created."""
        mock_clr.return_value = {"clearance_status": "FAST_TRACK_APPROVED", "audit_created": False}
        answers = {
            "initiative_type": "change",
            "ko1": "no", "ko2": "no", "ko3": "no",
            "ko4": "no", "ko5": "no", "ko6": "no",
            "d1": "internal", "b1": "minor",
        }
        res = self.manager.assess_security_by_design("App-C01", change_answers=answers, auto_sign_off=True)
        self.assertTrue(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "fast_track")
        self.assertEqual(res["gate_action"], "peer_review_only")
        self.assertFalse(res["requires_sbd_check"])
        self.assertEqual(len(res["triggered_knockouts"]), 0)
        self.assertIsNotNone(res["clearance_record"])
        self.assertFalse(res["clearance_record"]["audit_created"])

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c02_critical_iam_knockout(self, mock_delta, mock_tier, mock_fw):
        """Branch C-02: KO-2 (Core IAM) -> Critical, Deep SAR, mandatory pre-prod approval."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["deep_sar"]}
        answers = {
            "initiative_type": "change",
            "ko1": "no", "ko2": "yes", "ko3": "no",
            "ko4": "no", "ko5": "no", "ko6": "no",
        }
        res = self.manager.assess_security_by_design("App-C02", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "deep_sar")
        self.assertEqual(res["gate_action"], "mandatory_pre_prod_approval")
        self.assertEqual(res["criticality_tier"], "critical")
        self.assertTrue(res["requires_sbd_check"])

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c03_standard_public_exposure_knockout(self, mock_delta, mock_tier, mock_fw):
        """Branch C-03: KO-1 (Public Ingress) -> Important, Standard SbD, CAB review."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["infra_sbd"]}
        answers = {
            "initiative_type": "change",
            "ko1": "yes", "ko2": "no", "ko3": "no",
            "ko4": "no", "ko5": "no", "ko6": "no",
        }
        res = self.manager.assess_security_by_design("App-C03", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "standard_sbd")
        self.assertEqual(res["gate_action"], "standard_cab_sec_review")
        self.assertEqual(res["criticality_tier"], "important")

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c04_network_boundary_knockout(self, mock_delta, mock_tier, mock_fw):
        """Branch C-04: KO-3 (Network Boundary) -> Important, Standard SbD."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["infra_sbd"]}
        answers = {
            "initiative_type": "change",
            "ko1": "no", "ko2": "no", "ko3": "yes",
            "ko4": "no", "ko5": "no", "ko6": "no",
        }
        res = self.manager.assess_security_by_design("App-C04", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "standard_sbd")
        self.assertEqual(res["criticality_tier"], "important")

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c05_sensitive_secrets_knockout(self, mock_delta, mock_tier, mock_fw):
        """Branch C-05: KO-4 (Sensitive Secrets/Payment Data) -> Critical, Deep SAR."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["deep_sar"]}
        answers = {
            "initiative_type": "change",
            "ko1": "no", "ko2": "no", "ko3": "no",
            "ko4": "yes", "ko5": "no", "ko6": "no",
        }
        res = self.manager.assess_security_by_design("App-C05", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "deep_sar")
        self.assertEqual(res["criticality_tier"], "critical")

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c06_critical_third_party_saas_knockout(self, mock_delta, mock_tier, mock_fw):
        """Branch C-06: KO-5 (Critical 3rd Party SaaS) -> Important, Standard SbD."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["business_sbd"]}
        answers = {
            "initiative_type": "change",
            "ko1": "no", "ko2": "no", "ko3": "no",
            "ko4": "no", "ko5": "yes", "ko6": "no",
        }
        res = self.manager.assess_security_by_design("App-C06", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "standard_sbd")
        self.assertEqual(res["criticality_tier"], "important")

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c07_spof_resilience_knockout(self, mock_delta, mock_tier, mock_fw):
        """Branch C-07: KO-6 (SPOF Outage) -> Critical, Deep SAR."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["deep_sar"]}
        answers = {
            "initiative_type": "change",
            "ko1": "no", "ko2": "no", "ko3": "no",
            "ko4": "no", "ko5": "no", "ko6": "yes",
        }
        res = self.manager.assess_security_by_design("App-C07", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "deep_sar")
        self.assertEqual(res["criticality_tier"], "critical")

    @patch.object(ExamplesManager, "find_target_framework", return_value="appsec")
    @patch.object(ExamplesManager, "set_solution_tier")
    @patch.object(ExamplesManager, "update_application_audit_delta")
    def test_branch_c08_compound_knockouts(self, mock_delta, mock_tier, mock_fw):
        """Branch C-08: Compound KOs (KO-1 + KO-2) -> Critical dominates, Deep SAR."""
        mock_delta.return_value = {"updated": True, "delta_implementation_groups": ["deep_sar", "infra_sbd"]}
        answers = {
            "initiative_type": "change",
            "ko1": "yes", "ko2": "yes", "ko3": "no",
            "ko4": "no", "ko5": "no", "ko6": "no",
        }
        res = self.manager.assess_security_by_design("App-C08", change_answers=answers, auto_sign_off=True)
        self.assertFalse(res["fast_track_eligible"])
        self.assertEqual(res["review_level"], "deep_sar")
        self.assertEqual(res["criticality_tier"], "critical")
        self.assertEqual(len(res["triggered_knockouts"]), 2)


if __name__ == "__main__":
    unittest.main()
