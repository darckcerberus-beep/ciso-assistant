"""Multi-application integration test suite for risk scenario evaluation.

Tests 4 distinct application profiles with different security postures and classifications:
1. App-Secure-Core: High classification (Secret) + Full compliance (100%) -> Low Risk.
2. App-Vulnerable-Portal: High classification (Secret) + Non-compliant (0%) -> Critical/Very High Risk -> Urgent Priority.
3. App-Internal-Tool: Medium classification (Internal) + Mixed compliance -> Scenario-dependent Risks.
4. App-Public-Blog: Low classification (Public) + Mixed compliance -> Low Impact & Low Risk.
"""

import csv
from pathlib import Path
import unittest
import yaml

from classes.controls.applied import AppliedControlDict
from classes.integrations.csv_import import read_answers_file


class ApplicationRiskSimulator:
    """Simulates compliance questionnaire scoring and risk scenario derivation."""

    def __init__(self, framework_yaml_path="YML/newDPP.yml"):
        with open(framework_yaml_path, "r", encoding="utf-8") as f:
            self.framework_data = yaml.safe_load(f)

        self.req_nodes = {
            rn.get("ref_id"): rn
            for rn in self.framework_data["objects"]["framework"]["requirement_nodes"]
        }
        self.req_nodes_by_urn = {
            rn.get("urn"): rn
            for rn in self.framework_data["objects"]["framework"]["requirement_nodes"]
        }
        self.risk_scenarios = self.framework_data["objects"]["risk_scenarios"]
        self.risk_matrix = self.framework_data["objects"]["risk_matrix"][0]
        self.criticality_mapping = self.framework_data.get("criticality_mapping", {})
        self.applied_control_dict = AppliedControlDict.__new__(AppliedControlDict)

    def load_answers_from_csv(self, file_path):
        """Read CSV or YAML answers into a dictionary grouped by requirement ref_id."""
        answers_by_req = {}
        rows = read_answers_file(file_path)
        for row in rows:
            req = row.get("requirement", "").strip()
            question = row.get("question", "").strip()
            answer = row.get("answer", "").strip()
            if req not in answers_by_req:
                answers_by_req[req] = []
            answers_by_req[req].append({"question": question, "answer": answer})
        return answers_by_req

    def evaluate_application(self, source):
        """Evaluate an application from a CSV/YAML file path or live RequirementAssessment objects."""
        if isinstance(source, (list, tuple, dict)):
            items = list(source.values()) if isinstance(source, dict) else list(source)
            return self.evaluate_from_requirement_assessments(items)
        return self.evaluate_from_csv(source)

    def evaluate_from_requirement_assessments(self, req_assessments):
        """Evaluate dynamic risk scenarios directly from a collection of RequirementAssessment objects."""
        scores = {}
        answers_present_by_urn = set()
        answers_present_by_ref = set()
        data_class_choice_urn = None

        confidentiality_map = self.criticality_mapping.get("confidentiality", {})

        for ra in req_assessments:
            urn = ra.get_urn() if hasattr(ra, "get_urn") else (ra.get("urn") if isinstance(ra, dict) else None)
            req_json = ra.get_requirement_json() if hasattr(ra, "get_requirement_json") else ra
            rn_ref = None
            if isinstance(req_json, dict):
                req_obj = req_json.get("requirement")
                if isinstance(req_obj, dict):
                    rn_ref = req_obj.get("ref_id")
                    if not urn:
                        urn = req_obj.get("urn")
            if not rn_ref and urn:
                rn_ref = urn.rsplit(":", 1)[-1]

            answers_dict = ra.get_answers() if hasattr(ra, "get_answers") else (ra.get("answers") if isinstance(ra, dict) else {})
            has_answers = (
                ra.has_selected_answer()
                if hasattr(ra, "has_selected_answer")
                else (isinstance(answers_dict, dict) and any(v is not None for v in answers_dict.values()))
            )

            if not has_answers or not answers_dict:
                continue

            if urn:
                answers_present_by_urn.add(urn)
            if rn_ref:
                answers_present_by_ref.add(rn_ref)

            # Check for data classification
            if (rn_ref == "data_classification" or (urn and "data_classification" in urn)) and answers_dict:
                for a_val in answers_dict.values():
                    if a_val:
                        data_class_choice_urn = a_val
                        break

            # Get score
            score_val = ra.get_score() if hasattr(ra, "get_score") else (ra.get("score") if isinstance(ra, dict) else None)
            if score_val is not None and score_val != "":
                try:
                    num_score = int(score_val)
                    if urn:
                        scores[urn] = num_score
                    if rn_ref:
                        scores[rn_ref] = num_score
                    continue
                except (ValueError, TypeError):
                    pass

            # Otherwise compute score from choices
            rn = self.req_nodes_by_urn.get(urn) or self.req_nodes.get(rn_ref)
            if rn:
                total_score = 0
                questions_dict = rn.get("questions", {})
                for q_urn, choice_urn in answers_dict.items():
                    q_def = questions_dict.get(q_urn, {})
                    for choice in q_def.get("choices", []):
                        if choice.get("urn") == choice_urn or choice.get("value") == choice_urn:
                            add_score = choice.get("add_score")
                            if add_score is not None:
                                total_score += int(add_score)
                            break
                if urn:
                    scores[urn] = total_score
                if rn_ref:
                    scores[rn_ref] = total_score

        # 2. Determine Data Classification Impact
        impact_level = 1
        if data_class_choice_urn:
            if data_class_choice_urn in confidentiality_map:
                impact_level = confidentiality_map[data_class_choice_urn] + 1
            else:
                for k, v in confidentiality_map.items():
                    if k in str(data_class_choice_urn) or str(data_class_choice_urn).lower() in k.lower():
                        impact_level = v + 1
                        break

        # 3. Evaluate each Risk Scenario
        scenario_results = {}
        for scenario in self.risk_scenarios:
            sc_name = scenario.get("name")
            likelihood_urn = scenario.get("likelihood")
            impact_urn = scenario.get("impact")

            rn = self.req_nodes_by_urn.get(likelihood_urn)
            lh_ref_id = rn.get("ref_id") if rn else (likelihood_urn.rsplit(":", 1)[-1] if likelihood_urn else None)

            if likelihood_urn not in answers_present_by_urn and lh_ref_id not in answers_present_by_ref:
                continue

            if "data_classification" not in answers_present_by_ref and (impact_urn and impact_urn not in answers_present_by_urn):
                continue

            lh_score = scores.get(likelihood_urn, scores.get(lh_ref_id, 0))
            scaled_score = max(0, min(100, int(lh_score)))
            scaled_likelihood = min(4, max(1, 4 - ((scaled_score - 1) // 25)))

            proba_idx = scaled_likelihood - 1
            impact_idx = impact_level - 1
            risk_grid = self.risk_matrix["grid"]
            matrix_risk_id = risk_grid[proba_idx][impact_idx]
            risk_level_1_based = matrix_risk_id + 1
            control_priority = self.applied_control_dict.get_priority_from_risk_level(risk_level_1_based)

            scenario_results[sc_name] = {
                "likelihood_score": lh_score,
                "scaled_likelihood": scaled_likelihood,
                "scaled_impact": impact_level,
                "matrix_risk_id": matrix_risk_id,
                "risk_level_1_based": risk_level_1_based,
                "control_priority": control_priority,
            }

        return {
            "impact_level": impact_level,
            "requirement_scores": scores,
            "scenarios": scenario_results,
        }

    def evaluate_from_csv(self, csv_path):
        """Evaluate an application CSV and return computed scores, scenarios, and priorities."""
        answers_by_req = self.load_answers_from_csv(csv_path)

        # 1. Compute compliance scores for each requirement
        scores = {}
        for req_id, answers in answers_by_req.items():
            rn = self.req_nodes.get(req_id) or self.req_nodes_by_urn.get(req_id)
            if not rn:
                # Try finding by partial match
                for node in self.req_nodes.values():
                    if req_id in node.get("urn", "") or req_id in node.get("ref_id", ""):
                        rn = node
                        break
            if not rn:
                continue

            questions_dict = rn.get("questions", {})
            total_score = 0
            for ans_item in answers:
                q_text = ans_item["question"].strip().lower()
                ans_text = ans_item["answer"].strip().lower()

                # Find matching question in definition
                for q_urn, q_def in questions_dict.items():
                    if q_def.get("text", "").strip().lower() == q_text or len(questions_dict) == 1:
                        # Find matching choice
                        for choice in q_def.get("choices", []):
                            if choice.get("value", "").strip().lower() == ans_text:
                                add_score = choice.get("add_score")
                                if add_score is not None:
                                    total_score += int(add_score)
                                break
                        break

            scores[rn.get("ref_id")] = total_score
            scores[rn.get("urn")] = total_score

        # 2. Determine Data Classification Impact
        impact_level = 1
        confidentiality_map = self.criticality_mapping.get("confidentiality", {})
        data_class_answers = answers_by_req.get("data_classification", [])
        if data_class_answers:
            chosen_class_text = data_class_answers[0]["answer"].strip().lower()
            rn = self.req_nodes.get("data_classification", {})
            for q_urn, q_def in rn.get("questions", {}).items():
                for choice in q_def.get("choices", []):
                    if choice.get("value", "").strip().lower() == chosen_class_text:
                        choice_urn = choice.get("urn")
                        if choice_urn in confidentiality_map:
                            impact_level = confidentiality_map[choice_urn] + 1
                        break

        # 3. Evaluate each Risk Scenario
        scenario_results = {}
        for scenario in self.risk_scenarios:
            sc_name = scenario.get("name")
            likelihood_urn = scenario.get("likelihood")
            impact_urn = scenario.get("impact")

            # Skip scenario if likelihood requirement was not answered in the CSV
            rn = self.req_nodes_by_urn.get(likelihood_urn)
            lh_ref_id = rn.get("ref_id") if rn else None
            lh_answers = answers_by_req.get(lh_ref_id) or answers_by_req.get(likelihood_urn) or []
            if not lh_answers or not any(a.get("answer") for a in lh_answers):
                continue

            # Skip scenario if impact requirement was not answered in the CSV
            if "data_classification" not in answers_by_req and impact_urn not in answers_by_req:
                continue

            # Get likelihood requirement score
            lh_score = scores.get(likelihood_urn, scores.get(lh_ref_id, 0))
            scaled_score = max(0, min(100, int(lh_score)))
            scaled_likelihood = min(4, max(1, 4 - ((scaled_score - 1) // 25)))

            # Look up Risk in 4x4 Grid (0-based indexing for probability and impact)
            proba_idx = scaled_likelihood - 1
            impact_idx = impact_level - 1
            risk_grid = self.risk_matrix["grid"]
            matrix_risk_id = risk_grid[proba_idx][impact_idx]

            # Convert matrix risk id to 1-based risk level (1 to 5)
            # Risk Matrix: 0=very low(1), 1=low(2), 2=medium(3), 3=high(4), 4=very high(5)
            risk_level_1_based = matrix_risk_id + 1

            # Determine Applied Control Priority
            control_priority = self.applied_control_dict.get_priority_from_risk_level(risk_level_1_based)

            scenario_results[sc_name] = {
                "likelihood_score": lh_score,
                "scaled_likelihood": scaled_likelihood,
                "scaled_impact": impact_level,
                "matrix_risk_id": matrix_risk_id,
                "risk_level_1_based": risk_level_1_based,
                "control_priority": control_priority,
            }

        return {
            "impact_level": impact_level,
            "requirement_scores": scores,
            "scenarios": scenario_results,
        }


class TestApplicationScenarios(unittest.TestCase):
    """Test suite running multi-application profiles against the risk calculation engine."""

    @classmethod
    def setUpClass(cls):
        cls.simulator = ApplicationRiskSimulator("YML/newDPP.yml")

    def test_app_secure_core(self):
        """Test App-Secure-Core: Secret data (Impact=4) with 100% compliance across all in-scope controls.

        Expected:
        - Impact: 4 (Critical)
        - In-house app -> SaaS scenario is not evaluated (6 scenarios total)
        - All likelihoods: 1 (Unlikely)
        - Residual risk: Low / Acceptable
        - Control priorities: 3 or 4 (Low urgency for additional action)
        """
        results = self.simulator.evaluate_application("test_data/app_secure_core.csv")
        self.assertEqual(results["impact_level"], 4, "Impact for Secret data should be 4")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 6, "6 in-scope scenarios must be evaluated (SaaS excluded)")
        self.assertNotIn("SaaS provider data leakage", scenarios)

        for sc_name, sc_data in scenarios.items():
            self.assertEqual(
                sc_data["scaled_likelihood"], 1,
                f"Scenario '{sc_name}' should have likelihood 1 with 100% compliance"
            )
            self.assertEqual(
                sc_data["scaled_impact"], 4,
                f"Scenario '{sc_name}' should have impact 4"
            )
            # Grid[0][3] (Likelihood 1, Impact 4) = 1 (Low risk)
            self.assertEqual(sc_data["matrix_risk_id"], 1, f"Scenario '{sc_name}' matrix risk should be Low (id=1)")
            self.assertIn(sc_data["control_priority"], [3, 4])

    def test_app_vulnerable_portal(self):
        """Test App-Vulnerable-Portal: Secret data (Impact=4) with 0% compliance (Unimplemented controls).

        Expected:
        - Impact: 4 (Critical)
        - All 7 likelihoods: 4 (Very likely)
        - Grid[3][3] (Likelihood 4, Impact 4) = 4 (Very High / Unacceptable Risk)
        - Control Priority: 1 (Urgent remediation required!)
        """
        results = self.simulator.evaluate_application("test_data/app_vulnerable_portal.csv")
        self.assertEqual(results["impact_level"], 4, "Impact for Secret data should be 4")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 7, "All 7 scenarios must be evaluated for SaaS Secret app")
        for sc_name, sc_data in scenarios.items():
            self.assertEqual(
                sc_data["scaled_likelihood"], 4,
                f"Scenario '{sc_name}' should have likelihood 4 with 0% compliance"
            )
            self.assertEqual(
                sc_data["scaled_impact"], 4,
                f"Scenario '{sc_name}' should have impact 4"
            )
            self.assertEqual(
                sc_data["matrix_risk_id"], 4,
                f"Scenario '{sc_name}' matrix risk must be Very High (id=4)"
            )
            self.assertEqual(
                sc_data["control_priority"], 1,
                f"Scenario '{sc_name}' control priority must be Priority 1 (Urgent)"
            )

    def test_app_internal_tool(self):
        """Test App-Internal-Tool: Internal data (Impact=2) with SaaS hosting.

        Expected:
        - Impact: 2 (Significant)
        - Untriggered Chapter 2 requirements (confidential/secret) excluded -> 2 Scenarios
        - Missing stakeholders: evaluated
        - SaaS contract: 60% compliant (3/5 clauses) -> Likelihood 2
        """
        results = self.simulator.evaluate_application("test_data/app_internal_tool.csv")
        self.assertEqual(results["impact_level"], 2, "Impact for Internal data should be 2")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 2, "Only Stakeholders and SaaS scenarios should be evaluated for Internal tool")
        self.assertIn("Missing application stakeholders", scenarios)
        self.assertIn("SaaS provider data leakage", scenarios)
        self.assertNotIn("Exposure of unencrypted data in transit", scenarios)
        self.assertNotIn("Exposure of unencrypted data at rest", scenarios)

        saas_sc = scenarios["SaaS provider data leakage"]
        self.assertEqual(saas_sc["scaled_likelihood"], 2)
        self.assertEqual(saas_sc["scaled_impact"], 2)

    def test_app_public_blog(self):
        """Test App-Public-Blog: Public data (Impact=1 / Minor) with minimal sensitivity.

        Expected:
        - Impact: 1 (Minor)
        - Only applicable requirements answered (Stakeholders & SaaS Contract) -> 2 Scenarios
        - Confidential/Secret Chapter 2 scenarios NOT evaluated
        - Max priority is Priority 3 or 4 (No urgent priorities on public data).
        """
        results = self.simulator.evaluate_application("test_data/app_public_blog.csv")
        self.assertEqual(results["impact_level"], 1, "Impact for Public data should be 1")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 2, "Only Stakeholders and SaaS scenarios should be evaluated for Public blog")
        self.assertIn("Missing application stakeholders", scenarios)
        self.assertIn("SaaS provider data leakage", scenarios)
        self.assertNotIn("Exposure of unencrypted data in transit", scenarios)
        self.assertNotIn("Exposure of unencrypted data at rest", scenarios)
        self.assertNotIn("Disclosure of production data in non-production environments", scenarios)
        self.assertNotIn("Third-party data leakage", scenarios)
        self.assertNotIn("Excessive retention of sensitive data", scenarios)

        for sc_name, sc_data in scenarios.items():
            self.assertEqual(sc_data["scaled_impact"], 1)
            self.assertLessEqual(
                sc_data["matrix_risk_id"], 1,
                f"Public data scenario '{sc_name}' should not exceed Low Risk"
            )
            self.assertIn(
                sc_data["control_priority"], [3, 4],
                f"Public data scenario '{sc_name}' should only generate Medium/Low control priority"
            )

    def test_app_hr_people_system(self):
        """Test App-HR-People-System: Confidential data (Impact=3) with GDPR and non-prod gaps."""
        results = self.simulator.evaluate_application("test_data/app_hr_people_system.csv")
        self.assertEqual(results["impact_level"], 3, "Impact for Confidential HR data should be 3")

        scenarios = results["scenarios"]
        non_prod_sc = scenarios["Disclosure of production data in non-production environments"]
        self.assertEqual(non_prod_sc["scaled_likelihood"], 4)
        self.assertEqual(non_prod_sc["scaled_impact"], 3)
        self.assertEqual(non_prod_sc["matrix_risk_id"], 3)  # High Risk
        self.assertEqual(non_prod_sc["control_priority"], 1)  # Urgent Priority

        retention_sc = scenarios["Excessive retention of sensitive data"]
        self.assertEqual(retention_sc["scaled_likelihood"], 4)
        self.assertEqual(retention_sc["control_priority"], 1)

    def test_app_customer_payment_api(self):
        """Test App-Customer-Payment-API: Secret PCI data (Impact=4) with in-house deployment."""
        results = self.simulator.evaluate_application("test_data/app_customer_payment_api.csv")
        self.assertEqual(results["impact_level"], 4, "Impact for Secret PCI data should be 4")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 6, "In-house app must evaluate 6 scenarios (SaaS excluded)")
        self.assertNotIn("SaaS provider data leakage", scenarios)

        third_party_sc = scenarios["Third-party data leakage"]
        self.assertEqual(third_party_sc["scaled_likelihood"], 1)
        self.assertEqual(third_party_sc["scaled_impact"], 4)
        self.assertEqual(third_party_sc["matrix_risk_id"], 1)  # Low Risk (mitigated by contract)
        self.assertEqual(third_party_sc["control_priority"], 3)  # Medium Priority

        transit_sc = scenarios["Exposure of unencrypted data in transit"]
        self.assertEqual(transit_sc["scaled_likelihood"], 1)

    def test_app_legacy_erp_production(self):
        """Test App-Legacy-ERP-Production: Internal data (Impact=2) with in-house hosting.

        Expected:
        - Impact: 2 (Significant)
        - In-house app + Internal data: Chapter 2 and Chapter 3 excluded -> 1 Scenario
        - Missing stakeholders: evaluated
        """
        results = self.simulator.evaluate_application("test_data/app_legacy_erp_production.csv")
        self.assertEqual(results["impact_level"], 2, "Impact for Internal data should be 2")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 1, "Only Missing Stakeholders scenario should be evaluated for Legacy ERP")
        self.assertIn("Missing application stakeholders", scenarios)
        self.assertNotIn("SaaS provider data leakage", scenarios)
        self.assertNotIn("Exposure of unencrypted data in transit", scenarios)
        self.assertNotIn("Exposure of unencrypted data at rest", scenarios)

    def test_app_ai_analytics_workbench(self):
        """Test App-AI-Analytics-Workbench: Confidential data (Impact=3) with GenAI prompt and transfer risks."""
        results = self.simulator.evaluate_application("test_data/app_ai_analytics_workbench.csv")
        self.assertEqual(results["impact_level"], 3, "Impact for Confidential GenAI data should be 3")

        scenarios = results["scenarios"]
        non_prod_sc = scenarios["Disclosure of production data in non-production environments"]
        self.assertEqual(non_prod_sc["scaled_likelihood"], 4)
        self.assertEqual(non_prod_sc["matrix_risk_id"], 3)  # High Risk
        self.assertEqual(non_prod_sc["control_priority"], 1)

        third_party_sc = scenarios["Third-party data leakage"]
        self.assertEqual(third_party_sc["scaled_likelihood"], 4)
        self.assertEqual(third_party_sc["control_priority"], 1)

    def test_evaluate_from_requirement_assessments_with_unassessed_info_nodes(self):
        """Test that answered informational requirements (result=not_assessed) properly generate risk scenarios."""
        from classes.audits.requirement_assessment import RequirementAssessment

        mock_ras = [
            RequirementAssessment({
                "id": "ra-1",
                "requirement": {
                    "ref_id": "stakeholder_identification",
                    "urn": "urn:intuitem:risk:req_node:mls:stakeholder_identification",
                },
                "answers": {
                    "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:1": "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:1:choice:1",
                    "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:2": "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:2:choice:1",
                    "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:3": "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:3:choice:1",
                    "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:4": "urn:intuitem:risk:req_node:mls:stakeholder_identification:question:4:choice:2",
                },
                "score": 75,
                "result": "partially_compliant",
            }),
            RequirementAssessment({
                "id": "ra-2",
                "requirement": {
                    "ref_id": "data_classification",
                    "urn": "urn:intuitem:risk:req_node:mls:data_classification",
                },
                "answers": {
                    "urn:intuitem:risk:req_node:mls:data_classification:q1": "urn:intuitem:risk:req_node:mls:data_classification:q1:c2",
                },
                "score": 0,
                "result": "not_assessed",
            }),
            RequirementAssessment({
                "id": "ra-3",
                "requirement": {
                    "ref_id": "hosting",
                    "urn": "urn:intuitem:risk:req_node:mls:hosting",
                },
                "answers": {
                    "urn:intuitem:risk:req_node:mls:hosting:q1": "urn:intuitem:risk:req_node:mls:hosting:q1:c2",
                },
                "score": 0,
                "result": "not_assessed",
            }),
            RequirementAssessment({
                "id": "ra-4",
                "requirement": {
                    "ref_id": "saas_contract_compliance",
                    "urn": "urn:intuitem:risk:req_node:mls:saas_contract",
                },
                "answers": {
                    "urn:intuitem:risk:req_node:mls:saas_contract:question:1": "urn:intuitem:risk:req_node:mls:saas_contract:question:1:choice:1",
                    "urn:intuitem:risk:req_node:mls:saas_contract:question:2": None,
                },
                "score": 0,
                "result": "non_compliant",
            }),
            RequirementAssessment({
                "id": "ra-5",
                "requirement": {
                    "ref_id": "data_in_transit",
                    "urn": "urn:intuitem:risk:req_node:mls:data_in_transit",
                },
                "answers": {
                    "urn:intuitem:risk:req_node:mls:data_in_transit:q1": None,
                },
                "score": 0,
                "result": "not_assessed",
            }),
        ]

        results = self.simulator.evaluate_application(mock_ras)
        self.assertEqual(results["impact_level"], 2, "Internal data classification should give impact level 2")
        scenarios = results["scenarios"]
        self.assertIn("Missing application stakeholders", scenarios)
        self.assertIn("SaaS provider data leakage", scenarios)
        self.assertNotIn("Exposure of unencrypted data in transit", scenarios)
        self.assertEqual(scenarios["Missing application stakeholders"]["scaled_likelihood"], 2)
        self.assertEqual(scenarios["SaaS provider data leakage"]["scaled_likelihood"], 4)


if __name__ == "__main__":
    unittest.main()

