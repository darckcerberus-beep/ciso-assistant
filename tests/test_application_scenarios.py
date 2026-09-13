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

    def load_answers_from_csv(self, csv_path):
        """Read CSV answers into a dictionary grouped by requirement ref_id."""
        answers_by_req = {}
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                req = row.get("requirement", "").strip()
                question = row.get("question", "").strip()
                answer = row.get("answer", "").strip()
                if req not in answers_by_req:
                    answers_by_req[req] = []
                answers_by_req[req].append({"question": question, "answer": answer})
        return answers_by_req

    def evaluate_application(self, csv_path):
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

            # Get likelihood requirement score
            lh_score = scores.get(likelihood_urn, 0)
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
        """Test App-Secure-Core: Secret data (Impact=4) with 100% compliance across all controls.

        Expected:
        - Impact: 4 (Critical)
        - All likelihoods: 1 (Unlikely)
        - Residual risk: Low / Acceptable
        - Control priorities: 4 (Low urgency for additional action)
        """
        results = self.simulator.evaluate_application("test_data/app_secure_core.csv")
        self.assertEqual(results["impact_level"], 4, "Impact for Secret data should be 4")

        scenarios = results["scenarios"]
        self.assertEqual(len(scenarios), 7, "All 7 scenarios must be evaluated")

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
            # Risk Level 2 -> Priority 3 or 4
            self.assertIn(sc_data["control_priority"], [3, 4])

    def test_app_vulnerable_portal(self):
        """Test App-Vulnerable-Portal: Secret data (Impact=4) with 0% compliance (Unimplemented controls).

        Expected:
        - Impact: 4 (Critical)
        - All likelihoods: 4 (Very likely)
        - Grid[3][3] (Likelihood 4, Impact 4) = 4 (Very High / Unacceptable Risk)
        - Control Priority: 1 (Urgent remediation required!)
        """
        results = self.simulator.evaluate_application("test_data/app_vulnerable_portal.csv")
        self.assertEqual(results["impact_level"], 4, "Impact for Secret data should be 4")

        scenarios = results["scenarios"]
        for sc_name, sc_data in scenarios.items():
            self.assertEqual(
                sc_data["scaled_likelihood"], 4,
                f"Scenario '{sc_name}' should have likelihood 4 with 0% compliance"
            )
            self.assertEqual(
                sc_data["scaled_impact"], 4,
                f"Scenario '{sc_name}' should have impact 4"
            )
            # Grid[3][3] = 4 (Very High / unacceptable risk)
            self.assertEqual(
                sc_data["matrix_risk_id"], 4,
                f"Scenario '{sc_name}' matrix risk must be Very High (id=4)"
            )
            # Control priority must be 1 (Urgent)
            self.assertEqual(
                sc_data["control_priority"], 1,
                f"Scenario '{sc_name}' control priority must be Priority 1 (Urgent)"
            )

    def test_app_internal_tool(self):
        """Test App-Internal-Tool: Internal data (Impact=2) with mixed compliance levels.

        Expected:
        - Impact: 2 (Significant)
        - Transit Encryption (100% score) -> Likelihood 1 -> Risk id 0 (Very Low)
        - At-Rest Encryption (0% score) -> Likelihood 4 -> Risk id 1 (Low/Medium) -> Priority 3
        - SaaS Contract (60% score) -> Likelihood 2
        """
        results = self.simulator.evaluate_application("test_data/app_internal_tool.csv")
        self.assertEqual(results["impact_level"], 2, "Impact for Internal data should be 2")

        scenarios = results["scenarios"]

        # 1. Transit encryption: 100% compliant -> Likelihood 1
        transit_sc = scenarios["Exposure of unencrypted data in transit"]
        self.assertEqual(transit_sc["scaled_likelihood"], 1)
        self.assertEqual(transit_sc["scaled_impact"], 2)
        self.assertEqual(transit_sc["matrix_risk_id"], 0)  # Very Low risk

        # 2. At-rest encryption: 0% compliant -> Likelihood 4, Impact 2 -> Grid[3][1] = 2 (Medium Risk) -> Priority 2
        rest_sc = scenarios["Exposure of unencrypted data at rest"]
        self.assertEqual(rest_sc["scaled_likelihood"], 4)
        self.assertEqual(rest_sc["scaled_impact"], 2)
        self.assertEqual(rest_sc["matrix_risk_id"], 2)  # Medium risk (id=2)
        self.assertEqual(rest_sc["control_priority"], 2)  # Priority 2 (High)

        # 3. SaaS contract: 60% compliant (3/5 clauses) -> Likelihood 2 (Rather unlikely)
        saas_sc = scenarios["SaaS provider data leakage"]
        self.assertEqual(saas_sc["scaled_likelihood"], 2)
        self.assertEqual(saas_sc["scaled_impact"], 2)

    def test_app_public_blog(self):
        """Test App-Public-Blog: Public data (Impact=1 / Minor) with minimal sensitivity.

        Expected:
        - Impact: 1 (Minor)
        - Even when Likelihood is 4 (e.g. unencrypted at rest or missing destruction),
          Grid[3][0] = 1 (Low Risk).
        - Max priority is Priority 3 or 4 (No urgent priorities on public data).
        """
        results = self.simulator.evaluate_application("test_data/app_public_blog.csv")
        self.assertEqual(results["impact_level"], 1, "Impact for Public data should be 1")

        scenarios = results["scenarios"]
        for sc_name, sc_data in scenarios.items():
            self.assertEqual(sc_data["scaled_impact"], 1)
            # On public data (impact 1), risk never exceeds Low (matrix id <= 1)
            self.assertLessEqual(
                sc_data["matrix_risk_id"], 1,
                f"Public data scenario '{sc_name}' should not exceed Low Risk"
            )
            # Priority should never be Urgent (Priority 1) or High (Priority 2)
            self.assertIn(
                sc_data["control_priority"], [3, 4],
                f"Public data scenario '{sc_name}' should only generate Medium/Low control priority"
            )


if __name__ == "__main__":
    unittest.main()
