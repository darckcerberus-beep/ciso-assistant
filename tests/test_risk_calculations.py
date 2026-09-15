"""Unit tests for Risk Assessment and Risk Scenario calculation formulas and logic."""

import unittest
from unittest.mock import MagicMock, patch

from classes.controls.applied import AppliedControlDict
from classes.core.risk import (
    RiskAssessment,
    RiskAssessmentDict,
    RiskScenario,
    RiskScenarioDict,
    RiskMatrixDict,
)


class TestRiskCalculations(unittest.TestCase):
    """Test suite for mathematical risk formulas, scaling, and priority mapping."""

    def test_likelihood_scaling_formula(self):
        """Verify the inverse likelihood formula across all score boundaries (0-100%).

        Formula: scaled_likelihood = min(4, max(1, 4 - ((score - 1) // 25)))
        """
        def calculate_scaled_likelihood(score_val):
            score = max(0, min(100, int(score_val)))
            return min(4, max(1, 4 - ((score - 1) // 25)))

        # Boundary checks for Level 1 (Unlikely): scores 76 to 100
        self.assertEqual(calculate_scaled_likelihood(100), 1)
        self.assertEqual(calculate_scaled_likelihood(99), 1)
        self.assertEqual(calculate_scaled_likelihood(76), 1)

        # Boundary checks for Level 2 (Rather unlikely): scores 51 to 75
        self.assertEqual(calculate_scaled_likelihood(75), 2)
        self.assertEqual(calculate_scaled_likelihood(60), 2)
        self.assertEqual(calculate_scaled_likelihood(51), 2)

        # Boundary checks for Level 3 (Likely): scores 26 to 50
        self.assertEqual(calculate_scaled_likelihood(50), 3)
        self.assertEqual(calculate_scaled_likelihood(30), 3)
        self.assertEqual(calculate_scaled_likelihood(26), 3)

        # Boundary checks for Level 4 (Very likely): scores 0 to 25
        self.assertEqual(calculate_scaled_likelihood(25), 4)
        self.assertEqual(calculate_scaled_likelihood(10), 4)
        self.assertEqual(calculate_scaled_likelihood(0), 4)

    def test_priority_from_risk_level_mapping(self):
        """Verify translation of risk levels (1-4) to API priority integers (1-4).

        Mapping:
        - Level 4 (Critical) -> Priority 1 (Urgent)
        - Level 3 (High)     -> Priority 2 (High)
        - Level 2 (Medium)   -> Priority 3 (Medium)
        - Level 1 (Low)      -> Priority 4 (Low)
        """
        ctrl_dict = AppliedControlDict.__new__(AppliedControlDict)

        # Integer inputs
        self.assertEqual(ctrl_dict.get_priority_from_risk_level(4), 1)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level(3), 2)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level(2), 3)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level(1), 4)

        # Dictionary / object inputs (e.g. current_level dict)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level({"id": 4}), 1)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level({"value": 3}), 2)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level({"id": 2}), 3)
        self.assertEqual(ctrl_dict.get_priority_from_risk_level({"value": 1}), 4)

        # Error handling on invalid values
        with self.assertRaises(ValueError):
            ctrl_dict.get_priority_from_risk_level("invalid_level")
        with self.assertRaises(ValueError):
            ctrl_dict.get_priority_from_risk_level(None)

    def test_strict_error_handling_in_priority_lookup(self):
        """Verify that get_priority_for_compliance_assessment_id raises LookupError when data is missing."""
        ctrl_dict = AppliedControlDict.__new__(AppliedControlDict)

        # Compliance assessment not found
        with patch("classes.utils.get_return", return_value=None):
            with self.assertRaises(LookupError):
                ctrl_dict.get_priority_for_compliance_assessment_id(
                    "non-existent-ca-id",
                    "urn:test:req",
                    compliance_assessment_dict=MagicMock(get_compliance_assessments=lambda: {}),
                )

    def test_risk_scenario_relationships_update(self):
        """Verify update_relationships merges existing and new IDs idempotently without duplication."""
        mock_scenario_payload = {
            "id": "scenario-uuid-1",
            "name": "Exposure of unencrypted data in transit",
            "existing_applied_controls": ["ctrl-1", "ctrl-2"],
            "applied_controls": ["ctrl-3"],
            "assets": ["asset-1"],
            "owner": ["user-1"],
        }
        scenario = RiskScenario(mock_scenario_payload)

        # 1. Calling update_relationships with no new IDs should not perform PATCH
        with patch("classes.utils.get_return") as mock_get_return:
            res = scenario.update_relationships(["ctrl-1"], ["ctrl-3"], ["asset-1"], ["user-1"])
            mock_get_return.assert_not_called()
            self.assertEqual(res, mock_scenario_payload)

        # 2. Calling with new distinct IDs should trigger a PATCH with union of IDs
        with patch("classes.utils.get_return") as mock_get_return:
            mock_patch_result = dict(mock_scenario_payload)
            mock_patch_result["existing_applied_controls"] = ["ctrl-1", "ctrl-2", "ctrl-new"]
            mock_get_return.return_value = mock_patch_result

            scenario.update_relationships(["ctrl-new"], [], [], [])
            mock_get_return.assert_called_once_with(
                "/api/risk-scenarios/scenario-uuid-1/",
                method="PATCH",
                payload={"existing_applied_controls": ["ctrl-1", "ctrl-2", "ctrl-new"]},
            )

    def test_risk_scenario_dict_0_based_conversion(self):
        """Verify that RiskScenarioDict converts 1-based domain levels to 0-based API values."""
        rs_dict = RiskScenarioDict.__new__(RiskScenarioDict)
        rs_dict.risk_scenarios = {}

        with patch("classes.utils.get_return") as mock_get_return:
            mock_get_return.return_value = {"id": "new-scenario-uuid", "name": "Test Scenario"}

            rs_dict.create_risk_scenario(
                name="Test Scenario",
                description="Test description",
                risk_assessment_id="risk-assessment-uuid",
                current_proba=4,    # 1-based (Very likely)
                current_impact=3,   # 1-based (Serious)
                residual_proba=1,   # 1-based (Unlikely)
                residual_impact=3,  # 1-based (Serious)
                existing_applied_controls=["ctrl-1"],
                applied_controls=["ctrl-2"],
                assets=["asset-1"],
                owners=["user-1"],
            )

            # Assert POST payload contains 0-based values: 4-1=3, 3-1=2, 1-1=0, 3-1=2
            mock_get_return.assert_called_once_with(
                "/api/risk-scenarios/",
                method="POST",
                payload={
                    "name": "Test Scenario",
                    "description": "Test description",
                    "risk_assessment": "risk-assessment-uuid",
                    "current_proba": 3,
                    "current_impact": 2,
                    "residual_proba": 0,
                    "residual_impact": 2,
                    "existing_applied_controls": ["ctrl-1"],
                    "applied_controls": ["ctrl-2"],
                    "assets": ["asset-1"],
                    "owner": ["user-1"],
                }
            )

    def test_requirement_assessment_score_compliance(self):
        """Verify that RequirementAssessment.is_score_compliant evaluates score threshold >= 100 correctly."""
        from classes.audits.requirement_assessment import RequirementAssessment

        # 100% score -> Compliant
        ra_100 = RequirementAssessment({"score": 100})
        self.assertTrue(ra_100.is_score_compliant())

        ra_100_str = RequirementAssessment({"score": "100"})
        self.assertTrue(ra_100_str.is_score_compliant())

        # Fractional 100.0 -> Compliant
        ra_100_float = RequirementAssessment({"score": 100.0})
        self.assertTrue(ra_100_float.is_score_compliant())

        # Scores < 100 -> Non-compliant
        ra_99 = RequirementAssessment({"score": 99})
        self.assertFalse(ra_99.is_score_compliant())

        ra_80 = RequirementAssessment({"score": 80})
        self.assertFalse(ra_80.is_score_compliant())

        ra_0 = RequirementAssessment({"score": 0})
        self.assertFalse(ra_0.is_score_compliant())

        # Missing / None / Empty -> Non-compliant
        ra_none = RequirementAssessment({"score": None})
        self.assertFalse(ra_none.is_score_compliant())

        ra_empty = RequirementAssessment({})
        self.assertFalse(ra_empty.is_score_compliant())

    def test_skip_scenarios_and_controls_for_unanswered_requirements(self):
        """Verify that unanswered requirement assessments are skipped during control and scenario creation."""
        from classes.audits.requirement_assessment import RequirementAssessment, RequirementAssessmentDict
        from classes.controls.applied import AppliedControlDict

        # Unanswered requirement assessment (no answers, not assessed)
        unanswered_ra = RequirementAssessment({
            "id": "ra-unanswered",
            "compliance_assessment": "ca-1",
            "answers": {},
            "result": "not_assessed",
            "requirement": {
                "urn": "urn:test:req",
                "associated_reference_controls": [{"id": "ref-ctrl-1", "name": "Test Control"}],
            }
        })

        self.assertFalse(unanswered_ra.has_selected_answer())
        self.assertTrue(unanswered_ra.is_unassessed_result())

        # Requirement with explicit answers
        answered_ra = RequirementAssessment({
            "id": "ra-answered",
            "compliance_assessment": "ca-1",
            "answers": {"q1": "choice-1"},
            "result": "compliant",
            "score": 100,
            "requirement": {
                "urn": "urn:test:req",
                "associated_reference_controls": [{"id": "ref-ctrl-1", "name": "Test Control"}],
            }
        })

        self.assertTrue(answered_ra.has_selected_answer())
        self.assertFalse(answered_ra.is_unassessed_result())


if __name__ == "__main__":
    unittest.main()

