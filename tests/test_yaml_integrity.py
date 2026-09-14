"""Automated schema, foreign key, and logic integrity tests for YML/newDPP.yml."""

import unittest
from pathlib import Path
import yaml


class TestYamlIntegrity(unittest.TestCase):
    """Verifies relational integrity, foreign key consistency, and scoring logic in newDPP.yml."""

    @classmethod
    def setUpClass(cls):
        yaml_path = Path(__file__).resolve().parent.parent / "YML" / "newDPP.yml"
        cls.assertTrue(yaml_path.exists(), f"YAML file not found at {yaml_path}")
        with open(yaml_path, "r", encoding="utf-8") as f:
            cls.yaml_data = yaml.safe_load(f)

        cls.objects = cls.yaml_data.get("objects", {})
        cls.framework = cls.objects.get("framework", {})
        cls.threats = {t["urn"]: t for t in cls.objects.get("threats", [])}
        cls.vulns = {v["urn"]: v for v in cls.objects.get("vulnerabilities", [])}
        cls.ref_ctrls = {c["urn"]: c for c in cls.objects.get("reference_controls", [])}
        cls.scenarios = {s["urn"]: s for s in cls.objects.get("risk_scenarios", [])}
        cls.ig_defs_by_ref = {
            ig["ref_id"]: ig
            for ig in cls.framework.get("implementation_groups_definition", [])
            if "ref_id" in ig
        }
        cls.ig_defs_by_urn = {
            ig["urn"]: ig
            for ig in cls.framework.get("implementation_groups_definition", [])
            if "urn" in ig
        }
        cls.req_nodes = {rn["urn"]: rn for rn in cls.framework.get("requirement_nodes", [])}

    def test_global_urn_uniqueness(self):
        """Ensure all defined URNs across all object types are strictly unique."""
        all_urns = []
        for category, item_list in [
            ("threats", self.objects.get("threats", [])),
            ("vulnerabilities", self.objects.get("vulnerabilities", [])),
            ("reference_controls", self.objects.get("reference_controls", [])),
            ("risk_scenarios", self.objects.get("risk_scenarios", [])),
            ("risk_matrix", self.objects.get("risk_matrix", [])),
            ("implementation_groups", self.framework.get("implementation_groups_definition", [])),
            ("requirement_nodes", self.framework.get("requirement_nodes", [])),
        ]:
            for item in item_list:
                urn = item.get("urn")
                if urn:
                    self.assertNotIn(
                        urn,
                        all_urns,
                        f"Duplicate URN found in {category}: {urn}",
                    )
                    all_urns.append(urn)

    def test_requirement_nodes_hierarchy_and_depth(self):
        """Ensure parent_urn references exist and depth values accurately match hierarchy."""
        for urn, rn in self.req_nodes.items():
            parent_urn = rn.get("parent_urn")
            depth = rn.get("depth")
            if parent_urn is None:
                self.assertEqual(depth, 1, f"Root requirement node {urn} should have depth=1")
            else:
                self.assertIn(
                    parent_urn,
                    self.req_nodes,
                    f"Requirement node {urn} has invalid parent_urn: {parent_urn}",
                )
                parent_depth = self.req_nodes[parent_urn].get("depth", 1)
                self.assertEqual(
                    depth,
                    parent_depth + 1,
                    f"Requirement node {urn} depth ({depth}) must be parent depth + 1 ({parent_depth + 1})",
                )

    def test_requirement_nodes_foreign_keys(self):
        """Ensure requirement nodes only reference existing controls, vulnerabilities, and implementation groups."""
        for urn, rn in self.req_nodes.items():
            for rc_urn in rn.get("reference_controls", []):
                self.assertIn(
                    rc_urn,
                    self.ref_ctrls,
                    f"Requirement node {urn} references unknown reference_control: {rc_urn}",
                )
            for v_urn in rn.get("vulnerabilities", []):
                self.assertIn(
                    v_urn,
                    self.vulns,
                    f"Requirement node {urn} references unknown vulnerability: {v_urn}",
                )
            for ig in rn.get("implementation_groups", []):
                self.assertTrue(
                    ig in self.ig_defs_by_ref or ig in self.ig_defs_by_urn,
                    f"Requirement node {urn} references unknown implementation_group: {ig}",
                )

    def test_questions_choices_and_scoring_logic(self):
        """Ensure scoring values (add_score), compute_result booleans, and choice implementation groups are valid."""
        for rn_urn, rn in self.req_nodes.items():
            questions = rn.get("questions", {})
            for q_urn, q_def in questions.items():
                choices = q_def.get("choices", [])
                for choice in choices:
                    c_urn = choice.get("urn")
                    add_score = choice.get("add_score")
                    compute_result = choice.get("compute_result")

                    # If add_score is 0, compute_result should be False to avoid false positives
                    if add_score == 0:
                        self.assertFalse(
                            compute_result,
                            f"Choice {c_urn} has add_score=0 but compute_result is True",
                        )

                    # If add_score > 0, compute_result should be True
                    if add_score and add_score > 0:
                        self.assertTrue(
                            compute_result,
                            f"Choice {c_urn} has add_score={add_score} but compute_result is False",
                        )

                    # Implementation groups in choices
                    for ig in choice.get("implementation_groups", []):
                        self.assertTrue(
                            ig in self.ig_defs_by_ref or ig in self.ig_defs_by_urn,
                            f"Choice {c_urn} references unknown implementation_group: {ig}",
                        )

    def test_risk_scenarios_foreign_keys(self):
        """Ensure risk scenarios only reference existing threats, vulnerabilities, and controls."""
        for s_urn, scenario in self.scenarios.items():
            for t_urn in scenario.get("threats", []):
                self.assertIn(
                    t_urn,
                    self.threats,
                    f"Risk scenario {s_urn} references unknown threat: {t_urn}",
                )
            for v_urn in scenario.get("vulnerabilities", []):
                self.assertIn(
                    v_urn,
                    self.vulns,
                    f"Risk scenario {s_urn} references unknown vulnerability: {v_urn}",
                )
            for rc_urn in scenario.get("existing_reference_controls", []):
                self.assertIn(
                    rc_urn,
                    self.ref_ctrls,
                    f"Risk scenario {s_urn} references unknown existing_reference_control: {rc_urn}",
                )
            for rc_urn in scenario.get("reference_controls", []):
                self.assertIn(
                    rc_urn,
                    self.ref_ctrls,
                    f"Risk scenario {s_urn} references unknown reference_control: {rc_urn}",
                )

    def test_vulnerabilities_and_controls_cross_references(self):
        """Ensure vulnerabilities and controls reference valid threats and controls."""
        for v_urn, v_def in self.vulns.items():
            for t_urn in v_def.get("threats", []):
                self.assertIn(
                    t_urn,
                    self.threats,
                    f"Vulnerability {v_urn} references unknown threat: {t_urn}",
                )
            for rc_urn in v_def.get("reference_controls", []):
                self.assertIn(
                    rc_urn,
                    self.ref_ctrls,
                    f"Vulnerability {v_urn} references unknown reference_control: {rc_urn}",
                )

        for rc_urn, rc_def in self.ref_ctrls.items():
            for t_urn in rc_def.get("threats", []):
                self.assertIn(
                    t_urn,
                    self.threats,
                    f"Reference control {rc_urn} references unknown threat: {t_urn}",
                )

    def test_criticality_mapping_integrity(self):
        """Ensure all choice URNs referenced in criticality_mapping exist in questions."""
        crit_map = self.yaml_data.get("criticality_mapping", {})
        all_choice_urns = set()
        for rn in self.req_nodes.values():
            for q in rn.get("questions", {}).values():
                for c in q.get("choices", []):
                    all_choice_urns.add(c.get("urn"))

        for dim, mappings in crit_map.items():
            for choice_urn, level in mappings.items():
                self.assertIn(
                    choice_urn,
                    all_choice_urns,
                    f"Criticality mapping for {dim} references unknown choice URN: {choice_urn}",
                )
                self.assertIn(
                    level,
                    [0, 1, 2, 3, 4],
                    f"Criticality level for {choice_urn} must be 0-4, got: {level}",
                )


if __name__ == "__main__":
    unittest.main()
