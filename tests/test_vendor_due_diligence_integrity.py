"""Automated schema, foreign key, and logic integrity tests for YML/vendor-due-diligence.yaml."""

import unittest
from pathlib import Path
import yaml
from classes.core.framework import LibraryFile


class TestVendorDueDiligenceIntegrity(unittest.TestCase):
    """Verifies relational integrity, foreign key consistency, and scoring logic in vendor-due-diligence.yaml."""

    @classmethod
    def setUpClass(cls):
        yaml_path = Path(__file__).resolve().parent.parent / "YML" / "vendor-due-diligence.yaml"
        cls.assertTrue(yaml_path.exists(), f"YAML file not found at {yaml_path}")
        with open(yaml_path, "r", encoding="utf-8") as f:
            cls.yaml_data = yaml.safe_load(f)

        cls.objects = cls.yaml_data.get("objects", {})
        cls.framework = cls.objects.get("framework", {})
        cls.threats = {t["urn"]: t for t in cls.objects.get("threats", [])}
        cls.vulns = {v["urn"]: v for v in cls.objects.get("vulnerabilities", [])}
        cls.ref_ctrls = {c["urn"]: c for c in cls.objects.get("reference_controls", [])}
        cls.scenarios = {s["urn"]: s for s in cls.objects.get("risk_scenarios", [])}
        cls.req_nodes = {rn["urn"]: rn for rn in cls.framework.get("requirement_nodes", [])}

    def test_library_file_loading(self):
        """Ensure LibraryFile correctly parses vendor-due-diligence.yaml and exposes risk objects."""
        lib = LibraryFile("YML/vendor-due-diligence.yaml")
        self.assertEqual(lib.get_name(), "Vendor Due Diligence (VDD) - simple")
        self.assertEqual(len(lib.get_risk_scenarios()), 10)
        self.assertEqual(len(lib.get_vulnerabilities()), 12)
        self.assertEqual(len(lib.get_threats()), 8)
        impact_mapping = lib.get_impact_mapping()
        self.assertEqual(len(impact_mapping), 8)
        self.assertIn("urn:intuitem:risk:req_node:vendor-due-diligence:vendor_classification:q1:c1", impact_mapping)
        self.assertIn("urn:intuitem:risk:req_node:vendor-due-diligence:vendor_availability:q1:c1", impact_mapping)

    def test_global_urn_uniqueness(self):
        """Ensure all defined URNs across all object types are strictly unique."""
        all_urns = []
        for category, item_list in [
            ("threats", self.objects.get("threats", [])),
            ("vulnerabilities", self.objects.get("vulnerabilities", [])),
            ("reference_controls", self.objects.get("reference_controls", [])),
            ("risk_scenarios", self.objects.get("risk_scenarios", [])),
            ("risk_matrix", self.objects.get("risk_matrix", [])),
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
                self.assertEqual(depth, 1, f"Root node {urn} should have depth=1")
            else:
                self.assertIn(
                    parent_urn,
                    self.req_nodes,
                    f"Node {urn} has invalid parent_urn: {parent_urn}",
                )
                parent_depth = self.req_nodes[parent_urn].get("depth", 1)
                self.assertEqual(
                    depth,
                    parent_depth + 1,
                    f"Node {urn} depth ({depth}) must be parent depth + 1 ({parent_depth + 1})",
                )

    def test_requirement_nodes_foreign_keys(self):
        """Ensure requirement nodes only reference existing controls and vulnerabilities."""
        for urn, rn in self.req_nodes.items():
            for rc_urn in rn.get("reference_controls", []):
                self.assertIn(
                    rc_urn,
                    self.ref_ctrls,
                    f"Node {urn} references unknown control: {rc_urn}",
                )
            for v_urn in rn.get("vulnerabilities", []):
                self.assertIn(
                    v_urn,
                    self.vulns,
                    f"Node {urn} references unknown vulnerability: {v_urn}",
                )

    def test_questions_choices_and_scoring_logic(self):
        """Ensure questions, scoring, and compute_result booleans are valid."""
        for rn_urn, rn in self.req_nodes.items():
            questions = rn.get("questions", {})
            for q_urn, q_def in questions.items():
                choices = q_def.get("choices", [])
                self.assertGreater(len(choices), 0, f"Question {q_urn} has no choices")
                for choice in choices:
                    c_urn = choice.get("urn")
                    add_score = choice.get("add_score")
                    compute_result = choice.get("compute_result")

                    if add_score == 0:
                        self.assertFalse(
                            compute_result,
                            f"Choice {c_urn} has add_score=0 but compute_result is True",
                        )
                    if add_score and add_score > 0:
                        self.assertTrue(
                            compute_result,
                            f"Choice {c_urn} has add_score={add_score} but compute_result is False",
                        )

    def test_risk_scenarios_foreign_keys(self):
        """Ensure risk scenarios only reference existing threats, vulnerabilities, controls, and requirement nodes."""
        for s_urn, scenario in self.scenarios.items():
            for t_urn in scenario.get("threats", []):
                self.assertIn(
                    t_urn,
                    self.threats,
                    f"Scenario {s_urn} references unknown threat: {t_urn}",
                )
            for v_urn in scenario.get("vulnerabilities", []):
                self.assertIn(
                    v_urn,
                    self.vulns,
                    f"Scenario {s_urn} references unknown vulnerability: {v_urn}",
                )
            for rc_urn in scenario.get("reference_controls", []):
                self.assertIn(
                    rc_urn,
                    self.ref_ctrls,
                    f"Scenario {s_urn} references unknown reference_control: {rc_urn}",
                )
            lik_urn = scenario.get("likelihood")
            self.assertIn(
                lik_urn,
                self.req_nodes,
                f"Scenario {s_urn} likelihood {lik_urn} not in req_nodes",
            )
            self.assertTrue(
                self.req_nodes[lik_urn].get("assessable"),
                f"Scenario {s_urn} likelihood node must be assessable",
            )
            imp_urn = scenario.get("impact")
            self.assertIn(
                imp_urn,
                self.req_nodes,
                f"Scenario {s_urn} impact {imp_urn} not in req_nodes",
            )
            self.assertTrue(
                self.req_nodes[imp_urn].get("assessable"),
                f"Scenario {s_urn} impact node must be assessable",
            )

    def test_vulnerabilities_and_controls_cross_references(self):
        """Ensure cross-references between vulnerabilities, controls, and threats are consistent."""
        for v_urn, v_def in self.vulns.items():
            for t_urn in v_def.get("threats", []):
                self.assertIn(t_urn, self.threats)
            for rc_urn in v_def.get("reference_controls", []):
                self.assertIn(rc_urn, self.ref_ctrls)

        for rc_urn, rc_def in self.ref_ctrls.items():
            for t_urn in rc_def.get("threats", []):
                self.assertIn(t_urn, self.threats)

    def test_criticality_mapping_integrity(self):
        """Ensure criticality mapping choice URNs exist and levels are valid."""
        crit_map = self.yaml_data.get("criticality_mapping", {})
        all_choice_urns = set()
        for rn in self.req_nodes.values():
            for q in rn.get("questions", {}).values():
                for c in q.get("choices", []):
                    all_choice_urns.add(c.get("urn"))

        for dim, mappings in crit_map.items():
            for choice_urn, level in mappings.items():
                self.assertIn(choice_urn, all_choice_urns)
                self.assertIn(level, [0, 1, 2, 3, 4])

    def test_audit_configuration(self):
        """Ensure audit configuration specifies sum method and hidden score visibility for respondents."""
        audit_conf = self.yaml_data.get("audit", {})
        self.assertEqual(audit_conf.get("score_method"), "sum")
        score_vis = audit_conf.get("score_visibility")
        self.assertIsNotNone(score_vis)
        self.assertEqual(score_vis["score"].get("respondent"), "hidden")
        self.assertEqual(score_vis["status"].get("respondent"), "hidden")

    def test_splash_screens(self):
        """Ensure splash screens exist at the start and end of requirement nodes."""
        nodes = self.framework.get("requirement_nodes", [])
        first_node = nodes[0]
        self.assertEqual(first_node.get("ref_id"), "instructions_splash")
        self.assertEqual(first_node.get("display_mode"), "splash")
        self.assertFalse(first_node.get("assessable"))
        self.assertEqual(first_node.get("depth"), 1)

    def test_availability_configuration(self):
        """Ensure availability questions, criticality mapping, and risk scenario linkages are valid."""
        crit_map = self.yaml_data.get("criticality_mapping", {})
        self.assertIn("availability", crit_map)
        avail_map = crit_map["availability"]
        self.assertEqual(len(avail_map), 4)

        # Check PROF.02 requirement node
        avail_node_urn = "urn:intuitem:risk:req_node:vendor-due-diligence:vendor_availability"
        self.assertIn(avail_node_urn, self.req_nodes)
        avail_node = self.req_nodes[avail_node_urn]
        self.assertEqual(avail_node.get("ref_id"), "PROF.02")
        self.assertTrue(avail_node.get("assessable"))
        self.assertEqual(avail_node.get("parent_urn"), "urn:intuitem:risk:req_node:vendor-due-diligence:prof")

        # Check risk scenarios with availability impact
        svc_disrupt_urn = "urn:intuitem:risk:scenario:vendor-due-diligence:vendor_service_disruption"
        self.assertIn(svc_disrupt_urn, self.scenarios)
        self.assertEqual(self.scenarios[svc_disrupt_urn].get("impact"), avail_node_urn)

        exit_loss_urn = "urn:intuitem:risk:scenario:vendor-due-diligence:vendor_exit_data_loss"
        self.assertIn(exit_loss_urn, self.scenarios)
        self.assertEqual(self.scenarios[exit_loss_urn].get("impact"), avail_node_urn)

        # Check multi-question availability requirements (EXIT.01, BAK.05, BAK.06, INF.02)
        exit_01_urn = "urn:intuitem:risk:req_node:vendor-due-diligence:exit.01"
        self.assertEqual(len(self.req_nodes[exit_01_urn].get("questions", {})), 4)

        bak_05_urn = "urn:intuitem:risk:req_node:vendor-due-diligence:bak.05"
        self.assertEqual(len(self.req_nodes[bak_05_urn].get("questions", {})), 2)

        bak_06_urn = "urn:intuitem:risk:req_node:vendor-due-diligence:bak.06"
        self.assertEqual(len(self.req_nodes[bak_06_urn].get("questions", {})), 2)

        inf_02_urn = "urn:intuitem:risk:req_node:vendor-due-diligence:inf.02"
        self.assertEqual(len(self.req_nodes[inf_02_urn].get("questions", {})), 2)


if __name__ == "__main__":
    unittest.main()
