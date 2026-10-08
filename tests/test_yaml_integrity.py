"""Automated schema, foreign key, and logic integrity tests for GRC Framework YAML files.

This module provides a framework-independent test suite that validates the relational integrity,
foreign key consistency, scoring logic, and structural semantics of all GRC framework YAML definitions
registered in `FRAMEWORK_CATALOG`.
"""

import unittest
from pathlib import Path
from typing import Any
import yaml

from classes.core.framework import LibraryFile
from classes.examples_manager import FRAMEWORK_CATALOG


class TestYamlIntegrity(unittest.TestCase):
    """Framework-independent integrity tests for all GRC framework YAML definitions."""

    frameworks: list[dict[str, Any]] = []

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.frameworks = []
        base_dir = Path(__file__).resolve().parent.parent

        for entry in FRAMEWORK_CATALOG:
            yaml_rel = entry.get("yaml_path")
            if not yaml_rel:
                continue

            yaml_path = base_dir / yaml_rel
            if not yaml_path.exists():
                yaml_path = Path(yaml_rel)

            if not yaml_path.exists():
                continue

            with open(yaml_path, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)

            objects = yaml_data.get("objects", {})
            framework = objects.get("framework", {})

            cls.frameworks.append({
                "ref_id": entry.get("ref_id", ""),
                "name": entry.get("name", ""),
                "yaml_path": yaml_rel,
                "yaml_data": yaml_data,
                "objects": objects,
                "framework": framework,
                "threats": {t["urn"]: t for t in objects.get("threats", []) if "urn" in t},
                "vulns": {v["urn"]: v for v in objects.get("vulnerabilities", []) if "urn" in v},
                "ref_ctrls": {c["urn"]: c for c in objects.get("reference_controls", []) if "urn" in c},
                "scenarios": {s["urn"]: s for s in objects.get("risk_scenarios", []) if "urn" in s},
                "req_nodes": {rn["urn"]: rn for rn in framework.get("requirement_nodes", []) if "urn" in rn},
                "ig_defs_by_ref": {
                    ig["ref_id"]: ig
                    for ig in framework.get("implementation_groups_definition", [])
                    if "ref_id" in ig
                },
                "ig_defs_by_urn": {
                    ig["urn"]: ig
                    for ig in framework.get("implementation_groups_definition", [])
                    if "urn" in ig
                },
            })

    def setUp(self):
        super().setUp()
        self.assertTrue(len(self.frameworks) > 0, "No frameworks found in FRAMEWORK_CATALOG to test")

    def test_library_file_loading(self):
        """Ensure LibraryFile correctly parses each framework YAML and exposes risk objects."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                lib = LibraryFile(fw["yaml_path"])
                self.assertIsNotNone(lib.get_name())
                if fw["name"]:
                    self.assertEqual(lib.get_name(), fw["name"])

                self.assertEqual(len(lib.get_risk_scenarios()), len(fw["scenarios"]))
                self.assertEqual(len(lib.get_vulnerabilities()), len(fw["vulns"]))
                self.assertEqual(len(lib.get_threats()), len(fw["threats"]))

                impact_mapping = lib.get_impact_mapping()
                crit_map = fw["yaml_data"].get("criticality_mapping", {})
                if crit_map:
                    total_expected_mappings = sum(len(mappings) for mappings in crit_map.values())
                    self.assertEqual(len(impact_mapping), total_expected_mappings)
                    for choice_urn in impact_mapping:
                        self.assertTrue(
                            any(choice_urn in mappings for mappings in crit_map.values()),
                            f"Choice {choice_urn} from LibraryFile impact mapping not in criticality_mapping for {fw['ref_id']}",
                        )

    def test_global_urn_uniqueness(self):
        """Ensure all defined URNs across all object types are strictly unique within each framework."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                all_urns = []
                for category, item_list in [
                    ("threats", fw["objects"].get("threats", [])),
                    ("vulnerabilities", fw["objects"].get("vulnerabilities", [])),
                    ("reference_controls", fw["objects"].get("reference_controls", [])),
                    ("risk_scenarios", fw["objects"].get("risk_scenarios", [])),
                    ("risk_matrix", fw["objects"].get("risk_matrix", [])),
                    ("implementation_groups", fw["framework"].get("implementation_groups_definition", [])),
                    ("requirement_nodes", fw["framework"].get("requirement_nodes", [])),
                ]:
                    for item in item_list:
                        urn = item.get("urn")
                        if urn:
                            self.assertNotIn(
                                urn,
                                all_urns,
                                f"Duplicate URN found in {category} for framework {fw['ref_id']}: {urn}",
                            )
                            all_urns.append(urn)

    def test_requirement_nodes_hierarchy_and_depth(self):
        """Ensure parent_urn references exist and depth values accurately match hierarchy."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                req_nodes = fw["req_nodes"]
                for urn, rn in req_nodes.items():
                    parent_urn = rn.get("parent_urn")
                    depth = rn.get("depth")
                    if parent_urn is None:
                        self.assertEqual(depth, 1, f"Root requirement node {urn} should have depth=1 in {fw['ref_id']}")
                    else:
                        self.assertIn(
                            parent_urn,
                            req_nodes,
                            f"Requirement node {urn} has invalid parent_urn {parent_urn} in {fw['ref_id']}",
                        )
                        parent_depth = req_nodes[parent_urn].get("depth", 1)
                        self.assertEqual(
                            depth,
                            parent_depth + 1,
                            f"Requirement node {urn} depth ({depth}) must be parent depth + 1 ({parent_depth + 1}) in {fw['ref_id']}",
                        )

    def test_requirement_nodes_foreign_keys(self):
        """Ensure requirement nodes only reference existing controls, vulnerabilities, and implementation groups."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                ref_ctrls = fw["ref_ctrls"]
                vulns = fw["vulns"]
                ig_by_ref = fw["ig_defs_by_ref"]
                ig_by_urn = fw["ig_defs_by_urn"]

                for urn, rn in fw["req_nodes"].items():
                    for rc_urn in rn.get("reference_controls", []):
                        self.assertIn(
                            rc_urn,
                            ref_ctrls,
                            f"Requirement node {urn} references unknown reference_control {rc_urn} in {fw['ref_id']}",
                        )
                    for v_urn in rn.get("vulnerabilities", []):
                        self.assertIn(
                            v_urn,
                            vulns,
                            f"Requirement node {urn} references unknown vulnerability {v_urn} in {fw['ref_id']}",
                        )
                    for ig in rn.get("implementation_groups", []):
                        self.assertTrue(
                            ig in ig_by_ref or ig in ig_by_urn,
                            f"Requirement node {urn} references unknown implementation_group {ig} in {fw['ref_id']}",
                        )

    def test_questions_choices_and_scoring_logic(self):
        """Ensure scoring values (add_score), compute_result booleans, and choice implementation groups are valid."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                ig_by_ref = fw["ig_defs_by_ref"]
                ig_by_urn = fw["ig_defs_by_urn"]

                for rn_urn, rn in fw["req_nodes"].items():
                    questions = rn.get("questions", {})
                    for q_urn, q_def in questions.items():
                        choices = q_def.get("choices", [])
                        self.assertGreater(
                            len(choices), 0, f"Question {q_urn} in node {rn_urn} has no choices in {fw['ref_id']}"
                        )
                        for choice in choices:
                            c_urn = choice.get("urn")
                            add_score = choice.get("add_score")
                            compute_result = choice.get("compute_result")

                            if add_score == 0:
                                self.assertFalse(
                                    compute_result,
                                    f"Choice {c_urn} has add_score=0 but compute_result is True in {fw['ref_id']}",
                                )
                            if add_score and add_score > 0:
                                self.assertTrue(
                                    compute_result,
                                    f"Choice {c_urn} has add_score={add_score} but compute_result is False in {fw['ref_id']}",
                                )
                            for ig in choice.get("implementation_groups", []):
                                self.assertTrue(
                                    ig in ig_by_ref or ig in ig_by_urn,
                                    f"Choice {c_urn} references unknown implementation_group {ig} in {fw['ref_id']}",
                                )

    def test_risk_scenarios_foreign_keys(self):
        """Ensure risk scenarios only reference existing threats, vulnerabilities, controls, and assessable nodes."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                threats = fw["threats"]
                vulns = fw["vulns"]
                ref_ctrls = fw["ref_ctrls"]
                req_nodes = fw["req_nodes"]

                for s_urn, scenario in fw["scenarios"].items():
                    for t_urn in scenario.get("threats", []):
                        self.assertIn(
                            t_urn,
                            threats,
                            f"Risk scenario {s_urn} references unknown threat {t_urn} in {fw['ref_id']}",
                        )
                    for v_urn in scenario.get("vulnerabilities", []):
                        self.assertIn(
                            v_urn,
                            vulns,
                            f"Risk scenario {s_urn} references unknown vulnerability {v_urn} in {fw['ref_id']}",
                        )
                    for rc_urn in scenario.get("existing_reference_controls", []):
                        self.assertIn(
                            rc_urn,
                            ref_ctrls,
                            f"Risk scenario {s_urn} references unknown existing_reference_control {rc_urn} in {fw['ref_id']}",
                        )
                    for rc_urn in scenario.get("reference_controls", []):
                        self.assertIn(
                            rc_urn,
                            ref_ctrls,
                            f"Risk scenario {s_urn} references unknown reference_control {rc_urn} in {fw['ref_id']}",
                        )

                    lik_urn = scenario.get("likelihood")
                    if lik_urn:
                        self.assertIn(
                            lik_urn,
                            req_nodes,
                            f"Risk scenario {s_urn} likelihood reference {lik_urn} not in requirement nodes in {fw['ref_id']}",
                        )
                        self.assertTrue(
                            req_nodes[lik_urn].get("assessable"),
                            f"Risk scenario {s_urn} likelihood node {lik_urn} must be assessable in {fw['ref_id']}",
                        )

                    imp_urn = scenario.get("impact")
                    if imp_urn:
                        self.assertIn(
                            imp_urn,
                            req_nodes,
                            f"Risk scenario {s_urn} impact reference {imp_urn} not in requirement nodes in {fw['ref_id']}",
                        )
                        self.assertTrue(
                            req_nodes[imp_urn].get("assessable"),
                            f"Risk scenario {s_urn} impact node {imp_urn} must be assessable in {fw['ref_id']}",
                        )

    def test_vulnerabilities_and_controls_cross_references(self):
        """Ensure vulnerabilities and controls reference valid threats and controls."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                threats = fw["threats"]
                ref_ctrls = fw["ref_ctrls"]

                for v_urn, v_def in fw["vulns"].items():
                    for t_urn in v_def.get("threats", []):
                        self.assertIn(
                            t_urn,
                            threats,
                            f"Vulnerability {v_urn} references unknown threat {t_urn} in {fw['ref_id']}",
                        )
                    for rc_urn in v_def.get("reference_controls", []):
                        self.assertIn(
                            rc_urn,
                            ref_ctrls,
                            f"Vulnerability {v_urn} references unknown reference_control {rc_urn} in {fw['ref_id']}",
                        )

                for rc_urn, rc_def in ref_ctrls.items():
                    for t_urn in rc_def.get("threats", []):
                        self.assertIn(
                            t_urn,
                            threats,
                            f"Reference control {rc_urn} references unknown threat {t_urn} in {fw['ref_id']}",
                        )

    def test_criticality_mapping_integrity(self):
        """Ensure all choice URNs referenced in criticality_mapping exist in questions and levels are 0-4."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                crit_map = fw["yaml_data"].get("criticality_mapping", {})
                all_choice_urns = set()
                for rn in fw["req_nodes"].values():
                    for q in rn.get("questions", {}).values():
                        for c in q.get("choices", []):
                            all_choice_urns.add(c.get("urn"))

                for dim, mappings in crit_map.items():
                    for choice_urn, level in mappings.items():
                        self.assertIn(
                            choice_urn,
                            all_choice_urns,
                            f"Criticality mapping for {dim} references unknown choice URN {choice_urn} in {fw['ref_id']}",
                        )
                        self.assertIn(
                            level,
                            [0, 1, 2, 3, 4],
                            f"Criticality level for {choice_urn} must be 0-4, got: {level} in {fw['ref_id']}",
                        )

    def test_criticality_dimensions_and_scenarios(self):
        """Ensure active criticality dimensions map choices to assessable requirement nodes."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                crit_map = fw["yaml_data"].get("criticality_mapping", {})
                for dim, mappings in crit_map.items():
                    for choice_urn in mappings:
                        matching_node = any(
                            choice_urn in [c.get("urn") for c in q.get("choices", [])]
                            for rn in fw["req_nodes"].values()
                            if rn.get("assessable")
                            for q in rn.get("questions", {}).values()
                        )
                        self.assertTrue(
                            matching_node,
                            f"Choice {choice_urn} for dimension '{dim}' must belong to an assessable requirement node in {fw['ref_id']}",
                        )

    def test_audit_configuration(self):
        """Ensure audit score and status visibility are configured to be hidden for respondents."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                audit_conf = fw["yaml_data"].get("audit")
                if not audit_conf:
                    continue

                self.assertEqual(
                    audit_conf.get("score_method"),
                    "sum",
                    f"Score method must be 'sum' in {fw['ref_id']}",
                )
                score_vis = audit_conf.get("score_visibility") or audit_conf.get("field_visibility")
                self.assertIsNotNone(
                    score_vis,
                    f"Audit configuration must specify score_visibility in {fw['ref_id']}",
                )

                for field in ["score", "status"]:
                    self.assertIn(field, score_vis, f"Missing '{field}' visibility in {fw['ref_id']}")
                    self.assertEqual(
                        score_vis[field].get("respondent"),
                        "hidden",
                        f"Field '{field}' respondent visibility must be 'hidden' in {fw['ref_id']}",
                    )

                for opt in ["result", "extended_result"]:
                    if opt in score_vis:
                        self.assertEqual(
                            score_vis[opt].get("respondent"),
                            "hidden",
                            f"Field '{opt}' respondent visibility must be 'hidden' in {fw['ref_id']}",
                        )

    def test_splash_screens_configuration(self):
        """Ensure splash screens exist at beginning (instructions) and end (thank you) of requirement_nodes."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                nodes = fw["framework"].get("requirement_nodes", [])
                if not nodes:
                    continue

                self.assertGreaterEqual(
                    len(nodes), 2, f"requirement_nodes must contain at least 2 nodes in {fw['ref_id']}"
                )

                first_node = nodes[0]
                self.assertEqual(first_node.get("ref_id"), "instructions_splash")
                self.assertEqual(first_node.get("display_mode"), "splash")
                self.assertFalse(first_node.get("assessable"))
                self.assertEqual(first_node.get("depth"), 1)
                if fw["ig_defs_by_ref"]:
                    self.assertIn("info", first_node.get("implementation_groups", []))
                self.assertIn("how to", first_node.get("description", "").lower())

                last_node = nodes[-1]
                self.assertEqual(last_node.get("ref_id"), "thank_you_splash")
                self.assertEqual(last_node.get("display_mode"), "splash")
                self.assertFalse(last_node.get("assessable"))
                self.assertEqual(last_node.get("depth"), 1)
                if fw["ig_defs_by_ref"]:
                    self.assertIn("info", last_node.get("implementation_groups", []))
                self.assertIn("thank you", last_node.get("description", "").lower())

    def test_risk_matrix_grid_consistency(self):
        """Ensure risk matrix grid dimensions and integer cells are well-formed."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                risk_matrix_list = fw["objects"].get("risk_matrix", [])
                if not risk_matrix_list:
                    continue

                matrix = risk_matrix_list[0]
                grid = matrix.get("grid")
                self.assertIsInstance(grid, list, f"Risk matrix grid must be a list in {fw['ref_id']}")
                self.assertGreater(len(grid), 0, f"Risk matrix grid cannot be empty in {fw['ref_id']}")
                cols = len(grid[0])
                for r_idx, row in enumerate(grid):
                    self.assertEqual(
                        len(row), cols, f"Grid column count mismatch at row {r_idx} in {fw['ref_id']}"
                    )
                    for cell in row:
                        self.assertIsInstance(cell, int, f"Matrix cell must be an integer in {fw['ref_id']}")

    def test_embedded_metadata_consistency(self):
        """Ensure embedded test_metadata expectations match actual object counts if defined."""
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                meta = fw["yaml_data"].get("test_metadata")
                if not meta:
                    continue

                if "expected_risk_scenarios_count" in meta:
                    self.assertEqual(len(fw["scenarios"]), meta["expected_risk_scenarios_count"])
                if "expected_threats_count" in meta:
                    self.assertEqual(len(fw["threats"]), meta["expected_threats_count"])
                if "expected_vulnerabilities_count" in meta:
                    self.assertEqual(len(fw["vulns"]), meta["expected_vulnerabilities_count"])
                if "expected_reference_controls_count" in meta:
                    self.assertEqual(len(fw["ref_ctrls"]), meta["expected_reference_controls_count"])
                if "expected_requirement_nodes_count" in meta:
                    self.assertEqual(len(fw["req_nodes"]), meta["expected_requirement_nodes_count"])

    def test_recurrent_controls_and_task_specifications(self):
        """Validate recurrent controls and task specifications across frameworks.

        Ensures:
        - If is_recurrent is True or task definition exists, cadence and frequency are valid.
        - Supported cadences are in ('daily', 'weekly', 'biweekly', 'monthly', 'quarterly', 'biannually', 'annually', 'yearly').
        - Supported frequencies in task definitions are in ('DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY').
        - Interval is a positive integer >= 1.
        - Task names and descriptions are non-empty strings.
        """
        valid_cadences = {"daily", "weekly", "biweekly", "monthly", "quarterly", "biannually", "semiannually", "annually", "yearly"}
        valid_frequencies = {"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}

        total_recurrent = 0
        for fw in self.frameworks:
            with self.subTest(framework=fw["ref_id"]):
                for urn, ctrl in fw["ref_ctrls"].items():
                    is_rec = ctrl.get("is_recurrent", False)
                    task_spec = ctrl.get("task")
                    cadence = ctrl.get("cadence")

                    if is_rec or task_spec or cadence:
                        total_recurrent += 1
                        if cadence:
                            self.assertIn(
                                str(cadence).strip().lower(),
                                valid_cadences,
                                f"Invalid cadence {cadence!r} for control {urn} in {fw['ref_id']}",
                            )

                        if task_spec:
                            self.assertIsInstance(task_spec, dict, f"Task spec must be a dict for control {urn}")
                            if "name" in task_spec:
                                self.assertTrue(bool(str(task_spec["name"]).strip()), f"Task name cannot be empty for {urn}")
                            if "description" in task_spec:
                                self.assertTrue(bool(str(task_spec["description"]).strip()), f"Task description cannot be empty for {urn}")
                            if "frequency" in task_spec:
                                self.assertIn(
                                    str(task_spec["frequency"]).strip().upper(),
                                    valid_frequencies,
                                    f"Invalid task frequency in control {urn}",
                                )
                            if "interval" in task_spec:
                                self.assertGreaterEqual(
                                    int(task_spec["interval"]),
                                    1,
                                    f"Task interval must be >= 1 in control {urn}",
                                )

        self.assertGreater(total_recurrent, 0, "Expected at least one recurrent control across frameworks")

    def test_appsec_saas_contract_support(self):
        """Ensure AppSec framework comprehensively supports SaaS apps with contract-defined controls."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # 1. Check hosting question choices are In-house and SaaS
        hosting_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:hosting")
        self.assertIsNotNone(hosting_node)
        q1 = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:hosting:q1")
        self.assertIsNotNone(q1)
        choice_values = [c.get("value") for c in q1.get("choices", [])]
        self.assertEqual(choice_values, ["In-house", "SaaS"])

        # 2. Check questions do not contain redundant "Yes - Defined with a contract" choices
        yes_contract_choices = []
        for rn_urn, rn in appsec_fw["req_nodes"].items():
            for q_urn, q in rn.get("questions", {}).items():
                for c in q.get("choices", []):
                    if "Yes - Defined with a contract" in str(c.get("value", "")):
                        yes_contract_choices.append((q_urn, c.get("value")))

        self.assertEqual(len(yes_contract_choices), 0, f"Found unexpected 'Yes - Defined with a contract' choices: {yes_contract_choices}")

        # 3. Check reference controls evidence mentions SaaS / contracts
        ref_ctrls_with_contract_evidence = 0
        for ctrl in appsec_fw["ref_ctrls"].values():
            evidence = ctrl.get("typical_evidence", "")
            if "contract" in evidence.lower() or "saas" in evidence.lower():
                ref_ctrls_with_contract_evidence += 1

        self.assertEqual(ref_ctrls_with_contract_evidence, len(appsec_fw["ref_ctrls"]))

        # 4. Check Chapter 10 (SaaS Requirements) richness - Annexe Sécurité V1.5
        saas_chapter_children = [
            rn for rn in appsec_fw["req_nodes"].values()
            if rn.get("parent_urn") == "urn:intuitem:risk:req_node:appsec:saas_chapter"
        ]
        self.assertEqual(len(saas_chapter_children), 22, "Expected 22 assessable requirement nodes in Chapter 10")
        expected_saas_nodes = {
            "saas_contract_compliance",
            "saas_governance_and_policy",
            "saas_confidentiality_and_data_protection",
            "saas_security_awareness",
            "saas_iam",
            "saas_entitlements_and_privileges",
            "saas_logging_and_incidents",
            "saas_workstation_security",
            "saas_mobile_security",
            "saas_network_security",
            "saas_environment_isolation",
            "saas_secure_development",
            "saas_web_app_security",
            "saas_data_exchange_security",
            "saas_data_hosting_and_residency",
            "saas_physical_security",
            "saas_backup_and_business_continuity",
            "saas_secure_data_destruction",
            "saas_subcontractor_management",
            "saas_audit_and_compliance",
            "saas_pci_dss",
            "saas_non_conformity_remediation",
        }
        actual_saas_nodes = {rn.get("ref_id") for rn in saas_chapter_children}
        self.assertEqual(actual_saas_nodes, expected_saas_nodes)

        # 5. Check SaaS-specific reference controls and vulnerabilities
        expected_saas_controls = {
            "urn:intuitem:risk:control:appsec:saas_contract",
            "urn:intuitem:risk:control:appsec:saas_third_party_assurance",
            "urn:intuitem:risk:control:appsec:saas_tenant_isolation_and_residency",
            "urn:intuitem:risk:control:appsec:saas_cryptographic_sovereignty",
            "urn:intuitem:risk:control:appsec:saas_vendor_access_governance",
            "urn:intuitem:risk:control:appsec:saas_resilience_and_data_portability",
            "urn:intuitem:risk:control:appsec:saas_subprocessor_and_supply_chain",
            "urn:intuitem:risk:control:appsec:saas_telemetry_and_audit_export",
        }
        for ctrl_urn in expected_saas_controls:
            self.assertIn(ctrl_urn, appsec_fw["ref_ctrls"])

        expected_saas_vulns = {
            "urn:intuitem:risk:vulnerability:appsec:contractual_gap",
            "urn:intuitem:risk:vulnerability:appsec:unverified_saas_security",
            "urn:intuitem:risk:vulnerability:appsec:weak_tenant_isolation",
            "urn:intuitem:risk:vulnerability:appsec:uncontrolled_vendor_access",
        }
        for vuln_urn in expected_saas_vulns:
            self.assertIn(vuln_urn, appsec_fw["vulns"])

        # 6. Check saas_iam conditional branching: SSO bypasses password and MFA questions
        saas_iam_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_iam")
        self.assertIsNotNone(saas_iam_node, "saas_iam node missing in AppSec")
        iam_questions = saas_iam_node.get("questions", {})
        self.assertEqual(len(iam_questions), 4, "saas_iam should define 4 questions (q1: auth mode, q2: SSO/SCIM, q3: local passwords, q4: local MFA)")

        q1 = iam_questions.get("urn:intuitem:risk:req_node:appsec:saas_iam:q1")
        self.assertIsNotNone(q1)
        q1_choices = {c["urn"]: c for c in q1.get("choices", [])}
        sso_choice_urn = "urn:intuitem:risk:req_node:appsec:saas_iam:q1:c1"
        direct_choice_urn = "urn:intuitem:risk:req_node:appsec:saas_iam:q1:c2"
        self.assertIn(sso_choice_urn, q1_choices)
        self.assertIn(direct_choice_urn, q1_choices)
        self.assertEqual(q1_choices[sso_choice_urn]["add_score"], 50)
        self.assertEqual(q1_choices[direct_choice_urn]["add_score"], 0)

        # q2 depends on SSO choice
        q2 = iam_questions.get("urn:intuitem:risk:req_node:appsec:saas_iam:q2")
        self.assertIsNotNone(q2)
        self.assertEqual(q2.get("depends_on", {}).get("answers"), [sso_choice_urn])
        q2_yes = next(c for c in q2.get("choices", []) if c["value"] == "Yes")
        self.assertEqual(q2_yes["add_score"], 50)

        # q3 and q4 depend on direct authentication (passwords & MFA are irrelevant under SSO)
        q3 = iam_questions.get("urn:intuitem:risk:req_node:appsec:saas_iam:q3")
        self.assertIsNotNone(q3)
        self.assertEqual(q3.get("depends_on", {}).get("answers"), [direct_choice_urn])
        q3_yes = next(c for c in q3.get("choices", []) if c["value"] == "Yes")
        self.assertEqual(q3_yes["add_score"], 50)

        q4 = iam_questions.get("urn:intuitem:risk:req_node:appsec:saas_iam:q4")
        self.assertIsNotNone(q4)
        self.assertEqual(q4.get("depends_on", {}).get("answers"), [direct_choice_urn])
        q4_yes = next(c for c in q4.get("choices", []) if c["value"] == "Yes")
        self.assertEqual(q4_yes["add_score"], 50)

        # 7. Check access_control_and_rbac (baseline / on-premise / all apps) IGA (SailPoint) & recertifications
        rbac_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:access_control_and_rbac")
        self.assertIsNotNone(rbac_node, "access_control_and_rbac node missing in AppSec")
        rbac_questions = rbac_node.get("questions", {})
        self.assertEqual(len(rbac_questions), 3, "access_control_and_rbac should define 3 questions (RBAC, IGA/SailPoint, recertifications)")
        q1_rbac = rbac_questions.get("urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q1")
        q2_iga = rbac_questions.get("urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q2")
        q3_recert = rbac_questions.get("urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q3")
        self.assertIn("sailpoint", q2_iga.get("text", "").lower())
        self.assertIn("recertif", q3_recert.get("text", "").lower())
        self.assertEqual(next(c for c in q1_rbac["choices"] if c["value"] == "Yes")["add_score"], 50)
        self.assertEqual(next(c for c in q2_iga["choices"] if c["value"] == "Yes")["add_score"], 25)
        self.assertEqual(next(c for c in q3_recert["choices"] if c["value"] == "Yes")["add_score"], 25)

        # 8. Check saas_entitlements_and_privileges (SaaS) IGA (SailPoint) & recertifications
        saas_priv_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges")
        self.assertIsNotNone(saas_priv_node, "saas_entitlements_and_privileges node missing in AppSec")
        saas_priv_questions = saas_priv_node.get("questions", {})
        self.assertEqual(len(saas_priv_questions), 3, "saas_entitlements_and_privileges should define 3 questions (least privilege, IGA/SailPoint, recertifications)")
        q1_saas_priv = saas_priv_questions.get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q1")
        q2_saas_iga = saas_priv_questions.get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q2")
        q3_saas_recert = saas_priv_questions.get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q3")
        self.assertIn("sailpoint", q2_saas_iga.get("text", "").lower())
        self.assertIn("recertif", q3_saas_recert.get("text", "").lower())
        self.assertEqual(next(c for c in q1_saas_priv["choices"] if c["value"] == "Yes")["add_score"], 50)
        self.assertEqual(next(c for c in q2_saas_iga["choices"] if c["value"] == "Yes")["add_score"], 25)
        self.assertEqual(next(c for c in q3_saas_recert["choices"] if c["value"] == "Yes")["add_score"], 25)


if __name__ == "__main__":
    unittest.main()
