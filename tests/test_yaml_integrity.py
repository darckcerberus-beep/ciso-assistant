"""Automated schema, foreign key, and logic integrity tests for GRC Framework YAML files.

This module provides a framework-independent test suite that validates the relational integrity,
foreign key consistency, scoring logic, and structural semantics of all GRC framework YAML definitions
registered in `FRAMEWORK_CATALOG`.
"""

import unittest
from pathlib import Path
from typing import Any
import yaml

from classes import utils
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

            yaml_data = utils.load_yaml_file(yaml_path)

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

                version = lib.get_version()
                self.assertIsInstance(
                    version, int, f"Framework {fw['ref_id']} version must be an incremental integer"
                )
                self.assertGreaterEqual(version, 1, f"Framework {fw['ref_id']} version must be >= 1")

                impact_mapping = lib.get_impact_mapping()
                crit_map = fw["yaml_data"].get("criticality_mapping", {})
                if crit_map:
                    total_expected_mappings = sum(
                        len(mappings)
                        for k, mappings in crit_map.items()
                        if k in ("confidentiality", "integrity", "availability")
                    )
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
                        if "depends_on" in q_def:
                            dep = q_def["depends_on"]
                            dep_q = dep.get("question", "")
                            self.assertTrue(
                                dep_q.startswith(rn_urn),
                                f"Cross-node dependency forbidden (breaks CISO Assistant questionnaire forms): Question {q_urn} in node {rn_urn} depends on {dep_q} in {fw['ref_id']}",
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
                    if dim == "quantity_multiplier":
                        for choice_urn, mult in mappings.items():
                            self.assertIn(
                                choice_urn,
                                all_choice_urns,
                                f"Quantity multiplier mapping references unknown choice URN {choice_urn} in {fw['ref_id']}",
                            )
                            self.assertGreater(
                                mult,
                                0.0,
                                f"Quantity multiplier for {choice_urn} must be > 0 in {fw['ref_id']}",
                            )
                        continue
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
        """Ensure audit score, status, and applied controls visibility are configured to be hidden for respondents."""
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

                for field in ["score", "status", "applied_controls"]:
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

                # Ensure splash screens have display_mode == 'splash'
                splash_nodes = [n for n in nodes if n.get("display_mode") == "splash"]
                splash_ref_ids = [n.get("ref_id") for n in splash_nodes]
                expected_splash_ref_ids = (
                    ["instructions_splash", "baseline_splash", "thank_you_splash"]
                    if fw["ref_id"] in ("appsec", "appsec_manual")
                    else ["instructions_splash", "thank_you_splash"]
                )
                self.assertEqual(
                    splash_ref_ids,
                    expected_splash_ref_ids,
                    f"Unexpected splash screens in {fw['ref_id']}, found: {splash_ref_ids}",
                )

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

        # 1. Check hosting question choices distinguish Custom software, Bought software, and SaaS
        hosting_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:hosting")
        self.assertIsNotNone(hosting_node)
        q1 = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:hosting:q1")
        self.assertIsNotNone(q1)
        choice_values = [c.get("value") for c in q1.get("choices", [])]
        self.assertEqual(
            choice_values,
            [
                "Custom software created and deployed by my teams (In-house development)",
                "Bought software deployed by my teams (COTS / Vendor package)",
                "SaaS (Third-party software hosted and operated by a vendor)",
            ],
        )

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
        self.assertEqual(len(saas_chapter_children), 21, "Expected 21 assessable requirement nodes in Chapter 10")
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
            "saas_vulnerability_remediation_sla",
            "saas_data_hosting_and_residency",
            "saas_physical_security",
            "saas_backup_and_business_continuity",
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

        # 6. Check saas_iam: admin access to SaaS strictly enforces MFA
        saas_iam_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_iam")
        self.assertIsNotNone(saas_iam_node, "saas_iam node missing in AppSec")
        iam_questions = saas_iam_node.get("questions", {})
        self.assertEqual(len(iam_questions), 1, "saas_iam simplified to 1 question enforcing MFA for admin access")

        q1 = iam_questions.get("urn:intuitem:risk:req_node:appsec:saas_iam:q1")
        self.assertIsNotNone(q1)
        self.assertIn("mfa", q1.get("text", "").lower())
        q1_yes = next(c for c in q1.get("choices", []) if c["value"] == "Yes")
        self.assertEqual(q1_yes["add_score"], 100)

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

        # 8. Check saas_entitlements_and_privileges (SaaS) RBAC & recertifications
        saas_priv_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges")
        self.assertIsNotNone(saas_priv_node, "saas_entitlements_and_privileges node missing in AppSec")
        saas_priv_questions = saas_priv_node.get("questions", {})
        self.assertEqual(len(saas_priv_questions), 2, "saas_entitlements_and_privileges should define 2 questions (RBAC least privilege, recertifications)")
        q1_saas_priv = saas_priv_questions.get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q1")
        q2_saas_recert = saas_priv_questions.get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q2")
        self.assertIn("admin", q1_saas_priv.get("text", "").lower())
        self.assertIn("recertif", q2_saas_recert.get("text", "").lower())
        self.assertEqual(next(c for c in q1_saas_priv["choices"] if c["value"] == "Yes")["add_score"], 50)
        self.assertEqual(next(c for c in q2_saas_recert["choices"] if c["value"] == "Yes")["add_score"], 50)

    def test_appsec_network_exposure_and_conditional_branching(self):
        """Ensure AppSec exposure profiling assumes SaaS is always externally exposed, while self-hosted apps use network_exposure."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # 1. Validate hosting choice c3 (SaaS) activates saas_app and baseline (does not activate internet_facing)
        hosting_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:hosting")
        self.assertIsNotNone(hosting_node, "hosting node missing in AppSec")
        q1_hosting = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:hosting:q1")
        self.assertIsNotNone(q1_hosting)
        saas_choice = next(c for c in q1_hosting["choices"] if c["urn"] == "urn:intuitem:risk:req_node:appsec:hosting:q1:c3")
        self.assertEqual(saas_choice.get("select_implementation_groups", []), ["saas_app", "baseline"])
        self.assertNotIn("internet_facing", saas_choice.get("select_implementation_groups", []))

        # 2. Validate hosting question q2 (network exposure) is intra-node and depends on custom or cots hosting choices
        q2_hosting = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:hosting:q2")
        self.assertIsNotNone(q2_hosting, "hosting:q2 (network exposure) missing in AppSec hosting node")
        dep = q2_hosting.get("depends_on", {})
        self.assertEqual(dep.get("question"), "urn:intuitem:risk:req_node:appsec:hosting:q1")
        self.assertIn("urn:intuitem:risk:req_node:appsec:hosting:q1:c1", dep.get("answers", []))
        self.assertIn("urn:intuitem:risk:req_node:appsec:hosting:q1:c2", dep.get("answers", []))
        self.assertNotIn("urn:intuitem:risk:req_node:appsec:hosting:q1:c3", dep.get("answers", []))

        # Validate hosting question q3 (SaaS vendor ISO 27001 / SOC 2 certification) depends on SaaS hosting choice (c3)
        q3_hosting = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:hosting:q3")
        self.assertIsNotNone(q3_hosting, "hosting:q3 (SaaS vendor certification) missing in AppSec hosting node")
        dep_q3 = q3_hosting.get("depends_on", {})
        self.assertEqual(dep_q3.get("question"), "urn:intuitem:risk:req_node:appsec:hosting:q1")
        self.assertEqual(dep_q3.get("answers", []), ["urn:intuitem:risk:req_node:appsec:hosting:q1:c3"])
        q3_choices = {c["urn"]: c for c in q3_hosting.get("choices", [])}
        self.assertEqual(len(q3_choices), 2)
        cert_yes = q3_choices["urn:intuitem:risk:req_node:appsec:hosting:q3:c1"]
        cert_no = q3_choices["urn:intuitem:risk:req_node:appsec:hosting:q3:c2"]
        self.assertEqual(cert_yes["add_score"], 100)
        self.assertTrue(cert_yes["compute_result"])
        self.assertNotIn("select_implementation_groups", cert_yes)
        self.assertEqual(cert_no["add_score"], 100)
        self.assertTrue(cert_no["compute_result"])
        self.assertEqual(cert_no.get("select_implementation_groups"), ["saas_uncertified"])

        # network_exposure is no longer a standalone node
        self.assertNotIn("urn:intuitem:risk:req_node:appsec:network_exposure", appsec_fw["req_nodes"])

        q2_choices = {c["urn"]: c for c in q2_hosting.get("choices", [])}
        self.assertEqual(len(q2_choices), 2, "hosting:q2 should only have Internal and Internet-facing choices for self-hosted apps")
        internal_choice_urn = "urn:intuitem:risk:req_node:appsec:hosting:q2:c1"
        external_choice_urn = "urn:intuitem:risk:req_node:appsec:hosting:q2:c2"
        self.assertIn(internal_choice_urn, q2_choices)
        self.assertIn(external_choice_urn, q2_choices)

        # Both Internal and Internet-facing choices receive full 100 points
        self.assertEqual(q2_choices[internal_choice_urn]["add_score"], 100)
        self.assertTrue(q2_choices[internal_choice_urn]["compute_result"])
        self.assertEqual(q2_choices[external_choice_urn]["add_score"], 100)
        self.assertTrue(q2_choices[external_choice_urn]["compute_result"])
        self.assertIn("internet_facing", q2_choices[external_choice_urn].get("select_implementation_groups", []))

        # 2. Validate the 4 transferred requirements in Chapter 10 (contractualization part):
        # A. Cloudflare / WAF & anti-DDoS (saas_network_security)
        saas_net_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_network_security")
        self.assertIsNotNone(saas_net_node)
        q1_saas_net = saas_net_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_network_security:q1")
        self.assertIsNotNone(q1_saas_net)
        self.assertEqual(next(c for c in q1_saas_net["choices"] if c["value"] == "Yes")["add_score"], 100)
        self.assertIn("cloudflare", q1_saas_net.get("text", "").lower())
        for comp in ["aws", "cloud armor", "azure", "akamai"]:
            self.assertIn(comp, q1_saas_net.get("text", "").lower())

        # B. Testing security (saas_web_app_security & saas_audit_and_compliance)
        saas_web_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_web_app_security")
        self.assertIsNotNone(saas_web_node)
        q1_saas_web = saas_web_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_web_app_security:q1")
        self.assertIsNotNone(q1_saas_web)
        self.assertEqual(next(c for c in q1_saas_web["choices"] if c["value"] == "Yes")["add_score"], 100)
        self.assertIn("tls", q1_saas_web.get("text", "").lower())

        saas_sla_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_vulnerability_remediation_sla")
        self.assertIsNotNone(saas_sla_node)
        q1_saas_sla = saas_sla_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_vulnerability_remediation_sla:q1")
        self.assertIsNotNone(q1_saas_sla)
        self.assertIn("remediation", q1_saas_sla.get("text", "").lower())

        saas_audit_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance")
        self.assertIsNotNone(saas_audit_node)
        q1_saas_audit = saas_audit_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q1")
        self.assertIsNotNone(q1_saas_audit)
        self.assertEqual(next(c for c in q1_saas_audit["choices"] if c["value"] == "Yes")["add_score"], 50)
        self.assertIn("audit", q1_saas_audit.get("text", "").lower())
        q2_saas_pentest = saas_audit_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q2")
        self.assertIsNotNone(q2_saas_pentest)
        self.assertIn("penetration test", q2_saas_pentest.get("text", "").lower())

        # C. Admin accounts vs Client IGA (saas_entitlements_and_privileges & access_control_and_rbac)
        saas_priv_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges")
        self.assertIsNotNone(saas_priv_node)
        q1_priv = saas_priv_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q1")
        q2_recert = saas_priv_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q2")
        self.assertIsNotNone(q1_priv)
        self.assertIsNotNone(q2_recert)
        self.assertIn("admin", q1_priv.get("text", "").lower())
        self.assertIn("recertif", q2_recert.get("text", "").lower())
        # Client-side enterprise IGA (SailPoint) is verified under Chapter 2 for all apps
        rbac_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:access_control_and_rbac")
        self.assertIn("sailpoint", rbac_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q2", {}).get("text", "").lower())

        # D. Plugging SIEM / Security Monitoring (saas_logging_and_incidents & telemetry export)
        saas_log_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_logging_and_incidents")
        self.assertIsNotNone(saas_log_node)
        q1_log = saas_log_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_logging_and_incidents:q1")
        q2_log = saas_log_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_logging_and_incidents:q2")
        self.assertIsNotNone(q1_log)
        self.assertIsNotNone(q2_log)
        self.assertIn("monitoring", q1_log.get("text", "").lower())
        self.assertIn("48 hours", q2_log.get("text", "").lower())
        self.assertIn("urn:intuitem:risk:control:appsec:saas_telemetry_and_audit_export", saas_log_node.get("reference_controls", []))

        # 3. Verify no questions in AppSec use data classification or criticality to skip security questions
        # Criticality is reflected in the risk rating (Impact x Likelihood), not in questions
        for rn_urn, rn in appsec_fw["req_nodes"].items():
            if rn.get("ref_id") in ("data_classification", "info"):
                continue
            for q_urn, q_def in rn.get("questions", {}).items():
                self.assertNotIn(
                    "critical data",
                    q_def.get("text", "").lower(),
                    f"Question {q_urn} in {rn_urn} should not condition security controls on data criticality",
                )

    def test_appsec_iam_sso_and_credential_order(self):
        """Ensure IAM authentication is unified with SSO, Hybrid, and credential branch conditionality (mirroring saas_iam)."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # 1. In Chapter 2 (iam_chapter), authentication_and_mfa is the unified IAM requirement
        auth_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:authentication_and_mfa")
        self.assertIsNotNone(auth_node)
        auth_questions = list(auth_node.get("questions", {}).values())
        self.assertEqual(len(auth_questions), 3)

        # q1: auth mode (Exclusive SSO, Hybrid, Direct, M2M API)
        q1 = auth_questions[0]
        choices = q1.get("choices", [])
        self.assertEqual(len(choices), 4)
        self.assertIn("sso exclusively", choices[0].get("value", "").lower())
        self.assertEqual(choices[0].get("add_score"), 100)
        self.assertIn("hybrid", choices[1].get("value", "").lower())
        self.assertEqual(choices[1].get("add_score"), 40)
        self.assertIn("direct", choices[2].get("value", "").lower())
        self.assertEqual(choices[2].get("add_score"), 0)
        self.assertIn("machine-to-machine", choices[3].get("value", "").lower())
        self.assertEqual(choices[3].get("add_score"), 100)

        hybrid_choice_urn = choices[1].get("urn")
        direct_choice_urn = choices[2].get("urn")

        # q2: Local credential branch (password policy)
        q2 = auth_questions[1]
        self.assertIn("password", q2.get("text", "").lower())
        self.assertEqual(
            q2.get("depends_on", {}).get("answers"),
            [hybrid_choice_urn, direct_choice_urn],
        )
        self.assertEqual(q2.get("depends_on", {}).get("condition"), "any")
        self.assertEqual(q2.get("choices", [])[0].get("add_score"), 30)

        # q3: Local credential branch (MFA)
        q3 = auth_questions[2]
        self.assertIn("mfa", q3.get("text", "").lower())
        self.assertEqual(
            q3.get("depends_on", {}).get("answers"),
            [hybrid_choice_urn, direct_choice_urn],
        )
        self.assertEqual(q3.get("depends_on", {}).get("condition"), "any")
        self.assertEqual(q3.get("choices", [])[0].get("add_score"), 30)

        # 2. In Chapter 10 (saas_iam), verify admin access to SaaS strictly enforces MFA
        saas_iam_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_iam")
        self.assertIsNotNone(saas_iam_node)
        saas_questions = list(saas_iam_node.get("questions", {}).values())
        self.assertEqual(len(saas_questions), 1)
        self.assertIn("mfa", saas_questions[0].get("text", "").lower())
        self.assertEqual(saas_questions[0].get("choices", [])[0].get("add_score"), 100)

    def test_appsec_on_premise_iam_sso_conditional_authentication(self):
        """Ensure that in on-premise applications, SSO, Hybrid, and Direct branches score correctly."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        auth_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:authentication_and_mfa")
        self.assertIsNotNone(auth_node)
        q_dict = auth_node.get("questions", {})
        q1 = q_dict.get("urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1")
        q2 = q_dict.get("urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q2")
        q3 = q_dict.get("urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q3")
        self.assertIsNotNone(q1)
        self.assertIsNotNone(q2)
        self.assertIsNotNone(q3)

        # SSO branch max score: q1 (100) = 100
        sso_choice = q1["choices"][0]
        self.assertEqual(sso_choice["add_score"], 100)

        # Hybrid branch max score: q1 (40) + q2 (30) + q3 (30) = 100
        hybrid_choice = q1["choices"][1]
        q2_yes_choice = q2["choices"][0]
        q3_yes_choice = q3["choices"][0]
        self.assertEqual(hybrid_choice["add_score"] + q2_yes_choice["add_score"] + q3_yes_choice["add_score"], 100)

        # Direct branch max score: q1 (0) + q2 (30) + q3 (30) = 60 (caps at 60 / L2 because enterprise SSO is omitted)
        direct_choice = q1["choices"][2]
        self.assertEqual(direct_choice["add_score"] + q2_yes_choice["add_score"] + q3_yes_choice["add_score"], 60)

        # M2M API branch max score: q1 (100) = 100
        m2m_choice = q1["choices"][3]
        self.assertEqual(m2m_choice["add_score"], 100)

    def test_appsec_software_delivery_models_and_sdlc_scoping(self):
        """Verify clear distinction between SaaS, bought software, and custom software in AppSec framework using Implementation Groups."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # Incremental framework versioning: must be integer >= 5
        appsec_version = appsec_fw["yaml_data"].get("version")
        self.assertIsInstance(appsec_version, int)
        self.assertGreaterEqual(appsec_version, 5, "AppSec framework version must be incremented (>= 5)")

        # Verify API Gateway, WAF, Bot Protection & Rate Limiting requirement node
        api_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting")
        self.assertIsNotNone(api_node, "api_security_and_rate_limiting node missing in appsec")
        api_q1 = api_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting:q1")
        self.assertIsNotNone(api_q1, "q1 missing in api_security_and_rate_limiting")
        api_q1_text = api_q1.get("text", "")
        self.assertIn("WAF", api_q1_text)
        self.assertIn("Cloudflare", api_q1_text)
        self.assertIn("bot protection", api_q1_text.lower())
        api_q2 = api_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting:q2")
        self.assertIsNotNone(api_q2, "q2 missing in api_security_and_rate_limiting")
        api_q2_text = api_q2.get("text", "")
        self.assertIn("rate limiting", api_q2_text.lower())
        self.assertIn("throttling", api_q2_text.lower())

        # 1. Delivery & Hosting model discriminator in Chapter 1 (hosting:q1) selects implementation groups
        hosting_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:hosting")
        self.assertIsNotNone(hosting_node)
        q1 = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:hosting:q1")
        self.assertIsNotNone(q1)
        choices = q1.get("choices", [])
        self.assertEqual(len(choices), 3)

        custom_choice = next((c for c in choices if "custom software" in c.get("value", "").lower()), None)
        bought_choice = next((c for c in choices if "bought software" in c.get("value", "").lower()), None)
        saas_choice = next((c for c in choices if "saas" in c.get("value", "").lower()), None)

        self.assertIsNotNone(custom_choice, "Custom software choice missing in hosting:q1")
        self.assertIsNotNone(bought_choice, "Bought software (COTS) choice missing in hosting:q1")
        self.assertIsNotNone(saas_choice, "SaaS choice missing in hosting:q1")

        self.assertIn("custom_app", custom_choice.get("select_implementation_groups", []))
        self.assertIn("infra", custom_choice.get("select_implementation_groups", []))
        self.assertIn("baseline", custom_choice.get("select_implementation_groups", []))
        self.assertIn("cots_app", bought_choice.get("select_implementation_groups", []))
        self.assertIn("infra", bought_choice.get("select_implementation_groups", []))
        self.assertIn("baseline", bought_choice.get("select_implementation_groups", []))
        self.assertIn("saas_app", saas_choice.get("select_implementation_groups", []))
        self.assertNotIn("infra", saas_choice.get("select_implementation_groups", []))
        self.assertNotIn("internet_facing", saas_choice.get("select_implementation_groups", []))

        # 2. In Chapter 5 (sdlc_chapter), DevSecOps automation scopes custom_app to CI/CD and COTS/SaaS to vendor guidelines
        sdlc_chapter = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:sdlc_chapter")
        self.assertIsNotNone(sdlc_chapter)
        self.assertEqual(sdlc_chapter.get("implementation_groups", []), ["custom_app", "cots_app"])

        sdlc_reqs = ["automated_security_testing", "supply_chain_and_dependencies", "code_review_and_ci_cd_integrity"]
        for ref_id in sdlc_reqs:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Node {ref_id} missing in sdlc_chapter")
            self.assertEqual(
                node.get("implementation_groups"),
                ["custom_app"],
                f"SDLC node {ref_id} must be scoped strictly to custom_app implementation group",
            )

            questions = node.get("questions", {})
            self.assertGreater(len(questions), 0, f"Node {ref_id} has no questions (empty)")
            for q_urn, q_def in questions.items():
                choices = q_def.get("choices", [])
                self.assertGreater(len(choices), 0, f"Question {q_urn} in {ref_id} has no choices")
                if q_def.get("depends_on"):
                    dep_q = q_def["depends_on"].get("question", "")
                    self.assertTrue(
                        dep_q.startswith(node["urn"]),
                        f"Question {q_urn} in {ref_id} must not have cross-node depends_on",
                    )

        # Verify vendor secure development requirement is scoped to COTS only (SaaS is governed under Chapter 10)
        vendor_dev_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:vendor_secure_development")
        self.assertIsNotNone(vendor_dev_node)
        self.assertEqual(vendor_dev_node.get("implementation_groups", []), ["cots_app"])
        self.assertNotIn("saas_app", vendor_dev_node.get("implementation_groups", []))

        # 3. In Chapter 10 (saas_chapter), verify SaaS secure development and web app security requirements exist and use saas_uncertified
        saas_dev_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_secure_development")
        self.assertIsNotNone(saas_dev_node)
        self.assertIn("saas_uncertified", saas_dev_node.get("implementation_groups", []))
        saas_web_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_web_app_security")
        self.assertIsNotNone(saas_web_node)
        self.assertIn("saas_uncertified", saas_web_node.get("implementation_groups", []))

    def test_appsec_code_hygiene_and_hosting_defenses_scoping(self):
        """Verify session_management and Chapter 3 defenses use custom_app implementation groups and baseline nodes include cots_app."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        defenses_reqs = [
            "session_management",
            "owasp_top_10_defenses",
            "file_upload_security",
        ]

        for ref_id in defenses_reqs:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Node {ref_id} missing in appsec")
            self.assertEqual(
                node.get("implementation_groups"),
                ["custom_app"],
                f"Node {ref_id} must be scoped strictly to custom_app implementation group",
            )

            # Verify every requirement node has questions and choices (never renders empty in audits)
            questions = node.get("questions", {})
            self.assertGreater(len(questions), 0, f"Node {ref_id} has no questions (empty)")
            for q_urn, q_def in questions.items():
                choices = q_def.get("choices", [])
                self.assertGreater(len(choices), 0, f"Question {q_urn} in {ref_id} has no choices")
                if q_def.get("depends_on"):
                    dep_q = q_def["depends_on"].get("question", "")
                    self.assertTrue(
                        dep_q.startswith(node["urn"]),
                        f"Question {q_urn} in {ref_id} must not have cross-node depends_on",
                    )

        # Chapter 1 profiling requirements are scoped to info
        chapter1_reqs = [
            "instructions_splash",
            "info",
            "stakeholder_identification",
            "data_classification",
            "hosting",
        ]
        for ref_id in chapter1_reqs:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Chapter 1 profiling node {ref_id} missing in appsec")
            self.assertEqual(node.get("implementation_groups"), ["info"], f"{ref_id} must be scoped to ['info']")

        for ref_id in ["baseline_splash", "thank_you_splash"]:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Splash node {ref_id} missing in appsec")
            groups = node.get("implementation_groups", [])
            self.assertIn("info", groups, f"{ref_id} missing info group")
            self.assertIn("baseline", groups, f"{ref_id} missing baseline group")

        # Universal IAM requirements are grouped under the baseline track
        iam_ch = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:iam_chapter")
        self.assertIsNotNone(iam_ch)
        self.assertEqual(iam_ch.get("implementation_groups"), ["baseline", "custom_app"])

        for ref_id in ["authentication_and_mfa", "access_control_and_rbac"]:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Universal IAM node {ref_id} missing in appsec")
            self.assertEqual(node.get("implementation_groups"), ["baseline"], f"{ref_id} must be scoped to ['baseline']")

        # Self-hosted infrastructure requirements apply strictly to infra
        self_hosted_infra_reqs = [
            "secrets_management",
            "data_in_transit",
            "data_at_rest",
            "security_event_logging",
            "centralized_monitoring_and_alerting",
            "backup_and_disaster_recovery",
            "os_patching",
        ]
        for ref_id in self_hosted_infra_reqs:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Shared hosting node {ref_id} missing in appsec")
            self.assertEqual(node.get("implementation_groups"), ["infra"], f"{ref_id} must be scoped to ['infra']")

        # Verify os_patching exists in appsec, is scoped strictly to infra, and has 3 questions
        os_patch_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:os_patching")
        self.assertIsNotNone(os_patch_node, "os_patching node missing in appsec")
        self.assertEqual(os_patch_node.get("parent_urn"), "urn:intuitem:risk:req_node:appsec:resilience_chapter")
        self.assertEqual(os_patch_node.get("implementation_groups"), ["infra"])
        self.assertEqual(len(os_patch_node.get("questions", {})), 3, "os_patching must have 3 questions (q1, q2, q3)")
        self.assertIn("urn:intuitem:risk:scenario:appsec:os_and_host_unpatched_vulnerability", appsec_fw["scenarios"])

        # Verify sensitive data lifecycle requirements are scoped to self-hosted delivery models (custom_app, cots_app)
        # confidential_app and secret_app were removed to prevent duplicate questions for SaaS applications
        sensitive_data_reqs = [
            "non_prod_data",
            "data_destruction",
        ]
        for ref_id in sensitive_data_reqs:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Sensitive data node {ref_id} missing in appsec")
            groups = node.get("implementation_groups", [])
            self.assertNotIn("baseline", groups, f"{ref_id} must not include baseline group")
            self.assertIn("custom_app", groups, f"{ref_id} missing custom_app group")
            self.assertIn("cots_app", groups, f"{ref_id} missing cots_app group")
            self.assertNotIn("saas_app", groups, f"{ref_id} must not include saas_app group")
            self.assertNotIn("confidential_app", groups, f"{ref_id} must not include confidential_app group")
            self.assertNotIn("secret_app", groups, f"{ref_id} must not include secret_app group")

        # Verify data_exchange is scoped to self-hosted delivery models (custom_app, cots_app) and excludes saas_app and baseline
        de_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:data_exchange")
        self.assertIsNotNone(de_node, "data_exchange node missing in appsec")
        de_groups = de_node.get("implementation_groups", [])
        self.assertNotIn("baseline", de_groups)
        self.assertIn("custom_app", de_groups)
        self.assertIn("cots_app", de_groups)
        self.assertNotIn("saas_app", de_groups, "data_exchange must not include saas_app")

        # Verify internet-facing perimeter requirements are scoped to internet_facing
        perimeter_reqs = [
            "api_security_and_rate_limiting",
            "penetration_testing_and_vulnerability_management",
        ]
        for ref_id in perimeter_reqs:
            node = appsec_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec:{ref_id}")
            self.assertIsNotNone(node, f"Perimeter node {ref_id} missing in appsec")
            groups = node.get("implementation_groups", [])
            self.assertIn("internet_facing", groups, f"{ref_id} missing internet_facing group")
            self.assertNotIn("baseline", groups, f"{ref_id} must not include baseline group")
            self.assertNotIn("saas_app", groups, f"{ref_id} must not include saas_app group")

        manual_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec_manual"), None)
        if manual_fw:
            for ref_id in perimeter_reqs:
                node = manual_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec_manual:{ref_id}")
                self.assertIsNotNone(node, f"Perimeter node {ref_id} missing in appsec_manual")
                groups = node.get("implementation_groups", [])
                self.assertIn("internet_facing", groups, f"{ref_id} missing internet_facing group in appsec_manual")
                self.assertNotIn("baseline", groups, f"{ref_id} must not include baseline group in appsec_manual")
                self.assertNotIn("saas_app", groups, f"{ref_id} must not include saas_app group in appsec_manual")

        # Verify parent crypto_chapter is scoped to infra and excludes saas_app and baseline
        crypto_chapter = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:crypto_chapter")
        self.assertIsNotNone(crypto_chapter, "Chapter crypto_chapter missing in appsec")
        c_groups = crypto_chapter.get("implementation_groups", [])
        self.assertEqual(c_groups, ["infra"])
        self.assertNotIn("baseline", c_groups)
        self.assertNotIn("saas_app", c_groups, "Chapter crypto_chapter must not include saas_app group")

        # Verify parent data_lifecycle_chapter excludes saas_app and baseline (since all its requirements are self-hosted)
        dl_chapter = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:data_lifecycle_chapter")
        self.assertIsNotNone(dl_chapter, "Chapter data_lifecycle_chapter missing in appsec")
        dl_groups = dl_chapter.get("implementation_groups", [])
        self.assertIn("custom_app", dl_groups)
        self.assertIn("cots_app", dl_groups)
        self.assertNotIn("baseline", dl_groups)
        self.assertNotIn("saas_app", dl_groups, "Chapter data_lifecycle_chapter must not include saas_app group")

        # Verify confidential_app and secret_app are not present in framework implementation groups
        self.assertNotIn("confidential_app", appsec_fw["ig_defs_by_ref"], "confidential_app must be removed from AppSec implementation groups")
        self.assertNotIn("secret_app", appsec_fw["ig_defs_by_ref"], "secret_app must be removed from AppSec implementation groups")

    def test_appsec_data_protection_and_lifecycle_scoping(self):
        """Verify data protection scoping: unified non_prod_data in Ch 7, removal of duplicate saas_non_prod_data, and risk scenarios."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # 1. Unified non_prod_data node exists in Chapter 7 (Data Protection & Lifecycle)
        np_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:non_prod_data")
        self.assertIsNotNone(np_node, "non_prod_data missing in AppSec")
        self.assertEqual(np_node.get("parent_urn"), "urn:intuitem:risk:req_node:appsec:data_lifecycle_chapter")
        self.assertTrue(np_node.get("assessable"))
        self.assertEqual(np_node.get("implementation_groups"), ["custom_app", "cots_app"])

        # Redundant SaaS data security nodes must NOT exist in Chapter 10
        self.assertNotIn(
            "urn:intuitem:risk:req_node:appsec:saas_non_prod_data",
            appsec_fw["req_nodes"],
            "saas_non_prod_data must be removed to avoid duplicate non-prod questions",
        )
        self.assertNotIn(
            "urn:intuitem:risk:req_node:appsec:saas_data_exchange_security",
            appsec_fw["req_nodes"],
            "saas_data_exchange_security must be removed to avoid duplicate data exchange questions",
        )
        self.assertNotIn(
            "urn:intuitem:risk:req_node:appsec:saas_secure_data_destruction",
            appsec_fw["req_nodes"],
            "saas_secure_data_destruction must be removed to avoid duplicate data destruction questions",
        )

        # Check questions in non_prod_data
        np_questions = np_node.get("questions", {})
        self.assertEqual(len(np_questions), 3, "non_prod_data should have 3 questions (q1-q3)")
        q1 = np_questions.get("urn:intuitem:risk:req_node:appsec:non_prod_data:q1")
        q2 = np_questions.get("urn:intuitem:risk:req_node:appsec:non_prod_data:q2")
        q3 = np_questions.get("urn:intuitem:risk:req_node:appsec:non_prod_data:q3")
        self.assertIsNotNone(q1)
        self.assertIsNotNone(q2)
        self.assertIsNotNone(q3)

        q1_no = next(c for c in q1["choices"] if "No" in c["value"])
        q1_yes = next(c for c in q1["choices"] if "Yes" in c["value"])
        self.assertEqual(q1_no["add_score"], 100)
        self.assertEqual(q1_yes["add_score"], 0)

        # q2 and q3 depend on q1 == Yes
        self.assertEqual(q2.get("depends_on", {}).get("answers"), [q1_yes["urn"]])
        self.assertEqual(q3.get("depends_on", {}).get("answers"), [q1_yes["urn"]])

        # 2. Risk Scenario: nonprod_data_disclosure universally covers non-prod data leakage
        scenarios = {sc["ref_id"]: sc for sc in appsec_fw["yaml_data"].get("objects", {}).get("risk_scenarios", [])}
        self.assertIn("nonprod_data_disclosure", scenarios)
        sc = scenarios["nonprod_data_disclosure"]
        self.assertEqual(sc.get("likelihood"), "urn:intuitem:risk:req_node:appsec:non_prod_data")
        self.assertEqual(sc.get("impact"), "urn:intuitem:risk:req_node:appsec:data_classification")
        self.assertIn("urn:intuitem:risk:vulnerability:appsec:unprotected_non_prod", sc.get("vulnerabilities", []))
        self.assertIn("urn:intuitem:risk:control:appsec:protect_prod_data_in_non_prod", sc.get("reference_controls", []))

        # Redundant SaaS scenario must NOT exist
        self.assertNotIn("saas_nonprod_data_disclosure", scenarios)

        # 3. Data Exchange scoping: data_exchange is scoped to self-hosted apps; SaaS inherently exchanges data with provider
        de_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:data_exchange")
        self.assertIsNotNone(de_node, "data_exchange missing in AppSec")
        self.assertEqual(de_node.get("parent_urn"), "urn:intuitem:risk:req_node:appsec:data_lifecycle_chapter")
        self.assertEqual(de_node.get("implementation_groups"), ["custom_app", "cots_app"])

        # Self-hosted evaluates third_party_data_leakage via data_exchange and unencrypted_data_in_transit via data_in_transit
        self.assertIn("third_party_data_leakage", scenarios)
        self.assertEqual(scenarios["third_party_data_leakage"].get("likelihood"), "urn:intuitem:risk:req_node:appsec:data_exchange")
        self.assertIn("unencrypted_data_in_transit", scenarios)
        self.assertEqual(scenarios["unencrypted_data_in_transit"].get("likelihood"), "urn:intuitem:risk:req_node:appsec:data_in_transit")
        self.assertIn("saas_provider_data_leakage", scenarios)
        self.assertEqual(scenarios["saas_provider_data_leakage"].get("likelihood"), "urn:intuitem:risk:req_node:appsec:saas_contract_compliance")

    def test_appsec_penetration_testing_saas_contractual_management(self):
        """Verify that penetration testing is split between self-hosted and SaaS with contractual management."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # 1. Hosted node penetration_testing_and_vulnerability_management is scoped to internet-facing apps and excludes saas_app
        hosted_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:penetration_testing_and_vulnerability_management")
        self.assertIsNotNone(hosted_node)
        hosted_groups = hosted_node.get("implementation_groups", [])
        self.assertNotIn("saas_app", hosted_groups, "penetration_testing_and_vulnerability_management must not include saas_app")
        self.assertIn("internet_facing", hosted_groups)
        self.assertNotIn("baseline", hosted_groups)

        # Hosted q1 is simple Yes/No (100 points) covering independent pentest or bug bounty
        h_q1 = hosted_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:penetration_testing_and_vulnerability_management:q1")
        self.assertIsNotNone(h_q1)
        self.assertIn("bug bounty", h_q1.get("text", "").lower())
        h_q1_yes = next(c for c in h_q1.get("choices", []) if c.get("value") == "Yes")
        self.assertEqual(h_q1_yes.get("add_score"), 100)
        self.assertEqual(len(hosted_node.get("questions", {})), 1)

        # 2. Resilience chapter excludes saas_app
        resilience_chapter = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:resilience_chapter")
        self.assertIsNotNone(resilience_chapter)
        self.assertNotIn("saas_app", resilience_chapter.get("implementation_groups", []))

        # 3. SaaS node saas_audit_and_compliance is scoped to saas_app and merges audit rights (q1) and pentesting (q2)
        saas_audit_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance")
        self.assertIsNotNone(saas_audit_node, "saas_audit_and_compliance missing in AppSec")
        saas_audit_groups = saas_audit_node.get("implementation_groups", [])
        self.assertEqual(saas_audit_groups, ["saas_app"])

        q1 = saas_audit_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q1")
        self.assertIsNotNone(q1)
        q1_yes = next(c for c in q1.get("choices", []) if c.get("value") == "Yes")
        self.assertEqual(q1_yes.get("add_score"), 50)

        # 4. SaaS q2 includes the 3 contractual pentesting governance choices:
        # - allowed to pentest
        # - SaaS vendor does the pentest
        # - they refuse
        q2 = saas_audit_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q2")
        self.assertIsNotNone(q2)
        choices = q2.get("choices", [])
        self.assertEqual(len(choices), 3, "Expected 3 choices in SaaS pentest governance question")

        allowed_choice = next((c for c in choices if "allowed to pentest" in c.get("value", "").lower()), None)
        vendor_choice = next((c for c in choices if "vendor does the pentest" in c.get("value", "").lower()), None)
        refuse_choice = next((c for c in choices if "refuse" in c.get("value", "").lower()), None)

        self.assertIsNotNone(allowed_choice, "Choice 'allowed to pentest' missing")
        self.assertIsNotNone(vendor_choice, "Choice 'SaaS vendor does the pentest' missing")
        self.assertIsNotNone(refuse_choice, "Choice 'they refuse' missing")

        self.assertEqual(allowed_choice.get("add_score"), 50)
        self.assertTrue(allowed_choice.get("compute_result"))
        self.assertEqual(vendor_choice.get("add_score"), 50)
        self.assertTrue(vendor_choice.get("compute_result"))
        self.assertEqual(refuse_choice.get("add_score"), 0)
        self.assertFalse(refuse_choice.get("compute_result"))

        # 5. SaaS node saas_vulnerability_remediation_sla is scoped to saas_uncertified (100 points)
        saas_sla_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:saas_vulnerability_remediation_sla")
        self.assertIsNotNone(saas_sla_node, "saas_vulnerability_remediation_sla missing in AppSec")
        self.assertEqual(saas_sla_node.get("implementation_groups"), ["saas_uncertified"])
        sla_q1 = saas_sla_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec:saas_vulnerability_remediation_sla:q1")
        self.assertIsNotNone(sla_q1)
        sla_q1_yes = next(c for c in sla_q1.get("choices", []) if c.get("value") == "Yes")
        self.assertEqual(sla_q1_yes.get("add_score"), 100)

    def test_appsec_zero_orphaned_entities(self):
        """Verify that all reference controls and vulnerabilities in AppSec are mapped to risk scenarios (0 orphans)."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        ref_ctrls = appsec_fw["ref_ctrls"]
        vulns = appsec_fw["vulns"]
        scenarios = appsec_fw["scenarios"].values()

        used_controls = set()
        used_vulns = set()
        for sc in scenarios:
            for rc in sc.get("reference_controls", []):
                used_controls.add(rc)
            for rc in sc.get("existing_reference_controls", []):
                used_controls.add(rc)
            for v in sc.get("vulnerabilities", []):
                used_vulns.add(v)

        orphaned_controls = [c_urn for c_urn in ref_ctrls if c_urn not in used_controls]
        orphaned_vulns = [v_urn for v_urn in vulns if v_urn not in used_vulns]

        self.assertEqual(
            len(orphaned_controls), 0,
            f"Found orphaned reference controls in AppSec: {orphaned_controls}",
        )
        self.assertEqual(
            len(orphaned_vulns), 0,
            f"Found orphaned vulnerabilities in AppSec: {orphaned_vulns}",
        )

    def test_appsec_availability_criticality_mapping_and_scenarios(self):
        """Verify that risk evaluation focuses exclusively on confidentiality (data_classification)."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # Availability classification removed per maturity decision
        avail_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:availability_classification")
        self.assertIsNone(avail_node, "availability_classification must be removed to focus on confidentiality only")

        # All 44 risk scenarios route impact to data_classification
        scenarios = {s["ref_id"]: s for s in appsec_fw["scenarios"].values()}
        self.assertEqual(len(scenarios), 44)
        for sc_ref, sc in scenarios.items():
            self.assertEqual(
                sc.get("impact"),
                "urn:intuitem:risk:req_node:appsec:data_classification",
                f"Scenario {sc_ref} must evaluate impact against confidentiality (data_classification)",
            )

    def test_appsec_cots_hardening_track(self):
        """Verify COTS software deployment hardening requirements under cots_app implementation group."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        cots_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:cots_deployment_hardening")
        self.assertIsNotNone(cots_node, "cots_deployment_hardening node missing in AppSec")
        self.assertTrue(cots_node.get("assessable"))
        self.assertEqual(cots_node.get("implementation_groups"), ["cots_app"])
        questions = cots_node.get("questions", {})
        self.assertEqual(len(questions), 3)
        total_max_score = sum(max(c.get("add_score", 0) for c in q.get("choices", [])) for q in questions.values())
        self.assertEqual(total_max_score, 100)

    def test_appsec_integrity_criticality_mapping(self):
        """Verify that integrity profiling is removed and confidentiality mapping governs risk."""
        appsec_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec"), None)
        if not appsec_fw:
            return

        # Integrity classification removed per maturity decision
        integ_node = appsec_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec:integrity_classification")
        self.assertIsNone(integ_node, "integrity_classification must be removed to focus on confidentiality only")

        crit_map = appsec_fw["yaml_data"].get("criticality_mapping", {})
        conf_map = crit_map.get("confidentiality", {})
        self.assertEqual(len(conf_map), 12, "Expected 12 choices (q1 to q3) in confidentiality criticality mapping")
        self.assertEqual(set(conf_map.values()), {0, 1, 2, 3})

    def test_appsec_file_upload_controls(self):
        """Verify file upload security controls under custom_app implementation group with gating question."""
        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            if not fw:
                continue

            node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:file_upload_security")
            self.assertIsNotNone(node, f"file_upload_security node missing in {fw_ref}")
            self.assertTrue(node.get("assessable"))
            self.assertEqual(node.get("implementation_groups"), ["custom_app"])

            questions = node.get("questions", {})
            self.assertEqual(len(questions), 3, f"Expected 3 questions in file_upload_security in {fw_ref}")

            q1 = questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:file_upload_security:q1")
            q2 = questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:file_upload_security:q2")
            q3 = questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:file_upload_security:q3")
            self.assertIsNotNone(q1, f"q1 missing in {fw_ref}")
            self.assertIsNotNone(q2, f"q2 missing in {fw_ref}")
            self.assertIsNotNone(q3, f"q3 missing in {fw_ref}")

            # Gating question: "No" = 100 pts (not applicable / full compliance), "Yes" = 0 pts (triggers q2, q3)
            q1_no = q1["choices"][0]
            q1_yes = q1["choices"][1]
            self.assertEqual(q1_no.get("value"), "No")
            self.assertEqual(q1_no.get("add_score"), 100)
            self.assertTrue(q1_no.get("compute_result"))
            self.assertEqual(q1_yes.get("value"), "Yes")
            self.assertEqual(q1_yes.get("add_score"), 0)
            self.assertFalse(q1_yes.get("compute_result"))

            # Conditional checks: q2 and q3 depend on q1:c2 ("Yes")
            for q in [q2, q3]:
                dep = q.get("depends_on", {})
                self.assertEqual(dep.get("question"), f"urn:intuitem:risk:req_node:{fw_ref}:file_upload_security:q1")
                self.assertIn(f"urn:intuitem:risk:req_node:{fw_ref}:file_upload_security:q1:c2", dep.get("answers", []))

            # Branch max scores:
            # "No" branch = 100
            # "Yes" branch = 0 + 50 (q2: Yes) + 50 (q3: Yes) = 100
            q2_yes = q2["choices"][0]
            q3_yes = q3["choices"][0]
            self.assertEqual(q1_yes["add_score"] + q2_yes["add_score"] + q3_yes["add_score"], 100)

            for q_urn, q_def in questions.items():
                self.assertTrue(":q1" in q_urn or ":q2" in q_urn or ":q3" in q_urn, f"Question URN {q_urn} does not follow standard taxonomy")
                for choice in q_def.get("choices", []):
                    c_urn = choice.get("urn", "")
                    self.assertTrue(":c1" in c_urn or ":c2" in c_urn, f"Choice URN {c_urn} does not follow standard taxonomy")

    def test_appsec_manual_structure_and_scoping(self):
        """Ensure AppSec Manual variant has no triggered IGs and scopes Chapter 1 to info group."""
        manual_fw = next((fw for fw in self.frameworks if fw["ref_id"] == "appsec_manual"), None)
        self.assertIsNotNone(manual_fw, "appsec_manual framework not found in catalog")

        # 1. Implementation groups: info is default_selected, baseline is not
        ig_defs = manual_fw["ig_defs_by_ref"]
        self.assertIn("info", ig_defs)
        self.assertTrue(ig_defs["info"].get("default_selected", False))
        self.assertIn("baseline", ig_defs)
        self.assertFalse(ig_defs["baseline"].get("default_selected", False))
        self.assertIn("infra", ig_defs)
        self.assertFalse(ig_defs["infra"].get("default_selected", False))

        # 2. No choices have select_implementation_groups
        for n_urn, node in manual_fw["req_nodes"].items():
            for q_key, q in node.get("questions", {}).items():
                for c in q.get("choices", []):
                    self.assertNotIn(
                        "select_implementation_groups",
                        c,
                        f"Choice {c.get('urn')} in appsec_manual must not have select_implementation_groups",
                    )

        # 3. Chapter 1 profiling questions are scoped to info group
        chapter1_nodes = [
            "instructions_splash",
            "info",
            "stakeholder_identification",
            "data_classification",
            "hosting",
        ]
        for ref_id in chapter1_nodes:
            node = manual_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec_manual:{ref_id}")
            self.assertIsNotNone(node, f"Node {ref_id} missing in appsec_manual")
            self.assertEqual(
                node.get("implementation_groups"),
                ["info"],
                f"Node {ref_id} in appsec_manual must be scoped to ['info']",
            )

        # In appsec_manual, hosting node contains hosting model (q1), network exposure (q2), and SaaS certification (q3)
        hosting_node = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:hosting")
        self.assertIsNotNone(hosting_node, "Node hosting missing in appsec_manual")
        self.assertEqual(len(hosting_node.get("questions", {})), 3)
        q2_manual = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec_manual:hosting:q2")
        self.assertIsNotNone(q2_manual)
        dep_manual = q2_manual.get("depends_on", {})
        self.assertEqual(dep_manual.get("question"), "urn:intuitem:risk:req_node:appsec_manual:hosting:q1")
        self.assertIn("urn:intuitem:risk:req_node:appsec_manual:hosting:q1:c1", dep_manual.get("answers", []))
        self.assertIn("urn:intuitem:risk:req_node:appsec_manual:hosting:q1:c2", dep_manual.get("answers", []))
        self.assertNotIn("urn:intuitem:risk:req_node:appsec_manual:hosting:q1:c3", dep_manual.get("answers", []))

        q3_manual = hosting_node.get("questions", {}).get("urn:intuitem:risk:req_node:appsec_manual:hosting:q3")
        self.assertIsNotNone(q3_manual)
        dep_q3_manual = q3_manual.get("depends_on", {})
        self.assertEqual(dep_q3_manual.get("question"), "urn:intuitem:risk:req_node:appsec_manual:hosting:q1")
        self.assertEqual(dep_q3_manual.get("answers", []), ["urn:intuitem:risk:req_node:appsec_manual:hosting:q1:c3"])

        # network_exposure is no longer a standalone node
        self.assertNotIn("urn:intuitem:risk:req_node:appsec_manual:network_exposure", manual_fw["req_nodes"])

        # 4. Total requirement nodes (60) and scenarios (44)
        self.assertEqual(len(manual_fw["req_nodes"]), 60)
        self.assertEqual(len(manual_fw["scenarios"]), 44)
        self.assertEqual(len(manual_fw["threats"]), 9)
        self.assertEqual(len(manual_fw["vulns"]), 18)
        self.assertEqual(len(manual_fw["ref_ctrls"]), 26)

        # 5. Universal IAM nodes are grouped under the 'baseline' track
        for ref_id in ["authentication_and_mfa", "access_control_and_rbac"]:
            node = manual_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec_manual:{ref_id}")
            self.assertIsNotNone(node, f"Node {ref_id} missing in appsec_manual")
            self.assertEqual(
                node.get("implementation_groups"),
                ["baseline"],
                f"Node {ref_id} in appsec_manual must be scoped to ['baseline']",
            )

        # 6. COTS requirements & SaaS contractual vs "is effectively done" checks
        cots_hardening = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:cots_deployment_hardening")
        self.assertIsNotNone(cots_hardening, "cots_deployment_hardening missing in appsec_manual")
        self.assertEqual(cots_hardening.get("implementation_groups"), ["cots_app"])
        self.assertEqual(len(cots_hardening.get("questions", {})), 3)

        os_patching = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:os_patching")
        self.assertIsNotNone(os_patching, "os_patching missing in appsec_manual")
        self.assertEqual(os_patching.get("implementation_groups"), ["infra"])
        self.assertEqual(len(os_patching.get("questions", {})), 3)

        # 7. Infrastructure requirements are grouped under the 'infra' track
        infra_nodes = [
            "secrets_management",
            "data_in_transit",
            "data_at_rest",
            "security_event_logging",
            "centralized_monitoring_and_alerting",
            "backup_and_disaster_recovery",
            "os_patching",
        ]
        for ref_id in infra_nodes:
            node = manual_fw["req_nodes"].get(f"urn:intuitem:risk:req_node:appsec_manual:{ref_id}")
            self.assertIsNotNone(node, f"Node {ref_id} missing in appsec_manual")
            self.assertEqual(
                node.get("implementation_groups"),
                ["infra"],
                f"Node {ref_id} in appsec_manual must be scoped to ['infra']",
            )

        manual_de = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:data_exchange")
        self.assertIsNotNone(manual_de, "data_exchange missing in appsec_manual")
        self.assertEqual(manual_de.get("implementation_groups"), ["custom_app", "cots_app"])
        self.assertEqual(len(manual_de.get("questions", {})), 2)

        self.assertNotIn("urn:intuitem:risk:req_node:appsec_manual:saas_penetration_testing", manual_fw["req_nodes"])
        saas_audit = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:saas_audit_and_compliance")
        self.assertIsNotNone(saas_audit, "saas_audit_and_compliance missing in appsec_manual")
        self.assertEqual(saas_audit.get("implementation_groups"), ["saas_app"])
        self.assertEqual(len(saas_audit.get("questions", {})), 2)

        saas_sla = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:saas_vulnerability_remediation_sla")
        self.assertIsNotNone(saas_sla, "saas_vulnerability_remediation_sla missing in appsec_manual")
        self.assertEqual(saas_sla.get("implementation_groups"), ["saas_uncertified"])
        self.assertEqual(len(saas_sla.get("questions", {})), 1)

        saas_pci = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:saas_pci_dss")
        self.assertIsNotNone(saas_pci, "saas_pci_dss missing in appsec_manual")
        self.assertEqual(saas_pci.get("implementation_groups"), ["saas_app"])
        self.assertEqual(len(saas_pci.get("questions", {})), 3)

        hosted_pentest = manual_fw["req_nodes"].get("urn:intuitem:risk:req_node:appsec_manual:penetration_testing_and_vulnerability_management")
        self.assertIsNotNone(hosted_pentest, "penetration_testing_and_vulnerability_management missing in appsec_manual")
        self.assertEqual(hosted_pentest.get("implementation_groups"), ["internet_facing"])
        self.assertEqual(len(hosted_pentest.get("questions", {})), 1)
        q1_pentest = hosted_pentest.get("questions", {}).get("urn:intuitem:risk:req_node:appsec_manual:penetration_testing_and_vulnerability_management:q1")
        self.assertIsNotNone(q1_pentest)
        self.assertIn("bug bounty", q1_pentest.get("text", "").lower())
        q1_yes = next(c for c in q1_pentest.get("choices", []) if c.get("value") == "Yes")
        self.assertEqual(q1_yes.get("add_score"), 100)

    def test_appsec_saas_certification_and_uncertified_ig_scoping(self):
        """Verify ISO 27001 / SOC 2 certification question, saas_uncertified IG scoping, and SaaS PCI DSS certification question."""
        core_saas_nodes = {
            "saas_contract_compliance",
            "saas_confidentiality_and_data_protection",
            "saas_iam",
            "saas_data_hosting_and_residency",
            "saas_audit_and_compliance",
            "saas_pci_dss",
            "saas_non_conformity_remediation",
        }
        detailed_uncertified_common = {
            "saas_governance_and_policy",
            "saas_security_awareness",
            "saas_entitlements_and_privileges",
            "saas_logging_and_incidents",
            "saas_workstation_security",
            "saas_mobile_security",
            "saas_network_security",
            "saas_environment_isolation",
            "saas_secure_development",
            "saas_web_app_security",
            "saas_physical_security",
            "saas_backup_and_business_continuity",
            "saas_subcontractor_management",
        }

        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"{fw_ref} missing")

            # 1. Verify saas_uncertified implementation group exists
            self.assertIn("saas_uncertified", fw["ig_defs_by_ref"])
            self.assertFalse(fw["ig_defs_by_ref"]["saas_uncertified"].get("default_selected", False))

            # 2. Verify saas_chapter and thank_you_splash include saas_uncertified
            saas_ch = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_chapter")
            self.assertIsNotNone(saas_ch)
            self.assertEqual(saas_ch.get("implementation_groups"), ["saas_app", "saas_uncertified"])
            ty_splash = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:thank_you_splash")
            self.assertIn("saas_uncertified", ty_splash.get("implementation_groups", []))

            # 3. Verify Chapter 10 nodes partition between saas_app and saas_uncertified
            ch10_children = [
                rn for rn in fw["req_nodes"].values()
                if rn.get("parent_urn") == f"urn:intuitem:risk:req_node:{fw_ref}:saas_chapter"
            ]
            actual_core = {rn["ref_id"] for rn in ch10_children if rn.get("implementation_groups") == ["saas_app"]}
            actual_uncert = {rn["ref_id"] for rn in ch10_children if rn.get("implementation_groups") == ["saas_uncertified"]}
            self.assertEqual(actual_core, core_saas_nodes)
            expected_uncert = set(detailed_uncertified_common)
            expected_uncert.add("saas_vulnerability_remediation_sla")
            self.assertEqual(actual_uncert, expected_uncert)

            # 4. Verify saas_pci_dss has 3 questions: q1 (in-scope gating), q2 (vendor PCI DSS certified), q3 (contractual PCI DSS)
            pci_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_pci_dss")
            self.assertIsNotNone(pci_node)
            pci_qs = pci_node.get("questions", {})
            self.assertEqual(len(pci_qs), 3)
            q1 = pci_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_pci_dss:q1")
            q2 = pci_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_pci_dss:q2")
            q3 = pci_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_pci_dss:q3")
            self.assertIsNotNone(q1)
            self.assertIsNotNone(q2)
            self.assertIsNotNone(q3)
            self.assertIn("pci dss certified", q2.get("text", "").lower())
            self.assertIn("contract require", q3.get("text", "").lower())
            for q in (q2, q3):
                self.assertEqual(
                    q.get("depends_on", {}).get("answers"),
                    [f"urn:intuitem:risk:req_node:{fw_ref}:saas_pci_dss:q1:c2"],
                )
            self.assertEqual(q2["choices"][0]["add_score"] + q3["choices"][0]["add_score"], 100)

    def test_appsec_common_objects_externalization(self):
        """Verify that non-framework objects are externalized into appsec_objects.yml."""
        common_objects_path = Path("YML/appsec_objects.yml")
        self.assertTrue(common_objects_path.exists(), "YML/appsec_objects.yml does not exist")
        common_doc = utils.load_yaml_file(common_objects_path)
        self.assertEqual(common_doc.get("ref_id"), "appsec_objects")
        common_objs = common_doc.get("objects", {})
        for key in ["risk_matrix", "threats", "vulnerabilities", "reference_controls", "risk_scenarios"]:
            self.assertIn(key, common_objs, f"Missing {key} in common objects file")
            self.assertGreater(len(common_objs[key]), 0, f"Common objects {key} cannot be empty")

        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"{fw_ref} framework missing")
            # Verify raw YAML does NOT define non-framework objects directly under objects
            raw_path = Path(fw["yaml_path"])
            with open(raw_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)
            self.assertIn("common_objects_file", raw_data, f"{fw_ref} must declare common_objects_file")
            self.assertEqual(raw_data["common_objects_file"], "YML/appsec_objects.yml")
            self.assertEqual(list(raw_data.get("objects", {}).keys()), ["framework"], f"{fw_ref} raw objects should only contain framework")

            # Verify loaded objects contain all merged objects
            for key in ["risk_matrix", "threats", "vulnerabilities", "reference_controls", "risk_scenarios"]:
                self.assertIn(key, fw["objects"], f"{key} missing in merged objects of {fw_ref}")

    def test_appsec_intra_node_prerequisites(self):
        """Verify intra-node question prerequisite dependencies in appsec and appsec_manual."""
        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"{fw_ref} framework missing")

            # 1. cots_deployment_hardening: q3 depends on q2 == c1 (active vendor patches / not EOL)
            cots_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:cots_deployment_hardening")
            self.assertIsNotNone(cots_node, f"cots_deployment_hardening missing in {fw_ref}")
            cots_qs = cots_node.get("questions", {})
            q2_cots = cots_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:cots_deployment_hardening:q2")
            q3_cots = cots_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:cots_deployment_hardening:q3")
            self.assertIsNotNone(q2_cots, f"q2 missing in cots_deployment_hardening in {fw_ref}")
            self.assertIsNotNone(q3_cots, f"q3 missing in cots_deployment_hardening in {fw_ref}")

            dep_cots = q3_cots.get("depends_on")
            self.assertIsNotNone(dep_cots, f"q3 in cots_deployment_hardening must have depends_on in {fw_ref}")
            self.assertEqual(
                dep_cots.get("question"),
                f"urn:intuitem:risk:req_node:{fw_ref}:cots_deployment_hardening:q2",
                f"cots_deployment_hardening:q3 must depend on q2 in {fw_ref}",
            )
            self.assertEqual(
                dep_cots.get("answers"),
                [f"urn:intuitem:risk:req_node:{fw_ref}:cots_deployment_hardening:q2:c1"],
                f"cots_deployment_hardening:q3 must depend on choice c1 in {fw_ref}",
            )

            # 2. access_control_and_rbac: q3 depends on q1 == c1 (roles and permissions defined)
            rbac_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:access_control_and_rbac")
            self.assertIsNotNone(rbac_node, f"access_control_and_rbac missing in {fw_ref}")
            rbac_qs = rbac_node.get("questions", {})
            q1_rbac = rbac_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:access_control_and_rbac:q1")
            q3_rbac = rbac_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:access_control_and_rbac:q3")
            self.assertIsNotNone(q1_rbac, f"q1 missing in access_control_and_rbac in {fw_ref}")
            self.assertIsNotNone(q3_rbac, f"q3 missing in access_control_and_rbac in {fw_ref}")

            dep_rbac = q3_rbac.get("depends_on")
            self.assertIsNotNone(dep_rbac, f"q3 in access_control_and_rbac must have depends_on in {fw_ref}")
            self.assertEqual(
                dep_rbac.get("question"),
                f"urn:intuitem:risk:req_node:{fw_ref}:access_control_and_rbac:q1",
                f"access_control_and_rbac:q3 must depend on q1 in {fw_ref}",
            )
            self.assertEqual(
                dep_rbac.get("answers"),
                [f"urn:intuitem:risk:req_node:{fw_ref}:access_control_and_rbac:q1:c1"],
                f"access_control_and_rbac:q3 must depend on choice c1 in {fw_ref}",
            )

    def test_appsec_gdpr_profiling_and_saas_questions(self):
        """Verify GDPR data type and volume questions in info chapter and GDPR compliance question in saas_chapter."""
        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"{fw_ref} framework missing")

            # 1. Verify data_classification has 5 questions (q1: retail data category, q2: adverse impact, q3: aggregation scope, q4: GDPR category, q5: GDPR volume)
            data_class_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification")
            self.assertIsNotNone(data_class_node, f"data_classification missing in {fw_ref}")
            dc_questions = data_class_node.get("questions", {})
            self.assertEqual(len(dc_questions), 4, f"data_classification must have 4 questions in {fw_ref}")

            q1_dc = dc_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q1")
            q2_dc = dc_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q2")
            q3_dc = dc_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3")
            q4_dc = dc_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4")
            self.assertIsNotNone(q1_dc, f"q1 missing in data_classification in {fw_ref}")
            self.assertIsNotNone(q2_dc, f"q2 missing in data_classification in {fw_ref}")
            self.assertIsNotNone(q3_dc, f"q3 missing in data_classification in {fw_ref}")
            self.assertIsNotNone(q4_dc, f"q4 missing in data_classification in {fw_ref}")

            self.assertIn("category", q1_dc.get("text", "").lower())
            self.assertIn("impact", q2_dc.get("text", "").lower())
            self.assertIn("personal data", q3_dc.get("text", "").lower())
            self.assertIn("volume", q4_dc.get("text", "").lower())

            # Verify q3 choices: green (no personal data), yellow (contact data of employees), orange (contact and order details about customers), red (HR and financial details about employees and customer payment data)
            q3_choices = {c["urn"]: c for c in q3_dc.get("choices", [])}
            self.assertEqual(len(q3_choices), 4)
            c1_q3 = q3_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c1"]
            c2_q3 = q3_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c2"]
            c3_q3 = q3_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c3"]
            c4_q3 = q3_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c4"]

            self.assertEqual(c1_q3["value"], "No personal data")
            self.assertEqual(c1_q3["color"], "#33a745")
            self.assertEqual(c2_q3["value"], "Contact data of employees")
            self.assertEqual(c2_q3["color"], "#ffc107")
            self.assertEqual(c3_q3["value"], "Contact and order details about customers")
            self.assertEqual(c3_q3["color"], "#fd7e14")
            self.assertEqual(c4_q3["value"], "HR and financial details about employees and customer payment data")
            self.assertEqual(c4_q3["color"], "#dc3545")

            # Verify q4 choices have impact multipliers (Low: 1.0, Medium: 1.0, High: 1.5)
            q4_choices = {c["urn"]: c for c in q4_dc.get("choices", [])}
            self.assertEqual(len(q4_choices), 3)
            c1_q4 = q4_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4:c1"]
            c2_q4 = q4_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4:c2"]
            c3_q4 = q4_choices[f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4:c3"]
            self.assertEqual(c1_q4.get("multiplier"), 1.0)
            self.assertEqual(c2_q4.get("multiplier"), 1.0)
            self.assertEqual(c3_q4.get("multiplier"), 1.5)

            # Verify criticality_mapping has quantity_multiplier
            raw_fw = utils.load_yaml_file(f"YML/{fw_ref}.yml")
            crit_map = raw_fw.get("criticality_mapping", {})
            self.assertIn("quantity_multiplier", crit_map)
            qty_map = crit_map["quantity_multiplier"]
            self.assertEqual(qty_map.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4:c1"), 1.0)
            self.assertEqual(qty_map.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4:c2"), 1.0)
            self.assertEqual(qty_map.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q4:c3"), 1.5)

            # q4 depends on q3 being employees (c2), details about employees/customers (c3), or sensitive data (c4)
            dep_q4 = q4_dc.get("depends_on")
            self.assertIsNotNone(dep_q4, f"data_classification:q4 must depend on q3 in {fw_ref}")
            self.assertEqual(dep_q4.get("question"), f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3")
            self.assertEqual(
                sorted(dep_q4.get("answers", [])),
                sorted([
                    f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c2",
                    f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c3",
                    f"urn:intuitem:risk:req_node:{fw_ref}:data_classification:q3:c4",
                ]),
            )

            # 2. Verify saas_data_hosting_and_residency has 5 detailed GDPR questions (EU hosting, DPA Art 28, sub-processors, breach SLA, DSR assistance)
            saas_res_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_data_hosting_and_residency")
            self.assertIsNotNone(saas_res_node, f"saas_data_hosting_and_residency missing in {fw_ref}")
            saas_res_questions = saas_res_node.get("questions", {})
            self.assertEqual(len(saas_res_questions), 5, f"saas_data_hosting_and_residency must have 5 questions in {fw_ref}")

            q1_res = saas_res_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_data_hosting_and_residency:q1")
            q2_res = saas_res_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_data_hosting_and_residency:q2")
            q3_res = saas_res_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_data_hosting_and_residency:q3")
            q4_res = saas_res_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_data_hosting_and_residency:q4")
            q5_res = saas_res_questions.get(f"urn:intuitem:risk:req_node:{fw_ref}:saas_data_hosting_and_residency:q5")

            self.assertIsNotNone(q1_res, f"q1 missing in saas_data_hosting_and_residency in {fw_ref}")
            self.assertIsNotNone(q2_res, f"q2 missing in saas_data_hosting_and_residency in {fw_ref}")
            self.assertIsNotNone(q3_res, f"q3 missing in saas_data_hosting_and_residency in {fw_ref}")
            self.assertIsNotNone(q4_res, f"q4 missing in saas_data_hosting_and_residency in {fw_ref}")
            self.assertIsNotNone(q5_res, f"q5 missing in saas_data_hosting_and_residency in {fw_ref}")

            self.assertIn("european union", q1_res.get("text", "").lower())
            self.assertIn("article 28", q2_res.get("text", "").lower())
            self.assertIn("sub-processor", q3_res.get("text", "").lower())
            self.assertIn("breach", q4_res.get("text", "").lower())
            self.assertIn("data subject rights", q5_res.get("text", "").lower())

            # Scoring: 20 pts each for Yes (total 100 pts), 0 for No
            for idx, q_res in enumerate([q1_res, q2_res, q3_res, q4_res, q5_res], 1):
                q_yes = next(c for c in q_res["choices"] if c["value"] == "Yes")
                q_no = next(c for c in q_res["choices"] if c["value"] == "No")
                self.assertEqual(q_yes.get("add_score"), 20, f"q{idx} Yes must award 20 pts")
                self.assertTrue(q_yes.get("compute_result"))
                self.assertEqual(q_no.get("add_score"), 0, f"q{idx} No must award 0 pts")
                self.assertFalse(q_no.get("compute_result"))

    def test_appsec_phase1_scoring_and_standardized_choices(self):
        """Verify Phase 1 improvements: non_prod_data rebalanced, stakeholder_identification weights,
        data_destruction Yes/No choice ordering, and security_event_logging:q2 rephrasing."""
        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"{fw_ref} framework missing")

            # 1. stakeholder_identification scoring weights (30, 30, 25, 15)
            sh_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:stakeholder_identification")
            self.assertIsNotNone(sh_node, f"stakeholder_identification missing in {fw_ref}")
            sh_qs = sh_node.get("questions", {})
            self.assertEqual(len(sh_qs), 4, f"stakeholder_identification must have 4 questions in {fw_ref}")

            expected_weights = {
                f"urn:intuitem:risk:req_node:{fw_ref}:stakeholder_identification:q1": 30,
                f"urn:intuitem:risk:req_node:{fw_ref}:stakeholder_identification:q2": 30,
                f"urn:intuitem:risk:req_node:{fw_ref}:stakeholder_identification:q3": 25,
                f"urn:intuitem:risk:req_node:{fw_ref}:stakeholder_identification:q4": 15,
            }
            total_sh = 0
            for q_urn, exp_score in expected_weights.items():
                q = sh_qs.get(q_urn)
                self.assertIsNotNone(q, f"{q_urn} missing in {fw_ref}")
                yes_choice = next(c for c in q["choices"] if c["value"] == "Yes")
                self.assertEqual(yes_choice["add_score"], exp_score, f"{q_urn} score mismatch in {fw_ref}")
                total_sh += yes_choice["add_score"]
            self.assertEqual(total_sh, 100, f"stakeholder_identification total score must equal 100 in {fw_ref}")

            # 2. non_prod_data: q2 protective choices award 60, q3 Yes awards 40, c1 is Yes, c2 is No
            np_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:non_prod_data")
            self.assertIsNotNone(np_node, f"non_prod_data missing in {fw_ref}")
            np_qs = np_node.get("questions", {})
            q2_np = np_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:non_prod_data:q2")
            q3_np = np_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:non_prod_data:q3")
            self.assertIsNotNone(q2_np, f"non_prod_data:q2 missing in {fw_ref}")
            self.assertIsNotNone(q3_np, f"non_prod_data:q3 missing in {fw_ref}")

            # q2 protective choices (c2-c5: Hashing, Pseudonymisation, Encryption, Masking) award 60
            for choice in q2_np["choices"][1:]:
                self.assertEqual(choice["add_score"], 60, f"non_prod_data:q2 {choice['value']} must award 60 pts")
                self.assertTrue(choice["compute_result"])
            self.assertEqual(q2_np["choices"][0]["add_score"], 0)

            # q3 choice order: c1=Yes (40), c2=No (0)
            self.assertEqual(q3_np["choices"][0]["value"], "Yes")
            self.assertEqual(q3_np["choices"][0]["add_score"], 40)
            self.assertTrue(q3_np["choices"][0]["compute_result"])
            self.assertEqual(q3_np["choices"][1]["value"], "No")
            self.assertEqual(q3_np["choices"][1]["add_score"], 0)
            self.assertFalse(q3_np["choices"][1]["compute_result"])

            # 3. data_destruction: c1=Yes (50), c2=No (0), q2 depends on q1:c1
            dd_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:data_destruction")
            self.assertIsNotNone(dd_node, f"data_destruction missing in {fw_ref}")
            dd_qs = dd_node.get("questions", {})
            q1_dd = dd_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_destruction:q1")
            q2_dd = dd_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:data_destruction:q2")
            self.assertIsNotNone(q1_dd, f"data_destruction:q1 missing in {fw_ref}")
            self.assertIsNotNone(q2_dd, f"data_destruction:q2 missing in {fw_ref}")

            self.assertEqual(q1_dd["choices"][0]["value"], "Yes")
            self.assertEqual(q1_dd["choices"][0]["add_score"], 50)
            self.assertTrue(q1_dd["choices"][0]["compute_result"])
            self.assertEqual(q1_dd["choices"][1]["value"], "No")
            self.assertEqual(q1_dd["choices"][1]["add_score"], 0)
            self.assertFalse(q1_dd["choices"][1]["compute_result"])

            self.assertEqual(q2_dd["choices"][0]["value"], "Yes")
            self.assertEqual(q2_dd["choices"][0]["add_score"], 50)
            self.assertTrue(q2_dd["choices"][0]["compute_result"])
            self.assertEqual(q2_dd["choices"][1]["value"], "No")
            self.assertEqual(q2_dd["choices"][1]["add_score"], 0)
            self.assertFalse(q2_dd["choices"][1]["compute_result"])

            dep_dd = q2_dd.get("depends_on", {})
            self.assertEqual(
                dep_dd.get("answers"),
                [f"urn:intuitem:risk:req_node:{fw_ref}:data_destruction:q1:c1"],
                f"data_destruction:q2 must depend on choice c1 in {fw_ref}",
            )

            # 4. security_event_logging:q2 wording covers application, diagnostic, and error logs
            sel_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:security_event_logging")
            self.assertIsNotNone(sel_node, f"security_event_logging missing in {fw_ref}")
            sel_qs = sel_node.get("questions", {})
            q2_sel = sel_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:security_event_logging:q2")
            self.assertIsNotNone(q2_sel, f"security_event_logging:q2 missing in {fw_ref}")
            self.assertIn("diagnostic", q2_sel.get("text", "").lower())
            self.assertIn("error log", q2_sel.get("text", "").lower())

    def test_appsec_phase2_architecture_and_split_nodes(self):
        """Verify Phase 2 improvements: Hybrid Auth (4 choices, 40+30+30=100), stateless token session management,
        and 50+50 splits across backup_and_disaster_recovery, owasp_top_10_defenses, code_review_and_ci_cd_integrity,
        and api_security_and_rate_limiting."""
        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"{fw_ref} framework missing")

            # 1. authentication_and_mfa: 4 choices in q1, q2 and q3 depend on [c2, c3]
            auth_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:authentication_and_mfa")
            self.assertIsNotNone(auth_node, f"authentication_and_mfa missing in {fw_ref}")
            auth_qs = auth_node.get("questions", {})
            q1 = auth_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:authentication_and_mfa:q1")
            q2 = auth_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:authentication_and_mfa:q2")
            q3 = auth_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:authentication_and_mfa:q3")
            self.assertIsNotNone(q1)
            self.assertIsNotNone(q2)
            self.assertIsNotNone(q3)

            choices = q1.get("choices", [])
            self.assertEqual(len(choices), 4)
            self.assertIn("sso exclusively", choices[0]["value"].lower())
            self.assertEqual(choices[0]["add_score"], 100)
            self.assertIn("hybrid", choices[1]["value"].lower())
            self.assertEqual(choices[1]["add_score"], 40)
            self.assertIn("direct", choices[2]["value"].lower())
            self.assertEqual(choices[2]["add_score"], 0)
            self.assertIn("machine-to-machine", choices[3]["value"].lower())
            self.assertEqual(choices[3]["add_score"], 100)

            dep_answers = [choices[1]["urn"], choices[2]["urn"]]
            self.assertEqual(q2.get("depends_on", {}).get("answers"), dep_answers)
            self.assertEqual(q2.get("depends_on", {}).get("condition"), "any")
            self.assertEqual(q2["choices"][0]["add_score"], 30)

            self.assertEqual(q3.get("depends_on", {}).get("answers"), dep_answers)
            self.assertEqual(q3.get("depends_on", {}).get("condition"), "any")
            self.assertEqual(q3["choices"][0]["add_score"], 30)

            # 2. session_management: 1 question covering session identifiers and API bearer tokens
            sm_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:session_management")
            self.assertIsNotNone(sm_node, f"session_management missing in {fw_ref}")
            sm_qs = sm_node.get("questions", {})
            self.assertEqual(len(sm_qs), 1)
            sm_q1 = sm_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:session_management:q1")
            self.assertIsNotNone(sm_q1)
            self.assertIn("bearer token", sm_q1.get("text", "").lower())
            self.assertEqual(sm_q1["choices"][0]["add_score"], 100)

            # 3. backup_and_disaster_recovery: 2 questions (50 + 50 pts, q2 depends on q1:c1)
            bdr_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:backup_and_disaster_recovery")
            self.assertIsNotNone(bdr_node, f"backup_and_disaster_recovery missing in {fw_ref}")
            bdr_qs = bdr_node.get("questions", {})
            self.assertEqual(len(bdr_qs), 2, f"backup_and_disaster_recovery must have 2 questions in {fw_ref}")
            bdr_q1 = bdr_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:backup_and_disaster_recovery:q1")
            bdr_q2 = bdr_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:backup_and_disaster_recovery:q2")
            self.assertIsNotNone(bdr_q1)
            self.assertIsNotNone(bdr_q2)
            self.assertEqual(bdr_q1["choices"][0]["add_score"], 50)
            self.assertEqual(bdr_q2["choices"][0]["add_score"], 50)
            self.assertEqual(
                bdr_q2.get("depends_on", {}).get("answers"),
                [f"urn:intuitem:risk:req_node:{fw_ref}:backup_and_disaster_recovery:q1:c1"],
            )

            # 4. owasp_top_10_defenses: 2 questions (50 + 50 pts)
            owasp_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:owasp_top_10_defenses")
            self.assertIsNotNone(owasp_node, f"owasp_top_10_defenses missing in {fw_ref}")
            owasp_qs = owasp_node.get("questions", {})
            self.assertEqual(len(owasp_qs), 2, f"owasp_top_10_defenses must have 2 questions in {fw_ref}")
            owasp_q1 = owasp_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:owasp_top_10_defenses:q1")
            owasp_q2 = owasp_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:owasp_top_10_defenses:q2")
            self.assertIsNotNone(owasp_q1)
            self.assertIsNotNone(owasp_q2)
            self.assertEqual(owasp_q1["choices"][0]["add_score"], 50)
            self.assertEqual(owasp_q2["choices"][0]["add_score"], 50)

            # 5. code_review_and_ci_cd_integrity: 2 questions (50 + 50 pts)
            cr_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:code_review_and_ci_cd_integrity")
            self.assertIsNotNone(cr_node, f"code_review_and_ci_cd_integrity missing in {fw_ref}")
            cr_qs = cr_node.get("questions", {})
            self.assertEqual(len(cr_qs), 2, f"code_review_and_ci_cd_integrity must have 2 questions in {fw_ref}")
            cr_q1 = cr_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:code_review_and_ci_cd_integrity:q1")
            cr_q2 = cr_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:code_review_and_ci_cd_integrity:q2")
            self.assertIsNotNone(cr_q1)
            self.assertIsNotNone(cr_q2)
            self.assertEqual(cr_q1["choices"][0]["add_score"], 50)
            self.assertEqual(cr_q2["choices"][0]["add_score"], 50)

            # 6. api_security_and_rate_limiting: 2 questions (50 + 50 pts)
            api_node = fw["req_nodes"].get(f"urn:intuitem:risk:req_node:{fw_ref}:api_security_and_rate_limiting")
            self.assertIsNotNone(api_node, f"api_security_and_rate_limiting missing in {fw_ref}")
            api_qs = api_node.get("questions", {})
            self.assertEqual(len(api_qs), 2, f"api_security_and_rate_limiting must have 2 questions in {fw_ref}")
            api_q1 = api_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:api_security_and_rate_limiting:q1")
            api_q2 = api_qs.get(f"urn:intuitem:risk:req_node:{fw_ref}:api_security_and_rate_limiting:q2")
            self.assertIsNotNone(api_q1)
            self.assertIsNotNone(api_q2)
            self.assertEqual(api_q1["choices"][0]["add_score"], 50)
            self.assertEqual(api_q2["choices"][0]["add_score"], 50)

    def test_appsec_phase3_unlinked_requirements_risk_scenario_coverage(self):
        """Verify that Phase 3 Point 2 connects all assessable security requirements to risk scenarios.

        Asserts:
        - Exactly 44 risk scenarios exist in both AppSec and AppSec Manual.
        - Zero assessable security requirement nodes are unlinked (every assessable security node
          is mapped to at least one scenario via 'likelihood').
        - All 44 scenarios have valid likelihood and impact foreign keys.
        """
        for fw_ref in ["appsec", "appsec_manual"]:
            fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
            self.assertIsNotNone(fw, f"Framework {fw_ref} missing")

            scenarios = fw["scenarios"]
            self.assertEqual(len(scenarios), 44, f"Framework {fw_ref} must have 44 risk scenarios")

            # Collect all likelihood target nodes
            linked_req_urns = {s.get("likelihood") for s in scenarios.values() if s.get("likelihood")}
            linked_req_refs = {urn.split(":")[-1] for urn in linked_req_urns if urn}

            # Assessable nodes excluding profiling nodes (data_classification, hosting, application_description)
            req_nodes = fw["req_nodes"]
            assessable_sec_nodes = {
                ref_id: rn for urn, rn in req_nodes.items()
                if rn.get("assessable") and (ref_id := rn.get("ref_id")) not in ("data_classification", "hosting", "application_description")
            }

            self.assertEqual(len(assessable_sec_nodes), 44, f"Expected 44 assessable security nodes in {fw_ref}")

            unlinked_nodes = [
                ref_id for ref_id in assessable_sec_nodes
                if ref_id not in linked_req_refs
            ]
            self.assertEqual(
                len(unlinked_nodes), 0,
                f"Found unlinked assessable requirements in {fw_ref}: {unlinked_nodes}",
            )

    def test_appsec_application_description_screen(self):
        """Verify the presence, structure, questions, and profiling scoping of the application_description screen."""
        for fw_ref in ["appsec", "appsec_manual"]:
            with self.subTest(framework=fw_ref):
                fw = next((f for f in self.frameworks if f["ref_id"] == fw_ref), None)
                self.assertIsNotNone(fw, f"Framework {fw_ref} missing")

                node_urn = f"urn:intuitem:risk:req_node:{fw_ref}:application_description"
                node = fw["req_nodes"].get(node_urn)
                self.assertIsNotNone(node, f"application_description missing in {fw_ref}")

                # Hierarchy & scoping assertions
                self.assertTrue(node.get("assessable"), f"application_description must be assessable in {fw_ref}")
                self.assertEqual(node.get("depth"), 2, f"application_description depth must be 2 in {fw_ref}")
                self.assertEqual(
                    node.get("parent_urn"), f"urn:intuitem:risk:req_node:{fw_ref}:info",
                    f"application_description parent must be info in {fw_ref}",
                )
                self.assertEqual(
                    node.get("implementation_groups"), ["info"],
                    f"application_description must belong to ['info'] in {fw_ref}",
                )

                # Question structure assertions
                questions = node.get("questions", {})
                self.assertEqual(len(questions), 2, f"application_description must have 2 questions in {fw_ref}")

                q1_urn = f"urn:intuitem:risk:req_node:{fw_ref}:application_description:q1"
                q2_urn = f"urn:intuitem:risk:req_node:{fw_ref}:application_description:q2"
                self.assertIn(q1_urn, questions, f"q1 missing in {fw_ref}")
                self.assertIn(q2_urn, questions, f"q2 missing in {fw_ref}")

                q1 = questions[q1_urn]
                q2 = questions[q2_urn]
                self.assertEqual(q1.get("type"), "unique_choice")
                self.assertEqual(q2.get("type"), "unique_choice")
                self.assertGreaterEqual(len(q1.get("choices", [])), 5)
                self.assertGreaterEqual(len(q2.get("choices", [])), 4)

                # Check unique choice URNs
                q1_choice_urns = {c["urn"] for c in q1.get("choices", [])}
                q2_choice_urns = {c["urn"] for c in q2.get("choices", [])}
                self.assertEqual(len(q1_choice_urns), len(q1.get("choices", [])))
                self.assertEqual(len(q2_choice_urns), len(q2.get("choices", [])))


if __name__ == "__main__":
    unittest.main()


