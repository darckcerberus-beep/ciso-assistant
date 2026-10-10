"""Framework and application independent integration test suite for risk scenario evaluation.

Tests relational integrity, schema consistency, and risk scenario derivation dynamically:
1. Framework Integrity & Consistency:
   - Validates schema, foreign keys, risk matrix dimensions, and criticality mappings
     against each framework's embedded test_metadata in YML/*.
2. Application Scenario Evaluation Consistency:
   - Evaluates each application profile against its associated framework.
   - Validates computed impact levels, scenario counts, likelihoods, matrix risks,
     and control priorities against expected_evaluation and expected_risk_scenarios in test_data/*.
   - Validates that evaluating live RequirementAssessment objects yields identical results.
"""

from pathlib import Path
import unittest
import yaml

from classes.audits.requirement_assessment import RequirementAssessment
from classes.controls.applied import AppliedControlDict
from classes.examples_manager import FRAMEWORK_CATALOG
from classes.integrations.answers_import import read_answers_file, resolve_question_urn


class ApplicationRiskSimulator:
    """Simulates compliance questionnaire scoring and risk scenario derivation."""

    def __init__(self, framework_yaml_path="YML/newDPP.yml"):
        self.framework_yaml_path = Path(framework_yaml_path)
        with open(self.framework_yaml_path, "r", encoding="utf-8") as f:
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
        self.test_metadata = self.framework_data.get("test_metadata", {})
        self.applied_control_dict = AppliedControlDict.__new__(AppliedControlDict)

    def load_answers_from_file(self, file_path):
        """Read YAML answers profile into a dictionary grouped by requirement ref_id."""
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

    def build_mock_requirement_assessments(self, yml_path_or_dict):
        """Construct RequirementAssessment objects from a YAML application profile's answers."""
        if isinstance(yml_path_or_dict, (str, Path)):
            with open(yml_path_or_dict, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        else:
            data = yml_path_or_dict

        answers_by_req = {}
        for a in data.get("answers", []):
            req = a.get("requirement")
            if req:
                answers_by_req.setdefault(req, []).append(a)

        ras = []
        for idx, (req_ref, ans_list) in enumerate(answers_by_req.items(), 1):
            rn = self.req_nodes.get(req_ref) or self.req_nodes_by_urn.get(req_ref)
            if not rn:
                for cand in self.req_nodes.values():
                    if cand.get("ref_id", "").lower() == req_ref.lower():
                        rn = cand
                        break

            rn_urn = rn.get("urn") if rn else f"urn:mock:{req_ref}"
            rn_ref_id = rn.get("ref_id") if rn else req_ref
            q_dict = rn.get("questions", {}) if rn else {}

            answers_dict = {}
            total_score = 0
            has_score = False

            for a in ans_list:
                ans_text = str(a.get("answer", "")).strip().lower()
                q_text = str(a.get("question", "")).strip()

                matched_urn = resolve_question_urn(q_text, q_dict)
                if matched_urn:
                    q_def = q_dict[matched_urn]
                    for choice in q_def.get("choices", []):
                        c_val = str(choice.get("value", "")).strip().lower()
                        c_urn = str(choice.get("urn", "")).strip().lower()
                        if c_val == ans_text or c_urn == ans_text or (ans_text and (ans_text in c_val or c_val in ans_text)):
                            answers_dict[matched_urn] = choice.get("urn")
                            add_score = choice.get("add_score")
                            if add_score is not None:
                                total_score += int(add_score)
                                has_score = True
                            break
                    if matched_urn not in answers_dict:
                        if ans_text in ("yes", "compliant", "true"):
                            for choice in q_def.get("choices", []):
                                if choice.get("compute_result") or (choice.get("add_score", 0) > 0):
                                    answers_dict[matched_urn] = choice.get("urn")
                                    total_score += int(choice.get("add_score", 0))
                                    has_score = True
                                    break
                        elif ans_text in ("no", "non-compliant", "false"):
                            for choice in reversed(q_def.get("choices", [])):
                                if not choice.get("compute_result") or (choice.get("add_score", 0) == 0):
                                    answers_dict[matched_urn] = choice.get("urn")
                                    total_score += int(choice.get("add_score", 0))
                                    has_score = True
                                    break

            ras.append(RequirementAssessment({
                "id": f"ra-{idx}",
                "requirement": {"ref_id": rn_ref_id, "urn": rn_urn},
                "answers": answers_dict,
                "score": total_score if has_score else 0,
                "result": "compliant" if total_score > 0 else "not_assessed",
            }))
        return ras

    def evaluate_application(self, source):
        """Evaluate an application from a YAML file path or live RequirementAssessment objects."""
        if isinstance(source, (list, tuple, dict)):
            items = list(source.values()) if isinstance(source, dict) else list(source)
            return self.evaluate_from_requirement_assessments(items)
        return self.evaluate_from_file(source)

    def evaluate_from_requirement_assessments(self, req_assessments):
        """Evaluate dynamic risk scenarios directly from a collection of RequirementAssessment objects."""
        scores = {}
        answers_present_by_urn = set()
        answers_present_by_ref = set()
        data_class_choice_urn = None
        data_avail_choice_urn = None
        data_integ_choice_urn = None

        confidentiality_map = self.criticality_mapping.get("confidentiality", {})
        availability_map = self.criticality_mapping.get("availability", {})
        integrity_map = self.criticality_mapping.get("integrity", {})

        conf_node_ref = self.test_metadata.get("classification_node_ref")
        avail_node_ref = self.test_metadata.get("availability_node_ref")
        integ_node_ref = self.test_metadata.get("integrity_node_ref")

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
                answers_present_by_urn.add(urn.lower())
            if rn_ref:
                answers_present_by_ref.add(rn_ref)
                answers_present_by_ref.add(rn_ref.lower())

            # Check for data / vendor classification (confidentiality)
            is_conf_node = (
                rn_ref in (conf_node_ref, "data_classification", "PROF.01", "vendor_classification")
                or (urn and any(k in urn.lower() for k in ["data_classification", "vendor_classification", "prof.01"]))
            )
            if is_conf_node and answers_dict:
                for a_val in answers_dict.values():
                    if a_val:
                        data_class_choice_urn = a_val
                        break

            # Check for vendor availability
            is_avail_node = (
                rn_ref in (avail_node_ref, "vendor_availability", "PROF.02")
                or (urn and any(k in urn.lower() for k in ["vendor_availability", "prof.02"]))
            )
            if is_avail_node and answers_dict:
                for a_val in answers_dict.values():
                    if a_val:
                        data_avail_choice_urn = a_val
                        break

            # Check for data integrity
            is_integ_node = (
                rn_ref in (integ_node_ref, "integrity_classification")
                or (urn and "integrity_classification" in urn.lower())
            )
            if is_integ_node and answers_dict:
                for a_val in answers_dict.values():
                    if a_val:
                        data_integ_choice_urn = a_val
                        break

            # Score calculation
            score_val = ra.get_score() if hasattr(ra, "get_score") else (ra.get("score") if isinstance(ra, dict) else None)
            if score_val is not None and score_val != "":
                try:
                    num_score = int(score_val)
                    if urn:
                        scores[urn] = num_score
                    if rn_ref:
                        scores[rn_ref] = num_score
                        scores[rn_ref.lower()] = num_score
                    continue
                except (ValueError, TypeError):
                    pass

            rn = self.req_nodes_by_urn.get(urn) or self.req_nodes.get(rn_ref)
            if not rn and rn_ref:
                for cand in self.req_nodes.values():
                    if cand.get("ref_id", "").lower() == rn_ref.lower():
                        rn = cand
                        break
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
                    scores[rn_ref.lower()] = total_score

        # Determine Impact Levels
        conf_impact = 1
        if data_class_choice_urn:
            if data_class_choice_urn in confidentiality_map:
                conf_impact = confidentiality_map[data_class_choice_urn] + 1
            else:
                for k, v in confidentiality_map.items():
                    if k in str(data_class_choice_urn) or str(data_class_choice_urn).lower() in k.lower():
                        conf_impact = v + 1
                        break

        avail_impact = conf_impact
        if data_avail_choice_urn and availability_map:
            if data_avail_choice_urn in availability_map:
                avail_impact = availability_map[data_avail_choice_urn] + 1
            else:
                for k, v in availability_map.items():
                    if k in str(data_avail_choice_urn) or str(data_avail_choice_urn).lower() in k.lower():
                        avail_impact = v + 1
                        break

        integ_impact = conf_impact
        if data_integ_choice_urn and integrity_map:
            if data_integ_choice_urn in integrity_map:
                integ_impact = integrity_map[data_integ_choice_urn] + 1
            else:
                for k, v in integrity_map.items():
                    if k in str(data_integ_choice_urn) or str(data_integ_choice_urn).lower() in k.lower():
                        integ_impact = v + 1
                        break

        # Evaluate each Risk Scenario
        scenario_results = {}
        for scenario in self.risk_scenarios:
            sc_name = scenario.get("name")
            likelihood_urn = scenario.get("likelihood")
            impact_urn = scenario.get("impact")

            rn = self.req_nodes_by_urn.get(likelihood_urn)
            lh_ref_id = rn.get("ref_id") if rn else (likelihood_urn.rsplit(":", 1)[-1] if likelihood_urn else None)

            lh_present = (
                likelihood_urn in answers_present_by_urn
                or (likelihood_urn and likelihood_urn.lower() in answers_present_by_urn)
                or lh_ref_id in answers_present_by_ref
                or (lh_ref_id and lh_ref_id.lower() in answers_present_by_ref)
            )
            if not lh_present:
                continue

            is_avail_impact = (
                impact_urn and ("vendor_availability" in impact_urn.lower() or "availability" in impact_urn.lower())
            )
            sc_impact = avail_impact if is_avail_impact else conf_impact

            impact_present = False
            if is_avail_impact:
                impact_present = (
                    (avail_node_ref and (avail_node_ref in answers_present_by_ref or avail_node_ref.lower() in answers_present_by_ref))
                    or "vendor_availability" in answers_present_by_ref
                    or "prof.02" in answers_present_by_ref
                    or (impact_urn and (impact_urn in answers_present_by_urn or impact_urn.lower() in answers_present_by_urn))
                )
            else:
                impact_present = (
                    "data_classification" in answers_present_by_ref
                    or "vendor_classification" in answers_present_by_ref
                    or "prof.01" in answers_present_by_ref
                    or (impact_urn and (impact_urn in answers_present_by_urn or impact_urn.lower() in answers_present_by_urn))
                )

            if not impact_present:
                continue

            lh_score = scores.get(likelihood_urn, scores.get(lh_ref_id, scores.get(lh_ref_id.lower() if lh_ref_id else None, 0)))
            scaled_score = max(0, min(100, int(lh_score)))
            scaled_likelihood = min(4, max(1, 4 - ((scaled_score - 1) // 25)))

            proba_idx = scaled_likelihood - 1
            impact_idx = sc_impact - 1
            risk_grid = self.risk_matrix["grid"]
            matrix_risk_id = risk_grid[proba_idx][impact_idx]
            risk_level_1_based = matrix_risk_id + 1
            control_priority = self.applied_control_dict.get_priority_from_risk_level(risk_level_1_based)

            scenario_results[sc_name] = {
                "likelihood_score": lh_score,
                "scaled_likelihood": scaled_likelihood,
                "scaled_impact": sc_impact,
                "matrix_risk_id": matrix_risk_id,
                "risk_level_1_based": risk_level_1_based,
                "control_priority": control_priority,
            }

        return {
            "impact_level": conf_impact,
            "confidentiality_impact": conf_impact,
            "availability_impact": avail_impact,
            "integrity_impact": integ_impact,
            "requirement_scores": scores,
            "scenarios": scenario_results,
        }

    def evaluate_from_file(self, file_path):
        """Evaluate an application YAML file and return computed scores and scenarios."""
        answers_by_req = self.load_answers_from_file(file_path)

        scores = {}
        confidentiality_map = self.criticality_mapping.get("confidentiality", {})
        availability_map = self.criticality_mapping.get("availability", {})
        integrity_map = self.criticality_mapping.get("integrity", {})
        data_class_choice_urn = None
        data_avail_choice_urn = None
        data_integ_choice_urn = None

        for req_id, answers in answers_by_req.items():
            req_id_clean = req_id.strip()
            req_id_lower = req_id_clean.lower()
            rn = self.req_nodes.get(req_id_clean) or self.req_nodes_by_urn.get(req_id_clean)
            if not rn:
                for node in self.req_nodes.values():
                    if (
                        node.get("ref_id", "").lower() == req_id_lower
                        or node.get("urn", "").lower() == req_id_lower
                        or req_id_lower in node.get("urn", "").lower()
                    ):
                        rn = node
                        break
            if not rn:
                continue

            questions_dict = rn.get("questions", {})
            total_score = 0
            for ans_item in answers:
                q_text = ans_item["question"].strip()
                ans_text = ans_item["answer"].strip().lower()

                matched_urn = resolve_question_urn(q_text, questions_dict)
                if matched_urn:
                    q_def = questions_dict[matched_urn]
                    for choice in q_def.get("choices", []):
                        c_val = choice.get("value", "").strip().lower()
                        c_urn = choice.get("urn", "").strip().lower()
                        if c_val == ans_text or c_urn == ans_text or (ans_text and (ans_text in c_val or c_val in ans_text)):
                            add_score = choice.get("add_score")
                            if add_score is not None:
                                total_score += int(add_score)

                            if choice.get("urn") in confidentiality_map:
                                data_class_choice_urn = choice.get("urn")
                            elif choice.get("urn") in availability_map:
                                data_avail_choice_urn = choice.get("urn")
                            elif choice.get("urn") in integrity_map:
                                data_integ_choice_urn = choice.get("urn")
                            break

            node_ref = rn.get("ref_id")
            node_urn = rn.get("urn")
            if node_ref:
                scores[node_ref] = total_score
                scores[node_ref.lower()] = total_score
            if node_urn:
                scores[node_urn] = total_score
                scores[node_urn.lower()] = total_score

        # Determine Impact Levels
        conf_impact = 1
        if data_class_choice_urn and confidentiality_map:
            conf_impact = confidentiality_map.get(data_class_choice_urn, 0) + 1
        else:
            for k in ["data_classification", "PROF.01", "prof.01", "vendor_classification"]:
                ans_list = answers_by_req.get(k)
                if ans_list:
                    chosen_text = ans_list[0]["answer"].strip().lower()
                    for c_urn, c_idx in confidentiality_map.items():
                        if chosen_text in c_urn.lower():
                            conf_impact = c_idx + 1
                            break
                    break

        avail_node_ref = self.test_metadata.get("availability_node_ref")
        avail_impact = conf_impact
        if data_avail_choice_urn and availability_map:
            avail_impact = availability_map.get(data_avail_choice_urn, 0) + 1
        elif availability_map:
            for k in ([avail_node_ref] if avail_node_ref else []) + ["vendor_availability", "PROF.02", "prof.02"]:
                ans_list = answers_by_req.get(k)
                if ans_list:
                    chosen_text = ans_list[0]["answer"].strip().lower()
                    for c_urn, c_idx in availability_map.items():
                        if chosen_text in c_urn.lower():
                            avail_impact = c_idx + 1
                            break
                    break

        integ_node_ref = self.test_metadata.get("integrity_node_ref")
        integ_impact = conf_impact
        if data_integ_choice_urn and integrity_map:
            integ_impact = integrity_map.get(data_integ_choice_urn, 0) + 1
        elif integrity_map:
            for k in ([integ_node_ref] if integ_node_ref else []) + ["integrity_classification"]:
                ans_list = answers_by_req.get(k)
                if ans_list:
                    chosen_text = ans_list[0]["answer"].strip().lower()
                    for c_urn, c_idx in integrity_map.items():
                        if chosen_text in c_urn.lower():
                            integ_impact = c_idx + 1
                            break
                    break

        # Evaluate each Risk Scenario
        scenario_results = {}
        for scenario in self.risk_scenarios:
            sc_name = scenario.get("name")
            likelihood_urn = scenario.get("likelihood")
            impact_urn = scenario.get("impact")

            rn = self.req_nodes_by_urn.get(likelihood_urn)
            lh_ref_id = rn.get("ref_id") if rn else (likelihood_urn.rsplit(":", 1)[-1] if likelihood_urn else None)

            lh_answers = (
                answers_by_req.get(lh_ref_id)
                or answers_by_req.get(lh_ref_id.lower() if lh_ref_id else None)
                or answers_by_req.get(likelihood_urn)
                or answers_by_req.get(likelihood_urn.lower() if likelihood_urn else None)
                or []
            )
            if not lh_answers or not any(a.get("answer") for a in lh_answers):
                continue

            is_avail_impact = (
                impact_urn and ("vendor_availability" in impact_urn.lower() or "availability" in impact_urn.lower())
            )
            sc_impact = avail_impact if is_avail_impact else conf_impact

            impact_answered = False
            if is_avail_impact:
                impact_answered = (
                    (avail_node_ref and (avail_node_ref in answers_by_req or avail_node_ref.lower() in answers_by_req))
                    or "vendor_availability" in answers_by_req
                    or "prof.02" in answers_by_req
                    or "PROF.02" in answers_by_req
                    or (impact_urn and impact_urn in answers_by_req)
                )
            else:
                impact_answered = (
                    "data_classification" in answers_by_req
                    or "vendor_classification" in answers_by_req
                    or "prof.01" in answers_by_req
                    or "PROF.01" in answers_by_req
                    or (impact_urn and impact_urn in answers_by_req)
                )

            if not impact_answered:
                continue

            lh_score = scores.get(likelihood_urn, scores.get(lh_ref_id, scores.get(lh_ref_id.lower() if lh_ref_id else None, 0)))
            scaled_score = max(0, min(100, int(lh_score)))
            scaled_likelihood = min(4, max(1, 4 - ((scaled_score - 1) // 25)))

            proba_idx = scaled_likelihood - 1
            impact_idx = sc_impact - 1
            risk_grid = self.risk_matrix["grid"]
            matrix_risk_id = risk_grid[proba_idx][impact_idx]
            risk_level_1_based = matrix_risk_id + 1
            control_priority = self.applied_control_dict.get_priority_from_risk_level(risk_level_1_based)

            scenario_results[sc_name] = {
                "likelihood_score": lh_score,
                "scaled_likelihood": scaled_likelihood,
                "scaled_impact": sc_impact,
                "matrix_risk_id": matrix_risk_id,
                "risk_level_1_based": risk_level_1_based,
                "control_priority": control_priority,
            }

        return {
            "impact_level": conf_impact,
            "confidentiality_impact": conf_impact,
            "availability_impact": avail_impact,
            "integrity_impact": integ_impact,
            "requirement_scores": scores,
            "scenarios": scenario_results,
        }


class TestFrameworkIntegrityAndConsistency(unittest.TestCase):
    """Verifies relational integrity, foreign keys, and logic consistency across all frameworks."""

    @classmethod
    def _assert_framework_integrity(cls, test_case, framework_yaml_path):
        """Generic assertion verifying schema, counts, and relational integrity of any framework."""
        yaml_file = Path(framework_yaml_path)
        test_case.assertTrue(yaml_file.exists(), f"Framework file {yaml_file} does not exist")

        with open(yaml_file, "r", encoding="utf-8") as f:
            fw_data = yaml.safe_load(f)

        # 1. Required top-level fields
        for field in ["urn", "locale", "ref_id", "name", "objects"]:
            test_case.assertIn(field, fw_data, f"Missing required top-level key '{field}' in {yaml_file.name}")

        objects = fw_data.get("objects", {})
        test_case.assertIn("framework", objects, f"Missing 'framework' object in {yaml_file.name}")
        framework = objects["framework"]
        test_case.assertIn("requirement_nodes", framework, f"Missing 'requirement_nodes' in {yaml_file.name}")

        req_nodes = {rn["urn"]: rn for rn in framework.get("requirement_nodes", [])}
        req_nodes_by_ref = {rn["ref_id"]: rn for rn in framework.get("requirement_nodes", []) if rn.get("ref_id")}
        risk_scenarios = objects.get("risk_scenarios", [])
        threats = {t["urn"]: t for t in objects.get("threats", [])}
        vulns = {v["urn"]: v for v in objects.get("vulnerabilities", [])}
        ref_ctrls = {c["urn"]: c for c in objects.get("reference_controls", [])}
        risk_matrix_list = objects.get("risk_matrix", [])

        # 2. Validate against embedded test_metadata if specified
        test_metadata = fw_data.get("test_metadata", {})
        if test_metadata:
            if "expected_risk_scenarios_count" in test_metadata:
                test_case.assertEqual(
                    len(risk_scenarios), test_metadata["expected_risk_scenarios_count"],
                    f"Risk scenario count mismatch in {yaml_file.name}",
                )
            if "expected_threats_count" in test_metadata:
                test_case.assertEqual(
                    len(threats), test_metadata["expected_threats_count"],
                    f"Threat count mismatch in {yaml_file.name}",
                )
            if "expected_vulnerabilities_count" in test_metadata:
                test_case.assertEqual(
                    len(vulns), test_metadata["expected_vulnerabilities_count"],
                    f"Vulnerability count mismatch in {yaml_file.name}",
                )
            if "expected_reference_controls_count" in test_metadata:
                test_case.assertEqual(
                    len(ref_ctrls), test_metadata["expected_reference_controls_count"],
                    f"Reference controls count mismatch in {yaml_file.name}",
                )
            if "expected_requirement_nodes_count" in test_metadata:
                test_case.assertEqual(
                    len(req_nodes), test_metadata["expected_requirement_nodes_count"],
                    f"Requirement nodes count mismatch in {yaml_file.name}",
                )

        # 3. Risk matrix grid dimensions and consistency
        test_case.assertGreater(len(risk_matrix_list), 0, f"No risk_matrix found in {yaml_file.name}")
        matrix = risk_matrix_list[0]
        grid = matrix.get("grid")
        test_case.assertIsInstance(grid, list, f"Risk matrix grid must be a list in {yaml_file.name}")

        dims = test_metadata.get("matrix_dimensions", {})
        expected_rows = dims.get("likelihood_levels", len(grid))
        expected_cols = dims.get("impact_levels", len(grid[0]) if grid else 0)
        test_case.assertEqual(len(grid), expected_rows, f"Grid row count mismatch in {yaml_file.name}")
        for r_idx, row in enumerate(grid):
            test_case.assertEqual(len(row), expected_cols, f"Grid column count mismatch at row {r_idx} in {yaml_file.name}")
            for cell in row:
                test_case.assertIsInstance(cell, int, f"Matrix cell must be an int in {yaml_file.name}")
                test_case.assertTrue(0 <= cell < max(expected_rows, expected_cols) + 1)

        # 4. Criticality mapping integrity
        crit_map = fw_data.get("criticality_mapping", {})
        conf_map = crit_map.get("confidentiality", {})
        test_case.assertGreater(len(conf_map), 0, f"Confidentiality criticality mapping empty in {yaml_file.name}")
        for choice_urn, impact_idx in conf_map.items():
            test_case.assertTrue(0 <= impact_idx < expected_cols, f"Invalid confidentiality impact index {impact_idx}")

        avail_map = crit_map.get("availability", {})
        for choice_urn, impact_idx in avail_map.items():
            test_case.assertTrue(0 <= impact_idx < expected_cols, f"Invalid availability impact index {impact_idx}")

        # 5. Risk scenarios relational integrity (foreign keys)
        for sc in risk_scenarios:
            sc_name = sc.get("name")
            lh_ref = sc.get("likelihood")
            imp_ref = sc.get("impact")

            test_case.assertIsNotNone(lh_ref, f"Scenario '{sc_name}' missing likelihood reference")
            test_case.assertIsNotNone(imp_ref, f"Scenario '{sc_name}' missing impact reference")

            lh_exists = lh_ref in req_nodes or lh_ref in req_nodes_by_ref or any(lh_ref.endswith(f":{k}") for k in req_nodes_by_ref)
            imp_exists = imp_ref in req_nodes or imp_ref in req_nodes_by_ref or any(imp_ref.endswith(f":{k}") for k in req_nodes_by_ref)
            test_case.assertTrue(lh_exists, f"Scenario '{sc_name}' likelihood '{lh_ref}' not in requirement nodes")
            test_case.assertTrue(imp_exists, f"Scenario '{sc_name}' impact '{imp_ref}' not in requirement nodes")

            for t_urn in sc.get("threats", []):
                test_case.assertIn(t_urn, threats, f"Scenario '{sc_name}' references unknown threat: {t_urn}")
            for v_urn in sc.get("vulnerabilities", []):
                test_case.assertIn(v_urn, vulns, f"Scenario '{sc_name}' references unknown vulnerability: {v_urn}")

        # 6. Requirement nodes hierarchy and depth
        for urn, rn in req_nodes.items():
            parent_urn = rn.get("parent_urn")
            depth = rn.get("depth")
            if parent_urn is None:
                test_case.assertEqual(depth, 1, f"Root requirement node {urn} must have depth=1")
            else:
                test_case.assertIn(parent_urn, req_nodes, f"Node {urn} has invalid parent_urn: {parent_urn}")
                parent_depth = req_nodes[parent_urn].get("depth", 1)
                test_case.assertEqual(depth, parent_depth + 1, f"Node {urn} depth mismatch with parent {parent_urn}")

    def test_all_registered_frameworks_integrity(self):
        """Verify schema, foreign key, and matrix integrity across all catalog frameworks."""
        for cat in FRAMEWORK_CATALOG:
            with self.subTest(framework=cat["ref_id"]):
                self._assert_framework_integrity(self, cat["yaml_path"])


class TestApplicationProfileScenarioConsistency(unittest.TestCase):
    """Verifies that each application profile evaluates consistently with its embedded test data."""

    @classmethod
    def _assert_profile_evaluation(cls, test_case, app_yaml_path):
        """Generic assertion verifying an application's computed risk scenarios against its test data."""
        yaml_file = Path(app_yaml_path)
        test_case.assertTrue(yaml_file.exists(), f"Application profile {yaml_file} missing")

        with open(yaml_file, "r", encoding="utf-8") as f:
            app_data = yaml.safe_load(f)

        app_block = app_data.get("application", {})
        fw_ref = app_block.get("framework_ref")
        catalog_entry = next((c for c in FRAMEWORK_CATALOG if c["ref_id"] == fw_ref or c["name"] == app_block.get("framework_name")), None)
        fw_path = catalog_entry["yaml_path"] if catalog_entry else "YML/newDPP.yml"

        simulator = ApplicationRiskSimulator(fw_path)
        eval_results = simulator.evaluate_application(str(yaml_file))

        expected_eval = app_data.get("expected_evaluation", {})
        expected_scenarios = {s["scenario"]: s for s in app_data.get("expected_risk_scenarios", [])}

        # 1. Assert impact levels
        if "impact_level" in expected_eval:
            test_case.assertEqual(
                eval_results["impact_level"], expected_eval["impact_level"],
                f"Impact level mismatch in {yaml_file.name}",
            )
        if "confidentiality_impact" in expected_eval:
            test_case.assertEqual(
                eval_results["confidentiality_impact"], expected_eval["confidentiality_impact"],
                f"Confidentiality impact mismatch in {yaml_file.name}",
            )
        if "availability_impact" in expected_eval:
            test_case.assertEqual(
                eval_results["availability_impact"], expected_eval["availability_impact"],
                f"Availability impact mismatch in {yaml_file.name}",
            )
        if "integrity_impact" in expected_eval:
            test_case.assertEqual(
                eval_results["integrity_impact"], expected_eval["integrity_impact"],
                f"Integrity impact mismatch in {yaml_file.name}",
            )

        # 2. Assert scenario count
        evaluated_scenarios = eval_results["scenarios"]
        if "scenario_count" in expected_eval:
            test_case.assertEqual(
                len(evaluated_scenarios), expected_eval["scenario_count"],
                f"Evaluated scenario count mismatch in {yaml_file.name}",
            )
        if expected_scenarios:
            test_case.assertEqual(
                len(evaluated_scenarios), len(expected_scenarios),
                f"Scenario count does not match expected_risk_scenarios count in {yaml_file.name}",
            )

        # 3. Assert detailed scenario metrics
        for sc_name, sc_data in evaluated_scenarios.items():
            test_case.assertIn(sc_name, expected_scenarios, f"Unexpected scenario '{sc_name}' evaluated in {yaml_file.name}")
            exp = expected_scenarios[sc_name]
            test_case.assertEqual(
                sc_data["scaled_likelihood"], exp["scaled_likelihood"],
                f"Likelihood mismatch for '{sc_name}' in {yaml_file.name}",
            )
            test_case.assertEqual(
                sc_data["scaled_impact"], exp["scaled_impact"],
                f"Impact mismatch for '{sc_name}' in {yaml_file.name}",
            )
            test_case.assertEqual(
                sc_data["matrix_risk_id"], exp["matrix_risk_id"],
                f"Matrix risk ID mismatch for '{sc_name}' in {yaml_file.name}",
            )
            test_case.assertEqual(
                sc_data["control_priority"], exp["control_priority"],
                f"Control priority mismatch for '{sc_name}' in {yaml_file.name}",
            )
            if "risk_level" in exp:
                test_case.assertEqual(
                    sc_data["risk_level_1_based"], exp["risk_level"],
                    f"Risk level mismatch for '{sc_name}' in {yaml_file.name}",
                )

        # 4. Assert excluded scenarios are not evaluated
        for excluded_sc in expected_eval.get("excluded_scenarios", []):
            test_case.assertNotIn(
                excluded_sc, evaluated_scenarios,
                f"Excluded scenario '{excluded_sc}' should not be evaluated in {yaml_file.name}",
            )

        # 5. Assert evaluation from live RequirementAssessment objects matches
        mock_ras = simulator.build_mock_requirement_assessments(app_data)
        ra_eval_results = simulator.evaluate_from_requirement_assessments(mock_ras)
        test_case.assertEqual(
            len(ra_eval_results["scenarios"]), len(evaluated_scenarios),
            f"Scenario count mismatch when evaluating via RequirementAssessments in {yaml_file.name}",
        )
        for sc_name in evaluated_scenarios:
            test_case.assertIn(sc_name, ra_eval_results["scenarios"], f"Scenario '{sc_name}' missing in RA evaluation")
            ra_sc = ra_eval_results["scenarios"][sc_name]
            file_sc = evaluated_scenarios[sc_name]
            test_case.assertEqual(ra_sc["scaled_likelihood"], file_sc["scaled_likelihood"])
            test_case.assertEqual(ra_sc["scaled_impact"], file_sc["scaled_impact"])
            test_case.assertEqual(ra_sc["matrix_risk_id"], file_sc["matrix_risk_id"])
            test_case.assertEqual(ra_sc["control_priority"], file_sc["control_priority"])

    def test_all_application_profiles_scenario_evaluations(self):
        """Verify risk scenario evaluation consistency across all application profiles in test_data."""
        app_files = sorted(Path("test_data").glob("*.yml"))
        self.assertGreater(len(app_files), 0, "No application YAML profiles found in test_data")

        for app_file in app_files:
            with self.subTest(application=app_file.stem):
                self._assert_profile_evaluation(self, app_file)

    def test_appsec_saas_contract_defined_controls_evaluation(self):
        """Verify that a SaaS application whose controls are defined with a contract evaluates correctly."""
        yaml_file = Path("test_data/app_appsec_secure_api.yml")
        if not yaml_file.exists():
            return

        with open(yaml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        simulator = ApplicationRiskSimulator("YML/appsec.yml")
        mock_ras = simulator.build_mock_requirement_assessments(data)
        results = simulator.evaluate_from_requirement_assessments(mock_ras)

        self.assertEqual(results["confidentiality_impact"], 4)
        self.assertEqual(len(results["scenarios"]), 16)
        for name, sc in results["scenarios"].items():
            self.assertEqual(sc["scaled_likelihood"], 1, f"Expected min likelihood for {name}")
            self.assertEqual(sc["matrix_risk_id"], 1, f"Expected low risk for {name}")


# -----------------------------------------------------------------------------
# Dynamic test method generation
# Enables individual test discovery and execution for every framework and profile
# -----------------------------------------------------------------------------

def _make_framework_test(yaml_path):
    def test_method(self):
        self._assert_framework_integrity(self, yaml_path)
    return test_method

for _fw_cat in FRAMEWORK_CATALOG:
    _method_name = f"test_framework_{_fw_cat['ref_id'].replace('-', '_')}"
    setattr(TestFrameworkIntegrityAndConsistency, _method_name, _make_framework_test(_fw_cat["yaml_path"]))

def _make_profile_test(app_path):
    def test_method(self):
        self._assert_profile_evaluation(self, app_path)
    return test_method

for _app_path in sorted(Path("test_data").glob("*.yml")):
    _method_name = f"test_profile_{_app_path.stem}"
    setattr(TestApplicationProfileScenarioConsistency, _method_name, _make_profile_test(_app_path))

if __name__ == "__main__":
    unittest.main()
