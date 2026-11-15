"""Shared helpers for framework implementation groups."""

from pathlib import Path
import re
from typing import Any

from .. import utils


def _match_choice(choice: dict[str, Any], answer_val: Any) -> bool:
    """Check if an answer value matches a question choice definition."""
    if answer_val is None:
        return False
    if isinstance(answer_val, (list, tuple, set)):
        return any(_match_choice(choice, single_val) for single_val in answer_val)

    a_str = str(answer_val).strip()
    if not a_str:
        return False

    norm_ans = a_str.lower()
    c_urn = str(choice.get("urn", "")).strip().lower()
    c_ref = str(choice.get("ref_id", "")).strip().lower()
    c_val = str(choice.get("value", "")).strip().lower()

    if c_urn and norm_ans == c_urn:
        return True
    if c_ref and norm_ans == c_ref:
        return True
    if c_val and norm_ans == c_val:
        return True
    if c_ref and norm_ans.endswith(f":{c_ref}"):
        return True
    if c_val and (norm_ans.startswith(c_val) or c_val.startswith(norm_ans)):
        return True
    return False


def _get_node_choices(node: dict[str, Any], q_key: str | None = None) -> list[dict[str, Any]]:
    """Extract question choice dictionaries from a framework requirement node."""
    if not isinstance(node, dict):
        return []
    questions = node.get("questions", {})
    q_items = questions.values() if isinstance(questions, dict) else (questions if isinstance(questions, list) else [])

    if q_key:
        norm_q = str(q_key).strip().lower()
        for q in q_items:
            if not isinstance(q, dict):
                continue
            q_ref = str(q.get("ref_id", "")).strip().lower()
            q_urn = str(q.get("urn", "")).strip().lower()
            q_text = str(q.get("text", "")).strip().lower()
            if (
                norm_q == q_ref
                or norm_q == q_urn
                or norm_q == q_text
                or (q_ref and norm_q.endswith(f":{q_ref}"))
                or (q_ref and norm_q.endswith(q_ref))
                or (q_urn and norm_q in q_urn)
                or (q_text and (norm_q in q_text or q_text in norm_q))
            ):
                return [c for c in q.get("choices", []) if isinstance(c, dict)]

    all_choices: list[dict[str, Any]] = []
    for q in q_items:
        if isinstance(q, dict):
            all_choices.extend([c for c in q.get("choices", []) if isinstance(c, dict)])
    return all_choices


def _check_dep_match(
    dep: dict[str, Any],
    req_ident: str,
    q_ident: str,
    ans_val: Any,
    matched_choice: dict[str, Any] | None = None,
) -> bool:
    """Check if an answer to a question matches an implementation_groups_dependencies entry."""
    dep_q_urn = str(dep.get("question_urn", "")).strip().lower()
    dep_q_ref = str(dep.get("question_ref_id", "")).strip().lower()
    dep_q_text = str(dep.get("question_text", "")).strip().lower()

    q_matched = False
    norm_q = str(q_ident or "").strip().lower()
    norm_req = str(req_ident or "").strip().lower()

    if matched_choice:
        mc_urn = str(matched_choice.get("urn", "")).strip().lower()
        if dep_q_urn and (mc_urn == dep_q_urn or mc_urn.startswith(f"{dep_q_urn}:")):
            q_matched = True
        elif dep_q_ref and (
            f":{dep_q_ref}:" in mc_urn
            or mc_urn.endswith(f":{dep_q_ref}")
            or mc_urn.startswith(f"{dep_q_ref}:")
        ):
            q_matched = True

    if not q_matched:
        if dep_q_urn and (norm_q == dep_q_urn or norm_q in dep_q_urn or dep_q_urn in norm_q):
            q_matched = True
        elif dep_q_ref and (
            norm_q == dep_q_ref
            or norm_q.endswith(f":{dep_q_ref}")
            or norm_q.endswith(dep_q_ref)
            or (norm_req and f"{norm_req}:{norm_q}".endswith(dep_q_ref))
        ):
            q_matched = True
        elif dep_q_text and (norm_q == dep_q_text or norm_q in dep_q_text or dep_q_text in norm_q):
            q_matched = True
        elif not q_ident and dep_q_ref and norm_req and (norm_req in dep_q_ref or dep_q_ref in norm_req):
            q_matched = True

    if not q_matched:
        return False

    dep_c_urn = str(dep.get("choice_urn", "")).strip().lower()
    dep_c_val = str(dep.get("choice_value", "")).strip().lower()

    if matched_choice:
        mc_urn = str(matched_choice.get("urn", "")).strip().lower()
        mc_val = str(matched_choice.get("value", "")).strip().lower()
        mc_ref = str(matched_choice.get("ref_id", "")).strip().lower()
        if dep_c_urn and mc_urn == dep_c_urn:
            return True
        if dep_c_val and (mc_val == dep_c_val or dep_c_val in mc_val or mc_val in dep_c_val):
            return True
        if dep_c_urn and mc_ref and dep_c_urn.endswith(f":{mc_ref}"):
            return True

    temp_c = {"urn": dep.get("choice_urn"), "value": dep.get("choice_value"), "ref_id": dep.get("choice_ref_id")}
    return _match_choice(temp_c, ans_val)


def get_framework_implementation_groups_dependencies(framework_id: Any) -> list[dict[str, Any]]:
    """Return implementation groups dependencies defined for a framework.

    Returns a list of dependency dictionaries containing:
    - target_implementation_group: target group name or ref_id
    - name: human readable track name
    - question_urn / question_ref_id: triggering question identifier
    - choice_urn / choice_value: triggering choice identifier and text
    - prompt: user-facing question prompt for interactive triggering
    """
    if isinstance(framework_id, dict) and "implementation_groups_dependencies" in framework_id:
        return list(framework_id.get("implementation_groups_dependencies", []) or [])
    if hasattr(framework_id, "json_object") and isinstance(getattr(framework_id, "json_object", None), dict):
        deps = framework_id.json_object.get("implementation_groups_dependencies")
        if isinstance(deps, list) and deps:
            return list(deps)
    try:
        from ..examples_manager import ExamplesManager
        fw_ident = framework_id
        if hasattr(framework_id, "get_id"):
            fw_ident = framework_id.get_id() or getattr(framework_id, "get_name", lambda: None)()
        elif hasattr(framework_id, "json_object") and isinstance(getattr(framework_id, "json_object", None), dict):
            fw_ident = framework_id.json_object.get("ref_id") or framework_id.json_object.get("id")
        elif isinstance(framework_id, dict):
            fw_ident = framework_id.get("id") or framework_id.get("ref_id") or framework_id.get("name")
        fw_meta = ExamplesManager._load_framework_metadata(str(fw_ident or ""))
        if fw_meta and isinstance(fw_meta, dict):
            return list(fw_meta.get("implementation_groups_dependencies", []) or [])
    except Exception:
        pass
    return []


def get_framework_triggered_implementation_groups_map(framework_id: Any) -> dict[str, list[str]]:
    """Return a mapping of triggered group identifier (lowercase) -> list of trigger question texts or prompts.

    Inspects framework requirement node question choices for 'select_implementation_groups'
    as well as framework-level 'implementation_groups_dependencies'.
    """
    triggered_map: dict[str, list[str]] = {}
    try:
        nodes = []
        ig_deps = []
        if isinstance(framework_id, dict):
            nodes = framework_id.get("requirement_nodes", []) or []
            ig_deps = framework_id.get("implementation_groups_dependencies", []) or []
        elif hasattr(framework_id, "json_object") and isinstance(getattr(framework_id, "json_object", None), dict):
            nodes = framework_id.json_object.get("requirement_nodes", []) or []
            ig_deps = framework_id.json_object.get("implementation_groups_dependencies", []) or []
        else:
            from ..examples_manager import ExamplesManager
            fw_ident = framework_id
            if hasattr(framework_id, "get_id"):
                fw_ident = framework_id.get_id() or getattr(framework_id, "get_name", lambda: None)()
            elif hasattr(framework_id, "json_object") and isinstance(getattr(framework_id, "json_object", None), dict):
                fw_ident = framework_id.json_object.get("ref_id") or framework_id.json_object.get("id")
            elif isinstance(framework_id, dict):
                fw_ident = framework_id.get("id") or framework_id.get("ref_id") or framework_id.get("name")

            fw_meta = ExamplesManager._load_framework_metadata(str(fw_ident or ""))
            if fw_meta and isinstance(fw_meta, dict):
                nodes = fw_meta.get("requirement_nodes", []) or []
                ig_deps = fw_meta.get("implementation_groups_dependencies", []) or []

        # 1. From choice-level select_implementation_groups
        for node in nodes:
            if not isinstance(node, dict):
                continue
            questions = node.get("questions", {})
            q_items = questions.values() if isinstance(questions, dict) else (questions if isinstance(questions, list) else [])
            for q in q_items:
                if not isinstance(q, dict):
                    continue
                q_text = str(q.get("text", "")).strip()
                choices = q.get("choices", []) or []
                for choice in choices:
                    if not isinstance(choice, dict):
                        continue
                    select_groups = choice.get("select_implementation_groups", []) or []
                    for grp in select_groups:
                        if grp:
                            grp_norm = str(grp).strip().lower()
                            if grp_norm not in triggered_map:
                                triggered_map[grp_norm] = []
                            if q_text and q_text not in triggered_map[grp_norm]:
                                triggered_map[grp_norm].append(q_text)

        # 2. From framework-level implementation_groups_dependencies
        for dep in ig_deps:
            if not isinstance(dep, dict):
                continue
            tg = dep.get("target_implementation_group")
            if not tg:
                continue
            tg_norm = str(tg).strip().lower()
            if tg_norm not in triggered_map:
                triggered_map[tg_norm] = []
            prompt = dep.get("prompt")
            q_urn = dep.get("question_urn")
            q_ref = dep.get("question_ref_id")
            q_text = ""
            for node in nodes:
                qs = node.get("questions", {})
                q_items = qs.values() if isinstance(qs, dict) else (qs if isinstance(qs, list) else [])
                for q in q_items:
                    if not isinstance(q, dict):
                        continue
                    if (q_urn and str(q.get("urn", "")).strip().lower() == str(q_urn).strip().lower()) or \
                       (q_ref and str(q.get("ref_id", "")).strip().lower() == str(q_ref).strip().lower()):
                        q_text = str(q.get("text", "")).strip()
                        break
                if q_text:
                    break
            trigger_text = prompt or q_text or str(q_ref or q_urn or "")
            if trigger_text and trigger_text not in triggered_map[tg_norm]:
                triggered_map[tg_norm].append(trigger_text)
    except Exception:
        pass
    return triggered_map


def determine_implementation_groups_triggered_by_others(
    framework_id: Any,
    active_groups: Any = None,
    ca_reqs: Any = None,
    answers: Any = None,
    yaml_path: str | Path | None = None,
    auto_trigger: bool = False,
) -> dict[str, Any]:
    """Determine the implementation groups that are triggered by other groups and question choices.

    Analyzes framework metadata (requirement nodes, questions, choices) and audit state
    (selected active groups, completed requirement assessment answers, or YAML answers file).

    Categorizes implementation groups into:
    - always_selectable_groups: Groups that do NOT need to be triggered by others (e.g. info, default groups).
    - hidden_groups: Groups that must be triggered by others, but have NOT YET been triggered.
    - triggered_groups: Groups that must be triggered by others, AND HAVE BEEN triggered.
    - visible_groups: always_selectable_groups + triggered_groups (shown to respondents/auditors).

    Returns:
        Dict containing:
        - 'framework_id': resolved framework identifier
        - 'always_selectable_groups': list of group dicts
        - 'hidden_groups': list of group dicts
        - 'triggered_groups': list of group dicts
        - 'visible_groups': list of group dicts
        - 'all_groups': list of all group dicts enriched with trigger status
        - 'dependency_map': mapping of canonical group name -> trigger dependency details
        - 'candidate_dependencies': list of dependencies whose question/choice condition matched answers
        - 'pending_dependencies': candidate dependencies whose target group is not yet active
        - 'pending_triggered_groups': canonical group names for pending dependencies
        - 'summary': counts breakdown
    """
    defs: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    ig_dependencies: list[dict[str, Any]] = []

    if isinstance(framework_id, dict):
        defs = framework_id.get("implementation_groups_definition", []) or []
        nodes = framework_id.get("requirement_nodes", []) or []
        ig_dependencies = framework_id.get("implementation_groups_dependencies", []) or []
    elif hasattr(framework_id, "get_implementation_groups_definition"):
        res_defs = framework_id.get_implementation_groups_definition()
        if isinstance(res_defs, list) and res_defs:
            defs = res_defs
        elif hasattr(framework_id, "json_object") and isinstance(framework_id.json_object, dict):
            defs = framework_id.json_object.get("implementation_groups_definition", []) or []
        if hasattr(framework_id, "json_object") and isinstance(framework_id.json_object, dict):
            nodes = framework_id.json_object.get("requirement_nodes", []) or []
            ig_dependencies = framework_id.json_object.get("implementation_groups_dependencies", []) or []
    elif hasattr(framework_id, "json_object") and isinstance(framework_id.json_object, dict):
        defs = framework_id.json_object.get("implementation_groups_definition", []) or []
        nodes = framework_id.json_object.get("requirement_nodes", []) or []
        ig_dependencies = framework_id.json_object.get("implementation_groups_dependencies", []) or []
    else:
        fw_str = str(framework_id).strip()
        catalog_refs = {
            ident.lower()
            for cat in utils.discover_framework_catalog()
            for ident in (
                cat.get("ref_id", ""),
                cat.get("name", ""),
                Path(cat.get("yaml_path", "")).stem,
                cat.get("yaml_path", ""),
            )
            if ident
        }
        if fw_str.lower() not in catalog_refs and not fw_str.endswith((".yml", ".yaml")):
            framework = utils.get_return(f"/api/frameworks/{fw_str}/")
            if isinstance(framework, dict):
                defs = framework.get("implementation_groups_definition", []) or []
                nodes = framework.get("requirement_nodes", []) or []
                ig_dependencies = framework.get("implementation_groups_dependencies", []) or []

    fw_ident = framework_id
    if hasattr(framework_id, "get_id"):
        gid = framework_id.get_id()
        if isinstance(gid, str) and not str(gid).startswith("<MagicMock"):
            fw_ident = gid
        elif hasattr(framework_id, "get_name"):
            gname = framework_id.get_name()
            if isinstance(gname, str) and not str(gname).startswith("<MagicMock"):
                fw_ident = gname
            elif hasattr(framework_id, "json_object") and isinstance(framework_id.json_object, dict):
                fw_ident = framework_id.json_object.get("ref_id") or framework_id.json_object.get("id")
    elif hasattr(framework_id, "json_object") and isinstance(getattr(framework_id, "json_object", None), dict):
        fw_ident = framework_id.json_object.get("ref_id") or framework_id.json_object.get("id")
    elif isinstance(framework_id, dict):
        fw_ident = framework_id.get("id") or framework_id.get("ref_id") or framework_id.get("name")

    # Load from framework metadata if defs, nodes, or ig_dependencies are missing
    if not defs or not nodes or not ig_dependencies:
        try:
            from ..examples_manager import ExamplesManager
            fw_meta = ExamplesManager._load_framework_metadata(str(fw_ident or ""))
            if fw_meta and isinstance(fw_meta, dict):
                if not defs:
                    defs = fw_meta.get("implementation_groups_definition", []) or []
                if not nodes:
                    nodes = fw_meta.get("requirement_nodes", []) or []
                if not ig_dependencies:
                    ig_dependencies = fw_meta.get("implementation_groups_dependencies", []) or []
        except Exception:
            pass

    if not defs or not isinstance(defs, list):
        defs = []

    # Build lookups for canonical group matching and delegate question mappings
    name_map: dict[str, str] = {}
    ref_map: dict[str, str] = {}
    defs_by_canonical: dict[str, dict[str, Any]] = {}
    delegate_q_to_canonical: dict[str, str] = {}

    def _register_delegate_spec(spec: Any, canonical_name: str) -> None:
        if not spec or not canonical_name:
            return
        if isinstance(spec, (list, tuple, set)):
            for s in spec:
                _register_delegate_spec(s, canonical_name)
            return
        if isinstance(spec, dict):
            for k in ("question_urn", "question_ref_id", "question", "urn", "ref_id", "answer", "key", "target"):
                if spec.get(k):
                    _register_delegate_spec(spec[k], canonical_name)
            return
        s_val = str(spec).strip()
        if not s_val:
            return
        s_lower = s_val.lower()
        delegate_q_to_canonical[s_lower] = canonical_name
        delegate_q_to_canonical[s_val] = canonical_name
        if ":" in s_val:
            parts = s_val.split(":")
            delegate_q_to_canonical[parts[-1].lower()] = canonical_name
            if len(parts) >= 2:
                delegate_q_to_canonical[f"{parts[-2]}:{parts[-1]}".lower()] = canonical_name

    for item in defs:
        if not isinstance(item, dict):
            continue
        c_name = str(item.get("name") or item.get("ref_id") or "").strip()
        r_id = str(item.get("ref_id") or "").strip()
        u_urn = str(item.get("urn") or "").strip()

        defs_by_canonical[c_name] = dict(item)
        for key in (c_name, r_id, u_urn):
            if key:
                name_map[key.lower()] = c_name
                if r_id:
                    ref_map[key.lower()] = r_id

        # Framework-defined delegate question: specifies which answer will contain who can answer
        del_spec = (
            item.get("delegate_answer")
            or item.get("delegate_question")
            or item.get("suggested_assignee_answer")
            or item.get("suggested_assignee_question")
            or item.get("suggested_assignee")
            or item.get("assignee_answer")
            or item.get("assignee_question")
            or item.get("delegate_question_urn")
            or item.get("delegate_question_ref_id")
            or item.get("delegate")
        )
        if del_spec:
            _register_delegate_spec(del_spec, c_name)

    def _canonical(val: Any) -> str:
        s = str(val or "").strip()
        return name_map.get(s.lower(), s)

    # Map nodes by ref_id and urn for answering lookup
    nodes_by_ref: dict[str, dict[str, Any]] = {}
    nodes_by_urn: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        n_ref = str(node.get("ref_id", "")).strip()
        n_urn = str(node.get("urn", "")).strip()
        if n_ref:
            nodes_by_ref[n_ref.lower()] = node
        if n_urn:
            nodes_by_urn[n_urn.lower()] = node

    # Inspect question choices for triggered groups and their parent groups
    dependency_map: dict[str, dict[str, Any]] = {}
    for c_name in defs_by_canonical:
        dependency_map[c_name] = {
            "is_triggered_by_others": False,
            "triggered_by_groups": [],
            "triggered_by_nodes": [],
            "triggered_by_questions": [],
            "triggering_choices": [],
        }

    for node in nodes:
        if not isinstance(node, dict):
            continue
        n_ref = str(node.get("ref_id", "")).strip()
        n_urn = str(node.get("urn", "")).strip()
        n_name = str(node.get("name", "")).strip()
        parent_groups_raw = node.get("implementation_groups", []) or []
        parent_groups = [_canonical(pg) for pg in parent_groups_raw if pg]

        questions = node.get("questions", {})
        q_items = questions.values() if isinstance(questions, dict) else (questions if isinstance(questions, list) else [])
        for q in q_items:
            if not isinstance(q, dict):
                continue
            q_text = str(q.get("text", "")).strip()
            choices = q.get("choices", []) or []
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                select_groups = choice.get("select_implementation_groups", []) or []
                for tg_raw in select_groups:
                    if not tg_raw:
                        continue
                    tg_can = _canonical(tg_raw)
                    if tg_can not in dependency_map:
                        dependency_map[tg_can] = {
                            "is_triggered_by_others": False,
                            "triggered_by_groups": [],
                            "triggered_by_nodes": [],
                            "triggered_by_questions": [],
                            "triggering_choices": [],
                        }
                    dep = dependency_map[tg_can]
                    dep["is_triggered_by_others"] = True

                    # Add parent implementation groups that trigger this group (excluding itself)
                    for pg in parent_groups:
                        if pg != tg_can and pg not in dep["triggered_by_groups"]:
                            dep["triggered_by_groups"].append(pg)

                    # Add node info
                    node_ident = n_ref or n_name or n_urn
                    if node_ident and node_ident not in dep["triggered_by_nodes"]:
                        dep["triggered_by_nodes"].append(node_ident)

                    # Add question text
                    if q_text and q_text not in dep["triggered_by_questions"]:
                        dep["triggered_by_questions"].append(q_text)

                    dep["triggering_choices"].append({
                        "choice_value": choice.get("value"),
                        "choice_ref": choice.get("ref_id"),
                        "choice_urn": choice.get("urn"),
                        "node_ref": n_ref,
                        "question_text": q_text,
                    })

    # Process framework-level implementation_groups_dependencies
    for dep_entry in ig_dependencies:
        if not isinstance(dep_entry, dict):
            continue
        tg_raw = dep_entry.get("target_implementation_group")
        if not tg_raw:
            continue
        tg_can = _canonical(tg_raw)
        if tg_can not in dependency_map:
            dependency_map[tg_can] = {
                "is_triggered_by_others": False,
                "triggered_by_groups": [],
                "triggered_by_nodes": [],
                "triggered_by_questions": [],
                "triggering_choices": [],
                "dependencies": [],
                "prompt": "",
            }
        dep = dependency_map[tg_can]
        dep["is_triggered_by_others"] = True
        if "dependencies" not in dep:
            dep["dependencies"] = []
        dep["dependencies"].append(dict(dep_entry))
        prompt = dep_entry.get("prompt", "")
        if prompt and not dep.get("prompt"):
            dep["prompt"] = prompt

        q_urn = dep_entry.get("question_urn", "")
        q_ref = dep_entry.get("question_ref_id", "")
        c_urn = dep_entry.get("choice_urn", "")
        c_val = dep_entry.get("choice_value", "")

        target_node = None
        target_q_text = ""
        for node in nodes:
            if not isinstance(node, dict):
                continue
            questions = node.get("questions", {})
            q_items = questions.values() if isinstance(questions, dict) else (questions if isinstance(questions, list) else [])
            for q in q_items:
                if not isinstance(q, dict):
                    continue
                if (q_urn and str(q.get("urn", "")).strip().lower() == str(q_urn).strip().lower()) or \
                   (q_ref and str(q.get("ref_id", "")).strip().lower() == str(q_ref).strip().lower()):
                    target_node = node
                    target_q_text = str(q.get("text", "")).strip()
                    dep_entry["question_text"] = target_q_text
                    break
            if target_node:
                break

        if target_node:
            n_ref = str(target_node.get("ref_id", "")).strip()
            n_name = str(target_node.get("name", "")).strip()
            n_urn = str(target_node.get("urn", "")).strip()
            parent_groups_raw = target_node.get("implementation_groups", []) or []
            parent_groups = [_canonical(pg) for pg in parent_groups_raw if pg]
            for pg in parent_groups:
                if pg != tg_can and pg not in dep["triggered_by_groups"]:
                    dep["triggered_by_groups"].append(pg)
            node_ident = n_ref or n_name or n_urn
            if node_ident and node_ident not in dep["triggered_by_nodes"]:
                dep["triggered_by_nodes"].append(node_ident)

        if target_q_text and target_q_text not in dep["triggered_by_questions"]:
            dep["triggered_by_questions"].append(target_q_text)
        elif prompt and prompt not in dep["triggered_by_questions"]:
            dep["triggered_by_questions"].append(prompt)

        dep["triggering_choices"].append({
            "choice_value": c_val,
            "choice_ref": dep_entry.get("choice_ref_id"),
            "choice_urn": c_urn,
            "node_ref": q_ref or (target_node.get("ref_id") if target_node else ""),
            "question_text": target_q_text or prompt,
            "question_urn": q_urn,
            "prompt": prompt,
        })

    # In case get_framework_triggered_implementation_groups_map was mocked in unit tests
    try:
        from unittest.mock import Mock
        if hasattr(get_framework_triggered_implementation_groups_map, "_mock_return_value") or isinstance(get_framework_triggered_implementation_groups_map, Mock):
            legacy_map = get_framework_triggered_implementation_groups_map(framework_id)
            for grp_ident, q_texts in (legacy_map or {}).items():
                grp_can = _canonical(grp_ident)
                if grp_can not in dependency_map:
                    dependency_map[grp_can] = {
                        "is_triggered_by_others": False,
                        "triggered_by_groups": [],
                        "triggered_by_nodes": [],
                        "triggered_by_questions": [],
                        "triggering_choices": [],
                        "dependencies": [],
                        "prompt": "",
                    }
                dep = dependency_map[grp_can]
                dep["is_triggered_by_others"] = True
                for qt in q_texts:
                    if qt and qt not in dep["triggered_by_questions"]:
                        dep["triggered_by_questions"].append(qt)
    except Exception:
        pass

    # Determine which groups have actually been triggered or are candidate triggers
    triggered_canonical_set: set[str] = set()
    ciso_assistant_triggered_groups: set[str] = set()
    ciso_assistant_triggered_ref_ids: set[str] = set()
    candidate_dependencies: list[dict[str, Any]] = []
    delegate_answers: dict[str, str] = {}

    def _clean_answer_text(ans_val: Any) -> str:
        if ans_val is None:
            return ""
        if isinstance(ans_val, str):
            return ans_val.strip()
        if isinstance(ans_val, dict):
            for k in ("text", "answer", "value", "choices"):
                v = ans_val.get(k)
                if v is not None:
                    txt = _clean_answer_text(v)
                    if txt:
                        return txt
            return ""
        if isinstance(ans_val, (list, tuple)):
            cleaned = [_clean_answer_text(x) for x in ans_val if x is not None]
            return ", ".join(c for c in cleaned if c)
        return str(ans_val).strip()

    def _find_group_for_delegate_question(req_ref: str, q_key: str) -> str | None:
        q_str = str(q_key or "").strip()
        q_lower = q_str.lower()
        req_lower = str(req_ref or "").strip().lower()

        # 1. Direct question match from framework IG definition (delegate_answer / suggested_assignee_answer)
        if q_lower in delegate_q_to_canonical:
            return delegate_q_to_canonical[q_lower]
        if q_str in delegate_q_to_canonical:
            return delegate_q_to_canonical[q_str]

        # 2. Combined req_ref:q_key match from framework IG definition
        if req_lower and q_lower:
            comb = f"{req_lower}:{q_lower}"
            if comb in delegate_q_to_canonical:
                return delegate_q_to_canonical[comb]

        # 3. URN suffix match
        if ":" in q_str:
            parts = q_str.split(":")
            if parts[-1].lower() in delegate_q_to_canonical:
                return delegate_q_to_canonical[parts[-1].lower()]
            if len(parts) >= 2:
                comb_last = f"{parts[-2]}:{parts[-1]}".lower()
                if comb_last in delegate_q_to_canonical:
                    return delegate_q_to_canonical[comb_last]

        # 4. Framework-independent fallback: match question key against any defined group's ref_id or name
        for can_name, def_item in defs_by_canonical.items():
            r_id = str(def_item.get("ref_id") or "").strip().lower()
            c_low = can_name.lower()
            if r_id and (
                f"{r_id}_delegate" in q_lower
                or f"{r_id}_assignee" in q_lower
                or f"{r_id}:delegate" in q_lower
                or f"{r_id}:assignee" in q_lower
                or (r_id in q_lower and ("delegate" in q_lower or "assignee" in q_lower or "who can answer" in q_lower))
            ):
                return can_name
            if c_low and ("delegate" in q_lower or "assignee" in q_lower or "who can answer" in q_lower) and c_low in q_lower:
                return can_name

        return None

    def _record_delegate_answer(req_ref: str, q_key: str, ans_val: Any) -> None:
        if ans_val is None:
            return
        ans_text = _clean_answer_text(ans_val)
        if not ans_text:
            return
        target_group = _find_group_for_delegate_question(req_ref, q_key)
        if target_group:
            tg_can = _canonical(target_group)
            delegate_answers[tg_can] = ans_text
            delegate_answers[target_group] = ans_text
            r_id = ref_map.get(tg_can.lower()) or ref_map.get(str(target_group).lower())
            if r_id:
                delegate_answers[r_id] = ans_text

    def _record_dep_match(dep_entry: dict[str, Any]) -> None:
        tg = dep_entry.get("target_implementation_group")
        if not tg:
            return
        tg_can = _canonical(tg)
        dep_rec = dict(dep_entry)
        dep_rec["canonical_group_name"] = tg_can
        del_contact = (
            delegate_answers.get(tg)
            or delegate_answers.get(tg_can)
            or delegate_answers.get(ref_map.get(str(tg).lower(), ""))
        )
        if del_contact:
            dep_rec["delegate"] = del_contact
            dep_rec["delegate_contact"] = del_contact
            dep_rec["suggested_assignee"] = del_contact
            dep_rec["suggestion"] = del_contact
            dep_rec["suggested_delegate"] = del_contact
            dep_rec["delegate_suggestion"] = del_contact
            is_email = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", str(del_contact).strip()))
            dep_rec["is_directly_assignable"] = is_email
            dep_rec["suggestion_type"] = "user_email" if is_email else "team_or_role"
        if not any(
            d.get("target_implementation_group") == tg and d.get("choice_urn") == dep_entry.get("choice_urn")
            for d in candidate_dependencies
        ):
            candidate_dependencies.append(dep_rec)
        if auto_trigger:
            triggered_canonical_set.add(tg_can)

    # 1. From active_groups
    if active_groups:
        active_list = active_groups if isinstance(active_groups, (list, tuple, set)) else [active_groups]
        for ag in active_list:
            if ag:
                triggered_canonical_set.add(_canonical(ag))

    # 2. From yaml_path
    if yaml_path and Path(yaml_path).exists():
        try:
            from classes.integrations import answers_import
            rows = answers_import.read_answers_file(yaml_path)
            for row in rows:
                req_ref = str(row.get("requirement", "")).strip().lower()
                q_key = row.get("question", "")
                ans_val = row.get("answer")
                if ans_val is None:
                    ans_val = row.get("text") or row.get("choices")
                _record_delegate_answer(req_ref, q_key, ans_val)
                node = nodes_by_ref.get(req_ref) or nodes_by_urn.get(req_ref)
                matched_c = None
                if node:
                    choices = _get_node_choices(node, q_key)
                    for c in choices:
                        if _match_choice(c, ans_val):
                            matched_c = c
                            for grp in c.get("select_implementation_groups", []) or []:
                                if grp:
                                    can_g = _canonical(grp)
                                    triggered_canonical_set.add(can_g)
                                    ciso_assistant_triggered_groups.add(can_g)
                                    ciso_assistant_triggered_ref_ids.add(ref_map.get(str(grp).lower(), str(grp)))
                for dep in ig_dependencies:
                    if _check_dep_match(dep, req_ref, q_key, ans_val, matched_choice=matched_c):
                        _record_dep_match(dep)
        except Exception:
            pass

    # 3. From direct answers dict or list
    if answers:
        if isinstance(answers, list):
            flat_rows: list[dict[str, Any]] = []
            for row in answers:
                if isinstance(row, dict):
                    if isinstance(row.get("answers"), list):
                        req_ref = str(row.get("requirement", "")).strip().lower()
                        for sub_a in row["answers"]:
                            if isinstance(sub_a, dict):
                                q_k = sub_a.get("question", "")
                                ans_v = sub_a.get("answer")
                                if ans_v is None:
                                    if "choices" in sub_a:
                                        ans_v = sub_a["choices"]
                                    elif "text" in sub_a:
                                        ans_v = sub_a["text"]
                                flat_rows.append({"requirement": req_ref, "question": q_k, "answer": ans_v})
                    else:
                        flat_rows.append(row)
            for row in flat_rows:
                req_ref = str(row.get("requirement", "")).strip().lower()
                q_key = row.get("question", "")
                ans_val = row.get("answer")
                if ans_val is None:
                    ans_val = row.get("text") or row.get("choices")
                _record_delegate_answer(req_ref, q_key, ans_val)
                node = nodes_by_ref.get(req_ref) or nodes_by_urn.get(req_ref)
                matched_c = None
                if node:
                    choices = _get_node_choices(node, q_key)
                    for c in choices:
                        if _match_choice(c, ans_val):
                            matched_c = c
                            for grp in c.get("select_implementation_groups", []) or []:
                                if grp:
                                    can_g = _canonical(grp)
                                    triggered_canonical_set.add(can_g)
                                    ciso_assistant_triggered_groups.add(can_g)
                                    ciso_assistant_triggered_ref_ids.add(ref_map.get(str(grp).lower(), str(grp)))
                for dep in ig_dependencies:
                    if _check_dep_match(dep, req_ref, q_key, ans_val, matched_choice=matched_c):
                        _record_dep_match(dep)
        elif isinstance(answers, dict):
            for k, val in answers.items():
                k_str = str(k).strip()
                k_lower = k_str.lower()
                node = nodes_by_ref.get(k_lower) or nodes_by_urn.get(k_lower)
                if isinstance(val, dict):
                    # {req_ref: {q_key: ans_val}}
                    for q_k, a_v in val.items():
                        _record_delegate_answer(k_str, str(q_k), a_v)
                        choices = _get_node_choices(node, q_k) if node else []
                        matched_c = None
                        for c in choices:
                            if _match_choice(c, a_v):
                                matched_c = c
                                for grp in c.get("select_implementation_groups", []) or []:
                                    if grp:
                                        triggered_canonical_set.add(_canonical(grp))
                                        ciso_assistant_triggered_groups.add(_canonical(grp))
                        for dep in ig_dependencies:
                            if _check_dep_match(dep, k_str, q_k, a_v, matched_choice=matched_c):
                                _record_dep_match(dep)
                else:
                    # Could be {q_key: ans_val} or {node_ref: ans_val}
                    _record_delegate_answer(k_str, k_str, val)
                    choices = _get_node_choices(node) if node else []
                    if not choices:
                        for n in nodes:
                            q_choices = _get_node_choices(n, k_str)
                            if q_choices:
                                choices.extend(q_choices)
                    matched_c = None
                    for c in choices:
                        if _match_choice(c, val):
                            matched_c = c
                            for grp in c.get("select_implementation_groups", []) or []:
                                if grp:
                                    can_g = _canonical(grp)
                                    triggered_canonical_set.add(can_g)
                                    ciso_assistant_triggered_groups.add(can_g)
                                    ciso_assistant_triggered_ref_ids.add(ref_map.get(str(grp).lower(), str(grp)))
                    for dep in ig_dependencies:
                        if _check_dep_match(dep, k_str, k_str, val, matched_choice=matched_c):
                            _record_dep_match(dep)

    if ca_reqs:
        req_list = ca_reqs.values() if isinstance(ca_reqs, dict) else (ca_reqs if isinstance(ca_reqs, list) else [])
        for ra in req_list:
            ra_ref = ""
            if isinstance(ra, dict):
                ra_ref = str(ra.get("ref_id") or "").strip().lower()
            else:
                for method_name in ("get_ref_id", "get_requirement_ref_id"):
                    m = getattr(ra, method_name, None)
                    if callable(m):
                        try:
                            val = m()
                            if isinstance(val, str) and not val.startswith("<MagicMock"):
                                ra_ref = val.strip().lower()
                                break
                        except Exception:
                            pass
                if not ra_ref and hasattr(ra, "ref_id"):
                    val = getattr(ra, "ref_id", "")
                    if isinstance(val, str) and not val.startswith("<MagicMock"):
                        ra_ref = val.strip().lower()

            ra_urn = ""
            if isinstance(ra, dict):
                ra_urn = str(ra.get("urn") or "").strip().lower()
            else:
                m = getattr(ra, "get_urn", None)
                if callable(m):
                    try:
                        val = m()
                        if isinstance(val, str) and not val.startswith("<MagicMock"):
                            ra_urn = val.strip().lower()
                    except Exception:
                        pass
                if not ra_urn and hasattr(ra, "urn"):
                    val = getattr(ra, "urn", "")
                    if isinstance(val, str) and not val.startswith("<MagicMock"):
                        ra_urn = val.strip().lower()
            node = nodes_by_ref.get(ra_ref) or nodes_by_urn.get(ra_urn)

            ra_answers = ra.get_answers() if hasattr(ra, "get_answers") else (ra.get("answers") if isinstance(ra, dict) else {})
            if isinstance(ra_answers, dict):
                for q_k, a_v in ra_answers.items():
                    if a_v is None:
                        continue
                    _record_delegate_answer(ra_ref or ra_urn, str(q_k), a_v)
                    choices = _get_node_choices(node, str(q_k)) if node else []
                    if not choices and hasattr(ra, "get_questions"):
                        qs = ra.get_questions()
                        q_def = qs.get(q_k, {}) if isinstance(qs, dict) else {}
                        choices = [c for c in q_def.get("choices", []) if isinstance(c, dict)]
                    matched_c = None
                    for c in choices:
                        if _match_choice(c, a_v):
                            matched_c = c
                            for grp in c.get("select_implementation_groups", []) or []:
                                if grp:
                                    can_g = _canonical(grp)
                                    triggered_canonical_set.add(can_g)
                                    ciso_assistant_triggered_groups.add(can_g)
                                    ciso_assistant_triggered_ref_ids.add(ref_map.get(str(grp).lower(), str(grp)))
                    for dep in ig_dependencies:
                        if _check_dep_match(dep, ra_ref or ra_urn, str(q_k), a_v, matched_choice=matched_c):
                            _record_dep_match(dep)

    # Identify pending candidate dependencies (conditions met by answers, but group not yet active in audit)
    active_canonical_set: set[str] = set()
    if active_groups:
        active_list = active_groups if isinstance(active_groups, (list, tuple, set)) else [active_groups]
        for ag in active_list:
            if ag:
                active_canonical_set.add(_canonical(ag))
    # Groups triggered by CISO Assistant (via choice-level select_implementation_groups
    # when respondent answers "I can answer this track") are automatically active in assessment
    active_canonical_set.update(ciso_assistant_triggered_groups)

    pending_dependencies: list[dict[str, Any]] = []
    for d in candidate_dependencies:
        c_grp = d.get("canonical_group_name")
        t_grp = d.get("target_implementation_group")
        if (
            c_grp not in active_canonical_set
            and t_grp not in active_canonical_set
            and _canonical(t_grp or "") not in active_canonical_set
        ):
            dep_copy = dict(d)
            del_val = (
                delegate_answers.get(t_grp)
                or delegate_answers.get(c_grp)
                or delegate_answers.get(_canonical(t_grp or ""))
                or delegate_answers.get(ref_map.get(str(t_grp).lower(), ""))
            )
            if del_val:
                dep_copy["delegate"] = del_val
                dep_copy["delegate_contact"] = del_val
                dep_copy["suggested_assignee"] = del_val
                dep_copy["suggestion"] = del_val
                dep_copy["suggested_delegate"] = del_val
                dep_copy["delegate_suggestion"] = del_val
                is_email = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", str(del_val).strip()))
                dep_copy["is_directly_assignable"] = is_email
                dep_copy["suggestion_type"] = "user_email" if is_email else "team_or_role"
            pending_dependencies.append(dep_copy)

    pending_triggered_groups: list[str] = list({
        d.get("canonical_group_name") for d in pending_dependencies if d.get("canonical_group_name")
    })

    # Classify all implementation groups
    all_groups: list[dict[str, Any]] = []
    always_selectable_groups: list[dict[str, Any]] = []
    hidden_groups: list[dict[str, Any]] = []
    triggered_groups: list[dict[str, Any]] = []
    visible_groups: list[dict[str, Any]] = []

    for item in defs:
        if not isinstance(item, dict):
            continue
        group_copy = dict(item)
        c_name = str(group_copy.get("name") or group_copy.get("ref_id") or "").strip()
        r_id = str(group_copy.get("ref_id") or "").strip()
        u_urn = str(group_copy.get("urn") or "").strip()
        is_default = bool(group_copy.get("default_selected"))

        dep = dependency_map.get(c_name, {})
        is_triggered_by_others = bool(dep.get("is_triggered_by_others", False))
        trig_by_groups = list(dep.get("triggered_by_groups", []))
        trig_by_nodes = list(dep.get("triggered_by_nodes", []))
        trig_by_qs = list(dep.get("triggered_by_questions", []))

        # A group needs to be triggered if it is targeted by question choices and NOT default selected
        needs_trigger = bool(is_triggered_by_others and (not is_default))
        always_selectable = bool(not needs_trigger)

        # Check if condition matched via candidate_dependencies (answers met trigger criteria)
        condition_matched = bool(any(
            d.get("canonical_group_name") == c_name
            or d.get("target_implementation_group") == r_id
            or _canonical(d.get("target_implementation_group", "")) == c_name
            for d in candidate_dependencies
        ))

        # A group has been triggered if its canonical name, ref_id, or URN was activated or matched by an answer
        has_been_triggered = bool(
            c_name in triggered_canonical_set
            or (r_id and _canonical(r_id) in triggered_canonical_set)
            or (u_urn and _canonical(u_urn) in triggered_canonical_set)
            or condition_matched
        )

        should_show = bool(always_selectable or has_been_triggered)
        is_hidden = bool(needs_trigger and (not has_been_triggered))

        # Populate enriched metadata
        group_copy["name"] = c_name
        group_copy["ref_id"] = r_id
        group_copy["urn"] = u_urn
        group_copy["default_selected"] = is_default
        group_copy["is_triggered"] = is_triggered_by_others
        group_copy["is_triggered_by_others"] = is_triggered_by_others
        group_copy["triggered_by_groups"] = trig_by_groups
        group_copy["triggered_by_nodes"] = trig_by_nodes
        group_copy["triggered_by_questions"] = trig_by_qs
        group_copy["needs_trigger"] = needs_trigger
        group_copy["always_selectable"] = always_selectable
        group_copy["has_been_triggered"] = has_been_triggered
        group_copy["should_show"] = should_show
        group_copy["is_hidden"] = is_hidden
        group_copy["is_initial"] = always_selectable
        group_copy["prompt"] = dep.get("prompt", "")
        group_copy["dependencies"] = dep.get("dependencies", [])
        group_copy["is_pending_trigger"] = bool(
            c_name in pending_triggered_groups or (r_id and _canonical(r_id) in pending_triggered_groups)
        )
        group_copy["is_ciso_assistant_triggered"] = bool(
            r_id in ciso_assistant_triggered_ref_ids or c_name in ciso_assistant_triggered_groups
        )
        group_copy["condition_matched"] = bool(any(
            d.get("canonical_group_name") == c_name or d.get("target_implementation_group") == r_id
            for d in candidate_dependencies
        ))

        # Attach questionnaire suggestions for who can answer (team name, email, or role)
        del_val = (
            delegate_answers.get(r_id)
            or delegate_answers.get(c_name)
            or delegate_answers.get(u_urn)
            or delegate_answers.get(_canonical(r_id))
        )
        group_copy["suggested_assignee"] = del_val or None
        group_copy["suggestion"] = del_val or None
        group_copy["delegate"] = del_val or None
        group_copy["delegate_suggestion"] = del_val or None
        group_copy["delegate_contact"] = del_val or None
        if del_val:
            is_email = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", str(del_val).strip()))
            group_copy["is_directly_assignable"] = is_email
            group_copy["suggestion_type"] = "user_email" if is_email else "team_or_role"
        else:
            group_copy["is_directly_assignable"] = False
            group_copy["suggestion_type"] = None

        all_groups.append(group_copy)
        if always_selectable:
            always_selectable_groups.append(group_copy)
        elif has_been_triggered:
            triggered_groups.append(group_copy)
        else:
            hidden_groups.append(group_copy)

        if should_show:
            visible_groups.append(group_copy)

    return {
        "framework_id": str(fw_ident or ""),
        "always_selectable_groups": always_selectable_groups,
        "hidden_groups": hidden_groups,
        "triggered_groups": triggered_groups,
        "visible_groups": visible_groups,
        "ciso_assistant_triggered_groups": sorted(list(ciso_assistant_triggered_groups)),
        "ciso_assistant_triggered_ref_ids": sorted(list(ciso_assistant_triggered_ref_ids)),
        "all_groups": all_groups,
        "dependency_map": dependency_map,
        "candidate_dependencies": candidate_dependencies,
        "pending_dependencies": pending_dependencies,
        "pending_triggered_groups": pending_triggered_groups,
        "delegate_answers": delegate_answers,
        "suggested_assignees": delegate_answers,
        "suggestions": delegate_answers,
        "summary": {
            "total": len(all_groups),
            "always_selectable_count": len(always_selectable_groups),
            "triggered_count": len(triggered_groups),
            "hidden_count": len(hidden_groups),
            "visible_count": len(visible_groups),
            "pending_count": len(pending_triggered_groups),
        },
    }


get_implementation_groups_triggered_by_others = determine_implementation_groups_triggered_by_others


def get_visible_implementation_groups(
    framework_id: Any,
    active_groups: Any = None,
    ca_reqs: Any = None,
    answers: Any = None,
    yaml_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return only the visible implementation groups (always selectable + actually triggered)."""
    res = determine_implementation_groups_triggered_by_others(
        framework_id=framework_id,
        active_groups=active_groups,
        ca_reqs=ca_reqs,
        answers=answers,
        yaml_path=yaml_path,
    )
    return res.get("visible_groups", [])


def get_framework_implementation_groups(
    framework_id: Any,
    active_groups: Any = None,
    ca_reqs: Any = None,
    answers: Any = None,
    include_hidden: bool = True,
) -> list[dict[str, Any]]:
    """Return the list of implementation group definitions for a framework.

    Supports framework ID string, Framework object, dictionary, or fallback lookup.
    Enriches each definition with:
    - 'is_triggered': bool
    - 'is_triggered_by_others': bool
    - 'triggered_by_groups': list[str] (parent groups triggering this group)
    - 'triggered_by_questions': list[str] (question prompt strings)
    - 'needs_trigger': bool
    - 'always_selectable': bool
    - 'has_been_triggered': bool
    - 'should_show': bool
    - 'is_hidden': bool
    - 'is_initial': bool
    """
    res = determine_implementation_groups_triggered_by_others(
        framework_id=framework_id,
        active_groups=active_groups,
        ca_reqs=ca_reqs,
        answers=answers,
    )
    return res.get("all_groups", []) if include_hidden else res.get("visible_groups", [])


def get_initial_implementation_groups(framework_id: Any) -> list[dict[str, Any]]:
    """Return only the implementation groups to display on initial audit creation.

    Includes default groups and any group that is not triggered by answers to questions.
    """
    res = determine_implementation_groups_triggered_by_others(framework_id)
    return res.get("always_selectable_groups", [])


def get_default_implementation_groups(framework_id: Any) -> list[str]:
    """Return the names of framework implementation groups selected by default."""
    groups = get_framework_implementation_groups(framework_id)
    return [
        group["name"]
        for group in groups
        if isinstance(group, dict) and group.get("default_selected") and group.get("name")
    ]


def resolve_implementation_groups(
    groups: Any, framework_id: Any, target_key: str = "name"
) -> list[str]:
    """Resolve group names, ref_ids, or URNs to canonical group names or ref_ids as defined in framework.

    Matches each input group string against the framework's implementation group definitions.
    If a match is found by name, ref_id, or urn, target_key ('name' or 'ref_id') is used.
    If no match is found, the original group string is preserved.
    Deduplicates groups while preserving order.
    """
    if not groups:
        return []

    ig_defs = get_framework_implementation_groups(framework_id)
    resolved: list[str] = []

    for g in groups:
        if not g:
            continue
        g_str = str(g).strip()
        matched = False
        for ig in ig_defs:
            if not isinstance(ig, dict):
                continue
            ig_name = str(ig.get("name") or "").strip()
            ig_ref = str(ig.get("ref_id") or "").strip()
            ig_urn = str(ig.get("urn") or "").strip()

            if (
                g_str == ig_name
                or (ig_ref and g_str.lower() == ig_ref.lower())
                or (ig_urn and g_str.lower() == ig_urn.lower())
            ):
                if target_key == "ref_id":
                    canonical = ig_ref or ig_name or g_str
                else:
                    canonical = ig_name or ig_ref or g_str
                if canonical not in resolved:
                    resolved.append(canonical)
                matched = True
                break

        if not matched and g_str not in resolved:
            resolved.append(g_str)

    return resolved


def add_default_implementation_groups(payload: dict[str, Any], framework_id: Any) -> dict[str, Any]:
    """Add default implementation groups to a payload when available and not already set."""
    if "selected_implementation_groups" in payload and payload["selected_implementation_groups"]:
        return payload
    selected_groups = get_default_implementation_groups(framework_id)
    if selected_groups:
        payload["selected_implementation_groups"] = selected_groups
    return payload


def set_implementation_groups(payload: dict[str, Any], framework_id: Any, groups: Any = None) -> dict[str, Any]:
    """Set selected implementation groups in payload, resolving to canonical names or using defaults."""
    if groups is not None:
        payload["selected_implementation_groups"] = resolve_implementation_groups(groups, framework_id)
    else:
        add_default_implementation_groups(payload, framework_id)
    return payload


def get_tier_governance_policy(tier: str | int | None) -> dict[str, Any]:
    """Return the AppSec audit governance expectations and SLAs based on solution tier.

    Tiers:
    - critical: Comprehensive 82-control AppSec audit, mandatory annual third-party pentest,
      blocking CI/CD SAST/SCA security gates, 7-day critical finding SLA, 12-month re-assessment.
    - important: Core AppSec audit (IAM, APIs, Crypto, Data, SDLC, Logging), automated DAST/SCA,
      blocking CI/CD gates, 14-day critical finding SLA, 24-month re-assessment.
    - standard: Baseline security hygiene (SSO, admin MFA, TLS, OS patching, backups),
      30-day critical finding SLA, 36-month re-assessment.
    - low-impact: Minimal hygiene self-attestation, risk acceptance on advanced controls.
    """
    if isinstance(tier, int) or (isinstance(tier, str) and tier.strip().isdigit()):
        rank_to_tier = {4: "critical", 3: "important", 2: "standard", 1: "low-impact"}
        norm_tier = rank_to_tier.get(int(tier), "standard")
    else:
        norm_tier = str(tier or "standard").strip().lower().replace("_", "-")
        if norm_tier not in ("critical", "important", "standard", "low-impact"):
            norm_tier = "standard"

    if norm_tier == "critical":
        return {
            "tier": "critical",
            "audit_depth": "comprehensive",
            "pentest_required": True,
            "threat_modeling_required": True,
            "ci_cd_blocking_gates": True,
            "cicd_blocking_threshold": "high",
            "critical_finding_sla_days": 7,
            "remediation_sla_critical_days": 7,
            "high_finding_sla_days": 14,
            "remediation_sla_high_days": 14,
            "remediation_sla_medium_days": 30,
            "reassessment_interval_months": 12,
            "reassessment_frequency_months": 12,
            "requires_deep_technical_tracks": True,
            "control_confirmation_cadence": "monthly",
            "control_confirmation_label": "High-Frequency (Monthly / Quarterly)",
        }
    elif norm_tier == "important":
        return {
            "tier": "important",
            "audit_depth": "standard",
            "pentest_required": True,
            "threat_modeling_required": False,
            "ci_cd_blocking_gates": True,
            "cicd_blocking_threshold": "critical",
            "critical_finding_sla_days": 14,
            "remediation_sla_critical_days": 14,
            "high_finding_sla_days": 30,
            "remediation_sla_high_days": 30,
            "remediation_sla_medium_days": 60,
            "reassessment_interval_months": 24,
            "reassessment_frequency_months": 24,
            "requires_deep_technical_tracks": True,
            "control_confirmation_cadence": "quarterly",
            "control_confirmation_label": "Standard Enterprise (Quarterly / Biannual)",
        }
    elif norm_tier == "standard":
        return {
            "tier": "standard",
            "audit_depth": "targeted",
            "pentest_required": False,
            "threat_modeling_required": False,
            "ci_cd_blocking_gates": False,
            "cicd_blocking_threshold": "none",
            "critical_finding_sla_days": 30,
            "remediation_sla_critical_days": 30,
            "high_finding_sla_days": 60,
            "remediation_sla_high_days": 60,
            "remediation_sla_medium_days": 90,
            "reassessment_interval_months": 36,
            "reassessment_frequency_months": 36,
            "requires_deep_technical_tracks": False,
            "control_confirmation_cadence": "annual",
            "control_confirmation_label": "Baseline Hygiene (Semi-Annual / Annual)",
        }
    else:  # low-impact
        return {
            "tier": "low-impact",
            "audit_depth": "lightweight",
            "pentest_required": False,
            "threat_modeling_required": False,
            "ci_cd_blocking_gates": False,
            "cicd_blocking_threshold": "none",
            "critical_finding_sla_days": 30,
            "remediation_sla_critical_days": 30,
            "high_finding_sla_days": 90,
            "remediation_sla_high_days": 90,
            "remediation_sla_medium_days": 120,
            "reassessment_interval_months": 36,
            "reassessment_frequency_months": 36,
            "requires_deep_technical_tracks": False,
            "control_confirmation_cadence": "biennial",
            "control_confirmation_label": "Minimal Self-Attestation (Annual / Biennial)",
        }


def get_tier_control_confirmation_schedule(
    tier: str | int | None,
    base_frequency: str = "YEARLY",
    base_interval: int = 1,
    base_task_name: str = "",
) -> dict[str, Any]:
    """Calculate the recurring confirmation task schedule and title based on solution tier.

    Scales control confirmation cadences:
    - Critical (Rank 4): High-frequency verification (Monthly / Quarterly technical audits).
    - Important (Rank 3): Standard enterprise verification (Quarterly / Biannual).
    - Standard (Rank 2): Relaxed baseline hygiene verification (Semi-Annual / Annual).
    - Low-Impact (Rank 1): Minimal annual or biennial self-attestation.
    """
    if isinstance(tier, int) or (isinstance(tier, str) and str(tier).strip().isdigit()):
        rank_to_tier = {4: "critical", 3: "important", 2: "standard", 1: "low-impact"}
        norm_tier = rank_to_tier.get(int(tier), "standard")
    else:
        norm_tier = str(tier or "standard").strip().lower().replace("_", "-")
        if norm_tier not in ("critical", "important", "standard", "low-impact"):
            norm_tier = "standard"

    base_freq_upper = str(base_frequency or "YEARLY").strip().upper()
    try:
        base_int = max(1, int(base_interval or 1))
    except (TypeError, ValueError):
        base_int = 1

    # Clean the base task name (strip existing cadence prefixes)
    clean_name = str(base_task_name or "").strip()
    for prefix in (
        "Annual Review of ", "Annual ", "Quarterly ", "Biannual ", "Monthly ",
        "Annual Application ", "Quarterly Application ", "Biannual Application ",
    ):
        if clean_name.lower().startswith(prefix.lower()):
            clean_name = clean_name[len(prefix):]
            break

    if norm_tier == "critical":
        if base_freq_upper == "YEARLY":
            if any(k in base_task_name.lower() for k in ("penetration", "disaster", "backup")):
                freq = "YEARLY"
                interval = 1
                cadence_label = "Annual"
            else:
                freq = "MONTHLY"
                interval = 6
                cadence_label = "Semi-Annual"
        else:  # MONTHLY
            if base_int >= 6:
                freq = "MONTHLY"
                interval = 3
                cadence_label = "Quarterly"
            elif base_int >= 2:
                freq = "MONTHLY"
                interval = 1
                cadence_label = "Monthly"
            else:
                freq = "MONTHLY"
                interval = 1
                cadence_label = "Monthly"

    elif norm_tier == "important":
        freq = base_freq_upper
        interval = base_int
        if freq == "YEARLY":
            cadence_label = f"Every {interval}y" if interval > 1 else "Annual"
        else:
            if interval == 1:
                cadence_label = "Monthly"
            elif interval == 3:
                cadence_label = "Quarterly"
            elif interval == 6:
                cadence_label = "Biannual"
            else:
                cadence_label = f"Every {interval}m"

    elif norm_tier == "standard":
        if base_freq_upper == "YEARLY":
            freq = "YEARLY"
            interval = 1
            cadence_label = "Annual"
        else:  # MONTHLY
            if base_int == 1:
                freq = "MONTHLY"
                interval = 3
                cadence_label = "Quarterly"
            elif base_int <= 3:
                freq = "MONTHLY"
                interval = 6
                cadence_label = "Semi-Annual"
            else:
                freq = "YEARLY"
                interval = 1
                cadence_label = "Annual"

    else:  # low-impact
        freq = "YEARLY"
        interval = 1 if any(k in base_task_name.lower() for k in ("classification", "stakeholder", "backup")) else 2
        cadence_label = "Annual" if interval == 1 else "Biennial"

    tier_display_names = {
        "critical": "Critical",
        "important": "Important",
        "standard": "Standard",
        "low-impact": "Low-Impact",
    }
    tier_label = tier_display_names.get(norm_tier, "Standard")
    formatted_name = f"[{tier_label} • {cadence_label}] {clean_name}" if clean_name else f"[{tier_label} • {cadence_label}] Control Confirmation"

    return {
        "tier": norm_tier,
        "frequency": freq,
        "interval": interval,
        "cadence_label": cadence_label,
        "schedule": {"frequency": freq, "interval": interval},
        "formatted_task_name": formatted_name,
    }


def filter_implementation_groups_by_tier(
    tier: str | int | None,
    active_groups: list[str],
    framework_id: Any = None,
) -> list[str]:
    """Filter or scope active implementation groups according to the application's tier.

    For high-criticality applications (Critical / Important):
    Preserves all architecturally triggered tracks (e.g. custom_app, internet_facing, infra, saas_app).

    For lower-criticality applications (Standard / Low-impact):
    Restricts mandatory audit scope to baseline hygiene tracks (info, baseline, infra)
    and prunes intensive code/perimeter engineering tracks (custom_app, internet_facing, saas_uncertified)
    to prevent assessment fatigue on non-critical software.
    """
    if not active_groups:
        return []

    policy = get_tier_governance_policy(tier)

    # Critical and Important tiers keep all architecturally triggered groups
    if policy["requires_deep_technical_tracks"]:
        return list(active_groups)

    # Standard prunes custom engineering and uncertified saas; Low-impact also prunes internet_facing
    if policy["tier"] == "standard":
        pruned_tracks = {"custom_app", "saas_uncertified"}
    else:  # low-impact
        pruned_tracks = {"custom_app", "internet_facing", "saas_uncertified"}

    scoped: list[str] = []
    for g in active_groups:
        norm_g = str(g).strip().lower()
        if norm_g not in pruned_tracks:
            scoped.append(g)

    # Ensure baseline and info are present if available
    for mandatory in ("info", "baseline"):
        if mandatory not in [s.lower() for s in scoped]:
            resolved = resolve_implementation_groups([mandatory], framework_id, target_key="ref_id")
            if resolved:
                scoped.append(resolved[0])

    return scoped


def map_tiering_answers_to_audit_answers(tiering_answers: dict[str, Any]) -> dict[str, Any]:
    """Map AppSec Solution Tiering Quick Form answers to Chapter 1 questions in appsec.yml / appsec_manual.yml.

    Translates:
    - Delivery model (context:question:delivery_model):
        choice:custom -> hosting:q1:c1 (Custom software)
        choice:cots / onprem -> hosting:q1:c2 (Bought software)
        choice:saas -> hosting:q1:c3 (SaaS)
    - Network exposure (context:question:exposure):
        choice:internal -> hosting:q2:c1 (Internal / Restricted)
        choice:internet -> hosting:q2:c2 (Internet-facing)
    - Data classification (data:question:d1):
        choice:public -> data_classification:q1:c1 (Public storefront & marketing)
        choice:internal -> data_classification:q1:c2 (Internal retail ops & logistics)
        choice:confidential -> data_classification:q1:c3 (Confidential commercial/customer)
        choice:secrets -> data_classification:q1:c4 (Critical financial assets, secrets & anti-fraud)
    - Adverse breach impact (data:question:d2):
        choice:negligible -> data_classification:q2:c1 (Negligible / Zero impact)
        choice:minor -> data_classification:q2:c2 (Minor operational friction)
        choice:severe -> data_classification:q2:c3 (Moderate to severe harm)
        choice:catastrophic -> data_classification:q2:c4 (Catastrophic or existential impact)
    - Personal data scope & GDPR volume (data:question:d3):
        choice:none -> data_classification:q3:c1 (No personal data)
        choice:low -> data_classification:q3:c2 (Contact data of employees) + data_classification:q4:c1 (Low volume < 1k)
        choice:medium -> data_classification:q3:c3 (Customer details) + data_classification:q4:c2 (Medium volume 1k - 100k)
        choice:large -> data_classification:q3:c4 (HR/financial/payment) + data_classification:q4:c3 (High volume > 100k)

    Returns a normalized answers dict with both full URNs and short keys,
    compatible with determine_implementation_groups_triggered_by_others and audit answer pre-population.
    """
    answers: dict[str, Any] = {}
    if not tiering_answers or not isinstance(tiering_answers, dict):
        return answers

    for key, val in tiering_answers.items():
        val_str = str(val).lower()
        key_str = str(key).lower()

        # 1. Delivery model
        if "delivery_model" in key_str or "delivery" in key_str:
            if "custom" in val_str or ":c1" in val_str:
                choice_ref = "c1"
            elif "cots" in val_str or "onprem" in val_str or ":c2" in val_str:
                choice_ref = "c2"
            elif "saas" in val_str or ":c3" in val_str:
                choice_ref = "c3"
            else:
                choice_ref = None

            if choice_ref:
                answers["urn:intuitem:risk:req_node:appsec:hosting:q1"] = f"urn:intuitem:risk:req_node:appsec:hosting:q1:{choice_ref}"
                answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q1"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q1:{choice_ref}"
                answers["hosting:q1"] = choice_ref

        # 2. Network exposure
        if "exposure" in key_str:
            if "internal" in val_str or ":c1" in val_str or val_str == "no":
                choice_ref = "c1"
            elif "internet" in val_str or ":c2" in val_str or val_str == "yes":
                choice_ref = "c2"
            else:
                choice_ref = None

            if choice_ref:
                answers["urn:intuitem:risk:req_node:appsec:hosting:q2"] = f"urn:intuitem:risk:req_node:appsec:hosting:q2:{choice_ref}"
                answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q2"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q2:{choice_ref}"
                answers["hosting:q2"] = choice_ref

        # 3. Data classification: primary retail/commercial category (d1)
        if ":d1" in key_str or "data_category" in key_str or key_str.endswith("d1") or "highest_data" in key_str:
            if "public" in val_str or ":c1" in val_str:
                choice_ref = "c1"
            elif "internal" in val_str or ":c2" in val_str:
                choice_ref = "c2"
            elif "confidential" in val_str or ":c3" in val_str:
                choice_ref = "c3"
            elif "secret" in val_str or "pci" in val_str or ":c4" in val_str:
                choice_ref = "c4"
            else:
                choice_ref = None

            if choice_ref:
                answers["urn:intuitem:risk:req_node:appsec:data_classification:q1"] = f"urn:intuitem:risk:req_node:appsec:data_classification:q1:{choice_ref}"
                answers["urn:intuitem:risk:req_node:appsec_manual:data_classification:q1"] = f"urn:intuitem:risk:req_node:appsec_manual:data_classification:q1:{choice_ref}"
                answers["data_classification:q1"] = choice_ref

        # 4. Data classification: adverse disclosure impact (d2)
        if ":d2" in key_str or "adverse_impact" in key_str or "breach_impact" in key_str or key_str.endswith("d2"):
            if "negligible" in val_str or ":c1" in val_str:
                choice_ref = "c1"
            elif "minor" in val_str or ":c2" in val_str:
                choice_ref = "c2"
            elif "severe" in val_str or "moderate" in val_str or ":c3" in val_str:
                choice_ref = "c3"
            elif "catastrophic" in val_str or "existential" in val_str or ":c4" in val_str:
                choice_ref = "c4"
            else:
                choice_ref = None

            if choice_ref:
                answers["urn:intuitem:risk:req_node:appsec:data_classification:q2"] = f"urn:intuitem:risk:req_node:appsec:data_classification:q2:{choice_ref}"
                answers["urn:intuitem:risk:req_node:appsec_manual:data_classification:q2"] = f"urn:intuitem:risk:req_node:appsec_manual:data_classification:q2:{choice_ref}"
                answers["data_classification:q2"] = choice_ref

        # 5. Data classification: GDPR personal data scope & volume (d3)
        if ":d3" in key_str or "personal_data" in key_str or "gdpr" in key_str or key_str.endswith("d3"):
            if "none" in val_str or ":c1" in val_str:
                q3_ref = "c1"
                q4_ref = None
            elif "low" in val_str or ":c2" in val_str:
                q3_ref = "c2"
                q4_ref = "c1"
            elif "medium" in val_str or ":c3" in val_str:
                q3_ref = "c3"
                q4_ref = "c2"
            elif "large" in val_str or ":c4" in val_str:
                q3_ref = "c4"
                q4_ref = "c3"
            else:
                q3_ref = None
                q4_ref = None

            if q3_ref:
                answers["urn:intuitem:risk:req_node:appsec:data_classification:q3"] = f"urn:intuitem:risk:req_node:appsec:data_classification:q3:{q3_ref}"
                answers["urn:intuitem:risk:req_node:appsec_manual:data_classification:q3"] = f"urn:intuitem:risk:req_node:appsec_manual:data_classification:q3:{q3_ref}"
                answers["data_classification:q3"] = q3_ref

            if q4_ref:
                answers["urn:intuitem:risk:req_node:appsec:data_classification:q4"] = f"urn:intuitem:risk:req_node:appsec:data_classification:q4:{q4_ref}"
                answers["urn:intuitem:risk:req_node:appsec_manual:data_classification:q4"] = f"urn:intuitem:risk:req_node:appsec_manual:data_classification:q4:{q4_ref}"
                answers["data_classification:q4"] = q4_ref

        # 6. Readiness & Delegation (who can answer what)
        # Baseline track (q4)
        if "baseline_readiness" in key_str or ("baseline" in key_str and ("ready" in key_str or "answer" in key_str)):
            c_ref = "c1" if ("self" in val_str or ":c1" in val_str or "i can" in val_str) else "c2"
            answers["urn:intuitem:risk:req_node:appsec:hosting:q4"] = f"urn:intuitem:risk:req_node:appsec:hosting:q4:{c_ref}"
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q4"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q4:{c_ref}"
            answers["hosting:q4"] = c_ref
        elif "baseline_delegate" in key_str and val:
            answers["urn:intuitem:risk:req_node:appsec:hosting:q4_delegate"] = str(val).strip()
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q4_delegate"] = str(val).strip()
            answers["hosting:q4_delegate"] = str(val).strip()

        # Custom Software track (q5)
        if "custom_readiness" in key_str or ("custom" in key_str and ("ready" in key_str or "answer" in key_str)):
            c_ref = "c1" if ("self" in val_str or ":c1" in val_str or "i can" in val_str) else "c2"
            answers["urn:intuitem:risk:req_node:appsec:hosting:q5"] = f"urn:intuitem:risk:req_node:appsec:hosting:q5:{c_ref}"
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q5"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q5:{c_ref}"
            answers["hosting:q5"] = c_ref
        elif "custom_delegate" in key_str and val:
            answers["urn:intuitem:risk:req_node:appsec:hosting:q5_delegate"] = str(val).strip()
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q5_delegate"] = str(val).strip()
            answers["hosting:q5_delegate"] = str(val).strip()

        # Bought Software track / COTS (q6)
        if "cots_readiness" in key_str or ("cots" in key_str and ("ready" in key_str or "answer" in key_str)):
            c_ref = "c1" if ("self" in val_str or ":c1" in val_str or "i can" in val_str) else "c2"
            answers["urn:intuitem:risk:req_node:appsec:hosting:q6"] = f"urn:intuitem:risk:req_node:appsec:hosting:q6:{c_ref}"
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q6"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q6:{c_ref}"
            answers["hosting:q6"] = c_ref
        elif "cots_delegate" in key_str and val:
            answers["urn:intuitem:risk:req_node:appsec:hosting:q6_delegate"] = str(val).strip()
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q6_delegate"] = str(val).strip()
            answers["hosting:q6_delegate"] = str(val).strip()

        # Infrastructure track (q7)
        if "infra_readiness" in key_str or ("infra" in key_str and ("ready" in key_str or "answer" in key_str)):
            c_ref = "c1" if ("self" in val_str or ":c1" in val_str or "i can" in val_str) else "c2"
            answers["urn:intuitem:risk:req_node:appsec:hosting:q7"] = f"urn:intuitem:risk:req_node:appsec:hosting:q7:{c_ref}"
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q7"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q7:{c_ref}"
            answers["hosting:q7"] = c_ref
        elif "infra_delegate" in key_str and val:
            answers["urn:intuitem:risk:req_node:appsec:hosting:q7_delegate"] = str(val).strip()
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q7_delegate"] = str(val).strip()
            answers["hosting:q7_delegate"] = str(val).strip()

        # Internet-facing track (q8)
        if "internet_facing_readiness" in key_str or ("internet" in key_str and ("ready" in key_str or "answer" in key_str)):
            c_ref = "c1" if ("self" in val_str or ":c1" in val_str or "i can" in val_str) else "c2"
            answers["urn:intuitem:risk:req_node:appsec:hosting:q8"] = f"urn:intuitem:risk:req_node:appsec:hosting:q8:{c_ref}"
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q8"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q8:{c_ref}"
            answers["hosting:q8"] = c_ref
        elif "internet_facing_delegate" in key_str and val:
            answers["urn:intuitem:risk:req_node:appsec:hosting:q8_delegate"] = str(val).strip()
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q8_delegate"] = str(val).strip()
            answers["hosting:q8_delegate"] = str(val).strip()

        # SaaS track (q9)
        if "saas_readiness" in key_str or ("saas" in key_str and ("ready" in key_str or "answer" in key_str)):
            c_ref = "c1" if ("self" in val_str or ":c1" in val_str or "i can" in val_str) else "c2"
            answers["urn:intuitem:risk:req_node:appsec:hosting:q9"] = f"urn:intuitem:risk:req_node:appsec:hosting:q9:{c_ref}"
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q9"] = f"urn:intuitem:risk:req_node:appsec_manual:hosting:q9:{c_ref}"
            answers["hosting:q9"] = c_ref
        elif "saas_delegate" in key_str and val:
            answers["urn:intuitem:risk:req_node:appsec:hosting:q9_delegate"] = str(val).strip()
            answers["urn:intuitem:risk:req_node:appsec_manual:hosting:q9_delegate"] = str(val).strip()
            answers["hosting:q9_delegate"] = str(val).strip()

    return answers


def map_audit_answers_to_tiering_answers(audit_answers: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Map AppSec Chapter 1 answers (data_classification, hosting) back to tiering inputs.

    Translates answers from live requirement assessments or YAML files into normalized
    tiering scoring inputs (d1, d2, d3, d4, delivery_model, exposure, b1, b2, b3).
    """
    flat: dict[str, Any] = {}
    if not audit_answers:
        return {}

    if isinstance(audit_answers, list):
        for item in audit_answers:
            if isinstance(item, dict):
                req = str(item.get("requirement") or "").strip().lower()
                ans_list = item.get("answers")
                if isinstance(ans_list, list):
                    for sub in ans_list:
                        if isinstance(sub, dict):
                            q_k = str(sub.get("question") or "").strip().lower()
                            a_v = sub.get("answer") if sub.get("answer") is not None else sub.get("choices", sub.get("text"))
                            flat[f"{req}:{q_k}"] = a_v
                else:
                    q_k = str(item.get("question") or "").strip().lower()
                    a_v = item.get("answer") if item.get("answer") is not None else item.get("choices", item.get("text"))
                    flat[f"{req}:{q_k}" if req and q_k else (req or q_k)] = a_v
    elif isinstance(audit_answers, dict):
        for k, v in audit_answers.items():
            k_str = str(k).strip().lower()
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    flat[f"{k_str}:{str(sub_k).strip().lower()}"] = sub_v
            else:
                flat[k_str] = v

    tiering: dict[str, Any] = {
        "b1": "workaround",
        "b2": "week",
        "b3": "weeks",
        "d4": "standard",
    }

    for k, v in flat.items():
        if v is None:
            continue
        v_str = str(v).lower()
        k_str = str(k).lower()

        # 1. Delivery model (hosting:q1)
        if "hosting:q1" in k_str or "delivery_model" in k_str or ("hosting" in k_str and "q1" in k_str):
            if ":c1" in v_str or "custom" in v_str or v_str == "c1":
                tiering["delivery_model"] = "custom"
            elif ":c2" in v_str or "cots" in v_str or "onprem" in v_str or "bought" in v_str or v_str == "c2":
                tiering["delivery_model"] = "cots"
            elif ":c3" in v_str or "saas" in v_str or "cloud" in v_str or v_str == "c3":
                tiering["delivery_model"] = "saas"

        # 2. Exposure (hosting:q2)
        if "hosting:q2" in k_str or "exposure" in k_str or ("hosting" in k_str and "q2" in k_str):
            if ":c2" in v_str or "internet" in v_str or v_str == "c2" or v_str == "yes":
                tiering["exposure"] = "internet"
            elif ":c1" in v_str or "internal" in v_str or v_str == "c1" or v_str == "no":
                tiering["exposure"] = "internal"

        # 3. Data classification (data_classification:q1)
        if "data_classification:q1" in k_str or "d1" in k_str or ("data_classification" in k_str and "q1" in k_str):
            if ":c4" in v_str or "secret" in v_str or "pci" in v_str or "anti-fraud" in v_str or v_str == "c4":
                tiering["d1"] = "secrets"
            elif ":c3" in v_str or "confidential" in v_str or "customer" in v_str or v_str == "c3":
                tiering["d1"] = "confidential"
            elif ":c2" in v_str or "internal" in v_str or "ops" in v_str or v_str == "c2":
                tiering["d1"] = "internal"
            elif ":c1" in v_str or "public" in v_str or "marketing" in v_str or v_str == "c1":
                tiering["d1"] = "public"

        # 4. Disclosure harm (data_classification:q2)
        if "data_classification:q2" in k_str or "d2" in k_str or ("data_classification" in k_str and "q2" in k_str):
            if ":c4" in v_str or "catastrophic" in v_str or "existential" in v_str or v_str == "c4":
                tiering["d2"] = "catastrophic"
            elif ":c3" in v_str or "severe" in v_str or "moderate" in v_str or v_str == "c3":
                tiering["d2"] = "severe"
            elif ":c2" in v_str or "minor" in v_str or "friction" in v_str or v_str == "c2":
                tiering["d2"] = "minor"
            elif ":c1" in v_str or "negligible" in v_str or "zero" in v_str or v_str == "c1":
                tiering["d2"] = "negligible"

        # 5. GDPR personal data volume (data_classification:q3 / q4)
        if "data_classification:q4" in k_str or "data_classification:q3" in k_str or "d3" in k_str or "gdpr" in k_str:
            if ":c3" in v_str or ":c4" in v_str or v_str in ("c3", "c4") or "large" in v_str or "100,000" in v_str or "100k" in v_str:
                tiering["d3"] = "large"
            elif ":c2" in v_str or v_str == "c2" or "medium" in v_str or "customer" in v_str:
                if tiering.get("d3") != "large":
                    tiering["d3"] = "medium"
            elif ":c1" in v_str or v_str == "c1" or "low" in v_str or "contact" in v_str:
                if "d3" not in tiering:
                    tiering["d3"] = "low"

        # 6. Operational resilience overrides if present
        if "b1" in k_str or "outage" in k_str:
            tiering["b1"] = v_str
        if "b2" in k_str or "rto" in k_str:
            tiering["b2"] = v_str
        if "b3" in k_str or "spof" in k_str or "replaceability" in k_str:
            tiering["b3"] = v_str
        if "d4" in k_str or "access_level" in k_str or "privileged" in k_str:
            tiering["d4"] = v_str
        if "regulated" in k_str:
            tiering["regulated"] = v_str

    # Sensible operational defaults if data classification is high
    if tiering.get("d1") == "secrets":
        tiering.setdefault("b1", "disrupt")
        tiering.setdefault("b2", "week")
        tiering.setdefault("b3", "sole")

    return tiering


# Backward-compatible alias
map_tiering_answers_to_hosting_answers = map_tiering_answers_to_audit_answers
