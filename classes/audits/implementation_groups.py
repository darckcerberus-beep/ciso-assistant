"""Shared helpers for framework implementation groups."""

from .. import utils


def get_framework_triggered_implementation_groups_map(framework_id) -> dict[str, list[str]]:
    """Return a mapping of triggered group identifier (lowercase) -> list of trigger question texts.

    Inspects framework requirement node question choices for 'select_implementation_groups'.
    """
    triggered_map: dict[str, list[str]] = {}
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
            nodes = fw_meta.get("requirement_nodes", [])
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                questions = node.get("questions", {})
                q_items = questions.values() if isinstance(questions, dict) else (questions if isinstance(questions, list) else [])
                for q in q_items:
                    if not isinstance(q, dict):
                        continue
                    q_text = str(q.get("text", "")).strip()
                    choices = q.get("choices", [])
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
    except Exception:
        pass
    return triggered_map


def get_framework_implementation_groups(framework_id):
    """Return the list of implementation group definitions for a framework.

    Supports framework ID string, Framework object, dictionary, or fallback lookup.
    Enriches each definition with:
    - 'is_triggered': bool (True if triggered by question answers)
    - 'is_initial': bool (True if default_selected or not is_triggered)
    - 'triggered_by_questions': list of question prompt strings that trigger this group
    """
    defs = []
    if isinstance(framework_id, dict):
        framework = framework_id
        defs = framework.get("implementation_groups_definition", [])
    elif hasattr(framework_id, "get_implementation_groups_definition"):
        defs = framework_id.get_implementation_groups_definition()
        if not defs:
            framework = getattr(framework_id, "json_object", {}) or {}
            defs = framework.get("implementation_groups_definition", [])
    elif hasattr(framework_id, "json_object"):
        framework = getattr(framework_id, "json_object", {}) or {}
        defs = framework.get("implementation_groups_definition", [])
    else:
        fw_str = str(framework_id).strip()
        catalog_refs = {"mls", "vendor-due-diligence", "appsec"}
        if fw_str.lower() not in catalog_refs and not fw_str.endswith((".yml", ".yaml")):
            framework = utils.get_return(f"/api/frameworks/{fw_str}/")
            if isinstance(framework, dict):
                defs = framework.get("implementation_groups_definition", [])

    if not defs:
        # Fallback to local catalog / YAML definition if API response is empty or unauthenticated
        try:
            from ..examples_manager import ExamplesManager
            fw_meta = ExamplesManager._load_framework_metadata(str(framework_id))
            if fw_meta and fw_meta.get("implementation_groups_definition"):
                defs = fw_meta.get("implementation_groups_definition", [])
        except Exception:
            pass

    if not defs or not isinstance(defs, list):
        return []

    # Enrich definitions with triggered metadata
    triggered_map = get_framework_triggered_implementation_groups_map(framework_id)

    enriched_defs = []
    for item in defs:
        if not isinstance(item, dict):
            continue
        group_copy = dict(item)
        ref_norm = str(group_copy.get("ref_id", "")).strip().lower()
        name_norm = str(group_copy.get("name", "")).strip().lower()
        urn_norm = str(group_copy.get("urn", "")).strip().lower()

        trigger_qs = []
        is_triggered = False
        for identifier in (ref_norm, name_norm, urn_norm):
            if identifier and identifier in triggered_map:
                is_triggered = True
                for q_text in triggered_map[identifier]:
                    if q_text not in trigger_qs:
                        trigger_qs.append(q_text)

        is_default = bool(group_copy.get("default_selected"))
        is_initial = is_default or (not is_triggered)

        group_copy["is_triggered"] = is_triggered
        group_copy["is_initial"] = is_initial
        group_copy["triggered_by_questions"] = trigger_qs
        enriched_defs.append(group_copy)

    return enriched_defs


def get_initial_implementation_groups(framework_id):
    """Return only the implementation groups to display on initial audit creation.

    Includes default groups and any group that is not triggered by answers to questions.
    """
    groups = get_framework_implementation_groups(framework_id)
    return [
        group
        for group in groups
        if isinstance(group, dict) and (group.get("default_selected") or not group.get("is_triggered"))
    ]


def get_default_implementation_groups(framework_id):
    """Return the names of framework implementation groups selected by default."""
    groups = get_framework_implementation_groups(framework_id)
    return [
        group["name"]
        for group in groups
        if isinstance(group, dict) and group.get("default_selected") and group.get("name")
    ]


def resolve_implementation_groups(groups, framework_id):
    """Resolve group names, ref_ids, or URNs to canonical group names as defined in framework.

    Matches each input group string against the framework's implementation group definitions.
    If a match is found by name, ref_id, or urn, the canonical name is used.
    If no match is found, the original group string is preserved.
    Deduplicates groups while preserving order.
    """
    if not groups:
        return []

    ig_defs = get_framework_implementation_groups(framework_id)
    resolved = []

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
                canonical = ig_name or ig_ref or g_str
                if canonical not in resolved:
                    resolved.append(canonical)
                matched = True
                break

        if not matched and g_str not in resolved:
            resolved.append(g_str)

    return resolved


def add_default_implementation_groups(payload, framework_id):
    """Add default implementation groups to a payload when available and not already set."""
    if "selected_implementation_groups" in payload and payload["selected_implementation_groups"]:
        return payload
    selected_groups = get_default_implementation_groups(framework_id)
    if selected_groups:
        payload["selected_implementation_groups"] = selected_groups
    return payload


def set_implementation_groups(payload, framework_id, groups=None):
    """Set selected implementation groups in payload, resolving to canonical names or using defaults."""
    if groups is not None:
        payload["selected_implementation_groups"] = resolve_implementation_groups(groups, framework_id)
    else:
        add_default_implementation_groups(payload, framework_id)
    return payload