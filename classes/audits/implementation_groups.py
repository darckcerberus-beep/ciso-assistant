"""Shared helpers for framework implementation groups."""

from .. import utils


def get_framework_implementation_groups(framework_id):
    """Return the list of implementation group definitions for a framework.

    Supports framework ID string, Framework object, dictionary, or fallback lookup.
    """
    if isinstance(framework_id, dict):
        framework = framework_id
    elif hasattr(framework_id, "get_implementation_groups_definition"):
        defs = framework_id.get_implementation_groups_definition()
        if defs:
            return defs
        framework = getattr(framework_id, "json_object", {}) or {}
    elif hasattr(framework_id, "json_object"):
        framework = getattr(framework_id, "json_object", {}) or {}
    else:
        framework = utils.get_return(f"/api/frameworks/{framework_id}/")

    if isinstance(framework, dict):
        defs = framework.get("implementation_groups_definition", [])
        if defs:
            return defs

    # Fallback to local catalog / YAML definition if API response is empty or unauthenticated
    try:
        from ..examples_manager import ExamplesManager
        fw_meta = ExamplesManager._load_framework_metadata(str(framework_id))
        if fw_meta and fw_meta.get("implementation_groups_definition"):
            return fw_meta.get("implementation_groups_definition")
    except Exception:
        pass

    return []


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