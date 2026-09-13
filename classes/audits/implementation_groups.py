"""Shared helpers for framework implementation groups."""

from .. import utils


def get_default_implementation_groups(framework_id):
    """Return the names of framework implementation groups selected by default."""
    framework = utils.get_return(f'/api/frameworks/{framework_id}/')
    if not isinstance(framework, dict):
        return []
    return [
        group['name']
        for group in framework.get('implementation_groups_definition', [])
        if isinstance(group, dict) and group.get('default_selected') and group.get('name')
    ]


def add_default_implementation_groups(payload, framework_id):
    """Add default implementation groups to a payload when available."""
    selected_groups = get_default_implementation_groups(framework_id)
    if selected_groups:
        payload['selected_implementation_groups'] = selected_groups
    return payload