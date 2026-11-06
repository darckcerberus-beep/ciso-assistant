from pathlib import Path
from .. import utils

_YAML_REFERENCE_CONTROLS = None


def _get_yaml_reference_controls():
    """Load and index all reference controls declared in local YAML library files."""
    global _YAML_REFERENCE_CONTROLS
    if _YAML_REFERENCE_CONTROLS is not None:
        return _YAML_REFERENCE_CONTROLS

    yaml_controls = {}
    base_dir = Path(__file__).resolve().parent.parent.parent
    candidate_files = [
        base_dir / "YML/appsec_objects.yml",
        base_dir / "YML/newDPP.yml",
        base_dir / "YML/vendor-due-diligence.yaml",
    ]
    for yf in candidate_files:
        if not yf.exists():
            continue
        try:
            data = utils.load_yaml_file(str(yf))
            for c in data.get("objects", {}).get("reference_controls", []):
                if "urn" in c:
                    yaml_controls[c["urn"]] = c
                    urn_suffix = c["urn"].rsplit(":", 1)[-1]
                    yaml_controls[urn_suffix] = c
                if "ref_id" in c:
                    yaml_controls[c["ref_id"]] = c
                if "name" in c:
                    yaml_controls[c["name"]] = c
        except Exception:
            pass

    _YAML_REFERENCE_CONTROLS = yaml_controls
    return _YAML_REFERENCE_CONTROLS


class ReferenceControlDict:
    """Dictionary of reference controls."""

    def __init__(self):
        """Initialize and load all reference controls."""
        self.reload()

    def reload(self):
        """Reload all reference controls from the API."""
        self.controls = [ReferenceControl(c) for c in utils.get_all_results("/api/reference-controls/", force_reload=True)]

    def get_controls(self):
        """Return all controls."""
        return self.controls

    def print_controls(self):
        """Print all control names and IDs."""
        for c in self.controls:
            c.print_name()
            c.print_id()

    def get_control_from_id(self, control_id):
        """Get ReferenceControl instance by ID, URN, ref_id, or name.

        Args:
            control_id: The control ID, URN, ref_id, or name to search for

        Returns:
            ReferenceControl if found, None otherwise
        """
        if not control_id:
            return None

        # 1. Match by UUID id
        for c in self.controls:
            if c.get_id() == control_id:
                return c

        # 2. Match by URN
        for c in self.controls:
            if c.get_urn() == control_id:
                return c

        # 3. Match by ref_id
        for c in self.controls:
            if c.get_ref_id() == control_id:
                return c

        # 4. Match by name
        for c in self.controls:
            if c.get_name() == control_id:
                return c

        # 5. Fallback: match by URN suffix or YAML definition
        yaml_map = _get_yaml_reference_controls()
        if control_id in yaml_map:
            return ReferenceControl(yaml_map[control_id])
        control_suffix = control_id.rsplit(":", 1)[-1] if ":" in control_id else control_id
        if control_suffix in yaml_map:
            return ReferenceControl(yaml_map[control_suffix])

        return None

    def get_name_from_id(self, control_id):
        """Get control name by ID.

        Args:
            control_id: The control ID to search for

        Returns:
            Control name if found, None otherwise
        """
        ctrl = self.get_control_from_id(control_id)
        if ctrl:
            return ctrl.get_name()
        return None


class ReferenceControl:
    """Represents a reference control."""

    def __init__(self, json_control):
        """Initialize with control data."""
        self.json_object = dict(json_control) if isinstance(json_control, dict) else {}
        self._enrich_with_yaml()

    def _enrich_with_yaml(self):
        """Enrich API control data with recurrence and task definitions from YAML."""
        yaml_map = _get_yaml_reference_controls()
        urn = self.get_urn()
        ref_id = self.get_ref_id()
        name = self.get_name()

        match = None
        if urn and urn in yaml_map:
            match = yaml_map[urn]
        elif ref_id and ref_id in yaml_map:
            match = yaml_map[ref_id]
        elif urn and urn.rsplit(":", 1)[-1] in yaml_map:
            match = yaml_map[urn.rsplit(":", 1)[-1]]
        elif name and name in yaml_map:
            match = yaml_map[name]

        if match:
            for k in ("is_recurrent", "cadence", "task"):
                if k in match and k not in self.json_object:
                    self.json_object[k] = match[k]

    def get_name(self):
        """Return the control name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the control ID."""
        return self.json_object.get('id', '')

    def get_urn(self):
        """Return the control URN."""
        return self.json_object.get('urn', '')

    def get_ref_id(self):
        """Return the control ref_id."""
        return self.json_object.get('ref_id', '')

    def get_json(self):
        """Return the raw control dictionary."""
        return self.json_object

    def is_recurrent(self):
        """Return whether this control is recurrent."""
        return self.json_object.get('is_recurrent', False)

    def get_task(self):
        """Return the task configuration if defined."""
        return self.json_object.get('task')

    def print_name(self):
        """Print the control name."""
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        """Print the control ID."""
        utils.log(f"ID: {self.get_id()}")
