from .. import utils


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

    def get_name_from_id(self, control_id):
        """Get control name by ID.

        Args:
            control_id: The control ID to search for

        Returns:
            Control name if found, None otherwise
        """
        for c in self.controls:
            if c.get_id() == control_id:
                return c.get_name()
        return None


class ReferenceControl:
    """Represents a reference control."""

    def __init__(self, json_control):
        """Initialize with control data."""
        self.json_object = json_control

    def get_name(self):
        """Return the control name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the control ID."""
        return self.json_object.get('id', '')

    def print_name(self):
        """Print the control name."""
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        """Print the control ID."""
        utils.log(f"ID: {self.get_id()}")
