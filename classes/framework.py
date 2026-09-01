from pprint import pformat

from . import utils


class Library:
    """Represents a single library object from the API."""

    def __init__(self, json_library):
        self.json_object = json_library

    def get_json(self):
        """Return the raw JSON payload for the library."""
        return self.json_object


class LibraryDict:
    """Handle a collection of libraries loaded from the API."""

    def __init__(self):
        # Log the start of the library loading process.
        utils.log("Loading libraries...")
        self.reload()

    def reload(self):
        """Reload all libraries from the API."""
        self.libraries = {}
        for library in utils.get_all_results("/api/libraries/", force_reload=True):
            utils.log(
                f"Loading library: {library.get('name', '')} "
                f"(ID: {library.get('id', '')})"
            )
            self.libraries[library.get("id")] = Library(library)

    def get_libraries(self):
        """Return the dictionary of libraries keyed by ID."""
        return self.libraries

    def print_libraries(self):
        """Log each library payload for debugging purposes."""
        for library in self.libraries.values():
            utils.log(pformat(library.get_json()))


class Framework:
    """Represent a single framework object."""

    def __init__(self, json_framework):
        self.json_object = json_framework

    def get_name(self):
        return self.json_object.get("name", "")

    def get_id(self):
        return self.json_object.get("id", "")

    def print_name(self):
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        utils.log(f"ID: {self.get_id()}")

    def print_json(self):
        utils.log(pformat(self.json_object))

    def get_risk_scenarios(self):
        return self.json_object.get("objects", {}).get("risk_scenarios", [])

    def get_risk_matrix(self):
        return self.json_object.get("risk_matrix", [])

    def get_library_id(self):
        return self.json_object.get("library", {}).get("id", None)


class FrameworkDict:
    """Handle a collection of frameworks loaded from the API."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload all frameworks from the API."""
        self.frameworks = [Framework(f) for f in utils.get_all_results("/api/frameworks/", force_reload=True)]

    def get_frameworks(self):
        """Return the list of framework objects."""
        return self.frameworks

    def print_frameworks(self):
        """Log each framework name and ID."""
        for framework in self.frameworks:
            framework.print_name()
            framework.print_id()

    def print_framework_json(self):
        """Log the raw JSON for each framework."""
        for framework in self.frameworks:
            framework.print_json()

    def get_id_from_name(self, name):
        """Return a framework ID matching the given name."""
        for framework in self.frameworks:
            if framework.get_name() == name:
                return framework.get_id()
        return None

    def get_name_from_id(self, id):
        """Return the framework name matching the given ID."""
        for framework in self.frameworks:
            if framework.get_id() == id:
                return framework.get_name()
        return None

    def get_risk_scenarios_from_id(self, id):
        """Return the risk scenarios for the framework matching the given ID."""
        for framework in self.frameworks:
            if framework.get_id() == id:
                return framework.get_risk_scenarios()
        return None

    def get_all_risk_scenarios(self):
        """Flatten all risk scenarios from all frameworks into a single list."""
        all_risk_scenarios = []
        for framework in self.frameworks:
            all_risk_scenarios.extend(framework.get_risk_scenarios())
        return all_risk_scenarios

    def print_all_risk_scenarios(self):
        """Log each risk scenario with description and scoring details."""
        for framework in self.frameworks:
            utils.log(f"Framework: {framework.get_name()}")
            for risk_scenario in framework.get_risk_scenarios():
                utils.log(
                    f"Risk Scenario: {risk_scenario.get('name', '')}\n"
                    f"Description: {risk_scenario.get('description', '')}"
                )
                utils.log(
                    f"Likelihood: {risk_scenario.get('likelihood', '')}\n"
                    f"Impact: {risk_scenario.get('impact', '')}\n"
                )

    def get_risk_matrix_from_id(self, id):
        """Return the risk matrix for the framework matching the given ID."""
        for framework in self.frameworks:
            if framework.get_id() == id:
                return framework.get_risk_matrix()
        return None

    def get_all_risk_matrices(self):
        """Return a list containing each framework's risk matrix."""
        all_risk_matrices = []
        for framework in self.frameworks:
            all_risk_matrices.append(framework.get_risk_matrix())
        return all_risk_matrices

    def print_all_risk_matrices(self):
        """Log each framework risk matrix."""
        for framework in self.frameworks:
            utils.log(f"Framework: {framework.get_name()}")
            utils.log("Risk Matrix:")
            for row in framework.get_risk_matrix():
                utils.log(pformat(row))

    def print_library_ids(self):
        """Compatibility wrapper: log the library ID for each framework."""
        for framework in self.frameworks:
            utils.log(f"Framework: {framework.get_name()}")
            utils.log(f"Library ID: {framework.get_library_id()}")

    def get_library_id_from_framework_id(self, framework_id):
        """Return the library ID associated with a framework ID."""
        for framework in self.frameworks:
            if framework.get_id() == framework_id:
                return framework.get_library_id()
        return None


class FrameworkFile:
    """Represent a framework loaded from a YAML file."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.json_file = filepath
        self.json_object = utils.load_yaml_file(filepath)

    def get_name(self):
        return self.json_object.get("name", "")

    def get_id(self):
        return self.json_object.get("id", "")

    def print_name(self):
        utils.log(f"Name: {self.get_name()}")

    def print_id(self):
        utils.log(f"ID: {self.get_id()}")

    def print_json(self):
        utils.log(pformat(self.json_object))

    def read(self):
        """Reload the JSON payload from the configured file path."""
        self.json_object = utils.load_json_file(self.json_file)

    def load_from_yaml_file(self, yaml_file):
        """Load and return a framework from a YAML file."""
        return utils.load_yaml_file(yaml_file)

    def print_risk_scenario(self):
        """Log all risk scenarios declared in the local framework."""
        risk_scenarios = self.json_object.get("objects", {}).get("risk_scenarios", [])
        for risk_scenario in risk_scenarios:
            utils.log(
                f"Risk Scenario: {risk_scenario.get('name', '')}\n"
                f"Description: {risk_scenario.get('description', '')}"
            )
            utils.log(
                f"Likelihood: {risk_scenario.get('likelihood', '')}\n"
                f"Impact: {risk_scenario.get('impact', '')}\n"
            )

    def get_risk_scenarios(self):
        """Return the risk scenarios contained in the current framework."""
        return self.json_object.get("objects", {}).get("risk_scenarios", [])

    def get_criticality_mapping(self):
        """Return the framework's criticality mapping."""
        return self.json_object.get("criticality_mapping", {})

    def get_impact_mapping(self):
        """Return the data classification mapping used to derive impact levels."""
        criticality_mapping = self.get_criticality_mapping()
        if not isinstance(criticality_mapping, dict):
            return {}

        for objective in ("confidentiality", "integrity", "availability"):
            if objective in criticality_mapping and isinstance(criticality_mapping[objective], dict):
                return criticality_mapping[objective]
        return {}
        
