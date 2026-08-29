from pprint import pformat

from . import utils


class Library:
    """Represents a single library object from the API."""

    def __init__(self, json_library):
        self.json_object = json_library

    def getJSON(self):
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
        for library in utils.get_all_results("/api/libraries/"):
            utils.log(
                f"Loading library: {library.get('name', '')} "
                f"(ID: {library.get('id', '')})"
            )
            self.libraries[library.get("id")] = Library(library)

    def getLibraries(self):
        """Return the dictionary of libraries keyed by ID."""
        return self.libraries

    def printLibraries(self):
        """Log each library payload for debugging purposes."""
        for library in self.libraries.values():
            utils.log(pformat(library.getJSON()))


class Framework:
    """Represent a single framework object."""

    def __init__(self, json_framework):
        self.json_object = json_framework

    def getName(self):
        return self.json_object.get("name", "")

    def getID(self):
        return self.json_object.get("id", "")

    def printName(self):
        utils.log(f"Name: {self.getName()}")

    def printID(self):
        utils.log(f"ID: {self.getID()}")

    def printJSON(self):
        utils.log(pformat(self.json_object))

    def getRiskScenarios(self):
        return self.json_object.get("objects", {}).get("risk_scenarios", [])

    def getRiskMatrix(self):
        return self.json_object.get("risk_matrix", [])

    def getLibraryID(self):
        return self.json_object.get("library", {}).get("id", None)


class FrameworkDict:
    """Handle a collection of frameworks loaded from the API."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload all frameworks from the API."""
        self.frameworks = [Framework(f) for f in utils.get_all_results("/api/frameworks/")]

    def getFrameworks(self):
        """Return the list of framework objects."""
        return self.frameworks

    def printFrameworks(self):
        """Log each framework name and ID."""
        for framework in self.frameworks:
            framework.printName()
            framework.printID()

    def printFrameworkJSON(self):
        """Log the raw JSON for each framework."""
        for framework in self.frameworks:
            framework.printJSON()

    def getIDfromName(self, name):
        """Return a framework ID matching the given name."""
        for framework in self.frameworks:
            if framework.getName() == name:
                return framework.getID()
        return None

    def getNamefromID(self, id):
        """Return the framework name matching the given ID."""
        for framework in self.frameworks:
            if framework.getID() == id:
                return framework.getName()
        return None

    def getRiskScenariosfromID(self, id):
        """Return the risk scenarios for the framework matching the given ID."""
        for framework in self.frameworks:
            if framework.getID() == id:
                return framework.getRiskScenarios()
        return None

    def getAllRiskScenarios(self):
        """Flatten all risk scenarios from all frameworks into a single list."""
        all_risk_scenarios = []
        for framework in self.frameworks:
            all_risk_scenarios.extend(framework.getRiskScenarios())
        return all_risk_scenarios

    def printAllRiskScenarios(self):
        """Log each risk scenario with description and scoring details."""
        for framework in self.frameworks:
            utils.log(f"Framework: {framework.getName()}")
            for risk_scenario in framework.getRiskScenarios():
                utils.log(
                    f"Risk Scenario: {risk_scenario.get('name', '')}\n"
                    f"Description: {risk_scenario.get('description', '')}"
                )
                utils.log(
                    f"Likelihood: {risk_scenario.get('likelihood', '')}\n"
                    f"Impact: {risk_scenario.get('impact', '')}\n"
                )

    def getRiskMatrixfromID(self, id):
        """Return the risk matrix for the framework matching the given ID."""
        for framework in self.frameworks:
            if framework.getID() == id:
                return framework.getRiskMatrix()
        return None

    def getAllRiskMatrices(self):
        """Return a list containing each framework's risk matrix."""
        all_risk_matrices = []
        for framework in self.frameworks:
            all_risk_matrices.append(framework.getRiskMatrix())
        return all_risk_matrices

    def printAllRiskMatrices(self):
        """Log each framework risk matrix."""
        for framework in self.frameworks:
            utils.log(f"Framework: {framework.getName()}")
            utils.log("Risk Matrix:")
            for row in framework.getRiskMatrix():
                utils.log(pformat(row))

    def PrintLibraryIDs(self):
        """Compatibility wrapper: log the library ID for each framework."""
        for framework in self.frameworks:
            utils.log(f"Framework: {framework.getName()}")
            utils.log(f"Library ID: {framework.getLibraryID()}")

    def getLibraryIDfromFrameworkID(self, framework_id):
        """Return the library ID associated with a framework ID."""
        for framework in self.frameworks:
            if framework.getID() == framework_id:
                return framework.getLibraryID()
        return None


class FrameworkFile:
    """Represent a framework loaded from a YAML file."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.json_file = filepath
        self.json_object = utils.load_yaml_file(filepath)

    def getName(self):
        return self.json_object.get("name", "")

    def getID(self):
        return self.json_object.get("id", "")

    def printName(self):
        utils.log(f"Name: {self.getName()}")

    def printID(self):
        utils.log(f"ID: {self.getID()}")

    def printJSON(self):
        utils.log(pformat(self.json_object))

    def read(self):
        """Reload the JSON payload from the configured file path."""
        self.json_object = utils.load_json_file(self.json_file)

    def loadFromYAMLFile(self, yaml_file):
        """Load and return a framework from a YAML file."""
        return utils.load_yaml_file(yaml_file)

    def printRiskScenario(self):
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

    def getRiskScenarios(self):
        """Return the risk scenarios contained in the current framework."""
        return self.json_object.get("objects", {}).get("risk_scenarios", [])
        
