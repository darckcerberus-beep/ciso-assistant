from pprint import pprint

from . import utils


class Library:
    """Represents a single library object."""
    def __init__(self, json_library):
        self.json_object = json_library

    def getJSON(self):
        return self.json_object


class LibraryDict:
    """Handles a collection of Libraries."""
    def __init__(self):
        print("Loading libraries...")
        self.reload()

    def reload(self):
        self.libraries = {}
        for l in utils.get_all_results("/api/libraries/"):
            print(f"Loading library: {l.get('name', '')} (ID: {l.get('id', '')})")
            self.libraries[l.get('id')] = Library(l)

    def getLibraries(self):
        return self.libraries
    def printLibraries(self):
        for l in self.libraries.values():
            pprint.pprint(l.getJSON())    

class Framework:    
    def __init__(self,json_framework):        
        self.json_object = json_framework
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}")
    def printJSON(self):
        print(self.json_object)
    def getRiskScenarios(self):
        return self.json_object.get('objects', {}).get('risk_scenarios', []) 
    def getRiskMatrix(self):        
        return self.json_object.get('risk_matrix', [])
    def getLibraryID(self):
        return self.json_object.get('library', {}).get('id', None)

class FrameworkDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.frameworks = [Framework(f) for f in utils.get_all_results("/api/frameworks/")]

    def getFrameworks(self):
        return self.frameworks
    def printFrameworks(self):
        for f in self.frameworks:
            f.printName()
            f.printID()
    def printFrameworkJSON(self):
        for f in self.frameworks:
            f.printJSON()
    def getIDfromName(self, name):
        for f in self.frameworks:
            if f.getName() == name:
                return f.getID()
        return None
    def getNamefromID(self, id):
        for f in self.frameworks:
            if f.getID() == id:
                return f.getName()
        return None
    def getRiskScenariosfromID(self, id):
        for f in self.frameworks:
            if f.getID() == id:
                return f.getRiskScenarios()
        return None
    def getAllRiskScenarios(self):
        all_risk_scenarios = []
        for f in self.frameworks:
            all_risk_scenarios.extend(f.getRiskScenarios())
        return all_risk_scenarios
    def printAllRiskScenarios(self):
        for f in self.frameworks:
            print(f"Framework: {f.getName()}")
            for rs in f.getRiskScenarios():
                print(f"Risk Scenario: {rs.get('name', '')}\nDescription: {rs.get('description', '')}")
                print(f"Likelihood: {rs.get('likelihood', '')}\nImpact: {rs.get('impact', '')}\n")
    def getRiskMatrixfromID(self, id):
        for f in self.frameworks:
            if f.getID() == id:
                return f.getRiskMatrix()
        return None
    def getAllRiskMatrices(self):
        all_risk_matrices = []
        for f in self.frameworks:
            all_risk_matrices.append(f.getRiskMatrix())
        return all_risk_matrices
    def printAllRiskMatrices(self):
        for f in self.frameworks:
            print(f"Framework: {f.getName()}")
            print("Risk Matrix:")
            for row in f.getRiskMatrix():
                print(row)
    def PrintLibraryIDs(self):
        for f in self.frameworks:
            print(f"Framework: {f.getName()}")
            print(f"Library ID: {f.getLibraryID()}")   
    def getLibraryIDfromFrameworkID(self, framework_id):
        for f in self.frameworks:
            if f.getID() == framework_id:
                return f.getLibraryID()
        return None
                     

class FrameworkFile:
    def __init__(self, filepath):
        with open(filepath, 'r') as f:
            self.json_object = utils.load_yaml_file(filepath)
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}")
    def printJSON(self):
        print(self.json_object)
    def read(self):
        self.json_object = utils.load_json_file(self.json_file)
    def loadFromYAMLFile(self, yaml_file):
        with open(yaml_file, 'r') as f:
            return utils.load_yaml_file(yaml_file)
    def printRiskScenario(self):
        risk_scenarios = self.json_object.get('objects', {}).get('risk_scenarios', [])
        for rs in risk_scenarios:
            print(f"Risk Scenario: {rs.get('name', '')}\nDescription: {rs.get('description', '')}")
            print(f"Likelihood: {rs.get('likelihood', '')}\nImpact: {rs.get('impact', '')}\n")

    def getRiskScenarios(self):
        return self.json_object.get('objects', {}).get('risk_scenarios', [])        
