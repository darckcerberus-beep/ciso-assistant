from . import utils


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
        risk_scenarios = self.json_object.get('objects', {}).get('risk_scenario', [])
        for rs in risk_scenarios:
            print(f"Risk Scenario: {rs.get('name', '')}\nDescription: {rs.get('description', '')}")
            print(f"Likelihood: {rs.get('likelihood', '')}\nImpact: {rs.get('impact', '')}\n")
