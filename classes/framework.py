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
