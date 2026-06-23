from . import utils


MAPPINGS = {
    "confidentiality": {
        "urn:intuitem:risk:req_node:mls:data_classification:q1:c1": 0,  # Public
        "urn:intuitem:risk:req_node:mls:data_classification:q1:c2": 1,  # Internal
        "urn:intuitem:risk:req_node:mls:data_classification:q1:c3": 2,  # Confidential
        "urn:intuitem:risk:req_node:mls:data_classification:q1:c4": 3,  # Secret
    },
    "integrity": {},
    "availability": {}
}


class Domain:
    def __init__(self, json_domain):
        self.json_object = json_domain
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}") 

class DomainDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.domains = [Domain(d) for d in utils.get_all_results("/api/folders/")]

    def getDomains(self):
        return self.domains
    def printDomains(self):
        for d in self.domains:
            d.printName()
            d.printID()
    def getIDfromName(self, name):
        for d in self.domains:
            if d.getName() == name:
                return d.getID()
        return None
    def getNamefromID(self, id):
        for d in self.domains:
            if d.getID() == id:
                return d.getName()
        return None
    def UpsertFolder(self, name):
        # Check if the folder already exists
        for d in self.domains:
            if d.getName() == name:
                print(f"Folder '{name}' already exists.")
                return d
        # If the folder does not exist, create it
        payload = {'name': name}
        result = utils.get_return("/api/folders/", method="POST", payload=payload)
        print(f"Result: {result}")
        if result and not isinstance(result, dict) or not result.get("error"):
            print(f"Folder '{name}' created successfully.")
            self.reload()
            return result
        else:
            print(f"Failed to create folder '{name}': {result}")
            return None

class Perimeter:
    def __init__(self, json_perimeter):
        self.json_object = json_perimeter
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def getDefaultAssigneeID(self):
        return self.json_object.get('default_assignee', '')[0].get('id', '')
    def getDefaultAssignee(self):
        return self.json_object.get('default_assignee', '')[0].get('str', '')
    def getFolder(self):
        return self.json_object.get('folder', '')
    def getFolderUUID(self):
        return self.json_object.get('folder', '').get('id', '')
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}")
    def printDefaultAssignee(self):
        print(f"Default Assignee: {self.getDefaultAssignee()}")
    def printFolder(self):
        print(f"Folder: {self.getFolder()}")

class PerimeterDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.perimeters = [Perimeter(p) for p in utils.get_all_results("/api/perimeters/")]

    def getPerimeters(self):
        return self.perimeters
    def printPerimeters(self):
        for p in self.perimeters:
            p.printName()
            p.printID()
            p.printDefaultAssignee()
            p.printFolder()
    def getIDfromName(self, name):
        for p in self.perimeters:
            if p.getName() == name:
                return p.getID()
        return None
    def getNamefromID(self, id):
        for p in self.perimeters:
            if p.getID() == id:
                return p.getName()
        return None
    def getOwnerIDfromPerimeterID(self, perimeter_id):        
        for p in self.perimeters:
            if p.getID() == perimeter_id:
                return p.getDefaultAssigneeID()
        return None
    def getFolderUUIDfromPerimeterID(self, perimeter_id):
        for p in self.perimeters:
            if p.getID() == perimeter_id:
                return p.getFolderUUID()
        return None

class Asset:
    def __init__(self, json_asset):
        self.json_object = json_asset
    def getJSON(self):
        return self.json_object    
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def getAssetType(self):
        return self.json_object.get('type', '')
    def getOwner(self):
        return self.json_object.get('owner', '')
    def getFolder(self):
        return self.json_object.get('folder', '')
    def getMaxSecurityObjective(self):
        max_objective = 0
        for so_list in self.json_object.get('security_objectives', ''):
            for o_dict in so_list.values():
                max_objective = max(max_objective, o_dict)
        return max_objective
    
    def getSecurityObjectives(self):
        return self.json_object.get('security_objectives', '')
    def PrintSecurityObjectives(self):
        print(self.getSecurityObjectives())

    def SetSecurityObjective(self, criteria, value):
        """Update a specific security objective for the asset."""
        current_security_objectives_list = self.json_object.get('security_objectives', {})        
        print("Existing security_objectives:", current_security_objectives_list)
        security_objectives = {"objectives": {}}
        # Build the new security_objectives structure
        for exisiting_so in current_security_objectives_list:
            for existing_criteria, existing_value in exisiting_so.items(): 
                security_objectives["objectives"][existing_criteria] = {"value": existing_value, "is_enabled":  True}
        security_objectives["objectives"][criteria] = {"value": value, "is_enabled": True}
        # Replace the existing security_objectives with the new one


        payload = {'security_objectives': {'objectives': security_objectives["objectives"]}}
        print("Updated security_objectives:", payload)
        # Send the PATCH request
        result = utils.get_return(
            f"/api/assets/{self.getID()}/",
            method="PATCH",
            payload=payload
        )        
        # Refresh the asset's JSON object
        if result and not isinstance(result, dict) or not result.get("error"):
            self.json_object = utils.get_return(f"/api/assets/{self.getID()}/")
        else:
            print(f"Failed to update security objective: {result}")
        

        
    
    def printJSON(self):
        print(self.json_object)
    def printName(self):
        print(f"Name: {self.getName()}")
    def printID(self):
        print(f"ID: {self.getID()}") 
    def printAssetType(self):
        print(f"Asset Type: {self.getAssetType()}")
    def printOwner(self):
        print(f"Owner: {self.getOwner()}")
    def printFolder(self):
        print(f"Folder: {self.getFolder()}")

class AssetDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.assets = [Asset(a) for a in utils.get_all_results("/api/assets/")]

    def createAsset(self, name, asset_type,  folder):
        # checking if asset already exists
        for a in self.assets:
            if a.getName() == name:
                print("Asset already exists")
                return a
        # checking if domain exists        if not utils.get_return(f"/api/folders/{folder}/"):
            print("Folder does not exist")
            # Creating folder
            utils.get_return(f"/api/folders/", method="POST", payload={'name': folder})
        payload = {'name': name, 'type': asset_type , 'folder': folder}  
        res = utils.get_return("/api/assets/", method="POST", payload=payload)
        self.reload()
        return Asset(res)

    def createMissingAssets(self, PerimeterDict):
        created = False
        for p in PerimeterDict.getPerimeters():
            if not self.CheckAssetFromName(p.getName()):
                payload = {'name': p.getName(), 'type': "PR", 'folder': p.getFolderUUID()}
                utils.get_return("/api/assets/", method="POST", payload=payload)
                created = True
        if created:
            self.reload()
    
    def getAssetIDfromPerimeterName(self, name):
        for a in self.assets:
            if a.getName() == name:
                return a.getID()
        return None
    
    def getAssetIDfromPerimeterID(self, perimeter_id, PerimeterDict):
        perimeter_name = PerimeterDict.getNamefromID(perimeter_id)
        return self.getAssetIDfromPerimeterName(perimeter_name)
    
    def getAssets(self):
        return self.assets
    def CheckAssetFromName(self, name):
        for a in self.assets:
            if a.getName() == name:
                return True
        return False
    

    def printAssets(self):
        for a in self.assets:
            a.printJSON()
            print("Risk Impact: " + str(a.getMaxSecurityObjective()))
    def UpdateAssetCriticality(self, asset_ID, criteria, value):
        for a in self.assets:
            if a.getID() == asset_ID:
                a.SetSecurityObjective(criteria, value)
        self.reload()
    def PrintAssetSecurityObjectives(self):
        for a in self.assets:
            print(f"Asset: {a.getName()}")
            a.PrintSecurityObjectives()    
    
            