import logging

from . import utils

# Mapping for data classification criticality levels
CRITICALITY_MAPPING = {
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
    """Represents an organizational domain/folder."""
    def __init__(self, json_domain):
        self.json_object = json_domain
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def printName(self):
        utils.log(f"Name: {self.getName()}")
    def printID(self):
        utils.log(f"ID: {self.getID()}")

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
                utils.log(f"Folder '{name}' already exists.")
                return d
        # If the folder does not exist, create it
        payload = {'name': name, "create_iam_groups": True}
        result = utils.get_return("/api/folders/", method="POST", payload=payload)
        utils.log(f"Result: {result}")
        if result and not isinstance(result, dict) or not result.get("error"):
            utils.log(f"Folder '{name}' created successfully.")
            self.reload()
            return result
        else:
            utils.log(f"Failed to create folder '{name}': {result}", level=logging.ERROR)
            return None
    def UpsertFolderFromJSON(self, folder_dict):
        folders = folder_dict.get('domains', [])
        utils.log(f"Upserting folders from JSON: {folders}")
        for folder in folders:
            folder_name = folder.get('name')
            if folder_name:
                self.UpsertFolder(folder_name)
            else:
                utils.log("Folder name is missing in the provided JSON.", level=logging.WARNING)


class Perimeter:
    def __init__(self, json_perimeter):
        self.json_object = json_perimeter
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def getDefaultAssigneeID(self):
        assignees = self.json_object.get('default_assignee', [])
        if not assignees:
            return ''
        assignee = assignees[0]
        return assignee.get('id', '') if isinstance(assignee, dict) else assignee
    def getDefaultAssignee(self):
        return self.json_object.get('default_assignee', [])
    def getFolder(self):
        return self.json_object.get('folder', '')
    def getFolderUUID(self):
        return self.json_object.get('folder', '').get('id', '')
    def printName(self):
        utils.log(f"Name: {self.getName()}")
    def printID(self):
        utils.log(f"ID: {self.getID()}")
    def printDefaultAssignee(self):
        utils.log(f"Default Assignee: {self.getDefaultAssignee()}")
    def printFolder(self):
        utils.log(f"Folder: {self.getFolder()}")

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
    def printPerimeterJSON(self):
        for p in self.perimeters:
            utils.log(str(p.json_object))
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
    def CreatePerimeter(self, name, default_assignee_id, folder_uuid):
        # Check if the perimeter already exists
        for p in self.perimeters:
            if p.getName() == name:
                utils.log(f"Perimeter '{name}' already exists.")
                return p
        # If the perimeter does not exist, create it
        payload = {
            'name': name,            
            'folder': folder_uuid,
            'default_assignee':  [default_assignee_id]
        }
        result = utils.get_return("/api/perimeters/", method="POST", payload=payload)
        utils.log(f"Result: {result}")
        if result and not isinstance(result, dict) or not result.get("error"):
            utils.log(f"Perimeter '{name}' created successfully.")
            self.reload()
            return result
        else:
            utils.log(f"Failed to create perimeter '{name}': {result}", level=logging.ERROR)
            return None
    def CreatePerimetersFromDict(self,domain_dict, perimeter_dict_from_file,actor_dict,user_dict):
        perimeters = perimeter_dict_from_file.get('assets', [])
        utils.log(f"Creating perimeters from asset dict: {perimeters}")
        for perimeter in perimeters:
            perimeter_name = perimeter.get('name')
            # get assignee id from name
            default_assignee_id = actor_dict.getIDfromName(user_dict.getNamefromEmail(perimeter.get('it contact')))
            utils.log(f"Creating perimeter '{perimeter_name}' with default assignee ID '{default_assignee_id}'")
            # get folder uuid from name            
            folder_uuid = domain_dict.getIDfromName(perimeter.get('domain'))
            if perimeter_name and default_assignee_id and folder_uuid:
                self.CreatePerimeter(perimeter_name, default_assignee_id, folder_uuid)

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

    def getOwnerIDs(self):
        """Return identifiers for users assigned as asset owners."""
        owners = self.getOwner()
        if not isinstance(owners, list):
            return []
        return [owner.get('id', '') if isinstance(owner, dict) else owner for owner in owners]

    def setOwnerIfMissing(self, owner_id):
        """Assign an owner only when no owner is already configured."""
        if not owner_id or self.getOwnerIDs():
            return self.json_object

        response = utils.get_return(
            f"/api/assets/{self.getID()}/",
            method="PATCH",
            payload={"owner": [owner_id]},
        )
        if isinstance(response, dict) and not response.get("error"):
            self.json_object = response
        return response
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
        utils.log(str(self.getSecurityObjectives()))

    def SetSecurityObjective(self, criteria, value):
        """Update a specific security objective for the asset."""
        current_security_objectives_list = self.json_object.get('security_objectives', {})        
        utils.log(f"Existing security_objectives: {current_security_objectives_list}")
        security_objectives = {"objectives": {}}
        # Build the new security_objectives structure
        for exisiting_so in current_security_objectives_list:
            for existing_criteria, existing_value in exisiting_so.items(): 
                security_objectives["objectives"][existing_criteria] = {"value": existing_value, "is_enabled":  True}
        security_objectives["objectives"][criteria] = {"value": value, "is_enabled": True}
        # Replace the existing security_objectives with the new one


        payload = {'security_objectives': {'objectives': security_objectives["objectives"]}}
        utils.log(f"Updated security_objectives: {payload}")
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
            utils.log(f"Failed to update security objective: {result}", level=logging.ERROR)
        

        
    
    def printJSON(self):
        utils.log(str(self.json_object))
    def printName(self):
        utils.log(f"Name: {self.getName()}")
    def printID(self):
        utils.log(f"ID: {self.getID()}")
    def printAssetType(self):
        utils.log(f"Asset Type: {self.getAssetType()}")
    def printOwner(self):
        utils.log(f"Owner: {self.getOwner()}")
    def printFolder(self):
        utils.log(f"Folder: {self.getFolder()}")

class AssetDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.assets = [Asset(a) for a in utils.get_all_results("/api/assets/")]

    def createAsset(self, name, asset_type,  folder):
        # checking if asset already exists
        for a in self.assets:
            if a.getName() == name:
                utils.log("Asset already exists")
                return a
        # checking if domain exists        if not utils.get_return(f"/api/folders/{folder}/"):
            utils.log("Folder does not exist", level=logging.WARNING)
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
                owner_id = p.getDefaultAssigneeID()
                if owner_id:
                    payload['owner'] = [owner_id]
                utils.get_return("/api/assets/", method="POST", payload=payload)
                created = True
        if created:
            self.reload()

        updated = False
        for perimeter in PerimeterDict.getPerimeters():
            owner_id = perimeter.getDefaultAssigneeID()
            for asset in self.assets:
                if asset.getName() != perimeter.getName() or asset.getOwnerIDs():
                    continue
                asset.setOwnerIfMissing(owner_id)
                updated = True
        if updated:
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

    def getOwnerIDsForAssets(self, asset_ids):
        """Return unique owner IDs for the supplied asset IDs."""
        selected_asset_ids = set(asset_ids)
        owner_ids = []
        for asset in self.assets:
            if asset.getID() in selected_asset_ids:
                owner_ids.extend(asset.getOwnerIDs())
        return list(dict.fromkeys(owner_ids))

    def CheckAssetFromName(self, name):
        for a in self.assets:
            if a.getName() == name:
                return True
        return False
    

    def printAssets(self):
        for a in self.assets:
            a.printJSON()
            utils.log("Risk Impact: " + str(a.getMaxSecurityObjective()))
    def UpdateAssetCriticality(self, asset_ID, criteria, value):
        for a in self.assets:
            if a.getID() == asset_ID:
                a.SetSecurityObjective(criteria, value)
        self.reload()
    def PrintAssetSecurityObjectives(self):
        for a in self.assets:
            utils.log(f"Asset: {a.getName()}")
            a.PrintSecurityObjectives()    
    
            