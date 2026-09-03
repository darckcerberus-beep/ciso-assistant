import logging

from .. import utils


class Asset:
    def __init__(self, json_asset):
        self.json_object = json_asset
    def get_json(self):
        return self.json_object
    def get_name(self):
        return self.json_object.get('name', '')
    def get_id(self):
        return self.json_object.get('id', '')
    def get_asset_type(self):
        return self.json_object.get('type', '')
    def get_owner(self):
        return self.json_object.get('owner', '')

    def get_owner_ids(self):
        """Return identifiers for users assigned as asset owners."""
        owners = self.get_owner()
        if not isinstance(owners, list):
            return []
        return [owner.get('id', '') if isinstance(owner, dict) else owner for owner in owners]

    def set_owner_if_missing(self, owner_id):
        """Assign an owner only when no owner is already configured."""
        if not owner_id or self.get_owner_ids():
            return self.json_object

        response = utils.get_return(
            f"/api/assets/{self.get_id()}/",
            method="PATCH",
            payload={"owner": [owner_id]},
        )
        if isinstance(response, dict) and not response.get("error"):
            self.json_object = response
        return response
    def get_folder(self):
        return self.json_object.get('folder', '')
    def get_folder_id(self):
        folder = self.json_object.get('folder', {})
        if isinstance(folder, dict):
            return folder.get('id', '')
        return str(folder)
    def get_max_security_objective(self):
        max_objective = 0
        for so_list in self.json_object.get('security_objectives', ''):
            for o_dict in so_list.values():
                max_objective = max(max_objective, o_dict)
        return max_objective

    def get_security_objectives(self):
        return self.json_object.get('security_objectives', '')
    def print_security_objectives(self):
        utils.log(str(self.get_security_objectives()))

    def set_security_objective(self, criteria, value):
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
            f"/api/assets/{self.get_id()}/",
            method="PATCH",
            payload=payload
        )
        # Refresh the asset's JSON object
        if result and (not isinstance(result, dict) or not result.get("error")):
            self.json_object = utils.get_return(f"/api/assets/{self.get_id()}/")
        else:
            utils.log(f"Failed to update security objective: {result}", level=logging.ERROR)



    def print_json(self):
        utils.log(str(self.json_object))
    def print_name(self):
        utils.log(f"Name: {self.get_name()}")
    def print_id(self):
        utils.log(f"ID: {self.get_id()}")
    def print_asset_type(self):
        utils.log(f"Asset Type: {self.get_asset_type()}")
    def print_owner(self):
        utils.log(f"Owner: {self.get_owner()}")
    def print_folder(self):
        utils.log(f"Folder: {self.get_folder()}")


class AssetDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.assets = [Asset(a) for a in utils.get_all_results("/api/assets/", force_reload=True)]

    def create_asset(self, name, asset_type,  folder):
        # checking if asset already exists
        for a in self.assets:
            if a.get_name() == name:
                utils.log("Asset already exists")
                return a

        # checking if domain exists
        if not utils.get_return(f"/api/folders/{folder}/"):
            utils.log("Folder does not exist", level=logging.WARNING)
            # Creating folder
            utils.get_return("/api/folders/", method="POST", payload={'name': folder})
        payload = {'name': name, 'type': asset_type , 'folder': folder}
        res = utils.get_return("/api/assets/", method="POST", payload=payload)
        self.reload()
        return Asset(res)

    def create_missing_assets(self, perimeter_dict):
        created = False
        for p in perimeter_dict.get_perimeters():
            if not self.check_asset_from_name(p.get_name()):
                payload = {'name': p.get_name(), 'type': "PR", 'folder': p.get_folder_uuid()}
                owner_id = p.get_default_assignee_id()
                if owner_id:
                    payload['owner'] = [owner_id]
                utils.get_return("/api/assets/", method="POST", payload=payload)
                created = True
        if created:
            self.reload()

        updated = False
        for perimeter in perimeter_dict.get_perimeters():
            owner_id = perimeter.get_default_assignee_id()
            for asset in self.assets:
                if asset.get_name() != perimeter.get_name() or asset.get_owner_ids():
                    continue
                asset.set_owner_if_missing(owner_id)
                updated = True
        if updated:
            self.reload()

    def get_asset_id_from_perimeter_name(self, name):
        for a in self.assets:
            if a.get_name() == name:
                return a.get_id()
        return None

    def get_asset_id_from_perimeter_id(self, perimeter_id, perimeter_dict):
        perimeter_name = perimeter_dict.get_name_from_id(perimeter_id)
        return self.get_asset_id_from_perimeter_name(perimeter_name)

    def get_assets(self):
        return self.assets

    def get_owner_ids_for_assets(self, asset_ids):
        """Return unique owner IDs for the supplied asset IDs."""
        selected_asset_ids = set(asset_ids)
        owner_ids = []
        for asset in self.assets:
            if asset.get_id() in selected_asset_ids:
                owner_ids.extend(asset.get_owner_ids())
        return list(dict.fromkeys(owner_ids))

    def check_asset_from_name(self, name):
        for a in self.assets:
            if a.get_name() == name:
                return True
        return False


    def print_assets(self):
        for a in self.assets:
            a.print_json()
            utils.log("Risk Impact: " + str(a.get_max_security_objective()))
    def update_asset_criticality(self, asset_id, criteria, value):
        for a in self.assets:
            if a.get_id() == asset_id:
                a.set_security_objective(criteria, value)
        self.reload()
    def print_asset_security_objectives(self):
        for a in self.assets:
            utils.log(f"Asset: {a.get_name()}")
            a.print_security_objectives()
