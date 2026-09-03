import logging

from .. import utils


class Perimeter:
    def __init__(self, json_perimeter):
        self.json_object = json_perimeter
    def get_name(self):
        return self.json_object.get('name', '')
    def get_id(self):
        return self.json_object.get('id', '')
    def get_default_assignee_id(self):
        assignees = self.json_object.get('default_assignee', [])
        if not assignees:
            return ''
        assignee = assignees[0]
        return assignee.get('id', '') if isinstance(assignee, dict) else assignee
    def get_default_assignee(self):
        return self.json_object.get('default_assignee', [])
    def get_folder(self):
        return self.json_object.get('folder', '')
    def get_folder_uuid(self):
        return self.json_object.get('folder', '').get('id', '')
    def print_name(self):
        utils.log(f"Name: {self.get_name()}")
    def print_id(self):
        utils.log(f"ID: {self.get_id()}")
    def print_default_assignee(self):
        utils.log(f"Default Assignee: {self.get_default_assignee()}")
    def print_folder(self):
        utils.log(f"Folder: {self.get_folder()}")


class PerimeterDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.perimeters = [Perimeter(p) for p in utils.get_all_results("/api/perimeters/", force_reload=True)]

    def get_perimeters(self):
        return self.perimeters
    def print_perimeters(self):
        for p in self.perimeters:
            p.print_name()
            p.print_id()
            p.print_default_assignee()
            p.print_folder()
    def print_perimeter_json(self):
        for p in self.perimeters:
            utils.log(str(p.json_object))
    def get_id_from_name(self, name):
        for p in self.perimeters:
            if p.get_name() == name:
                return p.get_id()
        return None
    def get_name_from_id(self, id):
        for p in self.perimeters:
            if p.get_id() == id:
                return p.get_name()
        return None
    def get_owner_id_from_perimeter_id(self, perimeter_id):
        for p in self.perimeters:
            if p.get_id() == perimeter_id:
                return p.get_default_assignee_id()
        return None
    def get_folder_uuid_from_perimeter_id(self, perimeter_id):
        for p in self.perimeters:
            if p.get_id() == perimeter_id:
                return p.get_folder_uuid()
        return None
    def create_perimeter(self, name, default_assignee_id, folder_uuid):
        # Check if the perimeter already exists
        for p in self.perimeters:
            if p.get_name() == name:
                utils.log(f"Perimeter '{name}' already exists.")
                return p
        # If the perimeter does not exist, create it
        payload = {
            'name': name,
            'folder': folder_uuid,
            'default_assignee': [default_assignee_id]
        }
        result = utils.get_return("/api/perimeters/", method="POST", payload=payload)
        utils.log(f"Result: {result}")
        if result and (not isinstance(result, dict) or not result.get("error")):
            utils.log(f"Perimeter '{name}' created successfully.")
            self.reload()
            return result
        else:
            utils.log(f"Failed to create perimeter '{name}': {result}", level=logging.ERROR)
            return None
    def create_perimeters_from_dict(self,domain_dict, perimeter_dict_from_file,actor_dict,user_dict):
        perimeters = perimeter_dict_from_file.get('assets', [])
        utils.log(f"Creating perimeters from asset dict: {perimeters}")
        for perimeter in perimeters:
            perimeter_name = perimeter.get('name')
            # get assignee id from name
            default_assignee_id = actor_dict.get_id_from_name(user_dict.get_name_from_email(perimeter.get('it contact')))
            utils.log(f"Creating perimeter '{perimeter_name}' with default assignee ID '{default_assignee_id}'")
            # get folder uuid from name
            folder_uuid = domain_dict.get_id_from_name(perimeter.get('domain'))
            if perimeter_name and default_assignee_id and folder_uuid:
                self.create_perimeter(perimeter_name, default_assignee_id, folder_uuid)
