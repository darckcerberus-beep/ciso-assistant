import logging
from pathlib import Path

from .. import utils

# Load settings from library file
_library_path = Path(__file__).parent.parent.parent / "YML" / "newDPP.yml"
_library = utils.load_yaml_file(str(_library_path))
# Mapping for data classification criticality levels
criticality_mapping = _library.get("criticality_mapping", {
    "confidentiality": {},
    "integrity": {},
    "availability": {}
})


class Domain:
    """Represents an organizational domain/folder."""
    def __init__(self, json_domain):
        self.json_object = json_domain
    def get_name(self):
        return self.json_object.get('name', '')
    def get_id(self):
        return self.json_object.get('id', '')
    def print_name(self):
        utils.log(f"Name: {self.get_name()}")
    def print_id(self):
        utils.log(f"ID: {self.get_id()}")


class DomainDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.domains = [Domain(d) for d in utils.get_all_results("/api/folders/", force_reload=True)]

    def get_domains(self):
        return self.domains
    def print_domains(self):
        for d in self.domains:
            d.print_name()
            d.print_id()
    def get_id_from_name(self, name):
        for d in self.domains:
            if d.get_name() == name:
                return d.get_id()
        return None
    def get_name_from_id(self, id):
        for d in self.domains:
            if d.get_id() == id:
                return d.get_name()
        return None
    def upsert_folder(self, name):
        # Check if the folder already exists
        for d in self.domains:
            if d.get_name() == name:
                utils.log(f"Folder '{name}' already exists.")
                return d
        # If the folder does not exist, create it
        payload = {'name': name, "create_iam_groups": True}
        result = utils.get_return("/api/folders/", method="POST", payload=payload)
        utils.log(f"Result: {result}")
        if result and (not isinstance(result, dict) or not result.get("error")):
            utils.log(f"Folder '{name}' created successfully.")
            self.reload()
            return result
        else:
            utils.log(f"Failed to create folder '{name}': {result}", level=logging.ERROR)
            return None
    def upsert_folder_from_json(self, folder_dict):
        folders = folder_dict.get('domains', [])
        utils.log(f"Upserting folders from JSON: {folders}")
        for folder in folders:
            folder_name = folder.get('name')
            if folder_name:
                self.upsert_folder(folder_name)
            else:
                utils.log("Folder name is missing in the provided JSON.", level=logging.WARNING)
