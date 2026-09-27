"""Domain and folder management models with criticality mappings.

Domains (represented as folders in the API) organize perimeters, assessments, and controls
into hierarchical business units or domains.
"""

import logging
from pathlib import Path

from .. import utils

# Load settings from framework file
_framework_path = Path(__file__).parent.parent.parent / "YML" / "newDPP.yml"
_framework = utils.load_yaml_file(str(_framework_path))

# Mapping for data classification criticality levels (Confidentiality, Integrity, Availability)
criticality_mapping = _framework.get("criticality_mapping", {
    "confidentiality": {},
    "integrity": {},
    "availability": {}
})

# Merge mappings from other framework files in YML directory
_yml_dir = Path(__file__).parent.parent.parent / "YML"
if _yml_dir.exists():
    for _cat_path in _yml_dir.glob("*.y*ml"):
        if _cat_path == _framework_path:
            continue
        try:
            _cat_fw = utils.load_yaml_file(str(_cat_path))
            _cm = _cat_fw.get("criticality_mapping", {}) if isinstance(_cat_fw, dict) else {}
            for _k in ("confidentiality", "integrity", "availability"):
                if _k in _cm and isinstance(_cm[_k], dict):
                    criticality_mapping.setdefault(_k, {}).update(_cm[_k])
        except Exception:
            pass


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
    """Collection of organization domains/folders."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload all folders/domains from the API."""
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
