"""Unit tests for ReCyFDomainManager and NIS2 / ReCyF asset modeling."""

import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import yaml

from classes.integrations.recyf_domain_manager import (
    NIS2_DOMAIN_NAME,
    NIS2_DOMAIN_DESCRIPTION,
    RECYF_ASSET_DEFINITIONS,
    ReCyFDomainManager,
)


class TestReCyFAssetDefinitions(unittest.TestCase):
    """Test asset definition data structure and consistency with ReCyF requirements."""

    def test_asset_definitions_count_and_types(self):
        self.assertEqual(len(RECYF_ASSET_DEFINITIONS), 10)
        primary_assets = [a for a in RECYF_ASSET_DEFINITIONS if a["type"] == "PR"]
        support_assets = [a for a in RECYF_ASSET_DEFINITIONS if a["type"] == "SP"]
        self.assertEqual(len(primary_assets), 3)
        self.assertEqual(len(support_assets), 7)

    def test_total_requirements_count_matches_recyf(self):
        total_reqs = sum(a["req_count"] for a in RECYF_ASSET_DEFINITIONS)
        self.assertEqual(total_reqs, 152)

    def test_asset_model_yaml_exists_and_matches(self):
        model_path = Path(__file__).resolve().parent.parent / "YML" / "nis2_recyf_assets_model.yml"
        self.assertTrue(model_path.exists())
        with open(model_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.assertIn("domain", data)
        self.assertEqual(data["domain"]["name"], NIS2_DOMAIN_NAME)
        self.assertIn("assets", data)
        self.assertEqual(len(data["assets"]), 10)
        # Verify all 10 assets specify perimeter_name
        self.assertTrue(all(bool(a.get("perimeter_name")) for a in data["assets"]))

    def test_recyf_framework_yaml_has_asset_types(self):
        recyf_path = Path(__file__).resolve().parent.parent / "YML" / "recyf.yml"
        self.assertTrue(recyf_path.exists())
        with open(recyf_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        objects = data.get("objects", {})
        framework_meta = objects.get("framework", {})
        self.assertIn("asset_types_definition", framework_meta)
        asset_defs = framework_meta["asset_types_definition"]
        self.assertEqual(len(asset_defs), 10)

        # Check assessable requirement nodes
        req_nodes = framework_meta.get("requirement_nodes", [])
        assessable_nodes = [n for n in req_nodes if n.get("assessable")]
        self.assertEqual(len(assessable_nodes), 152)

        for node in assessable_nodes:
            self.assertIn("annotation", node)
            self.assertTrue(node["annotation"].startswith("Type d'actif évalué :"))
            self.assertIn("target_asset_types", node)
            self.assertGreater(len(node["target_asset_types"]), 0)


class TestReCyFDomainManagerLogic(unittest.TestCase):
    """Test ReCyFDomainManager provisioning and status logic with mocked API dependencies."""

    @patch("classes.integrations.recyf_domain_manager.AssetDict")
    @patch("classes.integrations.recyf_domain_manager.PerimeterDict")
    @patch("classes.integrations.recyf_domain_manager.DomainDict")
    def test_get_nis2_recyf_status_when_domain_not_found(self, mock_dom_cls, mock_per_cls, mock_ast_cls):
        mock_dom = mock_dom_cls.return_value
        mock_dom.get_id_from_name.return_value = None

        manager = ReCyFDomainManager()
        status = manager.get_nis2_recyf_status()

        self.assertFalse(status["exists"])
        self.assertEqual(status["domain_name"], NIS2_DOMAIN_NAME)

    @patch("classes.integrations.recyf_domain_manager.AssetDict")
    @patch("classes.integrations.recyf_domain_manager.PerimeterDict")
    @patch("classes.integrations.recyf_domain_manager.DomainDict")
    def test_get_nis2_recyf_status_when_domain_exists(self, mock_dom_cls, mock_per_cls, mock_ast_cls):
        mock_dom = mock_dom_cls.return_value
        mock_dom.get_id_from_name.return_value = "dom-uuid-123"

        mock_per = mock_per_cls.return_value
        mock_per.get_id_from_name.side_effect = lambda name: f"per-{name[:6]}"

        mock_ast = mock_ast_cls.return_value
        mock_ast.get_asset_id_from_perimeter_name.side_effect = lambda name: f"ast-{name[:6]}"

        manager = ReCyFDomainManager()
        status = manager.get_nis2_recyf_status()

        self.assertTrue(status["exists"])
        self.assertEqual(status["domain_id"], "dom-uuid-123")
        self.assertEqual(len(status["items"]), 10)
        self.assertTrue(all(item["perimeter_exists"] for item in status["items"]))
        self.assertTrue(all(item["asset_exists"] for item in status["items"]))

    @patch("classes.integrations.recyf_domain_manager.utils.get_return")
    @patch("classes.integrations.recyf_domain_manager.AssetDict")
    @patch("classes.integrations.recyf_domain_manager.PerimeterDict")
    @patch("classes.integrations.recyf_domain_manager.DomainDict")
    def test_provision_nis2_recyf_environment(self, mock_dom_cls, mock_per_cls, mock_ast_cls, mock_get_return):
        mock_dom = mock_dom_cls.return_value
        mock_dom.get_id_from_name.side_effect = [None, "dom-uuid-created"]
        mock_dom.create_domain.return_value = {"id": "dom-uuid-created", "name": NIS2_DOMAIN_NAME}

        mock_per = mock_per_cls.return_value
        mock_per.get_id_from_name.side_effect = [None, "per-id-1"] * 10
        mock_get_return.return_value = {"id": "created-id"}

        mock_ast = mock_ast_cls.return_value
        mock_ast.get_asset_id_from_perimeter_name.side_effect = [None, "ast-id-1"] * 10

        manager = ReCyFDomainManager()
        res = manager.provision_nis2_recyf_environment()

        self.assertEqual(res["domain_name"], NIS2_DOMAIN_NAME)
        self.assertEqual(res["domain_id"], "dom-uuid-created")
        self.assertEqual(len(res["perimeters"]), 10)
        self.assertEqual(len(res["assets"]), 10)


if __name__ == "__main__":
    unittest.main()
