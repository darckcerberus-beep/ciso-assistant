"""Unit tests for user model, protection rules, and deletion safety."""

import unittest
from unittest.mock import MagicMock, patch

from classes.core.user import User, UserDict
from classes.examples_manager import ExamplesManager


class TestUserProtection(unittest.TestCase):
    """Test suite ensuring administrator and internal accounts cannot be inadvertently deleted."""

    def test_user_role_methods(self):
        """Verify role detection methods on User instance."""
        admin_user = User({
            "id": "admin-1",
            "email": "admin@example.com",
            "is_superuser": True,
            "is_third_party": False,
            "user_groups": [{"str": "Global - Administrator"}],
        })
        self.assertTrue(admin_user.is_superuser())
        self.assertTrue(admin_user.is_admin())
        self.assertFalse(admin_user.is_third_party())

        group_admin_user = User({
            "id": "admin-2",
            "email": "manager@example.com",
            "is_superuser": False,
            "is_third_party": False,
            "user_groups": [{"str": "System - Administrator"}],
        })
        self.assertFalse(group_admin_user.is_superuser())
        self.assertTrue(group_admin_user.is_admin())
        self.assertFalse(group_admin_user.is_third_party())

        internal_user = User({
            "id": "internal-1",
            "email": "employee@example.com",
            "is_superuser": False,
            "is_third_party": False,
            "user_groups": [],
        })
        self.assertFalse(internal_user.is_superuser())
        self.assertFalse(internal_user.is_admin())
        self.assertFalse(internal_user.is_third_party())

        third_party_user = User({
            "id": "tp-1",
            "email": "vendor@external.com",
            "is_superuser": False,
            "is_third_party": True,
            "user_groups": [{"str": "Third-party respondent"}],
        })
        self.assertFalse(third_party_user.is_superuser())
        self.assertFalse(third_party_user.is_admin())
        self.assertTrue(third_party_user.is_third_party())

    @patch("classes.utils.get_all_results")
    def test_user_dict_is_protected_user(self, mock_get_all):
        """Verify is_protected_user identifies admin, superuser, and internal accounts."""
        mock_get_all.return_value = [
            {"id": "u-admin", "email": "admin@ciso.local", "is_superuser": True, "is_third_party": False},
            {"id": "u-internal", "email": "staff@ciso.local", "is_superuser": False, "is_third_party": False},
            {"id": "u-tp", "email": "tp@example.com", "is_superuser": False, "is_third_party": True},
        ]
        ud = UserDict()

        self.assertTrue(ud.is_protected_user(user_id="u-admin"))
        self.assertTrue(ud.is_protected_user(email="admin@ciso.local"))

        self.assertTrue(ud.is_protected_user(user_id="u-internal"))
        self.assertTrue(ud.is_protected_user(email="staff@ciso.local"))

        self.assertFalse(ud.is_protected_user(user_id="u-tp"))
        self.assertFalse(ud.is_protected_user(email="tp@example.com"))

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_delete_user_by_id_refuses_protected_user(self, mock_get_all, mock_get_return):
        """Verify delete_user_by_id refuses to delete protected users and does not call API."""
        mock_get_all.return_value = [
            {"id": "u-admin", "email": "admin@ciso.local", "is_superuser": True, "is_third_party": False},
            {"id": "u-tp", "email": "tp@example.com", "is_superuser": False, "is_third_party": True},
        ]
        ud = UserDict()

        # Attempt to delete admin user
        result = ud.delete_user_by_id("u-admin")
        self.assertFalse(result)
        mock_get_return.assert_not_called()

        # Delete third-party user successfully
        mock_get_return.return_value = True
        result_tp = ud.delete_user_by_id("u-tp")
        self.assertTrue(result_tp)
        mock_get_return.assert_called_once_with("/api/users/u-tp/", method="DELETE")

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_delete_user_by_email_refuses_protected_user(self, mock_get_all, mock_get_return):
        """Verify delete_user refuses to delete protected users by email."""
        mock_get_all.return_value = [
            {"id": "u-admin", "email": "admin@ciso.local", "is_superuser": True, "is_third_party": False},
        ]
        ud = UserDict()

        result = ud.delete_user("admin@ciso.local")
        self.assertFalse(result)
        mock_get_return.assert_not_called()

    def test_remove_example_application_protects_admin_representative(self):
        """Verify remove_example_application does not delete an administrator who was an entity representative."""
        manager = ExamplesManager()
        mock_data = {
            "perimeter_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "risk_assessment_dict": MagicMock(),
            "risk_scenario_dict": MagicMock(),
            "applied_control_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_representative_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "user_dict": MagicMock(),
            "findings_assessment_dict": MagicMock(),
            "finding_dict": MagicMock(),
            "vulnerability_dict": MagicMock(),
        }

        # Set up a custom demo app
        app_name = "App-Audit-Demo"
        entity_id = "ent-demo-1"
        admin_uid = "4cfbd026-4947-4113-8a4f-65c53915f97f"

        mock_data["perimeter_dict"].get_id_from_name.return_value = "p-1"
        mock_data["entity_dict"].get_id_from_name.return_value = entity_id
        mock_data["asset_dict"].get_asset_id_from_perimeter_name.return_value = "a-1"
        mock_data["entity_assessment_dict"].get_entity_assessments.return_value = []
        mock_data["entity_representative_dict"].delete_representatives_for_entity.return_value = 1
        mock_data["entity_dict"].delete_entity.return_value = True

        # The entity representative was the admin user
        rep_obj = MagicMock()
        rep_obj.get_user_id.return_value = admin_uid
        mock_data["entity_representative_dict"].get_representatives_for_entity.return_value = [rep_obj]
        mock_data["entity_representative_dict"].get_entity_ids_for_user.return_value = []

        # Configure user_dict to report admin_uid as protected
        mock_data["user_dict"].is_protected_user.side_effect = lambda user_id=None, email=None: user_id == admin_uid

        mock_data["findings_assessment_dict"].get_findings_assessments.return_value = {}
        mock_data["risk_assessment_dict"].get_risk_assessments.return_value = {}
        mock_data["applied_control_dict"].get_controls.return_value = {}
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {}
        mock_data["asset_dict"].delete_asset.return_value = True
        mock_data["perimeter_dict"].delete_perimeter.return_value = True

        with patch.object(manager, "_init_data", return_value=mock_data):
            res = manager.remove_example_application(app_name)

            self.assertEqual(res["users_deleted"], 0)
            mock_data["user_dict"].delete_user_by_id.assert_not_called()


if __name__ == "__main__":
    unittest.main()
