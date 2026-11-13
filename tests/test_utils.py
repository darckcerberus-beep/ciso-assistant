"""Unit tests for utility functions and logging configuration."""

import logging
import unittest
from unittest.mock import patch

from classes import utils


class TestUtilsLogging(unittest.TestCase):
    """Test suite for logging configuration and dynamic level changes."""

    def tearDown(self):
        # Reset log level to default WARNING after tests
        utils.set_log_level(logging.WARNING)

    def test_set_log_level_with_int(self):
        """Verify set_log_level sets int log level properly."""
        utils.set_log_level(logging.DEBUG)
        self.assertEqual(utils.LOGGER.level, logging.DEBUG)
        self.assertEqual(logging.getLogger().level, logging.DEBUG)

        utils.set_log_level(logging.ERROR)
        self.assertEqual(utils.LOGGER.level, logging.ERROR)
        self.assertEqual(logging.getLogger().level, logging.ERROR)

    def test_set_log_level_with_str(self):
        """Verify set_log_level converts string log level case-insensitively."""
        utils.set_log_level("info")
        self.assertEqual(utils.LOGGER.level, logging.INFO)

        utils.set_log_level("WARNING")
        self.assertEqual(utils.LOGGER.level, logging.WARNING)

        utils.set_log_level("invalid_level_name")
        self.assertEqual(utils.LOGGER.level, logging.WARNING)

    def test_log_filtering(self):
        """Verify log messages are filtered according to current log level."""
        utils.set_log_level(logging.WARNING)
        with self.assertLogs(utils.LOGGER, level="WARNING") as cm:
            utils.log("This is an info message", level=logging.INFO)
            utils.log("This is a warning message", level=logging.WARNING)
            utils.log("This is an error message", level=logging.ERROR)

        self.assertEqual(len(cm.output), 2)
        self.assertIn("This is a warning message", cm.output[0])
        self.assertIn("This is an error message", cm.output[1])


class TestUtilsApiErrors(unittest.TestCase):
    """Test suite for API error handling in get_return."""

    @patch("requests.request")
    def test_get_return_forbidden_403(self, mock_request):
        """Verify 403 Forbidden returns error dictionary without raising HTTPError."""
        mock_response = mock_request.return_value
        mock_response.status_code = 403
        mock_response.text = '{"error": "attemptToDeleteOnlyAdminAccountError"}'
        mock_response.json.return_value = {"error": "attemptToDeleteOnlyAdminAccountError"}

        result = utils.get_return("/api/users/admin-uuid/", method="DELETE")
        self.assertEqual(result, {"error": 403, "details": {"error": "attemptToDeleteOnlyAdminAccountError"}})

    @patch("requests.request")
    def test_get_return_unauthorized_401(self, mock_request):
        """Verify 401 Unauthorized returns error dictionary without raising HTTPError."""
        mock_response = mock_request.return_value
        mock_response.status_code = 401
        mock_response.text = '{"error": "Invalid token"}'
        mock_response.json.return_value = {"error": "Invalid token"}

        result = utils.get_return("/api/users/", method="GET")
        self.assertEqual(result, {"error": 401, "details": {"error": "Invalid token"}})


class TestFormatAuditName(unittest.TestCase):
    """Test suite for format_audit_name convention."""

    def test_format_audit_name_appsec_long_name(self):
        """Verify long AppSec framework name extracts acronym and formats as requested."""
        res = utils.format_audit_name("Mirakl", "Application Security Assessment Framework (AppSec)")
        self.assertEqual(res, "Assessment of Mirakl with AppSec framework")

    def test_format_audit_name_appsec_manual(self):
        """Verify AppSec Manual IG framework extracts acronym/variant and formats properly."""
        res = utils.format_audit_name("Mirakl", "Application Security Assessment Framework (AppSec - Manual IG)")
        self.assertEqual(res, "Assessment of Mirakl with AppSec - Manual IG framework")

    def test_format_audit_name_multi_level_dpp(self):
        """Verify framework without parentheses appends framework word cleanly."""
        res = utils.format_audit_name("App-Secure-Core", "Multi-level DPP")
        self.assertEqual(res, "Assessment of App-Secure-Core with Multi-level DPP framework")

    def test_format_audit_name_short_name(self):
        """Verify already concise framework name formats properly."""
        res = utils.format_audit_name("App-Demo", "AppSec")
        self.assertEqual(res, "Assessment of App-Demo with AppSec framework")

    def test_format_audit_name_already_ends_with_framework(self):
        """Verify framework ending with framework does not duplicate the word."""
        res = utils.format_audit_name("Portal", "NIST CSF Framework")
        self.assertEqual(res, "Assessment of Portal with NIST CSF Framework")

    def test_format_audit_name_with_ref_id_fallback(self):
        """Verify framework_ref is used when framework_name is missing or empty."""
        res = utils.format_audit_name("Mirakl", None, "appsec")
        self.assertEqual(res, "Assessment of Mirakl with AppSec framework")

    def test_format_audit_name_fallbacks(self):
        """Verify missing app_name or framework_name fallbacks."""
        self.assertEqual(utils.format_audit_name("", "AppSec"), "Assessment with AppSec framework")
        self.assertEqual(utils.format_audit_name("Mirakl", ""), "Assessment of Mirakl")
        self.assertEqual(utils.format_audit_name("", ""), "Compliance Assessment")



if __name__ == "__main__":
    unittest.main()


