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


if __name__ == "__main__":
    unittest.main()


