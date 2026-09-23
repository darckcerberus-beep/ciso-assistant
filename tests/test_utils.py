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


if __name__ == "__main__":
    unittest.main()

