"""Unit tests for CSV import parsing and question resolution."""

import unittest
from pathlib import Path

from classes.integrations import csv_import


class TestCsvImport(unittest.TestCase):
    """Test suite for CSV answer reading and header normalization."""

    def test_read_csv_rows_normalization(self):
        """Verify reading and normalization of application CSV files."""
        csv_path = Path("test_data/app_secure_core.csv")
        rows = csv_import.read_csv_rows(str(csv_path))

        self.assertGreater(len(rows), 0)
        first_row = rows[0]
        self.assertIn("requirement", first_row)
        self.assertIn("question", first_row)
        self.assertIn("answer", first_row)
        self.assertIn("result", first_row)
        self.assertEqual(first_row["requirement"], "data_classification")
        self.assertEqual(first_row["answer"], "Secret")

    def test_read_yaml_rows_normalization(self):
        """Verify reading and normalization of application YAML files."""
        yml_path = Path("test_data/app_secure_core.yml")
        rows = csv_import.read_answers_file(str(yml_path))

        self.assertGreater(len(rows), 0)
        first_row = rows[0]
        self.assertIn("requirement", first_row)
        self.assertIn("question", first_row)
        self.assertIn("answer", first_row)
        self.assertEqual(first_row["requirement"], "data_classification")
        self.assertEqual(first_row["answer"], "Secret")

    def test_split_multi_values(self):
        """Verify pipe and semicolon multi-value answer splitting."""
        self.assertEqual(csv_import._split_multi_values("Choice A | Choice B"), ["Choice A", "Choice B"])
        self.assertEqual(csv_import._split_multi_values("Choice 1 ; Choice 2"), ["Choice 1", "Choice 2"])
        self.assertEqual(csv_import._split_multi_values("Single Choice"), ["Single Choice"])

    def test_resolve_question_urn(self):
        """Verify question URN resolution from text and URN identifiers."""
        questions = {
            "urn:req:q1": {"text": "Is data encrypted in transit?"},
            "urn:req:q2": {"text": "What is the hosting model?"},
        }

        # Match by direct URN
        self.assertEqual(
            csv_import._resolve_question_urn(questions, "urn:req:q1"),
            "urn:req:q1"
        )
        # Match by exact text (case-insensitive)
        self.assertEqual(
            csv_import._resolve_question_urn(questions, "is data encrypted in transit?"),
            "urn:req:q1"
        )
        self.assertEqual(
            csv_import._resolve_question_urn(questions, "What is the hosting model?"),
            "urn:req:q2"
        )
        # Non-matching question
        self.assertIsNone(csv_import._resolve_question_urn(questions, "Non existent question text"))


if __name__ == "__main__":
    unittest.main()

