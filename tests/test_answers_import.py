"""Unit tests for YAML answers import parsing and question resolution."""

import unittest
from pathlib import Path

from classes.integrations import answers_import


class TestAnswersImport(unittest.TestCase):
    """Test suite for YAML answer reading, normalization, and question resolution."""

    def test_read_yaml_rows_normalization(self):
        """Verify reading and normalization of application YAML answer files."""
        yml_path = Path("test_data/app_secure_core.yml")
        self.assertTrue(yml_path.exists(), f"Profile {yml_path} missing")
        rows = answers_import.read_answers_file(str(yml_path))

        self.assertGreater(len(rows), 0)
        first_row = rows[0]
        self.assertIn("requirement", first_row)
        self.assertIn("question", first_row)
        self.assertIn("answer", first_row)
        self.assertEqual(first_row["requirement"], "data_classification")
        self.assertEqual(first_row["answer"], "Secret")

    def test_split_multi_values(self):
        """Verify pipe and semicolon multi-value answer splitting."""
        self.assertEqual(answers_import._split_multi_values("Choice A | Choice B"), ["Choice A", "Choice B"])
        self.assertEqual(answers_import._split_multi_values("Choice 1 ; Choice 2"), ["Choice 1", "Choice 2"])
        self.assertEqual(answers_import._split_multi_values("Single Choice"), ["Single Choice"])

    def test_resolve_question_urn(self):
        """Verify question URN resolution from text and URN identifiers."""
        questions = {
            "urn:req:q1": {"text": "Is data encrypted in transit?"},
            "urn:req:q2": {"text": "What is the hosting model?"},
        }

        # Match by direct URN
        self.assertEqual(
            answers_import._resolve_question_urn(questions, "urn:req:q1"),
            "urn:req:q1",
        )
        # Match by exact text (case-insensitive)
        self.assertEqual(
            answers_import._resolve_question_urn(questions, "is data encrypted in transit?"),
            "urn:req:q1",
        )
        self.assertEqual(
            answers_import._resolve_question_urn(questions, "What is the hosting model?"),
            "urn:req:q2",
        )
        # Non-matching question
        self.assertIsNone(answers_import._resolve_question_urn(questions, "Non existent question text"))

    def test_resolve_choice_value(self):
        """Verify choice resolution against choice definitions."""
        question = {
            "type": "unique_choice",
            "choices": [
                {"urn": "urn:choice:yes", "value": "Yes"},
                {"urn": "urn:choice:no", "value": "No"},
            ],
        }
        urn, unresolved = answers_import._resolve_choice_value(question, "Yes")
        self.assertEqual(urn, "urn:choice:yes")
        self.assertEqual(unresolved, [])

        # Case-insensitive
        urn, unresolved = answers_import._resolve_choice_value(question, "no")
        self.assertEqual(urn, "urn:choice:no")
        self.assertEqual(unresolved, [])

        # Direct URN
        urn, unresolved = answers_import._resolve_choice_value(question, "urn:choice:yes")
        self.assertEqual(urn, "urn:choice:yes")
        self.assertEqual(unresolved, [])


if __name__ == "__main__":
    unittest.main()
