"""Import questionnaire answers from a CSV file into a compliance assessment.

Expected CSV columns (header names are case-insensitive, extra columns are ignored):

- ``requirement`` (required): the requirement's URN or ref_id (e.g. "GV.OC-01") used
  to locate the target requirement assessment within the compliance assessment.
- ``question`` (optional): the question's URN or its exact question text. Can be left
  empty when the requirement has exactly one question.
- ``answer`` (required unless the row only sets result/observation): the answer value.
  For choice questions, match against the choice's display value (e.g. "Yes"/"No") or
  its URN directly. Multiple choices (for multiple_choice questions) can be separated
  with "|" or ";".
- ``result`` (optional): requirement assessment result, e.g. "compliant",
  "non_compliant", "partially_compliant", "not_applicable".
- ``observation`` (optional): free text comment set on the requirement assessment.

Rows referencing the same requirement (and different questions) are merged into a
single PATCH per requirement assessment.
"""

import csv
import logging

from .. import utils

_HEADER_ALIASES = {
    "requirement": "requirement",
    "requirement_urn": "requirement",
    "requirement_ref_id": "requirement",
    "ref_id": "requirement",
    "urn": "requirement",
    "question": "question",
    "question_urn": "question",
    "question_text": "question",
    "answer": "answer",
    "value": "answer",
    "result": "result",
    "observation": "observation",
    "comment": "observation",
    "comments": "observation",
}

_MULTI_VALUE_SEPARATORS = ["|", ";"]

_CHOICE_QUESTION_TYPES = {"unique_choice", "multiple_choice"}


def _normalize_row(row):
    """Return a dict keyed by the canonical column names understood by this module."""
    normalized = {}
    for key, value in row.items():
        if key is None:
            continue
        canonical = _HEADER_ALIASES.get(key.strip().lower())
        if canonical is None:
            continue
        normalized[canonical] = value.strip() if isinstance(value, str) else value
    return normalized


def read_csv_rows(csv_path, delimiter=None):
    """Read a CSV file and return a list of normalized row dicts.

    Args:
        csv_path: Path to the CSV file.
        delimiter: Optional explicit delimiter. Auto-detected (',' or ';') when omitted.
    """
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as csv_file:
        sample = csv_file.read(4096)
        csv_file.seek(0)
        if delimiter is None:
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t").delimiter
            except csv.Error:
                delimiter = ","
        reader = csv.DictReader(csv_file, delimiter=delimiter)
        return [_normalize_row(row) for row in reader]


def _split_multi_values(answer):
    """Split a raw answer string on the supported multi-value separators."""
    for separator in _MULTI_VALUE_SEPARATORS:
        if separator in answer:
            return [part.strip() for part in answer.split(separator) if part.strip()]
    return [answer.strip()]


def _resolve_question_urn(questions, identifier):
    """Resolve a question URN from an explicit URN or exact question text."""
    if identifier in questions:
        return identifier

    identifier_normalized = identifier.strip().lower()
    for question_urn, question in questions.items():
        if question_urn.strip().lower() == identifier_normalized:
            return question_urn
        if str(question.get("text", "")).strip().lower() == identifier_normalized:
            return question_urn
    return None


def _resolve_choice_value(question, raw_answer):
    """Resolve one or more choice URNs for a choice-type question's raw answer text."""
    choices = question.get("choices", []) or []
    question_type = question.get("type")
    raw_values = _split_multi_values(raw_answer) if question_type == "multiple_choice" else [raw_answer.strip()]

    resolved_urns = []
    unresolved = []
    for raw_value in raw_values:
        match = None
        raw_value_normalized = raw_value.strip().lower()
        for choice in choices:
            if choice.get("urn", "") == raw_value:
                match = choice.get("urn")
                break
            if str(choice.get("value", "")).strip().lower() == raw_value_normalized:
                match = choice.get("urn")
                break
        if match:
            resolved_urns.append(match)
        else:
            unresolved.append(raw_value)

    if unresolved:
        return None, unresolved

    if question_type == "multiple_choice":
        return resolved_urns, []
    return resolved_urns[0] if resolved_urns else None, []


def import_compliance_answers(csv_path, compliance_assessment_id, requirement_assessment_dict, delimiter=None):
    """Import questionnaire answers from a CSV file into a compliance assessment.

    Args:
        csv_path: Path to the CSV file containing the answers.
        compliance_assessment_id: ID of the target compliance assessment.
        requirement_assessment_dict: An audit.RequirementAssessmentDict instance.
        delimiter: Optional explicit CSV delimiter (auto-detected when omitted).

    Returns:
        A summary dict: {"updated": int, "errors": [{"row": int, "reason": str}, ...]}.
    """
    rows = read_csv_rows(csv_path, delimiter=delimiter)
    utils.log(f"Loaded {len(rows)} rows from CSV file: {csv_path}")

    # Accumulate per-requirement-assessment updates so multiple question rows
    # for the same requirement are merged into a single PATCH.
    pending = {}
    errors = []

    for row_index, row in enumerate(rows, start=2):  # header is row 1
        requirement_identifier = row.get("requirement")
        if not requirement_identifier:
            errors.append({"row": row_index, "reason": "Missing 'requirement' column value"})
            continue

        ra = requirement_assessment_dict.get_requirement_assessment_by_identifier(
            compliance_assessment_id, requirement_identifier
        )
        if ra is None:
            errors.append({
                "row": row_index,
                "reason": f"No requirement assessment found for identifier '{requirement_identifier}'",
            })
            continue

        entry = pending.setdefault(ra.get_id(), {"ra": ra, "answers": {}, "result": None, "observation": None})

        answer_raw = row.get("answer")
        if answer_raw:
            questions = ra.get_questions()
            question_identifier = row.get("question")
            if question_identifier:
                question_urn = _resolve_question_urn(questions, question_identifier)
            elif len(questions) == 1:
                question_urn = next(iter(questions))
            else:
                question_urn = None

            if question_urn is None:
                errors.append({
                    "row": row_index,
                    "reason": (
                        f"Could not resolve question for requirement '{requirement_identifier}' "
                        f"(identifier='{question_identifier}')"
                    ),
                })
            else:
                question = questions[question_urn]
                if question.get("type") in _CHOICE_QUESTION_TYPES:
                    resolved_value, unresolved = _resolve_choice_value(question, answer_raw)
                    if unresolved:
                        errors.append({
                            "row": row_index,
                            "reason": f"Unknown choice value(s) {unresolved} for question '{question_urn}'",
                        })
                    else:
                        entry["answers"][question_urn] = resolved_value
                else:
                    entry["answers"][question_urn] = answer_raw

        if row.get("result"):
            entry["result"] = row.get("result")
        if row.get("observation"):
            entry["observation"] = row.get("observation")

    updated = 0
    for entry in pending.values():
        ra = entry["ra"]
        if not entry["answers"] and entry["result"] is None and entry["observation"] is None:
            continue
        response = ra.update_answers(
            answers=entry["answers"],
            result=entry["result"],
            observation=entry["observation"],
        )
        if response is not None:
            updated += 1
        else:
            errors.append({
                "row": None,
                "reason": f"Failed to update requirement assessment '{ra.get_name()}' ({ra.get_id()})",
            })

    for error in errors:
        utils.log(f"CSV import issue: {error}", level=logging.WARNING)
    utils.log(f"CSV import complete: {updated} requirement assessment(s) updated, {len(errors)} issue(s)")

    return {"updated": updated, "errors": errors}
