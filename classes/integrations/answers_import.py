"""Import questionnaire answers from a YAML profile into a compliance assessment.

Expected answers YAML format:
application:
  ...
answers:
  - requirement: "data_classification"
    question: "What is the maximum classification level handled?"
    answer: "Secret"
    result: "compliant"
    observation: "Secret banking transaction records"

Rows referencing the same requirement (and different questions) are merged into a
single PATCH per requirement assessment.
"""

import logging
from pathlib import Path
import yaml

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


def read_answers_file(file_path):
    """Read a YAML file containing assessment answers and return normalized rows.

    Args:
        file_path: Path to the YAML answers file.

    Returns:
        List of normalized answer dictionaries.
    """
    path = Path(file_path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if isinstance(data, dict):
        raw_rows = data.get("answers", [])
    elif isinstance(data, list):
        raw_rows = data
    else:
        raw_rows = []

    return [_normalize_row(row) for row in raw_rows if isinstance(row, dict)]


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

    # Prefix/substring fallback for questions with detailed guidance, clarifications, or conditional prefixes
    identifier_clean = identifier_normalized.rstrip("?:.,; ").strip()
    for question_urn, question in questions.items():
        q_text = str(question.get("text", "")).strip().lower()
        q_clean = q_text.rstrip("?:.,; ").strip()
        if (
            q_text.startswith(identifier_normalized)
            or identifier_normalized.startswith(q_text)
            or identifier_normalized in q_text
            or q_text in identifier_normalized
            or q_clean.startswith(identifier_clean)
            or identifier_clean.startswith(q_clean)
            or identifier_clean in q_clean
            or q_clean in identifier_clean
        ):
            return question_urn

    # Keyword overlap fallback when question wording is merged or rephrased
    identifier_words = set(identifier_clean.replace("(", " ").replace(")", " ").replace("/", " ").split())
    best_urn = None
    best_overlap = 0
    for question_urn, question in questions.items():
        q_text = str(question.get("text", "")).strip().lower()
        q_words = set(q_text.rstrip("?:.,; ").replace("(", " ").replace(")", " ").replace("/", " ").split())
        overlap = len(identifier_words & q_words)
        if overlap > best_overlap:
            best_overlap = overlap
            best_urn = question_urn
    if best_overlap >= 4:
        return best_urn

    if len(questions) == 1:
        return next(iter(questions.keys()))

    return None


def resolve_question_urn(identifier, questions):
    """Public helper to resolve a question URN from identifier and questions dict."""
    return _resolve_question_urn(questions, identifier)


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
        if not match:
            candidates = [
                choice.get("urn")
                for choice in choices
                if raw_value_normalized in str(choice.get("value", "")).strip().lower()
                or str(choice.get("value", "")).strip().lower().startswith(raw_value_normalized)
            ]
            if len(candidates) == 1:
                match = candidates[0]
            elif not candidates and raw_value_normalized in ("yes", "compliant", "true"):
                compliant = [c.get("urn") for c in choices if c.get("compute_result") or (c.get("add_score", 0) > 0)]
                if compliant:
                    match = compliant[0]
            elif not candidates and raw_value_normalized in ("no", "non-compliant", "false"):
                non_compliant = [c.get("urn") for c in choices if not c.get("compute_result") or (c.get("add_score", 0) == 0)]
                if non_compliant:
                    match = non_compliant[-1]
        if match:
            resolved_urns.append(match)
        else:
            unresolved.append(raw_value)

    if unresolved:
        return None, unresolved

    if question_type == "multiple_choice":
        return resolved_urns, []
    return resolved_urns[0] if resolved_urns else None, []


def import_compliance_answers(answers_path, compliance_assessment_id, requirement_assessment_dict):
    """Import questionnaire answers from a YAML file into a compliance assessment.

    Args:
        answers_path: Path to the YAML file containing the answers.
        compliance_assessment_id: ID of the target compliance assessment.
        requirement_assessment_dict: An audit.RequirementAssessmentDict instance.

    Returns:
        A summary dict: {"updated": int, "errors": [{"row": int, "reason": str}, ...]}.
    """
    rows = read_answers_file(answers_path)
    utils.log(f"Loaded {len(rows)} answers from: {answers_path}")

    # Accumulate per-requirement-assessment updates so multiple question rows
    # for the same requirement are merged into a single PATCH.
    pending = {}
    errors = []

    for row_index, row in enumerate(rows, start=1):
        requirement_identifier = row.get("requirement")
        if not requirement_identifier:
            errors.append({"row": row_index, "reason": "Missing 'requirement' value"})
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
        questions = ra.get_questions()
        final_answers = {}
        for q_urn in questions:
            if q_urn in entry["answers"]:
                final_answers[q_urn] = entry["answers"][q_urn]
            else:
                final_answers[q_urn] = None
        response = ra.update_answers(
            answers=final_answers,
            result=entry["result"],
            observation=entry["observation"],
            merge=False,
        )
        if response is not None:
            updated += 1
        else:
            errors.append({
                "row": None,
                "reason": f"Failed to update requirement assessment '{ra.get_name()}' ({ra.get_id()})",
            })

    # Reset any requirement assessments belonging to this compliance assessment that are NOT in the answers file
    all_ra_ids = requirement_assessment_dict.get_requirement_assessment_id_list_from_compliance_assessment_id(compliance_assessment_id)
    cleared = 0
    for ra_id in all_ra_ids:
        if ra_id not in pending:
            ra = requirement_assessment_dict.requirement_assessments.get(ra_id)
            if ra and (not ra.is_unassessed_result() or ra.has_selected_answer()):
                questions = ra.get_questions()
                cleared_answers = {q_urn: None for q_urn in questions} if questions else {}
                res = ra.update_answers(
                    answers=cleared_answers,
                    result="not_assessed",
                    observation="",
                    merge=False,
                )
                if res is not None:
                    cleared += 1
    if cleared > 0:
        utils.log(f"Reset {cleared} untriggered/unmentioned requirement assessment(s) to not_assessed")

    for error in errors:
        utils.log(f"Answers import issue: {error}", level=logging.WARNING)
    utils.log(f"Answers import complete: {updated} requirement assessment(s) updated, {len(errors)} issue(s)")

    return {"updated": updated, "errors": errors}
