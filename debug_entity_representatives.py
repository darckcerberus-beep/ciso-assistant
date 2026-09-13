import argparse
from typing import Any

from classes import utils
from classes.organization import Entity, EntityDict, EntityRepresentativeDict


def _norm(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _lower(value: Any) -> str:
    return _norm(value).lower()


def _extract_id(value: Any) -> str:
    if isinstance(value, dict):
        return _norm(value.get('id'))
    return _norm(value)


def _pick_entity(entity_dict: EntityDict, entity_id: str | None, entity_name: str | None) -> Entity | None:
    entities = entity_dict.get_entities()

    if entity_id:
        for entity in entities:
            if _norm(entity.get_id()) == _norm(entity_id):
                return entity

    if entity_name:
        target = _lower(entity_name)
        exact_match = next((entity for entity in entities if _lower(entity.get_name()) == target), None)
        if exact_match:
            return exact_match
        partial_matches = [entity for entity in entities if target in _lower(entity.get_name())]
        if len(partial_matches) == 1:
            return partial_matches[0]

    return None


def _find_user(users: list[dict[str, Any]], user_id: str | None, user_email: str | None) -> dict[str, Any] | None:
    if user_id:
        for user in users:
            if _norm(user.get("id")) == _norm(user_id):
                return user

    if user_email:
        target = _lower(user_email)
        for user in users:
            if _lower(user.get("email")) == target:
                return user

    return None


def _extract_assessment_representatives(entity_id: str, assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for assessment in assessments:
        assessment_entity = assessment.get("entity", {})
        assessment_entity_id = assessment_entity.get("id") if isinstance(assessment_entity, dict) else assessment_entity
        if _norm(assessment_entity_id) != _norm(entity_id):
            continue

        representatives = assessment.get("representatives", []) or assessment.get("entity_representatives", [])
        if not isinstance(representatives, list):
            continue

        for representative in representatives:
            if not isinstance(representative, dict):
                continue

            user = representative.get("user", {})
            user_id = ""
            if isinstance(user, dict) and user.get("id") is not None:
                user_id = _norm(user.get("id"))
            elif representative.get("user_id") is not None:
                user_id = _norm(representative.get("user_id"))

            rows.append(
                {
                    "source": "entity-assessment",
                    "user_id": user_id,
                    "role": representative.get("role", ""),
                    "raw": representative,
                }
            )

    return rows


def _extract_representatives_endpoint(entity_id: str, representatives: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for representative in representatives:
        if not isinstance(representative, dict):
            continue
        rep_entity_id = _extract_id(representative.get('entity'))
        rep_user_id = _extract_id(representative.get('user'))
        if rep_entity_id != _norm(entity_id):
            continue
        rows.append(
            {
                'id': _norm(representative.get('id')),
                'entity': rep_entity_id,
                'user_id': rep_user_id,
                'email': _norm(representative.get('email')),
                'role': _norm(representative.get('role')),
            }
        )
    return rows


def _extract_group_matches(entity_name: str, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    entity_name_lower = _lower(entity_name)
    if not entity_name_lower:
        return matches

    for user in users:
        user_id = _norm(user.get("id"))
        if not user_id:
            continue
        for group in user.get("user_groups", []) or []:
            group_name = group.get("str", "") if isinstance(group, dict) else _norm(group)
            if entity_name_lower in _lower(group_name):
                matches.append(
                    {
                        "source": "user-group",
                        "user_id": user_id,
                        "group": group_name,
                    }
                )
                break

    return matches


def _extract_settings_matches(entity_name: str, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    configured = utils.get_external_entity_representative_emails().get(_lower(entity_name), [])
    users_by_email = {
        _lower(user.get("email")): _norm(user.get("id"))
        for user in users
        if isinstance(user, dict) and user.get("email") and user.get("id") is not None
    }

    for email in configured:
        user_id = users_by_email.get(_lower(email), "")
        matches.append(
            {
                "source": "settings",
                "email": email,
                "user_id": user_id,
                "resolved": bool(user_id),
            }
        )
    return matches


def _print_header(title: str) -> None:
    print(f"\n=== {title} ===")


def _print_user(user: dict[str, Any]) -> None:
    full_name = " ".join(
        part for part in [_norm(user.get("first_name")), _norm(user.get("last_name"))] if part
    ).strip()
    print(f"Target user: {full_name or '<no name>'} | email={_norm(user.get('email'))} | id={_norm(user.get('id'))}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Debug the link between an entity and its representatives.",
    )
    parser.add_argument("--entity-id", help="Entity ID to inspect")
    parser.add_argument("--entity-name", help="Entity name to inspect")
    parser.add_argument("--user-id", help="Representative user ID to validate")
    parser.add_argument("--user-email", help="Representative user email to validate")
    parser.add_argument(
        "--create-missing",
        action="store_true",
        help="If the target user is missing, create the entity-representative link via API.",
    )
    parser.add_argument(
        "--list-entities",
        action="store_true",
        help="List all external entities and representative counts.",
    )
    args = parser.parse_args()

    entity_dict = EntityDict()
    entity_representative_dict = EntityRepresentativeDict()
    users = utils.get_all_results("/api/users/", force_reload=True)

    if args.list_entities:
        _print_header("External entities representative snapshot")
        for entity in entity_dict.get_external_entities():
            user_ids = entity_representative_dict.get_user_ids_for_entity(entity.get_id())
            print(f"- {entity.get_name()} | id={entity.get_id()} | reps={len(user_ids)}")
        return

    entity = _pick_entity(entity_dict, args.entity_id, args.entity_name)
    if not entity:
        print("Entity not found. Use --entity-id or --entity-name. You can also run with --list-entities.")
        return

    target_user = _find_user(users, args.user_id, args.user_email)

    _print_header("Entity")
    print(f"Name={entity.get_name()} | id={entity.get_id()} | builtin={entity.is_builtin()} | external={entity.is_external()}")

    _print_header("Source 1: representatives endpoint")
    api_representatives = utils.get_all_results('/api/representatives/', force_reload=True, params={'entity': entity.get_id()})
    endpoint_rows = _extract_representatives_endpoint(entity.get_id(), api_representatives)
    print(f"Representative rows discovered: {len(endpoint_rows)}")
    for row in endpoint_rows:
        print(
            f"- rep_id={row.get('id')} entity={row.get('entity')} user_id={row.get('user_id')} "
            f"email={row.get('email')} role={row.get('role')}"
        )

    _print_header("Source 2: entity payload")
    entity_payload_reps = entity.get_representatives()
    print(f"Raw representative rows: {len(entity_payload_reps)}")
    for row in entity_payload_reps:
        print(f"- {row}")
    print(f"Resolved representative IDs via Entity.get_representative_ids(): {entity.get_representative_ids()}")

    _print_header("Source 3: entity-assessment payload")
    assessments = utils.get_all_results("/api/entity-assessments/", force_reload=True)
    assessment_reps = _extract_assessment_representatives(entity.get_id(), assessments)
    print(f"Representative rows discovered: {len(assessment_reps)}")
    for row in assessment_reps:
        print(f"- user_id={row.get('user_id')} role={row.get('role')} raw={row.get('raw')}")

    _print_header("Source 4: settings mapping")
    settings_matches = _extract_settings_matches(entity.get_name(), users)
    if settings_matches:
        for row in settings_matches:
            print(f"- email={row.get('email')} resolved_user_id={row.get('user_id')} resolved={row.get('resolved')}")
    else:
        print("No configured representative emails for this entity in settings.")

    _print_header("Source 5: user-group inference")
    group_matches = _extract_group_matches(entity.get_name(), users)
    print(f"Users inferred by group-name matching: {len(group_matches)}")
    for row in group_matches:
        print(f"- user_id={row.get('user_id')} via_group={row.get('group')}")

    _print_header("Aggregated EntityRepresentativeDict link")
    linked_user_ids = entity_representative_dict.get_user_ids_for_entity(entity.get_id())
    linked_user_ids_normalized = {_norm(user_id) for user_id in linked_user_ids if _norm(user_id)}
    print(f"Linked user IDs (raw): {linked_user_ids}")
    print(f"Linked user IDs (normalized): {sorted(linked_user_ids_normalized)}")

    if not target_user:
        if args.user_id or args.user_email:
            print("Target user not found with provided --user-id/--user-email.")
        else:
            print("No target user provided. Add --user-id or --user-email to validate one specific link.")
        return

    _print_header("Target user check")
    _print_user(target_user)
    target_user_id = _norm(target_user.get("id"))

    strict_present = target_user.get("id") in linked_user_ids
    normalized_present = target_user_id in linked_user_ids_normalized
    print(f"Present by strict comparison: {strict_present}")
    print(f"Present by normalized string comparison: {normalized_present}")

    if normalized_present:
        print("Result: target user is linked to entity.")
        return

    print("Result: target user is NOT linked to entity.")
    if args.create_missing:
        _print_header("Create missing link")
        result = entity_representative_dict.upsert_entity_representative(entity.get_id(), target_user_id)
        print(f"Upsert result: {result}")


if __name__ == "__main__":
    main()
