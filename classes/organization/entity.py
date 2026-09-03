import logging

from .. import utils


class Entity:
    def __init__(self, json_entity):
        self.json_object = json_entity
    def get_json(self):
        return self.json_object
    def get_name(self):
        return self.json_object.get('name', '')
    def get_id(self):
        return self.json_object.get('id', '')
    def is_builtin(self):
        return bool(self.json_object.get('builtin', False))
    def is_external(self):
        """Return True when the entity should be treated as external/third-party.

        The platform marks the internal root entity as builtin. External entities
        are non-builtin records.
        """
        return not self.is_builtin()
    def get_folder_id(self):
        """Return the folder ID associated with this entity."""
        folder = self.json_object.get('folder', {})
        if isinstance(folder, dict):
            return folder.get('id', '')
        return str(folder) if folder else ''
    def get_representatives(self):
        """Return the list of representatives attached to this entity.

        The API may expose representatives either as a direct list or nested in a
        dedicated field. This helper is intentionally tolerant to both shapes.
        """
        representatives = self.json_object.get('representatives', [])
        if representatives:
            return representatives
        return self.json_object.get('entity_representatives', [])
    def get_representative_ids(self):
        """Return all representative IDs attached to the entity."""
        representative_ids = []
        for representative in self.get_representatives():
            if isinstance(representative, dict):
                if representative.get('id'):
                    representative_ids.append(representative.get('id'))
                    continue
                user = representative.get('user', {})
                if isinstance(user, dict) and user.get('id'):
                    representative_ids.append(user.get('id'))
                    continue
                if representative.get('user_id'):
                    representative_ids.append(representative.get('user_id'))
            elif representative:
                representative_ids.append(representative)
        return list(dict.fromkeys(representative_ids))
    def print_json(self):
        utils.log(str(self.json_object))
    def print_name(self):
        utils.log(f"Name: {self.get_name()}")
    def print_id(self):
        utils.log(f"ID: {self.get_id()}")


class EntityRepresentative:
    """Represent a user linked to an entity as a third-party representative."""

    def __init__(self, json_entity_representative):
        self.json_object = json_entity_representative

    def get_json(self):
        return self.json_object

    def get_id(self):
        return self.json_object.get('id', '')

    def get_entity_id(self):
        entity = self.json_object.get('entity', {})
        if isinstance(entity, dict):
            return entity.get('id', '')
        return str(entity)

    def get_user_id(self):
        user = self.json_object.get('user', {})
        if isinstance(user, dict):
            return user.get('id', '')
        return str(user) if user else self.json_object.get('user_id', '')

    def get_role(self):
        return self.json_object.get('role', '')

    def get_name(self):
        user = self.json_object.get('user', {})
        if isinstance(user, dict):
            full_name = ' '.join(filter(None, [user.get('first_name', ''), user.get('last_name', '')])).strip()
            if full_name:
                return full_name
            return user.get('email', '')
        return self.json_object.get('name', '')


class EntityRepresentativeDict:
    """Manage the links between entities and their representatives."""

    def __init__(self):
        self.reload()

    def reload(self):
        self.entity_representatives = []
        # The API does not expose a dedicated entity-representatives endpoint.
        # Representatives are carried on entity-assessment records.
        for assessment in utils.get_all_results("/api/entity-assessments/", force_reload=True):
            entity = assessment.get('entity', {})
            entity_id = entity.get('id', '') if isinstance(entity, dict) else entity
            if not entity_id:
                continue

            representatives = assessment.get('representatives', []) or assessment.get('entity_representatives', [])
            if not isinstance(representatives, list):
                continue

            for representative in representatives:
                if not isinstance(representative, dict):
                    continue

                representative_id = representative.get('id') or representative.get('user_id')
                if not representative_id:
                    user = representative.get('user', {})
                    if isinstance(user, dict):
                        representative_id = user.get('id')
                if not representative_id:
                    continue

                self.entity_representatives.append(
                    EntityRepresentative({
                        'id': representative_id,
                        'entity': {'id': entity_id},
                        'user': {'id': representative_id},
                        'role': representative.get('role', 'representative'),
                    })
                )

        # Some APIs expose the user-to-entity link via the user's group names rather
        # than a dedicated entity-representatives endpoint. Match third-party users to
        # entities by their entity-specific user groups, e.g.:
        # "Mondial Relay/Entity assessment of Mondial Relay - Third-party respondent".
        entity_records = utils.get_all_results('/api/entities/', force_reload=True)
        entity_names = {}
        for entity in entity_records:
            if not isinstance(entity, dict):
                continue
            entity_id = entity.get('id')
            entity_name = entity.get('name')
            if entity_id and entity_name:
                entity_names[entity_name.lower()] = entity_id

        users = utils.get_all_results('/api/users/', force_reload=True)
        users_by_email = {
            str(user.get('email')).lower(): user.get('id')
            for user in users
            if isinstance(user, dict) and user.get('email') and user.get('id')
        }
        configured_representatives = utils.get_external_entity_representative_emails()
        for entity_name, entity_id in entity_names.items():
            for email in configured_representatives.get(entity_name, []):
                user_id = users_by_email.get(email.lower())
                if not user_id or any(
                    representative.get_entity_id() == entity_id
                    and representative.get_user_id() == user_id
                    for representative in self.entity_representatives
                ):
                    continue
                self.entity_representatives.append(
                    EntityRepresentative({
                        'id': user_id,
                        'entity': {'id': entity_id},
                        'user': {'id': user_id},
                        'role': 'representative',
                    })
                )

        for user in users:
            if not isinstance(user, dict):
                continue
            user_id = user.get('id')
            if not user_id:
                continue

            seen = False
            for representative in self.entity_representatives:
                if representative.get_user_id() == user_id:
                    seen = True
                    break
            if seen:
                continue

            for group in user.get('user_groups', []) or []:
                group_name = group.get('str', '') if isinstance(group, dict) else str(group)
                if not group_name:
                    continue
                group_name_lower = group_name.lower()
                for entity_name, entity_id in entity_names.items():
                    if entity_name in group_name_lower:
                        self.entity_representatives.append(
                            EntityRepresentative({
                                'id': user_id,
                                'entity': {'id': entity_id},
                                'user': {'id': user_id},
                                'role': 'representative',
                            })
                        )
                        seen = True
                        break
                if seen:
                    break

    def get_entity_representatives(self):
        return self.entity_representatives

    def get_representatives_for_entity(self, entity_id):
        return [
            representative for representative in self.entity_representatives
            if representative.get_entity_id() == entity_id
        ]

    def get_user_ids_for_entity(self, entity_id):
        return [
            representative.get_user_id()
            for representative in self.get_representatives_for_entity(entity_id)
            if representative.get_user_id()
        ]

    def get_entity_ids_for_user(self, user_id):
        return [
            representative.get_entity_id()
            for representative in self.entity_representatives
            if representative.get_user_id() == user_id
        ]

    def upsert_entity_representative(self, entity_id, user_id, role='representative'):
        """Create the link between an entity and a user when it is missing."""
        for representative in self.entity_representatives:
            if representative.get_entity_id() == entity_id and representative.get_user_id() == user_id:
                return representative

        payload = {
            'entity': entity_id,
            'user': user_id,
            'role': role,
        }
        result = utils.get_return('/api/entity-representatives/', method='POST', payload=payload)
        if result and (not isinstance(result, dict) or not result.get('error')):
            self.reload()
            return result
        utils.log(f"Failed to create entity representative for entity {entity_id} and user {user_id}: {result}", level=logging.ERROR)
        return None


class EntityDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.entities = [Entity(e) for e in utils.get_all_results("/api/entities/", force_reload=True)]

    def get_entities(self):
        return self.entities

    def get_id_from_name(self, name):
        for entity in self.entities:
            if entity.get_name() == name:
                return entity.get_id()
        return None

    def get_name_from_id(self, entity_id):
        for entity in self.entities:
            if entity.get_id() == entity_id:
                return entity.get_name()
        return None

    def get_external_entities(self):
        return [entity for entity in self.entities if entity.is_external()]
