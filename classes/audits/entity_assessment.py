"""Entity assessment models and external-entity audit orchestration."""

import logging
import uuid
from typing import Any

from .. import utils


class EntityAssessment:
    """Represent an entity assessment linked to a compliance assessment."""

    def __init__(self, json_ea):
        """Initialize from the API payload."""
        self.json_object = json_ea

    def get_name(self):
        """Return the entity assessment name."""
        return self.json_object.get('name', '')

    def get_id(self):
        """Return the entity assessment UUID."""
        return self.json_object.get('id', '')

    def get_compliance_assessment_id(self):
        """Return the parent compliance assessment ID."""
        compliance_assessment = self.json_object.get('compliance_assessment', {})
        if isinstance(compliance_assessment, dict):
            return compliance_assessment.get('id', '') or ''
        if compliance_assessment in (None, '', {}):
            return ''
        return str(compliance_assessment)

    def get_entity_id(self):
        """Return the linked entity ID."""
        entity = self.json_object.get('entity', {})
        if isinstance(entity, dict):
            return entity.get('id', '') or ''
        if entity in (None, '', {}):
            return ''
        return str(entity)

    def get_entity_name(self):
        """Return the linked entity name."""
        entity = self.json_object.get('entity', {})
        if isinstance(entity, dict):
            return entity.get('name', '') or ''
        if entity in (None, '', {}):
            return ''
        return str(entity)

    def get_representative_ids(self):
        """Return the representative user IDs attached to the entity assessment."""
        candidates = []
        candidates.extend(self.json_object.get('representatives', []) or [])
        candidates.extend(self.json_object.get('entity_representatives', []) or [])

        entity = self.json_object.get('entity', {})
        if isinstance(entity, dict):
            candidates.extend(entity.get('representatives', []) or [])
            candidates.extend(entity.get('entity_representatives', []) or [])

        if not candidates:
            return []

        representative_ids = []
        for representative in candidates:
            if isinstance(representative, dict):
                if representative.get('id'):
                    representative_ids.append(representative.get('id'))
                    continue
                user = representative.get('user', {})
                if isinstance(user, dict):
                    if user.get('id'):
                        representative_ids.append(user.get('id'))
                        continue
                if representative.get('user_id'):
                    representative_ids.append(representative.get('user_id'))
            elif representative:
                representative_ids.append(str(representative))
        return list(dict.fromkeys(representative_ids))

    def get_status(self):
        """Return the current assessment status."""
        return self.json_object.get('status', '')

    def get_result(self):
        """Return the assessment result."""
        return self.json_object.get('result', '')

    def get_json(self):
        """Return the raw assessment payload."""
        return self.json_object

    def resolve_actor_ids(self, representative_ids):
        """Translate representative user IDs to API actor IDs when an actor record exists."""
        actor_ids = []
        actor_records = utils.get_all_results('/api/actors/', force_reload=True)
        user_records = utils.get_all_results('/api/users/', force_reload=True)
        user_by_id = {
            user.get('id'): user
            for user in user_records
            if isinstance(user, dict) and user.get('id')
        }

        for representative_id in representative_ids:
            if not representative_id:
                continue
            normalized = str(representative_id)

            for actor in actor_records:
                if not isinstance(actor, dict):
                    continue
                actor_id = actor.get('id')
                if actor_id == normalized:
                    actor_ids.append(str(actor_id))
                    break

                specific = actor.get('specific', {})
                if isinstance(specific, dict):
                    if specific.get('id') == normalized:
                        actor_ids.append(str(actor.get('id')))
                        break
                    if specific.get('str') and representative_id in (specific.get('str'), str(representative_id)):
                        actor_ids.append(str(actor.get('id')))
                        break

                if actor.get('str') and actor.get('str') == user_by_id.get(normalized, {}).get('email'):
                    actor_ids.append(str(actor.get('id')))
                    break
            else:
                actor_ids.append(normalized)

        return list(dict.fromkeys(actor_ids))

    @staticmethod
    def _extract_assignment_actor_ids(assignment):
        """Return normalized actor IDs from a requirement-assignment payload."""
        actor_ids = []
        for actor in assignment.get('actor', []) or []:
            if isinstance(actor, dict):
                actor_id = actor.get('id') or actor.get('user_id')
                if actor_id:
                    actor_ids.append(str(actor_id))
            elif actor:
                actor_ids.append(str(actor))
        return list(dict.fromkeys(actor_ids))

    @staticmethod
    def _extract_assignment_requirement_ids(assignment):
        """Return normalized requirement-assessment IDs from a requirement-assignment payload."""
        requirement_ids = []
        for requirement_assessment in assignment.get('requirement_assessments', []) or []:
            if isinstance(requirement_assessment, dict):
                requirement_id = requirement_assessment.get('id')
                if requirement_id:
                    requirement_ids.append(str(requirement_id))
            elif requirement_assessment:
                requirement_ids.append(str(requirement_assessment))
        return list(dict.fromkeys(requirement_ids))

    def _find_matching_requirement_assignment(self, compliance_assessment_id, actor_ids, requirement_assessment_ids):
        """Return a matching requirement assignment when one exists for the target scope."""
        if not compliance_assessment_id or not actor_ids:
            return None

        required_actor_ids = {str(actor_id) for actor_id in actor_ids if actor_id}
        required_requirement_ids = {
            str(requirement_id)
            for requirement_id in requirement_assessment_ids
            if requirement_id
        }

        assignments = utils.get_all_results("/api/requirement-assignments/", force_reload=True)
        for assignment in assignments:
            compliance_assessment = assignment.get('compliance_assessment', {})
            assignment_compliance_id = compliance_assessment.get('id') if isinstance(compliance_assessment, dict) else compliance_assessment
            if assignment_compliance_id != compliance_assessment_id:
                continue

            assignment_actor_ids = set(self._extract_assignment_actor_ids(assignment))
            if not assignment_actor_ids.issuperset(required_actor_ids):
                continue

            assignment_requirement_ids = set(self._extract_assignment_requirement_ids(assignment))
            if required_requirement_ids and not assignment_requirement_ids.issuperset(required_requirement_ids):
                continue

            return assignment

        return None

    def assign_requirements_to_representatives(self, representative_ids=None, first_only=False):
        """Assign requirement assessments to linked entity representatives."""
        if representative_ids is None:
            representative_ids = self.get_representative_ids()
        else:
            representative_ids = list(dict.fromkeys(str(actor_id) for actor_id in representative_ids))

        if first_only and representative_ids:
            representative_ids = representative_ids[:1]

        compliance_assessment_id = self.get_compliance_assessment_id()
        if not compliance_assessment_id or not representative_ids:
            return None

        actor_ids = self.resolve_actor_ids(representative_ids)
        if not actor_ids:
            return None

        requirement_assessment_ids = []
        for requirement_assessment in utils.get_all_results("/api/requirement-assessments/", force_reload=True):
            compliance_assessment = requirement_assessment.get('compliance_assessment', {})
            assessment_id = compliance_assessment.get('id') if isinstance(compliance_assessment, dict) else compliance_assessment
            if assessment_id == compliance_assessment_id:
                requirement_assessment_id = requirement_assessment.get('id')
                if requirement_assessment_id:
                    requirement_assessment_ids.append(requirement_assessment_id)
        if not requirement_assessment_ids:
            return None

        existing_assignment = self._find_matching_requirement_assignment(
            compliance_assessment_id,
            actor_ids,
            requirement_assessment_ids,
        )
        if existing_assignment:
            utils.log(
                f"Requirement assignments already exist for entity assessment {self.get_id()} "
                f"with representative(s): {representative_ids}",
                level=logging.INFO,
            )
            return existing_assignment

        payload = {
            'requirement_assessments': requirement_assessment_ids,
            'compliance_assessment': compliance_assessment_id,
            'actor': actor_ids,
        }

        entity = self.json_object.get('entity', {})
        if isinstance(entity, dict):
            folder = entity.get('folder', {})
            if isinstance(folder, dict):
                folder_id = folder.get('id')
            else:
                folder_id = folder
            if folder_id:
                payload['folder'] = folder_id

        response = utils.get_return('/api/requirement-assignments/', method='POST', payload=payload)
        if response and (not isinstance(response, dict) or not response.get('error')):
            assignment_id = response.get('id') if isinstance(response, dict) else None
            if assignment_id:
                utils.get_return(
                    f"/api/requirement-assignments/{assignment_id}/set_status/",
                    method='POST',
                    payload={'status': 'in_progress'},
                )

            post_assignment = self._find_matching_requirement_assignment(
                compliance_assessment_id,
                actor_ids,
                requirement_assessment_ids,
            )
            if not post_assignment:
                utils.log(
                    f"Requirement assignment post-check failed for entity assessment {self.get_id()} "
                    f"and representative(s): {representative_ids}",
                    level=logging.WARNING,
                )
            return response

        utils.log(
            f"Failed to assign requirement assessments for entity assessment {self.get_id()} "
            f"to representatives {representative_ids}: {response}",
            level=logging.ERROR,
        )
        return None

    def ensure_linked_audit(self, framework_id, representative_ids=None, entity_assessment_dict=None):
        """Create a linked audit/compliance assessment if the entity assessment is missing one.
        
        Args:
            framework_id: The framework ID to link
            representative_ids: Optional list of representative IDs
            entity_assessment_dict: Optional EntityAssessmentDict for handling name conflicts
        """
        if not framework_id or self.get_compliance_assessment_id():
            return self.json_object

        payload = {
            'framework': framework_id,
            'create_audit': True,
        }
        response = utils.get_return(
            f"/api/entity-assessments/{self.get_id()}/",
            method='PATCH',
            payload=payload,
            log_errors=False,
        )
        if response and (not isinstance(response, dict) or not response.get('error')):
            self.json_object = response
            self.assign_requirements_to_representatives(representative_ids, first_only=True)
            return response
        
        # Check if the error is a name collision
        if isinstance(response, dict) and response.get('error') == 400:
            details = response.get('details', {})
            name_errors = details.get('name', []) if isinstance(details, dict) else []
            has_name_collision = any('already used' in str(error).lower() for error in name_errors)
            
            if has_name_collision and entity_assessment_dict:
                # Try to rename the assessment to resolve the conflict
                current_name = self.get_name()
                entity_name = self.get_entity_name()
                reserved_names = entity_assessment_dict._get_reserved_entity_assessment_names()
                
                # Generate candidate names
                candidates = entity_assessment_dict._build_entity_assessment_name_candidates(entity_name, self.get_entity_id())
                
                for candidate_name in candidates:
                    if candidate_name == current_name or candidate_name in reserved_names:
                        continue
                    
                    # Try renaming the assessment
                    rename_response = utils.get_return(
                        f"/api/entity-assessments/{self.get_id()}/",
                        method='PATCH',
                        payload={'name': candidate_name},
                        log_errors=False,
                    )
                    if rename_response and (not isinstance(rename_response, dict) or not rename_response.get('error')):
                        self.json_object = rename_response
                        utils.log(
                            f"Renamed entity assessment {self.get_id()} from '{current_name}' to '{candidate_name}' to resolve conflict",
                            level=logging.INFO,
                        )
                        # Now retry the audit linking with the new name
                        retry_response = utils.get_return(
                            f"/api/entity-assessments/{self.get_id()}/",
                            method='PATCH',
                            payload=payload,
                            log_errors=False,
                        )
                        if retry_response and (not isinstance(retry_response, dict) or not retry_response.get('error')):
                            self.json_object = retry_response
                            self.assign_requirements_to_representatives(representative_ids, first_only=True)
                            return retry_response
                        break

                # Deterministic candidates may all be exhausted in shared scopes.
                # Try a practically unique name to force conflict resolution.
                for _ in range(5):
                    unique_name = entity_assessment_dict._build_unique_entity_assessment_name(entity_name, self.get_entity_id())
                    if unique_name == current_name or unique_name in reserved_names:
                        continue

                    rename_response = utils.get_return(
                        f"/api/entity-assessments/{self.get_id()}/",
                        method='PATCH',
                        payload={'name': unique_name},
                        log_errors=False,
                    )
                    if rename_response and (not isinstance(rename_response, dict) or not rename_response.get('error')):
                        self.json_object = rename_response
                        utils.log(
                            f"Renamed entity assessment {self.get_id()} from '{current_name}' to '{unique_name}' to resolve conflict",
                            level=logging.INFO,
                        )
                        retry_response = utils.get_return(
                            f"/api/entity-assessments/{self.get_id()}/",
                            method='PATCH',
                            payload=payload,
                            log_errors=False,
                        )
                        if retry_response and (not isinstance(retry_response, dict) or not retry_response.get('error')):
                            self.json_object = retry_response
                            self.assign_requirements_to_representatives(representative_ids, first_only=True)
                            return retry_response
                        break
        
        utils.log(
            f"Failed to create linked audit for entity assessment {self.get_id()}: {response}",
            level=logging.ERROR,
        )
        return None


class EntityAssessmentDict:
    """ Manage a collection of entity assessments."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Refresh the internal entity assessment list from the API."""
        self.entity_assessments = [
            EntityAssessment(ea) for ea in utils.get_all_results("/api/entity-assessments/", force_reload=True)
        ]

    def get_entity_assessments(self):
        """Return the entity assessment objects."""
        return self.entity_assessments

    def get_entity_assessment_ids_for_entity(self, entity_id):
        """Return all entity assessment IDs for the supplied entity."""
        return [
            assessment.get_id()
            for assessment in self.entity_assessments
            if assessment.get_entity_id() == entity_id
        ]

    @staticmethod
    def _normalize_scoped_name(name):
        """Return the local object name when the API returns a scoped path."""
        if not name:
            return ''
        return str(name).rsplit('/', 1)[-1].strip()

    def _get_reserved_entity_assessment_names(self):
        """Collect assessment names already used by entity assessments."""
        reserved_names = set()

        for assessment in self.entity_assessments:
            assessment_name = assessment.get_name()
            if assessment_name:
                reserved_names.add(assessment_name)
                reserved_names.add(self._normalize_scoped_name(assessment_name))

        return {name for name in reserved_names if name}

    def _build_entity_assessment_name_candidates(self, entity_name, entity_id):
        """Generate deterministic fallback names to avoid scope collisions."""
        safe_entity_name = (entity_name or 'Entity').strip()
        short_entity_id = str(entity_id or '')[:8]

        candidates = [
            f"Entity assessment of {safe_entity_name}",
            f"Third-party assessment for {safe_entity_name}",
            f"{safe_entity_name} third-party assessment",
        ]
        if short_entity_id:
            candidates.append(f"Third-party assessment for {safe_entity_name} ({short_entity_id})")

        deduplicated_candidates = []
        seen = set()
        for candidate in candidates:
            if candidate not in seen:
                deduplicated_candidates.append(candidate)
                seen.add(candidate)
        return deduplicated_candidates

    @staticmethod
    def _build_unique_entity_assessment_name(entity_name, entity_id):
        """Generate a practically unique fallback name when deterministic options collide."""
        safe_entity_name = (entity_name or 'Entity').strip()
        short_entity_id = str(entity_id or '')[:8]
        unique_suffix = uuid.uuid4().hex[:8]
        if short_entity_id:
            return f"Third-party assessment for {safe_entity_name} ({short_entity_id}-{unique_suffix})"
        return f"Third-party assessment for {safe_entity_name} ({unique_suffix})"

    @staticmethod
    def _is_name_collision_response(response):
        """Return True when the API reports a scoped-name collision."""
        if not isinstance(response, dict) or response.get('error') != 400:
            return False

        details = response.get('details', {})
        if not isinstance(details, dict):
            return False

        name_errors = details.get('name', [])
        if not isinstance(name_errors, list):
            return False

        return any('already used' in str(error).lower() for error in name_errors)

    def _resolve_entity_folder_id(self, entity_id):
        """Return the folder ID associated with an entity when available."""
        if not entity_id:
            return None

        entity = utils.get_return(f'/api/entities/{entity_id}/')
        if not isinstance(entity, dict):
            return None

        folder = entity.get('folder', {})
        if isinstance(folder, dict):
            return folder.get('id')
        return folder or None

    def create_entity_assessment(self, name, entity_id, compliance_assessment_id=None, representative_ids=None, framework_id=None, create_audit=False, status='in_progress'):
        """Create a new entity assessment for a third-party entity.

        This method is intentionally additive and does not affect the existing
        compliance-assessment creation flow. It only creates entity-scoped audit
        records for a linked third party.
        
        If an assessment for the same entity already exists with the same name,
        creation is skipped.
        """
        existing_entity_assessments = [
            assessment
            for assessment in self.entity_assessments
            if assessment.get_entity_id() == entity_id
        ]
        matching_assessment = next(
            (
                assessment
                for assessment in existing_entity_assessments
                if assessment.get_name() == name or self._normalize_scoped_name(assessment.get_name()) == name
            ),
            None,
        )
        if matching_assessment:
            matching_json = matching_assessment.get_json() or {}
            entity_json = matching_json.get('entity', {}) if isinstance(matching_json, dict) else {}
            folder_json = matching_json.get('folder', {}) if isinstance(matching_json, dict) else {}
            utils.log(
                f"Skipping entity assessment creation for entity {entity_id}: "
                f"An entity assessment named '{name}' already exists for this entity | "
                f"assessment_id={matching_assessment.get_id()} | "
                f"name={matching_assessment.get_name()} | "
                f"entity_id={matching_assessment.get_entity_id()} | "
                f"entity_name={entity_json.get('str', '') if isinstance(entity_json, dict) else ''} | "
                f"folder_id={folder_json.get('id', '') if isinstance(folder_json, dict) else ''} | "
                f"folder_name={folder_json.get('str', '') if isinstance(folder_json, dict) else ''} | "
                f"compliance_assessment_id={matching_assessment.get_compliance_assessment_id()} | "
                f"status={matching_json.get('status', '') if isinstance(matching_json, dict) else ''} | "
                f"is_published={matching_json.get('is_published', '') if isinstance(matching_json, dict) else ''}",
                level=logging.INFO,
            )
            return None

        entity_name = ''
        entity = utils.get_return(f'/api/entities/{entity_id}/')
        if isinstance(entity, dict):
            entity_name = entity.get('name', '') or ''

        candidate_names = [name]
        for candidate in self._build_entity_assessment_name_candidates(entity_name, entity_id):
            if candidate not in candidate_names:
                candidate_names.append(candidate)

        folder_id = self._resolve_entity_folder_id(entity_id)

        for candidate_name in candidate_names:
            payload = {
                'name': candidate_name,
                'entity': entity_id,
                'status': status,
            }
            if folder_id:
                payload['folder'] = folder_id
            if framework_id:
                payload['framework'] = framework_id
            if create_audit:
                payload['create_audit'] = True
            if compliance_assessment_id:
                payload['compliance_assessment'] = compliance_assessment_id
            if representative_ids:
                payload['representatives'] = representative_ids

            response = utils.get_return(
                '/api/entity-assessments/',
                method='POST',
                payload=payload,
                log_errors=False,
            )
            is_success = response is not None and (not isinstance(response, dict) or not response.get('error'))
            if is_success:
                self.reload()
                if isinstance(response, dict):
                    created_assessment = EntityAssessment(response)
                    created_assessment.assign_requirements_to_representatives(
                        representative_ids,
                        first_only=bool(create_audit),
                    )
                return response

            if not self._is_name_collision_response(response):
                utils.log(f"Failed to create entity assessment for entity {entity_id}: {response}", level=logging.ERROR)
                return None

            utils.log(
                f"Name collision while creating entity assessment for entity {entity_id} with name '{candidate_name}'; trying fallback name",
                level=logging.INFO,
            )

        for _ in range(5):
            unique_name = self._build_unique_entity_assessment_name(entity_name, entity_id)
            payload = {
                'name': unique_name,
                'entity': entity_id,
                'status': status,
            }
            if folder_id:
                payload['folder'] = folder_id
            if framework_id:
                payload['framework'] = framework_id
            if create_audit:
                payload['create_audit'] = True
            if compliance_assessment_id:
                payload['compliance_assessment'] = compliance_assessment_id
            if representative_ids:
                payload['representatives'] = representative_ids

            response = utils.get_return(
                '/api/entity-assessments/',
                method='POST',
                payload=payload,
                log_errors=False,
            )
            is_success = response is not None and (not isinstance(response, dict) or not response.get('error'))
            if is_success:
                self.reload()
                if isinstance(response, dict):
                    created_assessment = EntityAssessment(response)
                    created_assessment.assign_requirements_to_representatives(
                        representative_ids,
                        first_only=bool(create_audit),
                    )
                return response

            if not self._is_name_collision_response(response):
                utils.log(f"Failed to create entity assessment for entity {entity_id}: {response}", level=logging.ERROR)
                return None

        utils.log(
            f"Failed to create entity assessment for entity {entity_id}: all candidate names were already used in scope",
            level=logging.ERROR,
        )
        return None


def create_external_entity_audits(data: dict[str, Any]) -> None:
    """Create one entity-level audit per external entity.

    This logic is additive: it does not replace the existing perimeter-based
    compliance workflow for internal perimeters.
    """
    entity_dict = data["entity_dict"]
    entity_representative_dict = data["entity_representative_dict"]
    entity_assessment_dict = data["entity_assessment_dict"]
    framework_dict = data["framework_dict"]
    frameworks = framework_dict.get_frameworks()
    default_framework_id = frameworks[0].get_id() if frameworks else None

    for entity in entity_dict.get_entities():
        if not entity.is_external():
            continue

        representative_ids = entity_representative_dict.get_user_ids_for_entity(entity.get_id())

        matching_assessment = next(
            (
                assessment
                for assessment in entity_assessment_dict.get_entity_assessments()
                if assessment.get_entity_id() == entity.get_id()
            ),
            None,
        )
        if matching_assessment:
            has_linked_audit = bool(matching_assessment.get_compliance_assessment_id())
            if not has_linked_audit and default_framework_id:
                matching_assessment.ensure_linked_audit(default_framework_id, representative_ids, entity_assessment_dict)
            if has_linked_audit:
                matching_assessment.assign_requirements_to_representatives(representative_ids)
            continue

        created_assessment = entity_assessment_dict.create_entity_assessment(
            name=f"Entity assessment of {entity.get_name()}",
            entity_id=entity.get_id(),
            compliance_assessment_id=None,
            representative_ids=representative_ids or None,
            framework_id=default_framework_id,
            create_audit=True,
            status="in_progress",
        )
