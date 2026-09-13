"""Import a department/application model into domains, external entities and assessments.

The expected YAML structure is:

    domains:
      - name: Finance
    external_entities:
      - name: SAP S/4HANA
        domain: Finance
        representative_emails:
          - owner@example.com
        assessment:
          name: Third-party assessment for SAP S/4HANA
          framework_name: Data protection policy of ACME Corp
          status: in_progress
"""

import logging

from .. import utils
from ..audits.entity_assessment import EntityAssessmentDict
from ..core.framework import FrameworkDict
from ..organization.domain import DomainDict
from ..organization.entity import EntityDict, EntityRepresentativeDict


def _norm(value):
    if value is None:
        return ""
    return str(value).strip()


def _extract_folder_id(entity_json):
    folder = entity_json.get('folder', {}) if isinstance(entity_json, dict) else {}
    if isinstance(folder, dict):
        return _norm(folder.get('id'))
    return _norm(folder)


def _extract_user_id(representative_json):
    if not isinstance(representative_json, dict):
        return ""
    user = representative_json.get('user', {})
    if isinstance(user, dict):
        return _norm(user.get('id'))
    if user:
        return _norm(user)
    return _norm(representative_json.get('user_id'))


def _build_name_parts_from_email(email):
    local_part = _norm(email).split('@')[0]
    tokens = [token for token in local_part.replace('.', ' ').replace('_', ' ').split(' ') if token]
    if not tokens:
        return "", ""
    if len(tokens) == 1:
        return tokens[0].capitalize(), ""
    first_name = tokens[0].capitalize()
    last_name = " ".join(token.capitalize() for token in tokens[1:])
    return first_name, last_name


def read_entity_model(yaml_path):
    """Load and validate the YAML model used for entity-assessment onboarding."""
    model = utils.load_yaml_file(yaml_path)
    if not isinstance(model, dict):
        raise ValueError("YAML model must be a mapping at the top level.")

    domains = model.get('domains', [])
    external_entities = model.get('external_entities', [])
    if not isinstance(domains, list):
        raise ValueError("'domains' must be a list.")
    if not isinstance(external_entities, list):
        raise ValueError("'external_entities' must be a list.")
    return model


def upsert_external_entity(name, folder_id, entity_dict, description=None, ref_id=None, is_active=True):
    """Create the entity when missing, else return the existing one."""
    target_name = _norm(name)
    target_folder_id = _norm(folder_id)
    if not target_name:
        return None

    for entity in entity_dict.get_entities():
        if _norm(entity.get_name()) != target_name:
            continue
        if target_folder_id and _extract_folder_id(entity.get_json()) != target_folder_id:
            continue
        return entity.get_json()

    payload = {
        'name': target_name,
        'is_active': bool(is_active),
    }
    if target_folder_id:
        payload['folder'] = target_folder_id
    if description is not None:
        payload['description'] = description
    if ref_id:
        payload['ref_id'] = ref_id

    response = utils.get_return('/api/entities/', method='POST', payload=payload, log_errors=False)
    if response and (not isinstance(response, dict) or not response.get('error')):
        entity_dict.reload()
        return response

    entity_dict.reload()
    for entity in entity_dict.get_entities():
        if _norm(entity.get_name()) != target_name:
            continue
        if target_folder_id and _extract_folder_id(entity.get_json()) != target_folder_id:
            continue
        return entity.get_json()

    utils.log(
        f"Failed to upsert external entity '{target_name}' in folder '{target_folder_id}': {response}",
        level=logging.ERROR,
    )
    return None


def upsert_entity_representative_by_email(entity_id, email, entity_representative_dict):
    """Link an entity to a representative identified by email.

    If no user exists for the email, create one through the representatives endpoint.
    """
    normalized_email = _norm(email).lower()
    if not normalized_email:
        return None

    users = utils.get_all_results('/api/users/', force_reload=True)
    users_by_email = {
        _norm(user.get('email')).lower(): _norm(user.get('id'))
        for user in users
        if isinstance(user, dict) and user.get('email') and user.get('id')
    }
    user_id = users_by_email.get(normalized_email)
    if user_id:
        result = entity_representative_dict.upsert_entity_representative(entity_id, user_id)
        return user_id if result else None

    first_name, last_name = _build_name_parts_from_email(normalized_email)
    payload = {
        'create_user': True,
        'email': normalized_email,
        'first_name': first_name,
        'last_name': last_name,
        'entity': entity_id,
        'role': 'representative',
    }
    response = utils.get_return('/api/representatives/', method='POST', payload=payload, log_errors=False)
    if response and (not isinstance(response, dict) or not response.get('error')):
        entity_representative_dict.reload()
        created_user_id = _extract_user_id(response)
        if created_user_id:
            return created_user_id

        users = utils.get_all_results('/api/users/', force_reload=True)
        for user in users:
            if _norm(user.get('email')).lower() == normalized_email:
                return _norm(user.get('id'))

    utils.log(
        f"Failed to upsert representative email '{normalized_email}' for entity {entity_id}: {response}",
        level=logging.WARNING,
    )
    return None


def import_department_external_entity_model(yaml_path, create_entity_assessments=False):
    """Import domains and external entities from a YAML model.

    Returns:
        A summary dict with created/linked counters and row-level issues.
    """
    model = read_entity_model(yaml_path)

    domain_dict = DomainDict()
    entity_dict = EntityDict()
    entity_representative_dict = EntityRepresentativeDict()
    framework_dict = FrameworkDict()
    entity_assessment_dict = EntityAssessmentDict()

    summary = {
        'domains_processed': 0,
        'entities_processed': 0,
        'representative_links_created': 0,
        'entity_assessments_created': 0,
        'issues': [],
    }

    domain_rows = model.get('domains', [])
    for domain_row in domain_rows:
        if not isinstance(domain_row, dict):
            summary['issues'].append({'domain': None, 'reason': 'Domain row must be an object'})
            continue
        domain_name = _norm(domain_row.get('name'))
        if not domain_name:
            summary['issues'].append({'domain': None, 'reason': "Domain row missing 'name'"})
            continue
        result = domain_dict.upsert_folder(domain_name)
        if result is None:
            summary['issues'].append({'domain': domain_name, 'reason': 'Failed to create/read domain'})
            continue
        summary['domains_processed'] += 1

    domain_dict.reload()

    default_framework_id = None
    frameworks = framework_dict.get_frameworks()
    if frameworks:
        default_framework_id = frameworks[0].get_id()

    for entity_row in model.get('external_entities', []):
        if not isinstance(entity_row, dict):
            summary['issues'].append({'entity': None, 'reason': 'External entity row must be an object'})
            continue

        entity_name = _norm(entity_row.get('name'))
        domain_name = _norm(entity_row.get('domain'))
        if not entity_name or not domain_name:
            summary['issues'].append({
                'entity': entity_name or None,
                'reason': "External entity row requires both 'name' and 'domain'",
            })
            continue

        folder_id = domain_dict.get_id_from_name(domain_name)
        if not folder_id:
            summary['issues'].append({
                'entity': entity_name,
                'reason': f"Domain '{domain_name}' not found",
            })
            continue

        entity_json = upsert_external_entity(
            name=entity_name,
            folder_id=folder_id,
            entity_dict=entity_dict,
            description=entity_row.get('description'),
            ref_id=entity_row.get('ref_id'),
            is_active=entity_row.get('is_active', True),
        )
        if not isinstance(entity_json, dict):
            summary['issues'].append({
                'entity': entity_name,
                'reason': 'Failed to create/read external entity',
            })
            continue

        entity_id = _norm(entity_json.get('id'))
        if not entity_id:
            summary['issues'].append({
                'entity': entity_name,
                'reason': 'Entity ID missing after upsert',
            })
            continue

        summary['entities_processed'] += 1

        representative_ids = []
        for email in entity_row.get('representative_emails', []) or []:
            user_id = upsert_entity_representative_by_email(entity_id, email, entity_representative_dict)
            if not user_id:
                summary['issues'].append({
                    'entity': entity_name,
                    'reason': f"Failed representative upsert for '{email}'",
                })
                continue
            if user_id not in representative_ids:
                representative_ids.append(user_id)
                summary['representative_links_created'] += 1

        if not create_entity_assessments:
            continue

        assessment_row = entity_row.get('assessment', {})
        if not isinstance(assessment_row, dict):
            assessment_row = {}
        framework_name = _norm(assessment_row.get('framework_name'))
        framework_id = framework_dict.get_id_from_name(framework_name) if framework_name else default_framework_id
        assessment_name = _norm(assessment_row.get('name')) or f"Entity assessment of {entity_name}"
        assessment_status = _norm(assessment_row.get('status')) or 'in_progress'

        created_assessment = entity_assessment_dict.create_entity_assessment(
            name=assessment_name,
            entity_id=entity_id,
            compliance_assessment_id=None,
            representative_ids=representative_ids or None,
            framework_id=framework_id,
            create_audit=True,
            status=assessment_status,
        )
        if created_assessment is not None:
            summary['entity_assessments_created'] += 1

    utils.log(
        "Entity model import summary: "
        f"domains={summary['domains_processed']} | "
        f"entities={summary['entities_processed']} | "
        f"representative_links={summary['representative_links_created']} | "
        f"entity_assessments_created={summary['entity_assessments_created']} | "
        f"issues={len(summary['issues'])}"
    )

    for issue in summary['issues']:
        utils.log(f"Entity model import issue: {issue}", level=logging.WARNING)

    return summary
