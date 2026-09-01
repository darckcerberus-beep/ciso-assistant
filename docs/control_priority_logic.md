# Control Priority Logic

This document describes the logic implemented in `classes/control.py` that determines the API `priority` for an applied control.

## Overview

- The priority is derived from a risk scenario's `current_level` for a requirement.
- Missing or invalid data is considered an error condition and raises exceptions instead of returning defaults.

## `get_priority_from_risk_level(risk_level)`

- Accepts a risk level which may be an `int`, numeric string, or a dict containing an `id` or `value` key.
- If `risk_level` is a dict, the function prefers `id` then `value`.
- If the value cannot be coerced to `int`, the function raises `ValueError("Invalid risk level value: ...")`.
- Mapping to API priority (lower number = higher urgency):
  - risk level >= 4 -> priority `1`
  - risk level == 3 -> priority `2`
  - risk level == 2 -> priority `3`
  - otherwise (1 or 0) -> priority `4`

## `get_priority_for_compliance_assessment_id(compliance_assessment_id, requirement_urn)`

Flow and error cases:

1. Look up the compliance assessment via `utils.get_all_results("/api/compliance-assessments/")` matching `id`.
   - If not found -> raises `LookupError("Compliance assessment with id ... not found")`.

2. Build `compliance_name = compliance_assessment.get("name")` and search `utils.get_all_results("/api/risk-assessments/")` for an entry where `name == f"{compliance_name} Risk Assessment"`.
   - If not found -> raises `LookupError("Risk assessment for compliance '...' not found")`.

3. Load scenarios from the framework file `YML/newDPP.yml` using `FrameworkFile(...).get_risk_scenarios()` and collect scenario names where `scenario.get('likelihood') == requirement_urn`.
   - If no such scenarios -> raises `LookupError("No risk scenarios reference requirement urn ...")`.

4. Iterate API `risk-scenarios` (`utils.get_all_results("/api/risk-scenarios/")`) and find a scenario where:
   - the scenario's `risk_assessment` (dict or id) matches the found `risk_assessment_id`, and
   - the scenario `name` is in the set of names from step 3.

5. For the matching scenario, inspect its `current_level` (must be a dict). If present, call `get_priority_from_risk_level(current_level.get('id', current_level.get('value')))`, and return that priority.

6. If no matching scenario with a `current_level` is found -> raises `LookupError("No matching risk scenario with a current level for compliance assessment ...")`.

## Callers & Impact

- `update_priority_for_requirement_assessment` and `create_missing_applied_controls` call `get_priority_for_compliance_assessment_id`.
- Because the updated functions raise `LookupError`/`ValueError` instead of returning fallback priorities, callers should be prepared to catch these exceptions and decide how to proceed (examples below).

## Suggested caller behavior

- Option A — fail fast: let exceptions propagate so upstream logic aborts and a visible failure occurs.
- Option B — log & skip: catch `LookupError`/`ValueError`, log a meaningful message, and skip setting priority for the affected control.
- Option C — remediate: catch and perform a fallback action (e.g., create an issue, enqueue for manual review).

Example handler pattern:

```

# Project Logic and Priority Determination

This document describes the end-to-end logic of the project and how `priority` values for applied controls are derived. It covers the high-level workflow implemented in `main.py`, the key class responsibilities, the API interaction patterns, and the specific control/risk priority logic implemented in `classes/control.py`.

## High-level workflow (entry point)

- The workflow is driven by `main.py` which instantiates the primary data objects and coordinates the following steps:
   1. Create or reload assets from organization perimeters.
   2. Ensure compliance assessments exist for each framework/perimeter combination.
   3. Assign requirements to perimeter owners when assignments are missing.
   4. Create missing applied controls based on requirement assessments.
   5. Create risk assessments and risk scenarios for each compliance assessment using the framework definitions.
   6. Update asset criticality mappings and re-run applied-control creation as needed.

   See [main.py](main.py) for the orchestration code.

## Key modules and responsibilities

- `classes/utils.py` — API interaction and helpers
   - `get_return(endpoint, method, payload, params)`: performs HTTP requests to the API, handles 204/404/400, logs errors, and returns parsed JSON or None/error dict.
   - `get_all_results(endpoint, params)`: paginates through API `results` pages and returns a consolidated list.
   - `load_yaml_file(path)`: loads YAML used by `FrameworkFile` and other classes.

- `classes/framework.py` — framework objects and YAML loader
   - `FrameworkFile(filepath)`: loads local YAML framework files (e.g., `YML/newDPP.yml`) and exposes `get_risk_scenarios()`, `get_impact_mapping()`, and `get_criticality_mapping()`.
   - `FrameworkDict` / `Framework`: fetch frameworks from API and expose helpers to query risk scenarios and matrices.

- `classes/audit.py` — compliance and requirement assessment management
   - `ComplianceAssessmentDict`: loads compliance assessments and coordinates creation of missing assessments, assigning requirements, creating risk assessments, and calling into requirement-assessment logic to create applied controls.
   - `RequirementAssessmentDict` (see file): manages requirement-level answers used to derive likelihood/impact scores; used heavily when creating risk scenarios.

- `classes/control.py` — applied/reference controls and priority logic
   - `AppliedControlDict`: loads applied controls and provides methods to create missing applied controls, update priority, update folder mapping, and determine existing/planned controls per requirement assessment.
   - `ReferenceControlDict` / `ReferenceControl`: manage reference control lookup and metadata.
   - Priority logic lives in `get_priority_from_risk_level` and `get_priority_for_compliance_assessment_id`.

- `classes/risk.py` — risk assessments, scenarios, and matrices
   - `RiskAssessmentDict`: create or retrieve risk assessments.
   - `RiskScenarioDict`: create, update, or delete risk scenarios; when creating, it converts 1-based inputs to 0-based API expectations for probability/impact.
   - `RiskMatrixDict`: maps risk matrices to library IDs.

- `classes/organization.py`, `classes/user.py`, `classes/task.py` — auxiliary data (perimeters, assets, users, tasks)
   - `PerimeterDict`, `AssetDict` are used to map perimeters -> folders/owners -> assets, and to create missing assets.

## API interaction patterns

- The project relies on the internal API via `utils.get_return` and `utils.get_all_results`.
- Typical pattern:
   - Load a set of objects with `get_all_results`.
   - Wrap API payloads in thin domain objects (e.g., `ComplianceAssessment`, `RiskScenario`, `AppliedControl`) and call `get_return` for single-object fetches or mutations.

## How priorities are determined (control & risk logic)

- Priority originates from a risk scenario's `current_level`. The mapping is performed by `AppliedControlDict.get_priority_from_risk_level`:
   - Input may be an `int`, numeric string, or a dict with `id` or `value`.
   - If the value cannot be coerced to an integer, the function raises `ValueError("Invalid risk level value: ...")`.
   - Mapping to API priority (API uses smaller integers for higher urgency):
      - risk level >= 4 => priority `1`
      - risk level == 3 => priority `2`
      - risk level == 2 => priority `3`
      - otherwise (1 or 0) => priority `4`

- To find the risk scenario associated with a requirement, `get_priority_for_compliance_assessment_id` follows these steps:
   1. Find the compliance assessment object by matching `id` from `/api/compliance-assessments/`.
       - If missing, raises `LookupError("Compliance assessment with id ... not found")`.
   2. Build the compliance name and find the corresponding risk assessment (API name `"{compliance_name} Risk Assessment"`).
       - If missing, raises `LookupError("Risk assessment for compliance '...' not found")`.
   3. Load framework scenarios from `YML/newDPP.yml` and collect scenario names where `scenario['likelihood'] == requirement_urn`.
       - If none found, raises `LookupError("No risk scenarios reference requirement urn ...")`.
   4. Iterate `/api/risk-scenarios/`, matching scenarios whose `risk_assessment` matches the id found in (2) and whose `name` is in the set from (3).
   5. When a matching scenario is found, inspect its `current_level` (must be a dict). Use its `id` or `value` and call `get_priority_from_risk_level` to get the API priority.
   6. If no matching scenario with a `current_level` is found, raises `LookupError("No matching risk scenario with a current level...")`.

## Recent change: surface missing data as errors

- The priority functions were changed to raise explicit `LookupError` or `ValueError` when required objects or values are missing/malformed. This prevents silent use of default priorities and surfaces data issues so they can be remediated.

## Callers and recommended handling

- Call sites within this project include:
   - `create_missing_applied_controls` (delegates to requirement-assessment logic to create applied controls and sets `priority` when available)
   - `update_priority_for_requirement_assessment` (patches priority on existing applied controls)

- Because the priority helpers now raise, callers should choose one of the following.
   - Fail fast: allow exceptions to propagate so the process clearly fails and can be investigated.
   - Log & skip: catch `LookupError`/`ValueError`, log the problem, and skip setting priority for the object.
   - Remediate: catch and create a ticket, send a notification, or add the item to a manual-review queue.

Example pattern to integrate gracefully:

```
try:
      priority = applied_control_dict.get_priority_for_compliance_assessment_id(ca_id, urn)
except (LookupError, ValueError) as e:
      utils.log(f"Could not determine priority for {ca_id} / {urn}: {e}", level=logging.WARNING)
      priority = None

if priority is not None:
      payload["priority"] = priority
```

## Files to inspect for implementation details

- `main.py` — orchestration and entry point. [main.py](main.py)
- `classes/utils.py` — API helper functions and YAML loader. [classes/utils.py](classes/utils.py)
- `classes/framework.py` — framework objects and YAML `FrameworkFile`. [classes/framework.py](classes/framework.py)
- `classes/audit.py` — compliance and requirement assessment workflows. [classes/audit.py](classes/audit.py)
- `classes/control.py` — applied/reference control logic and priority mapping. [classes/control.py](classes/control.py)
- `classes/risk.py` — risk assessment and scenario creation/update. [classes/risk.py](classes/risk.py)

## Suggested next steps

- Decide how callers should handle the newly raised exceptions (fail fast vs log & skip vs remediate). I can update callers in `classes/control.py` and `classes/audit.py` to implement your preferred strategy.
- Add unit tests that simulate missing API objects to ensure behavior is explicit and visible.

If you'd like, I can now implement one of the caller-handling strategies across the codebase and add a small test harness.
