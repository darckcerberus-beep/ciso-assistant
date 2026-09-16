# Project Status & Handover: UI Audit Controls & Risk Scenarios

## Context & Current State
We resolved the issue where answering an audit in CISO Assistant UI created applied controls in `to_do` status but generated 0 risk scenarios:
1. **Controls in `to_do`**: Controls only become `active` if compliance score is 100%. `App-Test-Lucie` scored 75% on stakeholders and 0% on SaaS contract, so `to_do` status is the correct remediation behavior.
2. **0 Scenarios Fixed**: Informational questions (`data_classification`, `hosting`) have `result="not_assessed"` in CISO Assistant. The scenario evaluator was skipping `is_unassessed_result()`, losing data classification impact. This was fixed across:
   - `tests/test_application_scenarios.py`: Switched to `has_selected_answer()`.
   - `classes/audits/compliance.py` & `classes/audits/requirement_assessment.py`: Switched to `has_selected_answer()`.
   - `classes/controls/applied.py`: Priority resolution supports perimeter matching & ref_id.
   - `classes/examples_manager.py`: Removed `is_unassessed_result()` skip and added priority sync on planned controls during linking.
3. **Live Server Verification**:
   - Ran `python3 main.py --generate-risks App-Test-Lucie` against `https://ciso-assistant.siege.red`.
   - Both scenarios created (`SaaS provider data leakage` [Likelihood 4, Impact 2, Medium], `Missing application stakeholders` [Likelihood 2, Impact 2, Low]).
   - Controls linked with priorities `P3` and `P4`.
   - All 43 automated unit tests are passing (`python3 -m unittest discover tests`).

---

## Remaining Tasks for Next Session

1. **Asset Security Objectives Persistence**:
   - Investigate why `compliance_dict.update_asset_criticality(criticality_mapping, asset_dict)` did not update `security_objectives` on the asset object in `App-Test-Lucie` on the live instance.
   - Check the PATCH payload format for `/api/assets/{id}/` (specifically `security_objectives` structure in `classes/organization/asset.py`: `set_security_objective`).
2. **Root Directory Cleanup**:
   - Safely remove obsolete files:
     - `test.py`
     - `simulate_applications.py`
     - `debug_entity_representatives.py`
     - `dpp.json`
   - Clean up `.gitignore` and clear `.pyc` caches.
3. **End-to-End Verification**:
   - Run the complete lifecycle via CLI: create an app (Option 4) -> answer audit in UI -> generate controls and risks (Option 5).

---

## Quick Reference Commands
- Run test suite: `python3 -m unittest discover tests`
- Offline evaluation: `python3 main.py --offline`
- Generate risks for app on live instance: `python3 main.py --generate-risks App-Test-Lucie`

