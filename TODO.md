# To-Do

- [ ] Add a proper dependency manifest (`requirements.txt` or `pyproject.toml`) and document setup/run steps.
- [ ] Secure API transport in `classes/utils.py` (enable TLS verification, remove global warning suppression, support custom CA if needed).
- [ ] Add structured error handling and explicit retry/backoff for API calls in `classes/utils.py`.
- [ ] Fix logic bug in `ComplianceAssessmentDict.CheckComplianceAssessmentFromIDs` (`classes/audit.py`) where dict keys are iterated instead of objects.
- [ ] Fix assignment-diff logic in `RequirementAssessmentDict.assignRequirementsToPerimeterOwner` (`classes/audit.py`) to use true "unassigned" computation.
- [ ] Fix method name mismatch (`updateAssetCriticality` vs `UpdateAssetCriticality`) in criticality update flow.
- [ ] Remove/complete placeholder code paths (`pass`) in `classes/audit.py` or delete dead code.
- [ ] Fix broken code in `FrameworkFile.read()` (`classes/framework.py`) that references undefined members/functions.
- [ ] Add automated tests for core workflows (compliance creation, assignment creation, applied control generation, risk scenario generation).
- [ ] Add input validation and null-safety guards around nested JSON access across class getters.
- [ ] Reduce N+1 API calls by avoiding per-item detail fetches unless required.
- [ ] Replace print-based logging with a consistent logging strategy and log levels.
