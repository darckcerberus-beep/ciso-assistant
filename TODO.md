# TO-DO: Technical Conditional Questions (AppSec Framework)

**Date**: October 9, 2026  
**Status**: [COMPLETED] SaaS Contractual Pentest Governance Implemented (Version 7)  
**Branch**: `main`  
**Test Suite**: All 211 automated unit tests pass (`python3 -m unittest discover tests`).

---

## 1. Architectural Principle: Technical Conditionality vs. Criticality

- **Technical Conditionality Only**: Conditional questions (`depends_on:`) are used strictly when an underlying architecture or technical deployment renders follow-up questions technically non-applicable (e.g. an application with no Internet-facing exposure has no public endpoints for WAF, DDoS mitigation, or public API throttling).
- **Criticality Belongs in the Risk Rating, Not the Questions**: Whether an application is critical or non-critical (Public, Internal, Confidential, Secret) is captured in `data_classification` and drives the **Impact Level (1-4)**. When evaluated against likelihood in the risk matrix ($\text{Likelihood} \times \text{Impact} \rightarrow \text{Risk Level}$), non-critical applications naturally result in Low/Medium risk ratings without distorting or bypassing the questions asked. Security controls are not conditioned on asking if an application is critical.
- **WAF / Anti-DDoS Solutions**:
  - In-house / internally managed applications frequently use **Cloudflare** for edge WAF, automated anti-DDoS, and bot management.
  - In third-party SaaS and cloud deployments, vendors often employ alternative market competitors: **AWS WAF & Shield**, **Google Cloud Armor**, **Azure WAF**, **Akamai App & API Protector**, **Fastly Next-Gen WAF**, or **Imperva**.
  - Questions and evidence guidelines explicitly cite Cloudflare and these major competitors so respondents identify them clearly across both hosting models.

---

## 2. Completed Implementation Summary

### A. [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml)

1. **Requirement Node `urn:intuitem:risk:req_node:appsec:network_exposure` (Chapter 1 `info`)**:
   - Evaluated for all applications (in-house and SaaS alike) strictly as the network exposure profiling discriminator.
   - **`q1` (Network Exposure Discriminator)**:
     - Choice `c1` (*"Internal / Restricted Network only"*): `add_score: 100`, `compute_result: true`.
     - Choice `c2` (*"Internet-facing (Public Web / Mobile API)"*): `add_score: 100`, `compute_result: true`, selects `internet_facing` implementation group.
   - Client-side operational controls (WAF deployment, pentesting) removed from Chapter 1 to avoid forcing clients to answer direct operational questions for SaaS providers.

2. **Chapter 10 (`saas_chapter` / Annexe Sécurité Contractualization)**:
   - For SaaS applications, vendors do not allow clients to test vendor infrastructure, put client Cloudflare in front of the platform, manage vendor admin accounts, or connect internal SIEM agents. These controls are enforced as contractual obligations:
     - **Cloudflare / Anti-DDoS & WAF (`saas_network_security:q1`)**: Vendor contractually commits to edge anti-DDoS and WAF protection (Cloudflare, AWS WAF & Shield, Google Cloud Armor, Azure WAF, Akamai, Fastly, Imperva).
     - **Vendor Security Testing (`saas_web_app_security:q2` & `saas_audit_and_compliance:q1`)**: Vendor contractually commits to annual independent third-party pentests, monthly vulnerability scanning, and provides audit attestations / letters of attestation.
     - **Admin Accounts vs. Enterprise IGA (`saas_entitlements_and_privileges:q1`, `q2`)**: Vendor manages internal administrative access under least privilege (`q1`), while enabling the client to manage tenant user identities and entitlements via enterprise IGA / SailPoint / SCIM (`q2`).
     - **SIEM & Incident Notification (`saas_logging_and_incidents:q1`, `q2` & `saas_telemetry_and_audit_export`)**: Vendor performs internal 24/7 security monitoring with tamper-resistant audit logs (`q1`), commits to a 48-hour security incident notification SLA (`q2`), and provides API/webhook telemetry export for ingestion into client SIEM.

3. **Unified IAM Architecture (Eliminating Empty Requirement Sections on SSO)**:
   - In Chapter 2 (`iam_chapter`), `federation_and_sso` and `authentication_and_mfa` are merged into a single comprehensive requirement node `authentication_and_mfa` (*"Centralized Identity, Authentication & MFA"*).
   - Root Question (`q1`): Asks how users authenticate (*"Enterprise SSO"* vs. *"Direct / Local application authentication"*).
   - Branch A (Enterprise SSO): Awards 100% compliance directly (`add_score: 100`, `compute_result: true`) without asking redundant central IT/IAM MFA questions to application owners.
   - Branch B (Direct / Local): Activates `q2` (*"If direct authentication is used, are strong password policies and brute-force lockout protections implemented?"*) and `q3` (*"If direct authentication is used, is Multi-Factor Authentication (MFA) enforced for all administrative and privileged access?"*), scoring 0 + 50 + 50 = 100.
   - Resolves empty section issue: The requirement node is never empty regardless of which authentication mode is selected.

### B. Test Data Profiles in [`test_data/`](file:///home/python/ciso-assistant/test_data/)

1. [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml):
   - Internet-facing SaaS app handling Secret data.
   - Answers `network_exposure:q1` with Internet-facing exposure.
   - Answers `authentication_and_mfa` with Enterprise SSO and admin MFA active (100% compliant).
2. [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml):
   - Internet-facing SaaS app handling Confidential data.
   - Answers `network_exposure:q1` with Internet-facing exposure.
   - Answers `authentication_and_mfa` with Enterprise SSO, but without mandatory administrative MFA (50% compliant).
3. [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml):
   - Internal on-premises application.
   - Answers `network_exposure:q1` with Internal/restricted exposure.
   - Answers `authentication_and_mfa` with Direct authentication and neither password policies nor MFA (0% compliant).

### C. Automated Unit Tests in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py)

- `test_appsec_network_exposure_and_conditional_branching`:
  - Verifies `network_exposure` defines 1 exposure discriminator question (`q1`), awarding 100 points for Internal or Internet-facing.
  - Verifies the 4 transferred requirements in Chapter 10 contractualization:
    - Vendor Cloudflare / WAF protection (`saas_network_security`).
    - Vendor independent penetration testing and right to audit (`saas_web_app_security`, `saas_audit_and_compliance`).
    - Vendor administrative account governance vs client IGA / SailPoint management (`saas_entitlements_and_privileges`).
    - Vendor continuous security monitoring, 48h incident SLA, and telemetry export into client SIEM (`saas_logging_and_incidents`, `saas_telemetry_and_audit_export`).
  - Verifies no questions in AppSec use data classification or criticality to condition security questions.
- `test_appsec_iam_sso_and_credential_order`:
  - Verifies `authentication_and_mfa` is the unified IAM requirement node in Chapter 2 (`iam_chapter`).
  - Verifies authentication mode question (`q1`) branches into `q2` for SSO or `q3` & `q4` for direct authentication.
  - Verifies SSO questions precede direct password and MFA questions in Chapter 10 (`saas_iam`).
- `test_appsec_on_premise_iam_sso_conditional_authentication`:
  - Verifies that both the SSO branch and the Direct authentication branch are non-empty and achieve up to 100 points maximum.

---

## 3. Verification Results

All automated test suites executed and passed:
- `python3 -m unittest tests/test_yaml_integrity.py`: **18/18 tests passed**
- `python3 -m unittest tests/test_tasks.py`: **8/8 tests passed**

---

## 4. Enrichment of newDPP Questions in AppSec Framework

All questions originating from `newDPP.yml` in [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) have been enriched with explicit technical guidance, algorithms, protocols, methods, and criteria:
- **Encryption in Transit (`data_in_transit`)**: specifies protocols and algorithms (TLS 1.2/1.3 with AES-GCM or ChaCha20, HTTPS/HSTS, mTLS, SSHv2, IPsec).
- **Encryption at Rest (`data_at_rest`)**: specifies storage tiers, algorithms (AES-256 / AES-GCM), and key management (KMS, HSM, TDE).
- **Control of Data Exchange (`data_exchange`)**: specifies automated API flows/transfers and legal agreements (DPA, DTA, NDA).
- **Non-Production Data Protection (`non_prod_data`)**: specifies segregation criteria, data sanitization methods (hashing, pseudonymisation, encryption), and post-test data purging.
- **Compliant Data Destruction (`data_destruction`)**: specifies retention schedules, cryptographic erasure, and disposal verification reporting.
- **Application Governance & Profiling (`stakeholder_identification`, `data_classification`, `hosting`)**: clarifies roles, sensitivity levels, and infrastructure models.
- **SaaS Contractual Compliance (`saas_contract_compliance`)**: clarifies MSA execution, SOC 2/ISO audit rights, 48h incident notification SLAs, and IAM/NDA requirements.
- **Zero changes to examples**: Example test data fixtures were left untouched. Backward compatibility is preserved via prefix resolution in [`classes/integrations/answers_import.py`](file:///home/python/ciso-assistant/classes/integrations/answers_import.py).

---

## 5. Software Delivery Models & SDLC Scoping (Custom vs. Bought COTS vs. SaaS)

A clear distinction is established between the three software procurement, development, and hosting models:
1. **Custom software created and deployed by my teams (In-house development)**:
   - Internally developed software where source code is maintained and built in corporate repositories.
   - Evaluated under full shift-left DevSecOps automation in Chapter 5 (`sdlc_chapter`): SAST in CI/CD pipelines, DAST / API security scanning, automated SCA for open-source libraries, audited SBOMs, and mandatory peer code reviews with branch protection.
2. **Bought software deployed by my teams (Commercial Off-The-Shelf / COTS / Vendor package)**:
   - Third-party commercial software packages or containerized applications deployed on internal on-premise or cloud infrastructure.
   - Teams do NOT write or modify vendor source code (no internal SAST or peer code review on vendor commits).
   - Scoped to operational and deployment integrity in Chapter 5: formal vendor security patch management SLAs, black-box vulnerability scanning of deployed instances, active monitoring of vendor CVE advisories, accurate package/version inventory, and deployment configuration hardening baselines.
3. **SaaS (Third-party software hosted and operated by a vendor)**:
   - External cloud platforms where codebase and infrastructure are entirely operated by the third-party provider.
   - Questions regarding secure development, vulnerability testing, and supply chain risk are strictly evaluated in **Chapter 10** (`saas_chapter`) via vendor contractual exhibits:
     - `saas_secure_development`: vendor secure coding practices, SCM repository branch protection, peer reviews, and developer training.
     - `saas_web_app_security`: independent third-party penetration testing letters, monthly vulnerability scans, and remediation SLAs.
     - `saas_subcontractor_management`: subprocessor and fourth-party supply chain oversight.

---

## 6. Code Hygiene & Application Defenses Scoping (Custom vs. Bought COTS vs. SaaS)

Clarified the operational boundary between software development and infrastructure hosting across Chapter 2 (`session_management`) and Chapter 3 (`app_defenses_chapter`):
1. **Custom software (Dev & Hosting)**:
   - Organization controls both source code development and infrastructure hosting.
   - Evaluated on code-level implementation: cryptographically secure session token generation, server-side input schema validation, parameterized queries / ORMs, context-aware output encoding across templates, and debug disabled in code.
2. **Bought software / COTS (Hosting only)**:
   - Organization controls only infrastructure and deployment hosting, not how the software was programmed.
   - Scoped to hosting and perimeter defenses:
     - `session_management`: HTTPS/TLS transmission enforcement, reverse proxy cookie hardening (Secure/SameSite flags), and idle session timeouts at API gateway or load balancer.
     - `input_validation_and_injection_defense`: Web Application Firewall (WAF) / API gateway inspection blocking injection payloads, database account least-privilege separation, and prompt vendor security patch deployment.
     - `output_encoding_and_web_defenses`: Standard HTTP security response headers configured on reverse proxy / ingress (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and WAF XSS filtering.
     - `error_handling_and_info_leakage`: Production deployment configuration disabling debug flags and reverse proxy generic error pages (4xx/5xx) masking vendor internal stack traces.
3. **SaaS (Neither)**:
   - Organization controls neither source code nor hosting.
   - Code hygiene, database security, and web application defenses are managed entirely by the third-party provider and governed contractually in Chapter 10 (`saas_web_app_security` and vendor compliance exhibits).

---

## 7. Delivery Model Scoping and Questionnaire Form Reliability

In CISO Assistant's architecture, questionnaire forms and audits are loaded per-requirement assessment node. Using cross-node dependencies (`depends_on` referencing a question in a different requirement node like `hosting:q1`) breaks the UI form evaluator and causes single-question requirement nodes (such as `session_management`) to render completely empty in audits.

To guarantee that all requirement nodes are fully populated, visible, and answerable across all audits:
- **Intra-node Conditionality Only**: `depends_on` is strictly restricted to questions within the *same* requirement node (e.g. `authentication_and_mfa:q2` depending on `authentication_and_mfa:q1`).
- **Scoping via Question Guidance & Annotations**: For requirement nodes spanning multiple delivery models (Chapters 2, 3, and 5):
  - Every question text explicitly guides respondents on what compliance means for **Custom software** (in-house code verification), **Bought software / COTS** (hosting-tier WAF, reverse proxy headers, least-privilege DB, deployment hardening baselines), and **SaaS** (governed via Chapter 10 or vendor compliance attestations).
  - Requirements are always populated with valid questions and choices in audits.

---

## 8. Incremental Framework Versioning System

From now on, all framework and library updates MUST adhere to an incremental integer numbering system:
- **Integer Versioning**: The top-level `version` field in framework YAML files (e.g. `YML/appsec.yml`) is an incremental integer (`version: 1`, `version: 2`, `version: 3`, `version: 4`, ...).
- **Mandatory Increment on Changes**: Whenever a framework structure, requirement node, question, threat, vulnerability, control, or metadata is modified, the `version` number is incremented by `+1`, and `publication_date` is updated to the modification date.
- **Automated Validation**: Unit tests (`tests/test_yaml_integrity.py`) enforce that all library/framework files maintain integer version numbers (`version >= 1`), and `LibraryFile.get_version()` provides programmatic access to the version attribute.

---

## 9. Implementation Groups Scoping Architecture (Custom vs. COTS vs. SaaS)

To cleanly separate requirements across software delivery tracks without empty forms or confusing multi-scope question texts, the framework leverages native CISO Assistant **Implementation Groups**:
1. **Implementation Group Definitions**:
   - `custom_app`: Custom software in-house development track.
   - `cots_app`: Bought software (COTS / vendor package) deployment track.
   - `saas_app`: Third-party SaaS contractual and governance track.
   - `baseline`: Technical baseline for self-hosted applications (Custom & COTS).
2. **Profiling Triggers (`hosting:q1`)**:
   - `c1` (Custom software): `select_implementation_groups: ["custom_app", "baseline"]`.
   - `c2` (Bought software COTS): `select_implementation_groups: ["cots_app", "baseline"]`.
   - `c3` (SaaS): `select_implementation_groups: ["saas_app"]`.
3. **Requirement Partitioning**:
   - **`custom_app` only**: `session_management`, Chapter 3 Code Hygiene (`input_validation_and_injection_defense`, `output_encoding_and_web_defenses`, `error_handling_and_info_leakage`), and Chapter 5 DevSecOps (`automated_security_testing`, `supply_chain_and_dependencies`, `code_review_and_ci_cd_integrity`). Excluded from COTS and SaaS audits.
   - **Shared Self-Hosted (`baseline`, `custom_app`, `cots_app`)**: Chapter 2 IAM (`authentication_and_mfa`, `access_control_and_rbac`), Chapter 4 Secrets (`secrets_management`), Chapter 8 Logging (`security_event_logging`, `centralized_monitoring_and_alerting`), Chapter 9 Resilience (`penetration_testing_and_vulnerability_management`, `backup_and_disaster_recovery`). Excluded from SaaS audits.
   - **`saas_app` only**: Chapter 10 SaaS Requirements (all 22 requirement nodes). Excluded from Custom and COTS audits.
---

## 10. Edge WAF, Cloudflare, Bot Protection & Rate Limiting Convergence (Version 5)

In Chapter 6 (`api_chapter`), `api_security_and_rate_limiting` has been converged into a unified edge WAF, anti-bot, and rate limiting requirement:
- **Node Metadata**:
  - `name`: `API Gateway, Edge WAF, Rate Limiting & Bot Protection`
  - `description`: "Protect exposed web and API endpoints against abusive traffic, automated bots, and volumetric attacks via an edge Web Application Firewall (WAF, e.g., Cloudflare), rate limiting, and schema validation."
  - `annotation`: Explicitly covers edge WAFs (Cloudflare, AWS WAF & Shield, Azure WAF, Cloud Armor), anti-bot protections, and API gateway rate limiting.
  - `typical_evidence`: Edge WAF and bot mitigation configs, API gateway throttling policies, and OpenAPI schema validation.
- **Merged Question 1 (`q1`)**:
  - Replaced legacy text with: `"Are exposed web and API endpoints protected against abusive traffic via an edge Web Application Firewall (WAF, e.g., Cloudflare, AWS WAF), bot protection, and automated rate limiting / throttling controls?"`
  - Awards 50 points (`compute_result: true`) for compliant protection.
- **Question 2 (`q2`)**:
  - `"Are API payloads strictly validated against documented API specifications (e.g. OpenAPI / JSON schema)?"` (50 points).
- **Framework Version**: Incremented to `version: 5`.

---

## 11. SaaS Contract Simplification & Merged Technical Subquestions (Version 6)

In Chapter 10 (`saas_chapter`), simplified the SaaS contract compliance assessment and eliminated redundancy between contractual clauses and operational questions:
- **Requirement Node 0 (`saas_contract_compliance`)**:
  - **Single Master Question (`q1`)**: Replaced 5 redundant subquestions (MSA execution, Audit clause, 48h Incident notification, IAM requirements, NDA) with a single comprehensive master question:
    > *"Is there a signed SaaS contract and binding Security Schedule? (e.g., legally executed Master Services Agreement / MSA and Security Exhibit with the provider)"*
  - **Score Normalization**: Awards 100 points directly (`add_score: 100`, `compute_result: true`), preserving requirement score weight without splitting points across duplicate legal clauses.
  - **Backwards-Compatible Choice URN**: Preserved choice URN `urn:intuitem:risk:req_node:appsec:saas_contract:question:1:choice:2` for seamless answer import compatibility.
- **Merged Technical Aspects Across Sections 1 to 20**:
  - For each technical domain in Chapter 10, merged the contractual mandate with operational implementation into cohesive, dual-aspect questions asking if the contract requires/mandates it and if it is operational/implemented:
    - **`saas_confidentiality_and_data_protection` (`q1`)**: Binding NDA safeguarding customer data merged with provider employee/subcontractor NDA enforcement.
    - **`saas_iam` (`q1`-`q4`)**: Centralized identity mode (SSO vs Direct), automated SCIM lifecycle deprovisioning, and contract-permitted direct authentication password/MFA controls.
    - **`saas_logging_and_incidents` (`q1`, `q2`)**: 24/7 continuous monitoring / SIEM export (`q1`) and legally binding 48-hour security incident notification SLA with operational alerting procedures (`q2`).
    - **`saas_audit_and_compliance` (`q1`)**: Right to audit (SOC 2 Type II / ISO 27001 review) combined with provider active delivery of compliance evidence and remediation plans.
    - **Comprehensive Alignment Across Technical Domains**: Systematic phrasing updates across governance (`saas_governance_and_policy`), awareness (`saas_security_awareness`), entitlements (`saas_entitlements_and_privileges`), endpoint security (`saas_workstation_security`, `saas_mobile_security`), edge & network security (`saas_network_security`), multi-tenancy & isolation (`saas_environment_isolation`), secure SDLC (`saas_secure_development`), application security (`saas_web_app_security`), data transfer & residency (`saas_data_exchange_security`, `saas_data_hosting_and_residency`), datacenter physical security (`saas_physical_security`), backup/DRP (`saas_backup_and_business_continuity`), data disposal (`saas_secure_data_destruction`), subcontractor governance (`saas_subcontractor_management`), and payment security (`saas_pci_dss`).
- **Synchronized Test Fixtures & Documentation**:
  - [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml): Updated to reference `saas_contract_compliance:q1`, scaled likelihood adjusted.
  - [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml): Updated to reference `saas_contract_compliance:q1`.
  - [`docs/appsec_policy_applicability_matrix.md`](file:///home/python/ciso-assistant/docs/appsec_policy_applicability_matrix.md): Updated matrix table and text descriptions.
- **Framework Version**: Incremented to `version: 6`.
- **Test Suite**: All 210 automated unit tests pass.

---

## 12. SaaS Contractual Penetration Testing Governance (Version 7)

In Chapter 9 (`resilience_chapter`), unified penetration testing governance across in-house and SaaS delivery models:
- **Contractual Governance for SaaS**: For third-party SaaS applications, penetration testing cannot be conducted arbitrarily without explicit contractual terms. The requirement node `penetration_testing_and_vulnerability_management` is expanded to include the `saas_app` implementation group alongside `resilience_chapter`.
- **Three Clear Governance Choices in Question 1 (`q1`)**:
  - *"We are allowed to pentest (in-house team conducts annual pentests, or SaaS contract authorizes client penetration testing)"* (`add_score: 50`, `compute_result: true`).
  - *"The SaaS vendor does the pentest (contract mandates that the vendor undergoes annual independent penetration tests and provides audit reports/attestations)"* (`add_score: 50`, `compute_result: true`).
  - *"They refuse (the SaaS vendor refuses penetration testing and provides no reports, or no penetration test is performed)"* (`add_score: 0`, `compute_result: false`).
- **Remediation SLA in Question 2 (`q2`)**:
  - Clarified that vulnerability remediation SLAs (Critical <= 7d, High <= 30d) are contractually committed by the SaaS vendor or enforced internally (50 points).
- **Graceful Choice Resolution**: Added fallbacks in [`classes/integrations/answers_import.py`](file:///home/python/ciso-assistant/classes/integrations/answers_import.py) and [`tests/test_application_scenarios.py`](file:///home/python/ciso-assistant/tests/test_application_scenarios.py) to support descriptive text matching, prefix matching, and boolean compliance fallbacks.
- **Synchronized Test Fixtures**: Updated [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml), [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml), and [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml) to reflect the contractual pentest governance choices while preserving exact risk ratings.
- **Framework Version**: Incremented to `version: 7`.
- **Test Suite**: All 211 automated unit tests pass.
