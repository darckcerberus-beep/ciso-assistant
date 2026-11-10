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

1. **Requirement Node `urn:intuitem:risk:req_node:appsec:hosting` & `network_exposure` (Chapter 1 `info`)**:
   - **SaaS External Exposure Assumption**: Third-party SaaS applications are unconditionally assumed to be externally exposed to the public Internet. Selecting SaaS in `hosting:q1` (`c3`) automatically activates both `saas_app` and `internet_facing` implementation groups.
   - **`network_exposure` Scoping**: Scoped strictly to self-hosted delivery models (`implementation_groups: ["baseline", "custom_app", "cots_app"]`), eliminating redundant network exposure questions for SaaS applications.
   - **`network_exposure:q1` (Self-Hosted Exposure Discriminator)**:
     - Choice `c1` (*"Internal / Restricted Network only"*): `add_score: 100`, `compute_result: true`.
     - Choice `c2` (*"Internet-facing (Public Web / Mobile API)"*): `add_score: 100`, `compute_result: true`, selects `internet_facing` implementation group.
   - Redundant SaaS-specific Choice 3 (`c3`) completely eliminated.

2. **Requirement Node `urn:intuitem:risk:req_node:appsec:data_exchange` (Chapter 7 `data_lifecycle_chapter`)**:
   - **SaaS External Data Exchange Assumption**: Third-party SaaS applications inherently and unconditionally exchange data with the external SaaS provider outside the corporate perimeter. Answering "No" on data exchange for SaaS is a false assertion, while answering "Yes" opened redundant DPA questions.
   - **`data_exchange` Scoping**: Scoped strictly to self-hosted delivery models (`implementation_groups: ["baseline", "custom_app", "cots_app"]`), eliminating redundant data exchange questions for SaaS applications.
   - **SaaS Contractual Governance in Chapter 10**: SaaS data transfers, DPAs, and confidentiality obligations remain governed directly under Chapter 10 (`saas_contract_compliance`).
   - **Risk Scenario Symmetry**: Self-hosted applications evaluate `Third-party data leakage` (likelihood: `data_exchange`), while SaaS applications evaluate `SaaS provider data leakage` (likelihood: `saas_contract_compliance`), giving both delivery models exactly 15 in-scope risk scenarios.

3. **Chapter 10 (`saas_chapter` / Annexe Sécurité Contractualization)**:
   - For SaaS applications, vendors do not allow clients to test vendor infrastructure, put client Cloudflare in front of the platform, manage vendor admin accounts, or connect internal SIEM agents. These controls are enforced as contractual obligations:
     - **Cloudflare / Anti-DDoS & WAF (`saas_network_security:q1`)**: Vendor contractually commits to edge anti-DDoS and WAF protection (Cloudflare, AWS WAF & Shield, Google Cloud Armor, Azure WAF, Akamai, Fastly, Imperva).
     - **Vendor Security Testing (`saas_web_app_security:q2` & `saas_audit_and_compliance:q1`)**: Vendor contractually commits to annual independent third-party pentests, monthly vulnerability scanning, and provides audit attestations / letters of attestation.
     - **Admin Accounts vs. Enterprise IGA (`saas_entitlements_and_privileges:q1`, `q2`)**: Vendor manages internal administrative access under least privilege (`q1`), while enabling the client to manage tenant user identities and entitlements via enterprise IGA / SailPoint / SCIM (`q2`).
     - **SIEM & Incident Notification (`saas_logging_and_incidents:q1`, `q2` & `saas_telemetry_and_audit_export`)**: Vendor performs internal 24/7 security monitoring with tamper-resistant audit logs (`q1`), commits to a 48-hour security incident notification SLA (`q2`), and provides API/webhook telemetry export for ingestion into client SIEM.

4. **Unified IAM Architecture (Eliminating Empty Requirement Sections on SSO)**:
   - In Chapter 2 (`iam_chapter`), `federation_and_sso` and `authentication_and_mfa` are merged into a single comprehensive requirement node `authentication_and_mfa` (*"Centralized Identity, Authentication & MFA"*).
   - Root Question (`q1`): Asks how users authenticate (*"Enterprise SSO"* vs. *"Direct / Local application authentication"*).
   - Branch A (Enterprise SSO): Awards 100% compliance directly (`add_score: 100`, `compute_result: true`) without asking redundant central IT/IAM MFA questions to application owners.
   - Branch B (Direct / Local): Activates `q2` (*"If direct authentication is used, are strong password policies and brute-force lockout protections implemented?"*) and `q3` (*"If direct authentication is used, is Multi-Factor Authentication (MFA) enforced for all administrative and privileged access?"*), scoring 0 + 50 + 50 = 100.
   - Resolves empty section issue: The requirement node is never empty regardless of which authentication mode is selected.

### B. Test Data Profiles in [`test_data/`](file:///home/python/ciso-assistant/test_data/)

1. [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml):
   - Internet-facing SaaS app handling Secret data.
   - Answers `hosting:q1` with SaaS (inherently assumes external exposure; no redundant `network_exposure` answer needed).
   - Answers `authentication_and_mfa` with Enterprise SSO and admin MFA active (100% compliant).
2. [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml):
   - Internet-facing SaaS app handling Confidential data.
   - Answers `hosting:q1` with SaaS (inherently assumes external exposure; no redundant `network_exposure` answer needed).
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
   - **`custom_app` only**: `session_management`, Chapter 3 Code Hygiene (`owasp_top_10_defenses`), and Chapter 5 DevSecOps (`automated_security_testing`, `supply_chain_and_dependencies`, `code_review_and_ci_cd_integrity`). Excluded from COTS and SaaS audits.
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

---

## 13. Universal Non-Production Data Governance (Version 12)

Consolidated non-production and sandbox test data governance into Chapter 7 (`data_lifecycle_chapter`):
- **Universal Requirement**: Merged `saas_non_prod_data` into `non_prod_data` (`urn:intuitem:risk:req_node:appsec:non_prod_data`), expanding phrasing to cover in-house staging/dev environments as well as SaaS sandbox tenants.
- **Removed Duplicate SaaS Node**: Eliminated `saas_non_prod_data` and duplicate scenario `saas_nonprod_data_disclosure`.
- **Framework Version**: Incremented to `version: 12`.
- **Test Suite**: All 217 automated unit tests pass.

---

## 14. Universal Data Security Consolidation & Duplication Elimination (Version 13)

Completely eliminated duplicated data security questions (`non_prod_data`, `data_destruction`, `data_exchange`) between general application chapters and Chapter 10:
- **Universal Data Destruction**: Enhanced `data_destruction` in Chapter 7 (`data_lifecycle_chapter`) to universally cover self-hosted retention/purging schedules as well as contractual SaaS exit management SLAs (<= 30-day export) and certified erasure (<= 60 days). Removed redundant `saas_secure_data_destruction` from Chapter 10.
- **Universal Data Exchange**: Enhanced `data_exchange` in Chapter 7 to universally govern cross-organizational transfers, APIs, webhooks, and SaaS integration security (TLS 1.2+, mTLS, DPA/DTA contracts). Removed redundant `saas_data_exchange_security` from Chapter 10.
- **Single Source of Truth**: Chapter 7 (`Data Protection & Lifecycle Governance`) serves as the sole, authoritative track for sensitive data lifecycle across all delivery models (`custom_app`, `cots_app`, `saas_app`), eliminating all duplicate data security questions for SaaS audits.
- **Integrity & Zero Orphans**: Maintained 0 orphaned controls, 0 orphaned vulnerabilities, and 100 max points per assessable requirement node across 62 total nodes (21 in Chapter 10).
- **Framework Version**: Incremented to `version: 13`.
- **Test Suite**: All 217 automated unit tests pass.

---

## 15. SaaS Questionnaire API Security & Rate Limiting Scoping (Version 18)

Removed the `api_security_and_rate_limiting` requirement from the SaaS questionnaire track:
- **Provider Implicit Infrastructure Protection**: In third-party SaaS delivery models, API rate limiting, bot throttling, and edge infrastructure protections are implicitly maintained by the cloud provider to safeguard their own multi-tenant systems. Evaluating self-hosted API gateway configurations against SaaS solutions is out of scope.
- **Implementation Group Scoping**: Removed `internet_facing` from `hosting:q1:c3` (`SaaS`), configuring SaaS to select only `["saas_app", "baseline"]`. Chapter 6 (`api_chapter`) and its requirement node `api_security_and_rate_limiting` remain strictly scoped to self-hosted internet-facing applications (`custom_app` and `cots_app` when `network_exposure == internet_facing`).
- **Contractual Coverage in Chapter 10**: SaaS cloud perimeter defenses, edge anti-DDoS, and WAF commitments remain contractually evaluated under Chapter 10 Section 9 (`saas_network_security`).
- **Framework Version**: Incremented to `version: 18`.
- **Test Suite**: Verified framework integrity and implementation group tests pass.

---

## 16. Rephrasing SaaS Confidentiality & Data Protection for Application Owners (Version 19)

Rephrased `saas_confidentiality_and_data_protection` in Chapter 10 (`saas_chapter`) of [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) to eliminate overly complex cryptographic terminology and clearly mandate data encryption in the contract:
- **Simplified Requirement Scope & Clarity**: Replaced technical jargon ("state-of-the-art key/certificate management", "Customer Lockbox") with clear obligations understandable to application owners:
  - **`description`**: "Enforce vendor personnel confidentiality (NDAs), customer data access controls, and data encryption mandated in the contract (in transit and at rest)."
  - **`annotation` & `typical_evidence`**: Aligned to contractual confidentiality (NDAs), tenant data access restrictions requiring customer approval, and contractual encryption mandates supported by DPAs and SOC 2 Type II reports.
- **Simplified Dual Questions**:
  - **Question 1 (`q1`)**: Rephrased from dense lockbox/charter phrasing to: *"Does the contract require vendor personnel to sign confidentiality agreements (NDAs) and restrict access to customer data (e.g. requiring client approval before vendor support or engineering can access tenant data)?"* (50 pts).
  - **Question 2 (`q2`)**: Replaced abstract key lifecycle question with clear contractual encryption mandate: *"Does the contract mandate data encryption for all customer data, both in transit (e.g. TLS/HTTPS) and at rest (e.g. AES-256)?"* (50 pts).
- **Framework Version**: Incremented to `version: 19`, publication date updated to `2026-10-19`.
- **Synchronized Documentation**: Updated [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md) and [`docs/appsec_policy_applicability_matrix.md`](file:///home/python/ciso-assistant/docs/appsec_policy_applicability_matrix.md).
- **Test Suite**: Verified all automated integrity and schema tests pass.

---

## 17. Removal of SaaS BYOK Requirement from Environment Isolation (Version 20)

Removed premature Customer-Managed Keys (BYOK/HYOK) cryptographic sovereignty requirement from `saas_environment_isolation` in Chapter 10 (`saas_chapter`) of [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml):
- **Requirement Simplification**: Eliminated BYOK / HYOK / KMS envelope isolation references from requirement node metadata:
  - **`description`**: "Ensure multi-tenant environment isolation, logical data segregation, and network traffic filtering."
  - **`annotation` & `typical_evidence`**: Focused on robust logical and physical tenant boundary isolation, network filtering, and SOC 2 Type II CC6.6 testing evidence, removing BYOK KMS configuration whitepaper requirements.
- **Single Question Normalization**:
  - Removed Question 2 (`q2` - BYOK / HYOK cryptographic sovereignty).
  - Normalized Question 1 (`q1` - logical/physical environment isolation and traffic filtering) to 100 points (`add_score: 100`, `compute_result: true`), maintaining 100 points per assessable requirement node across Chapter 10.
- **Framework Version**: Incremented to `version: 20`, publication date updated to `2026-10-19`.
- **Synchronized Documentation**: Updated [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md) (removed Q68, renumbered Q68-Q81) and [`docs/appsec_policy_applicability_matrix.md`](file:///home/python/ciso-assistant/docs/appsec_policy_applicability_matrix.md).
- **Test Suite**: Verified all automated integrity and schema tests pass (`python3 -m unittest tests/test_yaml_integrity.py`).

---

## 18. Manual Implementation Group AppSec Framework Variant (`appsec_manual.yml`)

Created a second version of the AppSec assessment framework at [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) with no triggered Implementation Groups (IGs) to enable two-stage manual audits:
- **Two-Stage Audit Workflow**: In this variant, auditors first assign the general info group (`info`), allowing the application owner to answer initial profiling questions (ownership, data sensitivity, hosting model, and exposure) before deciding and manually assigning subsequent implementation tracks (`custom_app`, `cots_app`, `saas_app`, `internet_facing`).
- **Elimination of Triggering Mechanism**: Completely removed `select_implementation_groups` from choice definitions in `hosting:q1` (Custom, COTS, SaaS) and `network_exposure:q1` (Internet-facing). `determine_implementation_groups_triggered_by_others` reports 0 hidden and 0 triggered groups, with all groups directly selectable.
- **Profiling Scoping to `info`**: Scoped all Chapter 1 requirements (`instructions_splash`, `info`, `stakeholder_identification`, `data_classification`, `hosting`, and `network_exposure`) to `implementation_groups: ["info"]`, with `info` as the sole `default_selected: true` group.
- **Catalog Registration & Isolated URN Namespace**: Registered `appsec_manual` in `FRAMEWORK_CATALOG` (`classes/examples_manager.py`) with dedicated URN namespace (`urn:intuitem:risk:*:appsec_manual:*`) preserving full foreign key and relational integrity without conflicting with `appsec`.
- **Automated Validation**: Added test assertions in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) (`test_appsec_manual_structure_and_scoping`) and [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py) (`test_appsec_manual_no_triggered_implementation_groups`). All 249 tests pass.

---

## 19. Separation of Contractual and Operational ("Is Effectively Done") Checks in `appsec_manual.yml` (Version 2)

Separated requirements in [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) that mixed contractual commitment questions with operational "is effectively done" questions into distinct requirements:
- **COTS Hardening & Vendor Support Split**:
  - `cots_deployment_hardening` ("is effectively done" check): Scoped to `cots_app`, retaining Q1 (default credentials changed & configuration hardened, 50 pts) and Q2 (published vendor patches deployed within formal SLAs, 50 pts), totalling 100 points.
  - `cots_vendor_support` (contractual check): Scoped to `cots_app`, validating that COTS software is covered by an active vendor maintenance/support contract and receives regular security updates (not EOL/EOS) (100 pts).
- **SaaS Penetration Testing & SLA Remediation Split**:
  - `saas_penetration_testing` ("is effectively done" check): Scoped to `saas_app`, verifying independent penetration testing on the SaaS platform via customer-led testing authorization or annual vendor pentest audit reports/attestations (100 pts).
  - `saas_vulnerability_remediation_sla` (contractual check): Scoped to `saas_app`, verifying contractual commitments in the security exhibit committing the provider to formal vulnerability remediation SLAs (Critical <= 7d, High <= 30d) (100 pts).
  - Updated risk scenario `saas_unpatched_vulnerability_exploitation` likelihood URN to point to `urn:intuitem:risk:req_node:appsec_manual:saas_penetration_testing`.
- **Framework Version & Metadata**: Incremented to `version: 2` with `expected_requirement_nodes_count: 62`.
- **Automated Validation**: Updated test assertions in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) (`test_appsec_manual_structure_and_scoping`). All tests pass.

---

## 20. Orchestrator-Driven Dynamic Implementation Group Triggering & Relevance Scoping in `appsec_manual`

Enhanced `appsec_manual` and the orchestration engine to mimic dynamic implementation group triggering without auto-activating tracks in the respondent's UI, enabling auditors to ask basic profiling info first, hide non-relevant tracks, and selectively trigger/assign relevant tracks to different team members in the orchestrator:
- **Framework-Level Implementation Group Dependencies**: Added `implementation_groups_dependencies` to [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml#L1367) mapping question choices in Chapter 1 (`hosting:q1` choices for Custom, COTS, and SaaS; `network_exposure:q1` choices for Internet-facing) to target implementation tracks (`custom_app`, `cots_app`, `saas_app`, `baseline`, `internet_facing`) with prompt metadata.
- **Initial Relevance & Scoping**:
  - `info` is the sole `default_selected: true` group.
  - On initial audit creation, all dependent tracks (`custom_app`, `cots_app`, `saas_app`, `baseline`, `internet_facing`) are categorized into `hidden_groups`, with only `info` active and visible.
  - Updated intermediate splash screen `baseline_splash` implementation groups to `["info", "baseline"]` so profiling respondents receive guidance upon completing basic info questions.
- **Orchestrator-Driven Answer Evaluation**:
  - Enhanced `determine_implementation_groups_triggered_by_others` in [`classes/audits/implementation_groups.py`](file:///home/python/ciso-assistant/classes/audits/implementation_groups.py) so answers matching `implementation_groups_dependencies` mark matching tracks as condition-matched and visible/triggered, while non-matching tracks remain strictly hidden and non-selectable.
  - Candidate dependencies whose target groups are not yet active in the audit are populated in `pending_dependencies` and `pending_triggered_groups`.
- **Multi-Role Assignment Orchestration**:
  - In Web UI: Pending dynamic tracks are detected and surfaced in the assignment drawer, allowing the auditor to assign each track to designated team members (e.g. `custom_app` to developers, `internet_facing` to secops).
  - In CLI: Updated `select_audit_implementation_groups_ui` in [`main.py`](file:///home/python/ciso-assistant/main.py) to prioritize relevant/visible tracks and indicate non-relevant tracks hidden based on profiling answers.
- **Automated Validation**: Added test assertions in [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py) (`test_appsec_manual_triggered_implementation_groups_orchestration`). All unit tests pass.

---

## 21. Fix Non-Relevant Questions for SaaS Applications in `appsec_manual` Audit

Identified and resolved the issue where non-relevant Custom software, COTS, and self-hosted exposure questions were appearing during a SaaS application audit:
- **Active Assessment Implementation Group Scoping**:
  - Found active compliance assessment `2fe15fde-680d-4f95-85d5-6624fd37cb70` (`Assessment of Application Security Assessment Framework (AppSec - Manual IG) in App-Audit-Demo-Manual-CISO`) was created with `selected_implementation_groups: []`. In CISO Assistant, empty implementation groups cause the platform to render all 62 requirements across all tracks.
  - Resolved `selected_implementation_groups` via the API using canonical ref_ids `['info', 'saas_app']` (mapped by CISO Assistant to `['Application information & Governance', 'SaaS Application Track']`).
  - Cleared unassessed stray answers on non-applicable `session_management` and `network_exposure`.
- **Framework Scoping Alignment in `YML/appsec_manual.yml`**:
  - `network_exposure`: Updated implementation groups from `["info"]` to `["custom_app", "cots_app"]` to match `appsec.yml` and [`docs/appsec_policy_applicability_matrix.md`](file:///home/python/ciso-assistant/docs/appsec_policy_applicability_matrix.md). For SaaS applications, perimeter/exposure protections are managed by the SaaS vendor and governed under Chapter 10, so network exposure questions are bypassed.
  - `sdlc_chapter`: Updated implementation groups from `["custom_app", "cots_app", "saas_app"]` to `["custom_app", "cots_app"]`, removing empty SDLC chapter artifacts for SaaS respondents.
  - Synchronized updated requirement nodes directly to CISO Assistant via `/api/requirement-nodes/`.
- **API Serializer Compatibility in `classes/audits/compliance.py`**:
  - Updated `ComplianceAssessment.set_selected_implementation_groups` and `resolve_implementation_groups` to resolve group identifiers to canonical `ref_id` strings (`info`, `saas_app`) when communicating with CISO Assistant API endpoints, preventing silent fallback to `[]`.
- **Automated Verification**:
  - Updated unit test assertions in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) (`test_appsec_manual_structure_and_scoping`).
  - Verified live audit questionnaire reduced from 62 to exactly 27 relevant questions (Chapter 1 info, Chapter 2 IAM SSO & RBAC, Chapter 10 SaaS requirements).
  - All 252 unit tests pass (`python3 -m unittest discover tests`).

---

## 22. Generalized PCI-DSS Scoping Phrasing in SaaS Track (Version 3)

Maintained PCI-DSS scoping and contractual governance strictly under Chapter 10 (`saas_chapter` / `saas_pci_dss`) for SaaS applications only, while generalizing the scoping question phrasing to capture all in-scope systems (including connected-to and security-impacting applications that do not directly handle cardholder data):
- **SaaS-Only Scoping & Governance**: Kept PCI-DSS evaluation strictly under [`saas_pci_dss`](file:///home/python/ciso-assistant/YML/appsec_manual.yml#L3770) (`implementation_groups: ["saas_app"]`), keeping Chapter 1 (`info`) focused strictly on baseline organizational profiling (stakeholders, data classification, hosting model).
- **Generalized Scoping Question (`q1`)**:
  - Text: *"Is the application or service in scope for PCI DSS? (e.g., processes, stores, or transmits cardholder data, connects to the Cardholder Data Environment, or can impact the security of the CDE)"*.
  - Choices: `No - Out of scope / Not applicable` (100 pts) and `Yes - In scope for PCI DSS` (0 pts).
- **Conditional Contractual Compliance Question (`q2`)**:
  - Text: *"If in scope for PCI DSS, does the contract require and does the provider maintain active PCI DSS certification, provide an annual AOC, and enforce dedicated payment incident procedures with immediate notification?"*.
  - Choices: `Yes` (100 pts) and `No` (0 pts).
  - Evaluated conditionally when `q1` indicates in scope (`Yes`).
- **Synchronized Frameworks**: Aligned generic PCI DSS scoping phrasing across both [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) and [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml).
- **Framework Version & Test Metadata**: Maintained `version: 3` with `expected_requirement_nodes_count: 62`.
- **Automated Validation**: Verified all test assertions in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) (`test_appsec_manual_structure_and_scoping`). All 50 tests pass.

---

## 23. Network Exposure Scoped to Info Section in `appsec_manual.yml` (Version 3)

Reinstated the network exposure question (`network_exposure`) into the general profiling `info` section in [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml#L1618):
- **Scoping to Info Group**: Changed `implementation_groups` from `["custom_app", "cots_app"]` to `["info"]` under Chapter 1 (`parent_urn: urn:intuitem:risk:req_node:appsec_manual:info`), ensuring all applications answer network accessibility tier profiling (`Internal / Restricted Network only` vs. `Internet-facing`) during the initial `info` audit stage before specific tracks are assigned.
- **Generic Profiling Description**: Updated description to *"Determine whether the application is accessible from the public Internet or restricted to private internal networks."*
- **Automated Validation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) to include `network_exposure` among Chapter 1 `info`-scoped nodes.
  - Verified tests pass in both [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) and [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py) (50/50 passed).

---

## 24. Unified Infrastructure & Hosting Security Track and OS Patching with No-Downtime Architecture in `appsec_manual.yml` (Version 4)

Consolidated all infrastructure questions across COTS and custom software together under a dedicated `infra` implementation group, and added requirements for host-level OS patching and zero-downtime architecture:
- **Dedicated Implementation Group Track (`infra`)**: Added `urn:intuitem:risk:ig:appsec_manual:infra` (*"Infrastructure & Hosting Security Track"*) under `implementation_groups_definition` in [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml).
- **Core Infrastructure Scope**: Grouped all self-hosted infrastructure requirements under the `infra` track so auditors can assign them directly to the IT / Infrastructure / SysAdmin lead for both Custom and COTS software:
  - `crypto_chapter`: `secrets_management`, `data_in_transit`, `data_at_rest`.
  - `logging_chapter`: `security_event_logging`, `centralized_monitoring_and_alerting`.
  - `resilience_chapter`: `backup_and_disaster_recovery`, `cots_deployment_hardening` (generalized to *"Deployment Hardening & Patch SLAs"* for both Custom and COTS).
- **New Requirement Node: `os_patching` (*"Operating System Patching & High Availability"*)**:
  - **Node Metadata**: Added [`os_patching`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) under `resilience_chapter` with `implementation_groups: ["infra"]`.
  - **Question 1 (`q1`)**: *"Are operating system (OS) security patches, kernel updates, and host/container security updates systematically applied within formal SLAs? (e.g. Critical <= 14 days, High <= 30 days)"* (50 pts).
  - **Question 2 (`q2`)**: *"Does the application and infrastructure architecture allow no-downtime patching from a business perspective? (e.g., high-availability clusters, rolling updates, or blue-green deployments preventing business downtime during maintenance)"* (50 pts).
- **Orchestrator-Driven Dynamic Triggering**:
  - Configured `implementation_groups_dependencies` so selecting either Custom software (`hosting:q1:c1`) or COTS software (`hosting:q1:c2`) dynamically triggers the `infra` track alongside the developer/vendor tracks (`custom_app` or `cots_app`).
  - Hides `infra` for SaaS applications, preserving third-party cloud boundary isolation.
- **Framework Version & Test Metadata**: Incremented to `version: 4` with `expected_requirement_nodes_count: 63`.
- **Automated Validation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) to assert `infra` definition, 63 requirement nodes, and verify core infra nodes are scoped to `["infra"]`.
  - Updated [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py) to verify `infra` dynamic triggering for Custom and COTS models and proper hiding for SaaS.
  - All test suites pass.

---

## 25. Merge COTS Vendor Support & COTS Deployment Hardening into Unified Requirement in `appsec_manual.yml`

Merged `cots_vendor_support` (contractual vendor maintenance/support check) and `cots_deployment_hardening` (operational deployment hardening and patch SLAs) into a single consolidated COTS requirement node:
- **Consolidated Requirement Node**: Preserved canonical URN `urn:intuitem:risk:req_node:appsec_manual:cots_deployment_hardening` with ref_id `cots_deployment_hardening` (*"COTS Deployment Hardening, Vendor Support & Patch SLAs"*):
  - **Question 1 (`q1`)**: *"Are default vendor credentials changed, sample modules removed, and configuration hardened against vendor or CIS benchmarks?"* (40 pts).
  - **Question 2 (`q2`)**: *"Does the COTS software actively receive security patches and vulnerability updates from the vendor (under an active maintenance/support contract, not End-of-Life / EOL or End-of-Support / EOS)?"* (30 pts).
  - **Question 3 (`q3`)**: *"Are published vendor security patches, hotfixes, and critical vulnerability updates deployed within formal SLAs (Critical <= 14 days)?"* (30 pts).
  - **Scoring**: $40 + 30 + 30 = 100$ total points.
  - **Implementation Groups**: Scoped strictly to `["cots_app"]`, aligning COTS vendor requirements under the Bought Software Track while keeping the Infrastructure (`infra`) track focused on host-level OS patching (`os_patching`), backups, logging, and encryption.
- **Removed Redundant Node**: Completely eliminated `urn:intuitem:risk:req_node:appsec_manual:cots_vendor_support`.
- **Framework Metadata**: Updated `expected_requirement_nodes_count: 62` in [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml).
- **Automated Validation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) to assert 62 requirement nodes, verify `cots_deployment_hardening` belongs to `["cots_app"]` with 3 questions, and verify `infra` track contains 7 pure infrastructure nodes.
  - All test suites pass.

---

## 26. Streamline `penetration_testing_and_vulnerability_management` to Eliminate Duplicate SLA Questions in `appsec_manual.yml`

Eliminated question overlap between `penetration_testing_and_vulnerability_management` and the specialized SLA requirements (`os_patching`, `cots_deployment_hardening`):
- **Streamlined Requirement Node**: Refocused `penetration_testing_and_vulnerability_management` in [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) purely on conducting independent annual penetration testing:
  - **Question 1 (`q1`)**: *"Is independent penetration testing conducted on the application and underlying infrastructure at least annually by qualified internal or external penetration testers?"* Updated to full 100 points (`add_score: 100`).
  - **Removed Duplicate Question 2 (`q2`)**: Removed generic vulnerability remediation SLA question (`"Are identified vulnerabilities remediated within defined SLAs..."`) which duplicated the dedicated patch SLA checks in `os_patching` (OS/container updates) and `cots_deployment_hardening` (vendor patch SLAs).
  - **Implementation Groups**: Retained `["internet_facing"]`.
- **Automated Validation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) to assert `penetration_testing_and_vulnerability_management` has exactly 1 question with 100 points.
  - All unit tests pass.

---

## 27. Remove `ssrf_and_cloud_metadata_defense` from `appsec.yml` and `appsec_manual.yml`

Removed `ssrf_and_cloud_metadata_defense` requirement node across both standard and manual AppSec frameworks due to organizational maturity scoping:
- **Removed Requirement Node**:
  - Deleted `urn:intuitem:risk:req_node:appsec:ssrf_and_cloud_metadata_defense` from [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml).
  - Deleted `urn:intuitem:risk:req_node:appsec_manual:ssrf_and_cloud_metadata_defense` from [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml).
- **Test Data Synchronization**:
  - Cleaned up answers for `ssrf_and_cloud_metadata_defense` from example application profiles:
    - [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml)
    - [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml)
    - [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml)
- **Framework Versioning & Metadata**:
  - [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml): Incremented to `version: 22`, updated `publication_date: 2026-11-05`, updated `expected_requirement_nodes_count: 59`.
  - [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml): Incremented to `version: 5`, updated `expected_requirement_nodes_count: 61`.
- **Automated Validation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) to remove SSRF checks and assert new node counts (59 for `appsec`, 61 for `appsec_manual`).
  - Verified tests pass across `test_yaml_integrity.py`, `test_implementation_groups.py`, and `test_application_scenarios.py`.

---

## 28. Remove API Payload Schema Validation Question from `api_security_and_rate_limiting`

Removed question `q2` (*"Are API payloads strictly validated against documented API specifications (e.g. OpenAPI / JSON schema)?"*) from requirement node `api_security_and_rate_limiting`:
- **Framework Updates**:
  - [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) and [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml):
    - Deleted question `q2` (`api_security_and_rate_limiting:q2`).
    - Allocated full 100 points (`add_score: 100`) to question `q1` (*"Are exposed web and API endpoints protected against abusive traffic via an edge Web Application Firewall (WAF, e.g., Cloudflare, AWS WAF), bot protection, and automated rate limiting / throttling controls?"*).
    - Refined node descriptions and typical evidence removing schema validation references.
- **Test Data Synchronization**:
  - Removed answer for `api_security_and_rate_limiting:q2` from [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml).
- **Automated Validation**:
  - Verified tests pass across `test_yaml_integrity.py`, `test_implementation_groups.py`, and `test_application_scenarios.py`.

---

## 30. Merge `data_in_transit` (Encryption in Transit) into `data_exchange` (Control of Data Exchange)

Merged `data_in_transit` into `data_exchange` across `appsec.yml` and `appsec_manual.yml`, structuring the unified requirement with an initial gating question asking if the application exchanges data externally:
- **Consolidated Requirement Node**: Preserved canonical URN `data_exchange` (`Control of Data Exchange & Encryption in Transit`) under Chapter 7 (`data_lifecycle_chapter`):
  - **Question 1 (`q1`, Gating)**: *"Does the application exchange data externally? (e.g., transfers, automated API integrations, webhooks, or network communications with external partners, third-party vendors, or public services)"*
    - `No`: 100 points (`compute_result: true`, `#33a745`) - satisfies requirement with no external risk.
    - `Yes`: 0 points (`compute_result: false`, `#fd7e14`) - conditionally triggers transit encryption and contract checks.
  - **Question 2 (`q2`, In-Transit Encryption)**: *"Is data encrypted during transit? (Specify protocols, algorithms and methods: e.g., TLS 1.2 / TLS 1.3 with AES-GCM or ChaCha20, HTTPS with HSTS, mTLS for service APIs, SSHv2, or IPsec across external and internal boundaries)"*
    - `depends_on`: `data_exchange:q1` (`Yes`)
    - `Yes`: 50 points (`compute_result: true`, `#33a745`)
    - `No`: 0 points (`compute_result: false`, `#dc3545`)
  - **Question 3 (`q3`, Formal Data Exchange Contract)**: *"Is there a data exchange contract with the appropriate confidentiality clauses? (e.g., formal Data Processing Agreement / DPA, Data Transfer Agreement / DTA, or NDA)"*
    - `depends_on`: `data_exchange:q1` (`Yes`)
    - `Contract!`: 50 points (`compute_result: true`, `#33a745`)
    - `No contract`: 0 points (`compute_result: false`, `#dc3545`)
  - **Scoring**: $50 + 50 = 100$ total points when external data exchange is active; 100 points when no external exchange occurs.
  - **Associated Controls & Vulnerabilities**: Linked both `information_exchange_contract` and `encrypt_data_in_transit` reference controls, and associated both `contractual_gap` and `lack_of_encryption` vulnerabilities.
  - **Implementation Groups**: Retained `["custom_app", "cots_app"]`.
- **Eliminated Redundant Node**: Completely removed `data_in_transit` from Chapter 4 (`crypto_chapter`) across both `appsec.yml` and `appsec_manual.yml`.
- **Scenario Likelihood Mapping**:
  - Pointed scenario `unencrypted_data_in_transit` (`Exposure of unencrypted data in transit`) likelihood to `data_exchange`.
- **Framework Metadata**:
  - `YML/appsec.yml`: Incremented to `version: 23`, updated `expected_requirement_nodes_count: 58`.
  - `YML/appsec_manual.yml`: Incremented to `version: 6`, updated `expected_requirement_nodes_count: 60`.
- **Test Data Synchronization**:
  - [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml): Updated answers to answer all 3 questions of `data_exchange` (Yes to q1, No to q2, No contract to q3); updated `Exposure of unencrypted data in transit` likelihood requirement to `data_exchange`.
  - [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml) and [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml): Removed `data_in_transit` answers, excluded `Exposure of unencrypted data in transit` scenario for SaaS delivery model (`scenario_count: 10`).
- **Automated Validation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) to assert new requirement node counts (58 for `appsec`, 60 for `appsec_manual`), verified 3-question structure for `data_exchange`, and removed `data_in_transit` from infra nodes.
  - Updated [`tests/test_application_scenarios.py`](file:///home/python/ciso-assistant/tests/test_application_scenarios.py) SaaS scenario count assertion to 10.
  - All test suites pass.

---

## 31. Gating Question for `file_upload_security` (File Upload Security & Malware Hygiene)

Restructured requirement node `file_upload_security` across both `appsec.yml` and `appsec_manual.yml` with an initial gating question to determine whether the application accepts file uploads before assessing magic byte validation and malware scanning:
- **Requirement Node Structure**:
  - **Question 1 (`q1`, Gating Question)**: *"Can files be uploaded to the application? (e.g., user attachments, documents, images, media, or data imports)"*
    - `No`: 100 points (`compute_result: true`, `#33a745`) - satisfies requirement with full compliance when no file upload capabilities exist.
    - `Yes`: 0 points (`compute_result: false`, `#fd7e14`) - conditionally activates downstream file validation and malware scanning checks.
  - **Question 2 (`q2`, Magic Bytes & Path Traversal)**: *"Are uploaded files validated via server-side magic byte inspection, assigned randomized filenames (UUIDs), and stripped of path traversal characters?"*
    - `depends_on`: `file_upload_security:q1` (`Yes`)
    - `Yes`: 50 points (`compute_result: true`, `#33a745`)
    - `No`: 0 points (`compute_result: false`, `#dc3545`)
  - **Question 3 (`q3`, Malware Scanning & Segregated Storage)**: *"Are uploaded files scanned for malware and stored exclusively in dedicated, non-executable private object storage (e.g. private S3 with presigned URLs)?"*
    - `depends_on`: `file_upload_security:q1` (`Yes`)
    - `Yes`: 50 points (`compute_result: true`, `#33a745`)
    - `No`: 0 points (`compute_result: false`, `#dc3545`)
  - **Scoring**: $0 + 50 + 50 = 100$ total points on the `Yes` branch; 100 total points on the `No` branch.
  - **Implementation Groups**: Retained strict scoping to `["custom_app"]` in both frameworks.
- **Test Data Synchronization**:
  - [`test_data/app_appsec_secure_api.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_secure_api.yml): Added answer for `file_upload_security:q1` (`Yes`).
  - [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml): Added answer for `file_upload_security:q1` (`Yes`).
  - [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml): Added answer for `file_upload_security:q1` (`Yes`).
- **Integrity Tests & Documentation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py):
    - Adjusted `test_appsec_code_hygiene_and_hosting_defenses_scoping` to permit intra-node `depends_on` (asserting `dep_q.startswith(node["urn"])`).
    - Updated `test_appsec_file_upload_controls` to assert 3 questions, gating choice scores, dependency conditionality on `q1:c2`, and branch score totals for both `appsec` and `appsec_manual`.
  - Updated [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md): Updated summary table and node details for `file_upload_security`.
- **Automated Validation**:
  - All test suites pass.

## 32. SaaS Scoping Optimization: Excluding `api_security_and_rate_limiting` and `penetration_testing_and_vulnerability_management`

Addressed the architectural requirement that `api_security_and_rate_limiting` and `penetration_testing_and_vulnerability_management` must not be asked for SaaS applications (`saas_app`), purely via framework metadata and implementation group scoping without modifying Python source code:
- **Rationale**:
  - `api_security_and_rate_limiting`: Edge WAF, anti-DDoS, and rate limiting / throttling are managed implicitly by the SaaS vendor to protect their multi-tenant infrastructure. Contractual commitments are evaluated under `saas_network_security` (Chapter 10).
  - `penetration_testing_and_vulnerability_management`: Independent technical penetration tests against third-party multi-tenant SaaS environments are under the operational choice and purview of the vendor. Contractual pentest governance and vulnerability remediation SLAs are evaluated under `saas_penetration_testing_and_vulnerability_management` (Chapter 10).
- **Framework Implementation (Zero Python Code Modifications)**:
  - In [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml):
    - Adjusted requirement node `network_exposure` from `implementation_groups: ["info"]` to `implementation_groups: ["custom_app", "cots_app"]` (mirroring [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml)).
    - Because SaaS applications only select `saas_app` (and `baseline`), `network_exposure` is never presented for SaaS applications, preventing choice `c2` ("Internet-facing") from ever triggering `internet_facing`.
    - Clarified track description for `internet_facing` and requirement descriptions/annotations for `network_exposure`, `api_security_and_rate_limiting`, and `penetration_testing_and_vulnerability_management` across both YAML frameworks.
    - Incremented framework versions (`appsec.yml` v24, `appsec_manual.yml` v7).
- **Automated Tests & Integrity**:
  - In [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py):
    - Updated `test_appsec_manual_structure_and_scoping` to assert `network_exposure` is scoped to `{"custom_app", "cots_app"}` rather than `info`.
    - Updated `test_appsec_code_hygiene_and_hosting_defenses_scoping` to assert `appsec_manual` perimeter requirements exclude `saas_app`.
  - In [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py):
    - Added verification in `test_appsec_manual_triggered_implementation_groups_orchestration` ensuring SaaS answers trigger `saas_app` while keeping `internet_facing`, `custom_app`, `cots_app`, and `infra` hidden.
- **Verification**:
  - Verified `classes/` remains completely clean (`git diff classes/` is empty).
  - All automated test suites pass.

## 33. Merge Hosting Model and Network Exposure into Single Node (`hosting`)

Merged requirement node `network_exposure` into `hosting` across both `YML/appsec.yml` and `YML/appsec_manual.yml`, creating a single unified requirement node for delivery model and network accessibility in Chapter 1:
- **Requirement Node Structure (`hosting`)**:
  - **Question 1 (`hosting:q1`)**: *"What is the delivery and hosting model of the application?"*
    - `c1`: Custom software created and deployed by my teams (In-house development)
    - `c2`: Bought software deployed by my teams (COTS / Vendor package)
    - `c3`: SaaS (Third-party software hosted and operated by a vendor)
  - **Question 2 (`hosting:q2`, Network Exposure)**: *"What is the network exposure of the application?"*
    - `depends_on`: `hosting:q1` in `[c1, c2]` (`condition: any`).
    - `c1`: Internal / Restricted Network only (100 pts, compute_result: true)
    - `c2`: Internet-facing (Public Web / Mobile API) (100 pts, compute_result: true)
      - In `appsec.yml`: `select_implementation_groups: ["internet_facing"]`.
      - In `appsec_manual.yml`: connected to `internet_facing` track via `implementation_groups_dependencies`.
  - **SaaS Handling**: When SaaS (`hosting:q1:c3`) is selected, question 2 is dynamically hidden via `depends_on`, ensuring SaaS applications are never asked the network exposure question and cannot trigger `internet_facing`.
- **Framework Synchronization**:
  - Removed standalone requirement node `network_exposure`.
  - Updated expected requirement nodes count: `appsec.yml` from 58 to 57; `appsec_manual.yml` from 60 to 59.
  - Incremented versions: `appsec.yml` v25, `appsec_manual.yml` v8.
  - Updated [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml) requirement mapping from `network_exposure` to `hosting`.
- **Tests & Documentation**:
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py):
    - In `test_appsec_network_exposure_and_conditional_branching`, verified `hosting:q2` dependency on `hosting:q1` (`c1`, `c2`) and confirmed `network_exposure` is no longer a standalone node.
    - In `test_appsec_manual_structure_and_scoping`, verified `hosting` node contains 2 questions with intra-node dependency and confirmed total requirement nodes count is 59.
  - Updated [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py) to supply `q1` and `q2` under `hosting`.
  - Updated [`docs/appsec_policy_applicability_matrix.md`](file:///home/python/ciso-assistant/docs/appsec_policy_applicability_matrix.md) and [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md).
- **Automated Validation**:
  - Verified `classes/` remains completely clean (`git diff classes/` is empty).
  - All automated test suites pass.

---

## 34. SaaS Vendor ISO 27001 / SOC 2 Certification Question, `saas_uncertified` IG, and PCI DSS Vendor Certification Question

Added a conditional question in `hosting` asking whether the SaaS vendor is ISO/IEC 27001 or SOC 2 Type II certified, introduced the `saas_uncertified` implementation group for detailed vendor security assessment when the vendor is not certified, and added a dedicated PCI DSS vendor certification question in `saas_pci_dss`:
- **SaaS Vendor ISO 27001 / SOC 2 Certification Profiling (`hosting:q3`)**:
  - Added `hosting:q3` (*"Is the SaaS vendor ISO/IEC 27001 or SOC 2 Type II certified?"*) with intra-node `depends_on` on `hosting:q1:c3` (SaaS).
  - `c1`: *"Yes - The SaaS vendor holds an active ISO/IEC 27001 certification or SOC 2 Type II report"* (100 pts, `compute_result: true`).
  - `c2`: *"No - The SaaS vendor is not ISO/IEC 27001 or SOC 2 Type II certified"* (100 pts, `compute_result: true`), dynamically triggering `saas_uncertified` via `select_implementation_groups` in [`YML/appsec.yml`](file:///home/romain/ciso-assistant/YML/appsec.yml) and `implementation_groups_dependencies` in [`YML/appsec_manual.yml`](file:///home/romain/ciso-assistant/YML/appsec_manual.yml).
- **New Implementation Group (`saas_uncertified`)**:
  - Defined `urn:intuitem:risk:ig:appsec:saas_uncertified` and `urn:intuitem:risk:ig:appsec_manual:saas_uncertified` (*"Uncertified SaaS Vendor Track (Detailed Security Assessment)"*).
  - Kept core contractual & tenant requirements in `["saas_app"]` (`saas_contract`, `saas_confidentiality_and_data_protection`, `saas_iam`, `saas_data_hosting_and_residency`, `saas_audit_and_compliance`, `saas_pci_dss`, `saas_non_conformity_remediation`).
  - Scoped detailed vendor operational/security nodes in Chapter 10 to `["saas_uncertified"]` (`saas_governance_and_policy`, `saas_security_awareness`, `saas_entitlements_and_privileges`, `saas_logging_and_incidents`, `saas_workstation_security`, `saas_mobile_security`, `saas_network_security`, `saas_environment_isolation`, `saas_secure_development`, `saas_web_app_security`, `saas_penetration_testing_and_vulnerability_management` / `saas_penetration_testing` + `saas_vulnerability_remediation_sla`, `saas_physical_security`, `saas_backup_and_business_continuity`, `saas_subcontractor_management`).
- **SaaS Vendor PCI DSS Certification Question (`saas_pci_dss:q2` & `q3`)**:
  - When `saas_pci_dss:q1` is *"Yes - In scope for PCI DSS"* (`c2`), `q2` asks whether the SaaS vendor is PCI DSS certified with a valid annual AOC (50 pts) and `q3` verifies contractual PCI DSS obligations and incident notification procedures (50 pts).
- **Framework Versions**: Incremented `YML/appsec.yml` to `version: 26` and `YML/appsec_manual.yml` to `version: 9`.
- **Automated Validation**: Updated unit tests in [`tests/test_yaml_integrity.py`](file:///home/romain/ciso-assistant/tests/test_yaml_integrity.py) and [`tests/test_implementation_groups.py`](file:///home/romain/ciso-assistant/tests/test_implementation_groups.py), and updated SaaS test profiles in `test_data/`. All tests pass.

---

## 35. Externalization of Non-Framework Objects to Shared Library (`appsec_objects.yml`)

Externalized all common, non-framework objects out of `YML/appsec.yml` and `YML/appsec_manual.yml` into a dedicated shared library file `YML/appsec_objects.yml`, enabling both frameworks (one fully automated via choice-triggered implementation groups, and one manually triggered) to share common risk scenarios, risk matrix, threats, vulnerabilities, and reference controls:
- **Shared Library File (`YML/appsec_objects.yml`)**:
  - Registered under `urn:intuitem:risk:library:appsec_objects`.
  - Defines the 4x4 risk matrix (`urn:intuitem:risk:matrix:appsec`).
  - Defines the 9 core threats (`urn:intuitem:risk:threat:appsec:...`).
  - Defines the 18 core vulnerabilities (`urn:intuitem:risk:vulnerability:appsec:...`).
  - Defines the 26 core reference controls (`urn:intuitem:risk:control:appsec:...`).
  - Defines all 25 risk scenarios (`urn:intuitem:risk:scenario:appsec:...`). Scenarios 1 to 20 are tagged for both `appsec` and `appsec_manual`; scenarios 21 to 25 are tagged for `appsec_manual`.
- **Framework YAML Simplification**:
  - In [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) and [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml), removed all non-framework object definitions under `objects:` (retaining only `framework:`).
  - Added root declaration `common_objects_file: "YML/appsec_objects.yml"`.
  - In `YML/appsec_manual.yml`, updated requirement nodes' `reference_controls` and `vulnerabilities` to reference the canonical shared URNs `urn:intuitem:risk:control:appsec:...` and `urn:intuitem:risk:vulnerability:appsec:...`.
- **Python Loading & Simulation Architecture**:
  - Updated [`classes/utils.py`](file:///home/python/ciso-assistant/classes/utils.py) (`load_yaml_file`): Automatically resolves and merges `common_objects_file` into `objects`, adapting risk scenario namespaces and requirement node links for target frameworks.
  - Updated [`classes/core/framework.py`](file:///home/python/ciso-assistant/classes/core/framework.py): `LibraryFile` leverages `load_yaml_file` to access all common risk scenarios, threats, and vulnerabilities.
  - Updated [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py) and [`tests/test_application_scenarios.py`](file:///home/python/ciso-assistant/tests/test_application_scenarios.py): Uses `load_yaml_file` to seamlessly test merged frameworks, and added `test_appsec_common_objects_externalization`.
  - Updated [`classes/examples_manager.py`](file:///home/python/ciso-assistant/classes/examples_manager.py) and [`classes/audits/compliance.py`](file:///home/python/ciso-assistant/classes/audits/compliance.py): Enhanced requirement assessment resolution to match across namespaces by requirement ref_id.
- **Automated Validation**: All automated unit test suites pass cleanly.

---

## 36. Intra-Node Question Prerequisites & Dependency Gating in AppSec Framework (`appsec_manual.yml` & `appsec.yml`) [COMPLETED]

Implemented intra-node prerequisite gating (`depends_on`) across both `YML/appsec_manual.yml` and `YML/appsec.yml` where follow-up questions logically presuppose prior conditions:

1. **`cots_deployment_hardening:q3` depends on `cots_deployment_hardening:q2 == c1` (Vendor Patch SLA Prerequisites)**:
   - **Context**: `q2` asks if the COTS software actively receives security patches from the vendor under an active maintenance contract (not EOL/EOS). `q3` asks if published vendor security patches are deployed within formal SLAs (Critical <= 14 days).
   - **Implementation**: Added `depends_on` in `q3` pointing to `q2:c1` (`urn:intuitem:risk:req_node:<fw_ref>:cots_deployment_hardening:q2:c1`).
   - **Result**: When COTS software is unsupported or End-of-Life (`q2 == c2`), `q3` is safely hidden/bypassed.

2. **`access_control_and_rbac:q3` depends on `access_control_and_rbac:q1 == c1` (Entitlement Recertification Prerequisites)**:
   - **Context**: `q1` asks if granular roles and permissions (RBAC/ABAC) are defined. `q3` asks if user entitlements and privileged permissions are periodically reviewed and recertified via formal recertification campaigns.
   - **Implementation**: Added `depends_on` in `q3` pointing to `q1:c1` (`urn:intuitem:risk:req_node:<fw_ref>:access_control_and_rbac:q1:c1`).
   - **Result**: If no roles or permissions are defined for the application (`q1 == c2`), formal entitlement recertification campaigns (`q3`) are safely hidden/bypassed.

3. **Multi-Question Nodes Retained Independent**:
   - `security_event_logging:q2` (sensitive data masking): Retained as independent from `q1` so applications leaking secrets in error/debug logs are held accountable even without structured security event logging.
   - `stakeholder_identification:q1-q4`: Retained as independent parallel inquiries for ownership and CMDB synchronization.
   - SaaS contractual controls: Retained as independent parallel clauses per enterprise security schedules.

4. **Test Profiles & Framework Synchronization**:
   - Updated `test_data/app_appsec_vulnerable_legacy.yml` to omit `access_control_and_rbac:q3` when `q1` is `No` (`c2`).
   - Added unit test `test_appsec_intra_node_prerequisites` in `tests/test_yaml_integrity.py` asserting `depends_on` presence, intra-node target, and exact choice URNs for both frameworks.
   - Verified 100% pass across all 268 test cases in `python3 -m unittest discover tests`.

---

## 37. Automated AppSec Framework 6-Example Suite & Live UI Provisioning (`appsec`) [COMPLETED]

Created and provisioned the comprehensive 6-case application example suite for the choice-automated framework [`YML/appsec.yml`](file:///home/romain/ciso-assistant/YML/appsec.yml) (`ref_id: "appsec"`) in fully answered states across CISO Assistant:

1. **Framework Installation & Database Migration**:
   - Replaced the outdated November 5th database instance of `appsec_manual` with the latest `appsec` framework (`urn:intuitem:risk:framework:appsec`, version 28) containing dynamic choice-level implementation group triggering (`select_implementation_groups`) and intra-node prerequisites.
   - Successfully loaded into `LoadedLibrary` and `Framework` in CISO Assistant backend.

2. **Created Application Example Profiles (`test_data/`)**:
   - [`test_data/app_appsec_custom_internal.yml`](file:///home/romain/ciso-assistant/test_data/app_appsec_custom_internal.yml) (Order 22, Case 1: Custom + Internal, 4 IGs: `info`, `baseline`, `custom_app`, `infra`, 21 nodes, 15 scenarios).
   - [`test_data/app_appsec_custom_internet.yml`](file:///home/romain/ciso-assistant/test_data/app_appsec_custom_internet.yml) (Order 23, Case 2: Custom + Internet-Facing, 5 IGs: `info`, `baseline`, `custom_app`, `infra`, `internet_facing`, 23 nodes, 17 scenarios).
   - [`test_data/app_appsec_cots_internal.yml`](file:///home/romain/ciso-assistant/test_data/app_appsec_cots_internal.yml) (Order 24, Case 3: Bought COTS + Internal, 4 IGs: `info`, `baseline`, `cots_app`, `infra`, 17 nodes, 13 scenarios).
   - [`test_data/app_appsec_cots_internet.yml`](file:///home/romain/ciso-assistant/test_data/app_appsec_cots_internet.yml) (Order 25, Case 4: Bought COTS + Internet-Facing, 5 IGs: `info`, `baseline`, `cots_app`, `infra`, `internet_facing`, 19 nodes, 15 scenarios).
   - [`test_data/app_appsec_saas_certified.yml`](file:///home/romain/ciso-assistant/test_data/app_appsec_saas_certified.yml) (Order 26, Case 5: SaaS + Certified Vendor, 3 IGs: `info`, `baseline`, `saas_app`, 12 nodes, 7 scenarios).
   - [`test_data/app_appsec_saas_uncertified.yml`](file:///home/romain/ciso-assistant/test_data/app_appsec_saas_uncertified.yml) (Order 27, Case 6: SaaS + Uncertified Vendor, 4 IGs: `info`, `baseline`, `saas_app`, `saas_uncertified`, 26 nodes, 10 scenarios).

3. **Live Instance Provisioning**:
   - All 6 applications were provisioned via `ExamplesManager.create_example_application()` into domain `Example Applications` at `https://localhost:8443`.
   - Each application has its Perimeter, Compliance Assessment (with all responses, results, and observations imported), and Risk Assessment (with all risk scenarios, likelihood/impact ratings, and linked controls) completely populated.

4. **Automated Test Validation**:
   - Added `test_appsec_example_suite_all_6_combinations` in [`tests/test_implementation_groups.py`](file:///home/romain/ciso-assistant/tests/test_implementation_groups.py).
   - Updated `test_example_applications_definitions` in [`tests/test_examples_manager.py`](file:///home/romain/ciso-assistant/tests/test_examples_manager.py) (27 application profiles).
   - Dynamic testing in [`tests/test_application_scenarios.py`](file:///home/romain/ciso-assistant/tests/test_application_scenarios.py).
   - All 275 tests pass cleanly (`Ran 275 tests in 53.360s, OK (skipped=22)`).

---

## 38. Phase 1: Scoring Mathematics & Standardized Choice Ordering (`appsec.yml` & `appsec_manual.yml`) [COMPLETED]

Implemented Phase 1 of the AppSec Framework Questions & Risk Evaluation Improvement Plan across both [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) and [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml):

1. **Rebalanced `non_prod_data` Scoring (Eliminating Dead-Weight Math Defect)**:
   - **Context**: In `non_prod_data`, when production data is used in non-prod (`q1 = Yes`, +0), `q2` previously awarded `+90` and `q3` awarded `+10`. Under integer bucket division $\lfloor\frac{\text{score}-1}{25}\rfloor$, $q_3$ (`+10`) could never alter the computed likelihood (both 0 and 10 produced Likelihood 4; both 90 and 100 produced Likelihood 1).
   - **Implementation**:
     - `non_prod_data:q2`: protective choices (`c2`–`c5`: Hashing, Pseudonymisation, Encryption, Masking / Anonymization) rebalanced to **`add_score: 60`** (was 90).
     - `non_prod_data:q3`: Choice `c1` ("Yes") rebalanced to **`add_score: 40`** (was 10), and Choice `c2` ("No") awards `0`.
   - **Result**: Unlocks all 4 likelihood tiers dynamically:
     - Sanitized + Purged ($60 + 40 = 100$) $\rightarrow$ **Likelihood 1** (*Unlikely*)
     - Sanitized but Retained ($60 + 0 = 60$) $\rightarrow$ **Likelihood 2** (*Rather unlikely*)
     - Unsanitized but Purged ($0 + 40 = 40$) $\rightarrow$ **Likelihood 3** (*Likely*)
     - Unsanitized and Retained ($0 + 0 = 0$) $\rightarrow$ **Likelihood 4** (*Very likely*)

2. **Fixed `stakeholder_identification` Score Buckets**:
   - **Context**: Questions `q1`–`q4` each awarded 25 points. Because $25$ falls into the `0–25` bucket ($\lfloor\frac{25-1}{25}\rfloor = 0$), having 1 designated stakeholder scored identical to having 0 stakeholders (Likelihood 4).
   - **Implementation**: Weighted core operational owners higher:
     - `q1` (Business Contact): **`add_score: 30`**
     - `q2` (IT Contact): **`add_score: 30`**
     - `q3` (Data Owner): **`add_score: 25`**
     - `q4` (LeanIX / CMDB): **`add_score: 15`**
     - Total maximum score = $30 + 30 + 25 + 15 = 100$.
   - **Result**:
     - 1 designated owner ($30$ pts) $\rightarrow$ **Likelihood 3** (elevated from L4)
     - 2 designated owners ($55–60$ pts) $\rightarrow$ **Likelihood 2**
     - Full governance ($85–100$ pts) $\rightarrow$ **Likelihood 1**

3. **Standardized `c1 = Yes` / `c2 = No` Choice Ordering**:
   - Inverted non-standard `c1 = No` / `c2 = Yes` order in:
     - `non_prod_data:q3`: `c1` = "Yes" (40 pts), `c2` = "No" (0 pts).
     - `data_destruction:q1`: `c1` = "Yes" (50 pts), `c2` = "No" (0 pts).
     - `data_destruction:q2`: `c1` = "Yes" (50 pts), `c2` = "No" (0 pts).
   - Updated `data_destruction:q2` `depends_on` answers to `["urn:intuitem:risk:req_node:<fw>:data_destruction:q1:c1"]`.

4. **Rephrased `security_event_logging:q2`**:
   - Updated text to: *"Are sensitive data fields (passwords, payment cards, tokens, PII) systematically sanitized/masked from application, diagnostic, and error log outputs?"*.
   - Retained independent assessment from `q1` so applications leaking secrets in error/diagnostic logs are held accountable even without structured security event logging.

5. **Framework Version Increments**:
   - [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml): Incremented to **`version: 32`** (`publication_date: 2026-11-09`).
   - [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml): Incremented to **`version: 14`** (`publication_date: 2026-11-09`).

6. **Synchronized Test Profiles & Documentation**:
   - Updated [`test_data/app_appsec_vulnerable_legacy.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_vulnerable_legacy.yml): `Missing application stakeholders` scenario updated to `likelihood_score: 30`, `scaled_likelihood: 3`, `matrix_risk_id: 1`, `risk_level: 2`, `control_priority: 3` (Low risk due to IT contact).
   - Updated [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml): `Missing application stakeholders` scenario updated to `likelihood_score: 85`, `scaled_likelihood: 1` (3 designated owners achieve full governance Likelihood 1).
   - Updated [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md), [`docs/appsec_manual_conditional_ig_graph.md`](file:///home/python/ciso-assistant/docs/appsec_manual_conditional_ig_graph.md), and checked Step 1 in [`docs/appsec_framework_improvement_plan.md`](file:///home/python/ciso-assistant/docs/appsec_framework_improvement_plan.md).

7. **Automated Unit Tests**:
   - Added `test_appsec_phase1_scoring_and_standardized_choices` in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py).
   - Ran full test suite: **278 passed, 0 failures, 0 errors, 22 skipped** (`python3 -m unittest discover tests`).

### 39. Phase 2: Real-World Architecture & Question Granularity Implementation (Completed 2026-11-09)

Implemented all Phase 2 requirements from [`docs/appsec_framework_improvement_plan.md`](file:///home/python/ciso-assistant/docs/appsec_framework_improvement_plan.md) across both [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) and [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml), synchronized all 15 test profiles in [`test_data/`](file:///home/python/ciso-assistant/test_data/), updated documentation, and passed 100% of automated unit and integration tests:

1. **Hybrid Authentication & Break-Glass Admin Accounts (`authentication_and_mfa`)**:
   - Replaced binary choice in `authentication_and_mfa:q1` with 4 distinct architectural options:
     - `c1`: `"Enterprise SSO exclusively (SAML 2.0 / OIDC federated IdP, with no local accounts)"` (`+100` pts, `compute_result: true`, `#33a745`)
     - `c2`: `"Hybrid: Enterprise SSO for users, with local admin / break-glass or external accounts"` (`+40` pts, `compute_result: true`, `#ffc107`)
     - `c3`: `"Direct / Local application authentication only (Username & Password)"` (`+0` pts, `compute_result: false`, `#dc3545`)
     - `c4`: `"Machine-to-Machine / API only (mTLS, OAuth2 Client Credentials, or signed tokens; no interactive user login)"` (`+100` pts, `compute_result: true`, `#33a745`)
   - Updated `q2` (local password policies & lockout) and `q3` (administrative MFA) `depends_on`:
     - Triggers when `q1` answers either `c2` (Hybrid) or `c3` (Direct) with `condition: any`.
     - Re-weighted `q2` and `q3` from $50 \rightarrow 30$ pts:
       - Hybrid SSO + Passwords + Admin MFA: $40 + 30 + 30 = 100$ pts (Likelihood 1 / Compliant)
       - Direct + Passwords + Admin MFA: $0 + 30 + 30 = 60$ pts (Likelihood 2 / Capped because Enterprise SSO is omitted)
       - Exclusive SSO or M2M API: $100$ pts (Likelihood 1 / Fully compliant)

2. **Stateless Token Architecture in `session_management`**:
   - Rephrased `session_management:q1` to explicitly accommodate modern stateless token APIs (JWT, OAuth2 Bearer tokens) alongside cookie-based web applications:
     *"Are session identifiers and API bearer tokens cryptographically secure, protected in transit/storage (e.g. HttpOnly, Secure, SameSite cookie flags or secure token storage), and invalidated upon logout, expiration, or inactivity?"* (`100` pts).

3. **Split Compound 100-Point Questions into Granular 50 + 50 Point Controls**:
   - **`backup_and_disaster_recovery`**:
     - `q1` (`+50` pts): *"Are automated and encrypted backups maintained for application state and databases?"*
     - `q2` (`+50` pts, `depends_on: q1:c1`): *"Are backup restoration and disaster recovery drills tested at least annually against documented RTO/RPO targets?"*
   - **`owasp_top_10_defenses`**:
     - `q1` (`+50` pts): *"Are server-side input validation and parameterized queries/ORMs enforced to prevent injection flaws (SQLi, command injection, SSRF)?"*
     - `q2` (`+50` pts): *"Are context-aware output encoding, security headers (CSP), and generic production error handlers enforced to prevent XSS and stack-trace leakage?"*
   - **`code_review_and_ci_cd_integrity`**:
     - `q1` (`+50` pts): *"Are mandatory peer code reviews enforced prior to merging changes into deployment branches?"*
     - `q2` (`+50` pts): *"Do repository branch protection rules block direct commits, force-pushes, and failing CI status checks on deployment branches?"*
   - **`api_security_and_rate_limiting`**:
     - `q1` (`+50` pts): *"Are internet-facing endpoints fronted by an Edge WAF and anti-DDoS / bot protection (e.g. Cloudflare, AWS WAF)?"*
     - `q2` (`+50` pts): *"Are API rate limiting, throttling, and payload size quotas enforced to prevent scraping and resource exhaustion?"*

4. **Framework Version Increments**:
   - [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml): Incremented to **`version: 33`** (`publication_date: 2026-11-09`).
   - [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml): Incremented to **`version: 15`** (`publication_date: 2026-11-09`).

5. **Synchronized All 15 Test Profiles in [`test_data/`](file:///home/python/ciso-assistant/test_data/)**:
   - Updated profiles answering the split nodes to provide answers for `q1` and `q2`:
     - Compliant profiles (`custom_internal`, `custom_internet`, `cots_internal`, `cots_internet`, `manual_*`): answer `Yes` to both `q1` and `q2` (100 pts total).
     - Non-compliant profiles (`vulnerable_legacy`): answer `No` to `q1` and `q2` (0 pts total).
   - Updated compliant profiles utilizing local/break-glass administrative or customer accounts (`cots_internet`, `custom_internet`, `saas_uncertified`, and `manual_*`) to select the new Hybrid option (`c2`: 40 pts) with `q2 = Yes` (30 pts) and `q3 = Yes` (30 pts), maintaining their 100-point Likelihood 1 evaluation.
   - Updated [`test_data/app_appsec_hybrid_saas.yml`](file:///home/python/ciso-assistant/test_data/app_appsec_hybrid_saas.yml): `Account takeover via weak authentication` likelihood score updated to $30$ pts ($0 + 0 + 30$, `scaled_likelihood: 3`, `risk_level: 3`).

6. **Documentation & Verification**:
   - Updated [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md) (summary table & detailed question blocks).
   - Updated [`docs/appsec_manual_conditional_ig_graph.md`](file:///home/python/ciso-assistant/docs/appsec_manual_conditional_ig_graph.md) (flowchart & intra-node dependencies).
   - Marked Step 2 as completed in [`docs/appsec_framework_improvement_plan.md`](file:///home/python/ciso-assistant/docs/appsec_framework_improvement_plan.md).
   - Updated automated tests in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py), including `test_appsec_iam_sso_and_credential_order`, `test_appsec_on_premise_iam_sso_conditional_authentication`, `test_appsec_software_delivery_models_and_sdlc_scoping`, and added dedicated `test_appsec_phase2_architecture_and_split_nodes`.
   - Full test suite execution: **279 passed, 0 failures, 0 errors, 22 skipped** (`python3 -m unittest discover tests`).


## 40. Phase 3 Point 2: Connect Unlinked Requirements to Risk Scenarios (Completed 2026-11-09)

Implemented **Point 2 of Phase 3** from [`docs/appsec_framework_improvement_plan.md`](file:///home/python/ciso-assistant/docs/appsec_framework_improvement_plan.md) (*"Connect Unlinked Requirements to Risk Scenarios"*), achieving 100% bidirectional coverage between assessable security requirements and threat scenarios.

### 1. Risk Scenario Expansion (`YML/appsec_objects.yml`)
- Incremented [`YML/appsec_objects.yml`](file:///home/python/ciso-assistant/YML/appsec_objects.yml) to **`version: 3`** (`publication_date: 2026-11-09`).
- Created **19 new dedicated risk scenarios** (scenarios 26 through 44), expanding the library from 25 to **44 risk scenarios**:
  1. `session_hijacking_and_token_replay` (Scenario 26) $\rightarrow$ Likelihood: `session_management`
  2. `ci_cd_pipeline_compromise_and_unreviewed_code` (Scenario 27) $\rightarrow$ Likelihood: `code_review_and_ci_cd_integrity`
  3. `undetected_code_vulnerabilities_missing_testing` (Scenario 28) $\rightarrow$ Likelihood: `automated_security_testing`
  4. `cots_vendor_insecure_development_practices` (Scenario 29) $\rightarrow$ Likelihood: `vendor_secure_development`
  5. `sensitive_data_exposure_in_logs` (Scenario 30) $\rightarrow$ Likelihood: `security_event_logging`
  6. `saas_cross_border_data_transfer_noncompliance` (Scenario 31) $\rightarrow$ Likelihood: `saas_data_hosting_and_residency`
  7. `saas_cardholder_data_compromise` (Scenario 32) $\rightarrow$ Likelihood: `saas_pci_dss`
  8. `saas_unremediated_nonconformity_and_remedy_gap` (Scenario 33) $\rightarrow$ Likelihood: `saas_non_conformity_remediation`
  9. `saas_unmonitored_incidents` (Scenario 34) $\rightarrow$ Likelihood: `saas_logging_and_incidents`
  10. `saas_service_disruption_and_data_loss` (Scenario 35) $\rightarrow$ Likelihood: `saas_backup_and_business_continuity`
  11. `saas_subcontractor_supply_chain_breach` (Scenario 36) $\rightarrow$ Likelihood: `saas_subcontractor_management`
  12. `saas_unverified_vendor_sdlc_exploitation` (Scenario 37) $\rightarrow$ Likelihood: `saas_secure_development`
  13. `saas_web_transport_exploitation` (Scenario 38) $\rightarrow$ Likelihood: `saas_web_app_security`
  14. `saas_network_perimeter_breach` (Scenario 39) $\rightarrow$ Likelihood: `saas_network_security`
  15. `saas_endpoint_compromise_and_theft` (Scenario 40) $\rightarrow$ Likelihood: `saas_workstation_security`
  16. `saas_mobile_device_compromise` (Scenario 41) $\rightarrow$ Likelihood: `saas_mobile_security`
  17. `saas_missing_governance_and_policies` (Scenario 42) $\rightarrow$ Likelihood: `saas_governance_and_policy`
  18. `saas_personnel_social_engineering` (Scenario 43) $\rightarrow$ Likelihood: `saas_security_awareness`
  19. `saas_physical_datacenter_breach` (Scenario 44) $\rightarrow$ Likelihood: `saas_physical_security`

### 2. Complete Coverage & Zero Orphans
- Across all 46 assessable nodes in the framework:
  - 2 profiling/discriminator nodes (`data_classification` for confidentiality impact, `hosting` for implementation group scoping).
  - 44 security requirements mapped **1-to-1** as likelihood drivers for all 44 risk scenarios.
  - **Zero unlinked assessable requirements** remain in the framework.
  - **Zero orphaned entities**: every reference control (26) and vulnerability (18) is actively mapped to scenarios.

### 3. Framework Version Increments & Test Metadata
- [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml): Incremented to **`version: 34`** (`publication_date: 2026-11-09`), `expected_risk_scenarios_count: 44`.
- [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml): Incremented to **`version: 16`** (`publication_date: 2026-11-09`), `expected_risk_scenarios_count: 44`.

### 4. Application Profiles Synchronization in [`test_data/`](file:///home/python/ciso-assistant/test_data/)
Synchronized all 15 application profiles in `test_data/` with exact scenario counts, excluded scenarios, and detailed risk scenario metrics:
- **`app_appsec_cots_internal.yml`** & **`app_manual_cots_internal.yml`**: $13 \rightarrow 15$ scenarios (+2: SDLC, Logging)
- **`app_appsec_cots_internet.yml`** & **`app_manual_cots_internet.yml`**: $15 \rightarrow 17$ scenarios (+2: SDLC, Logging)
- **`app_appsec_custom_internal.yml`** & **`app_manual_custom_internal.yml`**: $15 \rightarrow 19$ scenarios (+4: CI/CD, SAST/DAST, Logging, Session)
- **`app_appsec_custom_internet.yml`** & **`app_manual_custom_internet.yml`**: $17 \rightarrow 21$ scenarios (+4: CI/CD, SAST/DAST, Logging, Session)
- **`app_appsec_vulnerable_legacy.yml`**: $15 \rightarrow 19$ scenarios (all 4 newly evaluated scenarios reflect score 0, L4 / High Risk)
- **`app_appsec_saas_certified.yml`** & **`app_manual_saas_certified.yml`**: $7 \rightarrow 10$ scenarios (+3: Residency, PCI DSS, Non-Conformity)
- **`app_appsec_secure_api.yml`**: $7 \rightarrow 10$ scenarios (+3: Residency, PCI DSS, Non-Conformity)
- **`app_appsec_saas_uncertified.yml`** & **`app_manual_saas_uncertified.yml`**: $10 \rightarrow 24$ scenarios (+14: Residency, PCI, Non-Conformity, and all 11 uncertified operational nodes)
- **`app_appsec_hybrid_saas.yml`**: $10 \rightarrow 24$ scenarios (+14, with elevated risks calculated for uncertified SDLC and subcontractor gaps)

### 5. Automated Test Suite Verification
- Added `test_appsec_phase3_unlinked_requirements_risk_scenario_coverage` in [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py).
- Synchronized `test_appsec_availability_criticality_mapping_and_scenarios` and `test_appsec_manual_structure_and_scoping` to validate 44 scenarios.
- Synchronized `test_appsec_saas_contract_defined_controls_evaluation` in [`tests/test_application_scenarios.py`](file:///home/python/ciso-assistant/tests/test_application_scenarios.py) (10 scenarios).
- Synchronized `expected_cases` across both automated suite tests in [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py).
- Ran full automated test suite: **280 tests ran, 280 passed, 0 failures, 0 errors, 22 skipped** (`python3 -m unittest discover tests`).

---

## 41. Added "Application Description & Business Purpose" Screen to Both AppSec Frameworks

### 1. Functional Requirement & Placement
- Added a dedicated assessment screen in **Chapter 1: Application Information & Governance** (`info` implementation group) where respondents can describe what the application is doing, including its primary functional domain, business capabilities, intended users, and operational scope:
  - **Ref ID**: `application_description`
  - **Frameworks**:
    - [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) (`urn:intuitem:risk:req_node:appsec:application_description`)
    - [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) (`urn:intuitem:risk:req_node:appsec_manual:application_description`)
  - **Hierarchy**: `parent_urn: info`, `depth: 2`, `assessable: true`, `implementation_groups: ["info"]`.
  - **Position**: Located directly under `info` (before `stakeholder_identification`, `data_classification`, and `hosting`), establishing the foundational functional context before stakeholder assignment and technical classification.

### 2. Screen Questions & Architecture
- **Question 1 (`q1`)**: Functional Domain & Business Purpose (`type: unique_choice`)
  - Choices:
    1. Customer-Facing & Digital Commerce (e-commerce, customer portals, public web services, mobile apps)
    2. Internal Operations & Enterprise Management (ERP, CRM, HR, finance, supply chain, intranet)
    3. Data Analytics, AI & Business Intelligence (data warehouse, ETL pipelines, reporting, ML models)
    4. Integration Middleware & Core APIs (API gateways, message brokers, microservices hub)
    5. Infrastructure, Platform & DevOps Management (CI/CD, monitoring, ITSM, security tooling)
    6. Other / Specialized Functional Purpose
- **Question 2 (`q2`)**: Target User Audience & Consumer Base (`type: unique_choice`)
  - Choices:
    1. Internal workforce (employees, internal contractors)
    2. Business partners and vendors (B2B suppliers, distributors, affiliates)
    3. External public consumers and customers (B2C)
    4. Automated systems / Machine-to-Machine clients only (APIs, daemons, backend services)
- **Rich Assessment Observation**: Explicitly prompts respondents in the annotation and guidance to record the narrative business purpose, solution architecture document (SAD) references, and functional capabilities.

### 3. Framework Version Increments & Metadata
- [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml): Incremented to **`version: 35`** (`publication_date: 2026-11-09`), `expected_requirement_nodes_count: 60`.
- [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml): Incremented to **`version: 17`** (`publication_date: 2026-11-09`), `expected_requirement_nodes_count: 60`.

### 4. Application Profiles Synchronization in [`test_data/`](file:///home/python/ciso-assistant/test_data/)
Synchronized all 15 application profiles in `test_data/` with answers and observations for `application_description`:
- In-house tools (`app_appsec_custom_internal.yml`, `app_manual_custom_internal.yml`) $\rightarrow$ Internal Operations, Internal workforce.
- Public web/mobile portals (`app_appsec_custom_internet.yml`, `app_manual_custom_internet.yml`) $\rightarrow$ Digital Commerce, External customers.
- Enterprise COTS packages (`app_appsec_cots_internal.yml`, `app_manual_cots_internal.yml`) $\rightarrow$ Internal Operations, Internal workforce.
- Customer support COTS (`app_appsec_cots_internet.yml`, `app_manual_cots_internet.yml`) $\rightarrow$ Digital Commerce, External customers.
- HR SaaS applications (`app_appsec_saas_certified.yml`, `app_manual_saas_certified.yml`) $\rightarrow$ Internal Operations, Internal workforce.
- Data analytics SaaS (`app_appsec_saas_uncertified.yml`, `app_manual_saas_uncertified.yml`, `app_appsec_hybrid_saas.yml`) $\rightarrow$ Data Analytics & AI, Internal workforce / analysts.
- Payment processing SaaS API (`app_appsec_secure_api.yml`) $\rightarrow$ Integration Middleware & Core APIs, Automated M2M clients.
- Legacy monolith (`app_appsec_vulnerable_legacy.yml`) $\rightarrow$ Internal Operations, Internal workforce.

### 5. Automated Test Suite Updates
- [`tests/test_yaml_integrity.py`](file:///home/python/ciso-assistant/tests/test_yaml_integrity.py):
  - Updated `manual_fw` requirement node count assertion from 59 to 60.
  - Added `application_description` to profiling exclusions in `test_appsec_phase3_unlinked_requirements_risk_scenario_coverage`.
  - Added dedicated test `test_appsec_application_description_screen` verifying node presence, hierarchy, questions, choices, and `info` scoping across both frameworks.
- [`tests/test_implementation_groups.py`](file:///home/python/ciso-assistant/tests/test_implementation_groups.py):
  - Incremented `node_count` by +1 across all 6 test cases for both `appsec` and `appsec_manual`.
- [`docs/appsec_questions_cases.md`](file:///home/python/ciso-assistant/docs/appsec_questions_cases.md):
  - Added `application_description:q1` and `q2` to Quick Reference Matrix and Chapter 1 detailed specifications.

---

## 42. Uploaded and Activated New Frameworks on Live CISO Assistant Instance

### 1. Library Upload via CISO Assistant API
- Uploaded library definitions to `/api/stored-libraries/upload/` using `Content-Disposition: attachment; filename="..."`:
  - [`YML/appsec_objects.yml`](file:///home/python/ciso-assistant/YML/appsec_objects.yml): Uploaded Version 3 (44 risk scenarios, 1 risk matrix, 9 threats, 18 vulnerabilities, 26 reference controls).
  - [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml): Uploaded Version 35 (60 requirement nodes, including `application_description`).
  - [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml): Uploaded Version 17 (60 requirement nodes, including `application_description`).

### 2. Resolution of ORM Model Compatibility
- Discovered and resolved a schema constraint in CISO Assistant's Django `RequirementNode` model where direct `vulnerabilities` keyword arguments on requirement nodes triggered `TypeError("RequirementNode() got unexpected keyword arguments: 'vulnerabilities'")` during framework update.
- Aligned framework YAMLs to standard CISO Assistant referential integrity: vulnerabilities are strictly declared in library `objects.vulnerabilities` and linked to `objects.risk_scenarios[...].vulnerabilities`. Removed redundant node-level `vulnerabilities` attributes while preserving all 44 scenario-level vulnerability mappings and reference controls.

### 3. Activation & Live Verification
- Activated updates across all three loaded libraries via `/api/loaded-libraries/{id}/update/`:
  - `appsec_objects` (`3f48b564-a6cf-4588-8704-1482b69c5492`): Activated at **Version 3** (`has_update: False`).
  - `appsec` (`0bd6e998-2440-437c-a2df-b9fd3d2643ca`): Activated at **Version 35** (`has_update: False`).
  - `appsec_manual` (`a1146527-c24f-4bea-93ca-50761f3be76b`): Activated at **Version 17** (`has_update: False`).
- Verified live framework state via `/api/frameworks/` and `/api/requirement-nodes/`:
  - `Application Security Assessment Framework (AppSec)`: Exactly 60 requirement nodes, with `application_description` (`q1`, `q2`) active in Chapter 1.
  - `Application Security Assessment Framework (AppSec - Manual IG)`: Exactly 60 requirement nodes, with `application_description` (`q1`, `q2`) active in Chapter 1.

---

## 43. Resolution of Web UI REST API & Test Suite Flakiness

### 1. Root Cause Analysis
- **Background Task Mock Expiration**: In [`tests/test_web_ui.py`](file:///home/python/ciso-assistant/tests/test_web_ui.py), several test cases (`test_domains_endpoint`, `test_link_controls_endpoint`, `test_remove_endpoint`, `test_model_import_endpoint`) submitted asynchronous tasks to `TASK_MANAGER` and exited immediately without awaiting completion. This caused the `unittest.mock.patch` contexts to unpatch before the background worker thread executed the job, resulting in the worker invoking unmocked methods against the live CISO Assistant instance.
- **Queue Worker Contention**: Real network operations in background worker threads blocked the single queue worker thread (`max_workers=1`) for 20-30 seconds, causing subsequent tests (`test_task_manager_execution`, `test_task_manager_queue_sequential_execution`, `test_provision_app_endpoint`) to time out with `'queued' != 'completed'`.
- **API Signature & Validation Mismatches**:
  - In `api_audit_implementation_groups` ([`web/app.py`](file:///home/python/ciso-assistant/web/app.py)), `sync_existing_assignments=False` was passed unconditionally to `manager.select_audit_implementation_groups`, conflicting with callers expecting default keyword behavior.
  - In `api_audit_assign_implementation_groups` ([`web/app.py`](file:///home/python/ciso-assistant/web/app.py)), non-list `groups` inputs were coerced to a list instead of returning 400 Bad Request, and missing `"success": True` in the JSON response broke test assertions.
  - In `test_framework_implementation_groups_endpoint`, the test mocked `get_framework_implementation_groups` instead of `determine_implementation_groups_triggered_by_others` which is called by the route.

### 2. Fixes Applied
- **[`web/app.py`](file:///home/python/ciso-assistant/web/app.py)**:
  - Validated that `groups` must be a list in `api_audit_assign_implementation_groups`, returning 400 if invalid.
  - Passed `app_name` positionally and added `"success": True` to assignment API response payload.
  - Only passed `sync_existing_assignments` keyword to `select_audit_implementation_groups` when explicitly provided in request body.
- **[`tests/test_web_ui.py`](file:///home/python/ciso-assistant/tests/test_web_ui.py)**:
  - Added `TASK_MANAGER.clear_queue()` to `setUp` and `tearDown` in `TestWebUI`.
  - Awaited background task completion inside mock contexts for domain creation, control linking, application removal, and model import.
  - Properly patched `determine_implementation_groups_triggered_by_others` for framework implementation group testing.

### 3. Automated Test Suite Verification
- `python3 -m unittest tests/test_web_ui.py`: **24/24 passed in 33.28s**.
- Full test suite run (`python3 -m unittest discover tests`): **281 tests ran, 281 passed, 0 failures, 0 errors, 22 skipped in 114.36s**.

---

## 44. Multi-Question Data Classification Refinement (AppSec Framework)

### 1. Requirements & Problem Statement
- **Problem**: Previously, AppSec asked the data classification tier directly via a single question (`data_classification:q1`: *"What is the maximum classification level handled? -> Public, Internal, Confidential, Secret"*). This relied heavily on subjective respondent interpretation and often led to misclassifications or under-reporting of risk.
- **Requirement**: Replace the direct single-question prompt with multiple objective questions that narrow down the actual classification level systematically.
- **Scope**:
  - Incorporate realistic online-retail operational data categories.
  - Implement a cumulative / matrix-based derivation model combining data category, adverse disclosure impact severity, aggregation scope escalation, and GDPR personal data / volume profiling.
  - Synchronize both [`YML/appsec.yml`](file:///home/python/ciso-assistant/YML/appsec.yml) (dynamic variant, version bumped to 36) and [`YML/appsec_manual.yml`](file:///home/python/ciso-assistant/YML/appsec_manual.yml) (manual IG variant, version bumped to 18).

### 2. Multi-Question Questionnaire Structure (`data_classification`)
Requirement node `data_classification` in Chapter 1 (`info`) now comprises 4 structured questions (with the aggregation question removed for streamlined usability):
1. **`q1`: Primary Retail & Operational Data Category**:
   - `c1` — Public storefront & published brand content (Product descriptions, size guides, retail prices, delivery/return policies, public marketing collateral).
   - `c2` — Internal operations, logistics & non-sensitive enterprise workflows (Warehouse operating procedures, staff training materials, aggregated order-volume dashboards, org charts, sales figures).
   - `c3` — Confidential commercial, supplier & customer operational records (Customer PII/contact details & delivery addresses, customer order/return/refund histories, support tickets, supplier costs/margins, unreleased campaign plans, inventory forecasts).
   - `c4` — Critical financial, cryptographic secrets, cardholder data & anti-fraud rules (Customer payment-card data / PAN / CVV, refund bank accounts / IBANs, production admin credentials / API secrets / TLS keys, anti-fraud rules & evasion thresholds).
2. **`q2`: Adverse Impact Severity of Unauthorized Disclosure**:
   - `c1` — Negligible / None (Data intended for public release; zero business or regulatory harm).
   - `c2` — Minor operational friction (Internal workforce inconvenience, minor productivity delay, no external customer or financial harm).
   - `c3` — Moderate to severe harm (Damage to customer trust, competitive disadvantage, significant operational disruption, or GDPR regulatory notifications).
   - `c4` — Catastrophic or existential impact (Systemic payment fraud, loss of merchant processing agreement, severe GDPR/PCI-DSS fines, root cloud account compromise).
3. **`q3`: GDPR Personal Data Category**:
   - `c1` — No personal data processed.
   - `c2` — Contact data of employees (Workforce directories, internal emails).
   - `c3` — Contact and order details about customers (E-commerce buyers, delivery addresses, customer order histories).
   - `c4` — HR and financial details about employees and customer payment data (Payroll, banking details, cardholder data).
4. **`q4`: GDPR Data Subject Volume / Scale** (Conditional on `q3` being personal data):
   - `c1` — Low volume (< 1,000 individuals; multiplier 1.0x).
   - `c2` — Medium volume (1,000 to 100,000 individuals; multiplier 1.0x).
   - `c3` — High volume / Large-scale processing (> 100,000 individuals; multiplier 1.5x).

### 3. Cumulative / Matrix Scoring Engine
Implemented in [`classes/audits/compliance.py`](file:///home/python/ciso-assistant/classes/audits/compliance.py) via `derive_confidentiality_impact`:
1. **Base 2D Matrix ($D \times I$)**:
   $$\text{Base Score} = \text{Matrix}[D][I]$$
   - $D=0$ (Public): $[0, 0, 1, 2]$
   - $D=1$ (Internal): $[0, 1, 2, 3]$
   - $D=2$ (Confidential): $[1, 2, 2, 3]$
   - $D=3$ (Critical / Secret): $[2, 2, 3, 3]$
2. **GDPR Volume Scaling**:
   $$I_{gdpr} = \min(4, \text{round}((G + 1) \times M_{qty})) - 1 \quad \text{if } G > 0 \text{ else } 0$$
3. **Overall Confidentiality & Risk Scenario Impact**:
   $$\text{Confidentiality Score} = \max(\text{Base Score}, I_{gdpr}) \in \{0, 1, 2, 3\}$$
   $$\text{Risk Scenario Impact} = \text{Confidentiality Score} + 1 \in \{1, 2, 3, 4\}$$
   (Fully backward-compatible with legacy frameworks lacking `q2`).

### 4. Updates to Test Data Profiles
All 15 application profiles in [`test_data/`](file:///home/python/ciso-assistant/test_data/) updated to replace legacy direct classification questions with answers for `q1`, `q2`, `q3`, `q4`:
- `app_appsec_custom_internal.yml`, `app_manual_custom_internal.yml`, `app_appsec_vulnerable_legacy.yml` $\rightarrow$ Internal ($D=1, I=1 \Rightarrow 1$).
- `app_appsec_cots_internal.yml`, `app_manual_cots_internal.yml`, `app_appsec_cots_internet.yml`, `app_manual_cots_internet.yml`, `app_appsec_hybrid_saas.yml`, `app_appsec_saas_certified.yml`, `app_manual_saas_certified.yml` $\rightarrow$ Confidential ($D=2, I=2 \Rightarrow 2$).
- `app_appsec_custom_internet.yml`, `app_manual_custom_internet.yml`, `app_appsec_saas_uncertified.yml`, `app_manual_saas_uncertified.yml`, `app_appsec_secure_api.yml` $\rightarrow$ Secret ($D=3, I=3 \Rightarrow 3$).

---

## 44. Framework Version & Questionnaire Answers Backup & Restoration Solution

### 1. Context & Motivation
- Live compliance assessments in CISO Assistant (e.g. `App-Audit-Demo-ThibaultR`, `Adobe Campaign`, `Ravelin`, `PIM`, `Stripe`) contain real respondent answers, compliance results (`compliant`, `partially_compliant`, etc.), and detailed auditor observations.
- Updating a framework (e.g. updating `appsec` from version 35 to 36 via `/api/loaded-libraries/{id}/update/`) modifies requirement nodes, question schemas, and choice URNs.
- To prevent answer loss or orphaning during framework upgrades, developed an end-to-end framework version and questionnaire answers backup, restoration, and diffing solution.

### 2. Core Architecture & Capabilities
- **Pre-Update Framework & Answers Snapshot**:
  - Exports framework metadata, library version, requirement nodes catalog, and question definitions.
  - Captures all compliance assessment requirement assessments with raw answers, compliance status, results, observations, scores, and applied control links.
  - Enriches answers with human-readable question text and choice values alongside machine URNs.
  - Computes SHA-256 integrity hash and stores structured JSON under `backups/framework_snapshots/`.
- **Intelligent Semantic Question & Choice Remapping**:
  - Matches questions by exact URN when unchanged.
  - Matches re-indexed, renamed, or rephrased questions via text similarity and keyword overlap across framework versions.
  - Resolves choice URNs by choice label text when choice IDs shift between library versions.
  - Safely handles deprecated questions while preserving audit observations and results.
  - Supports dry-run simulation mode (`--dry-run`) to preview updates before making API calls.
- **Framework Diffing & Version Audit**:
  - Compares two snapshot files or compares a snapshot against live CISO Assistant state.
  - Identifies library version transitions (`v35 -> v36`), added/removed requirements, added/removed/reworded questions, and application answer drift.
- **Backup Discovery & Verification**:
  - Updates `BackupManager.list_backups()` and `inspect_backup()` to recognize framework snapshots with version metadata, audit counts, and answer statistics.

### 3. Implementation Details
- [`classes/integrations/backup.py`](file:///home/python/ciso-assistant/classes/integrations/backup.py):
  - Implemented `create_framework_snapshot()`, `restore_framework_snapshot()`, and `diff_framework_snapshots()`.
  - Updated `list_backups()` to scan `backups/` and `backups/framework_snapshots/` subdirectories.
  - Updated `inspect_backup()` to extract framework metadata, library version, notes, and assessment breakdowns.
- [`classes/examples_manager.py`](file:///home/python/ciso-assistant/classes/examples_manager.py):
  - Added convenience methods `create_framework_snapshot()`, `restore_framework_snapshot()`, and `diff_framework_snapshots()`.
- [`manage_framework_snapshots.py`](file:///home/python/ciso-assistant/manage_framework_snapshots.py):
  - Standalone CLI supporting `snapshot`, `list`, `inspect`, `restore`, and `diff` subcommands.
- [`main.py`](file:///home/python/ciso-assistant/main.py):
  - Updated Backup & Restore submenu (Option 9) with options to create framework snapshots, restore answers with dry run, and diff snapshots.
  - Added CLI flags: `--backup framework`, `--notes`, `--diff-snapshots`, `--dry-run`.
- [`web/app.py`](file:///home/python/ciso-assistant/web/app.py):
  - Added REST API endpoints: `GET /api/framework-snapshots`, `POST /api/framework-snapshots/create`, `POST /api/framework-snapshots/restore`, `POST /api/framework-snapshots/diff`.
  - Updated `/api/backups/create` and `/api/backups/restore` to handle `framework_snapshot` types.
- [`docs/framework_snapshots_guide.md`](file:///home/python/ciso-assistant/docs/framework_snapshots_guide.md):
  - Complete guide with schema overview, workflow steps, CLI cheat sheet, SDK reference, and REST API documentation.

### 4. Verification & Testing
- Live Verification: Successfully took live snapshot of `appsec` v35 (`framework_appsec_v35_20261110_150115.json`, 399 KB, 80 answers across 5 assessments) on `https://ciso-assistant.siege.red`.
- Tested snapshot inspection, live diffing (`v35 -> v35`, 0 diffs), and dry-run restoration.
- Unit Tests:
  - [`tests/test_backup.py`](file:///home/python/ciso-assistant/tests/test_backup.py): 21 tests covering snapshot creation, exact match restoration, cross-version semantic remapping, dry run, error handling, diffing, and manager delegates.
  - [`tests/test_web_ui.py`](file:///home/python/ciso-assistant/tests/test_web_ui.py): Added tests for `/api/framework-snapshots` listing, creation, and diffing.
  - Full test suite: **293 tests passing in 118s (0 failures, 0 errors, OK)**.



















