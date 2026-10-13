# Application Security Assessment (appsec.yml) — Questions & Applicability Cases
> **Purpose**: This file catalogs all 82 questions defined in `YML/appsec.yml`.
> You can use this document to specify which requirements and questions apply to which situations/cases.
> Below is both a **Quick Reference Table** and a **Detailed Breakdown** by Chapter and Requirement Node.

## Table of Contents
- [1. Situations & Cases Definitions](#1-situations--cases-definitions)
- [2. Quick Reference Matrix (All 82 Questions)](#2-quick-reference-matrix)
- [3. Detailed Questions by Chapter](#3-detailed-questions-by-chapter)
  - [Application Information & Governance](#info)
  - [Identity, Authentication & Access Control](#iam_chapter)
  - [Application Vulnerability Defense & Code Hygiene](#app_defenses_chapter)
  - [Cryptography & Secrets Management](#crypto_chapter)
  - [Secure SDLC & DevSecOps Automation](#sdlc_chapter)
  - [API Security & Edge Protections](#api_chapter)
  - [Data Protection & Lifecycle Governance](#data_lifecycle_chapter)
  - [Security Logging & Monitoring](#logging_chapter)
  - [Penetration Testing & Resilience](#resilience_chapter)
  - [SaaS Requirements & Vendor Security Exhibit](#saas_chapter)

---

## 1. Situations & Cases Definitions

Define or customize your operational situations/cases here for reference:

| Case ID | Situation / Case Name | Scope Description | Example Applications |
| :--- | :--- | :--- | :--- |
| **Case 1** | *In-House Custom Software* | Internally developed software, full source code and CI/CD control | Core internal business apps, proprietary APIs |
| **Case 2** | *COTS Software (Self-Hosted)* | Commercial off-the-shelf software deployed on internal infrastructure | Vendor ERP, packaged tooling, on-prem solutions |
| **Case 3** | *SaaS (Vendor-Hosted)* | Third-party cloud hosted, multi-tenant software | Salesforce, Workday, Slack, Jira Cloud |
| **Case 4** | *Internet-Facing Applications* | Exposed directly to public internet without VPN | Customer portals, public APIs, e-commerce |
| **Case 5** | *Internal-Only Applications* | Restricted strictly to internal private network / VPN | Internal admin portals, intranet, batch processors |
| **Case 6** | *High Sensitivity (Confidential / Secret)* | Processes PII, financial data, credentials, or trade secrets | Payment processing, HR systems, core DBs |
| **Case 7** | *Custom Case (Specify)* | *Describe situation...* | *...* |

---

## 2. Quick Reference Matrix

| # | Chapter | Requirement Node | Q ID | Question Summary | Current IGs | Applicable Cases / Situations |
| :-: | :--- | :--- | :-: | :--- | :--- | :--- |
| 1 | Application Information & Governance | `stakeholder_identification` | `q1` | Is there a designated business contact? (Designated business owner or product spon... | `info` | All applications (Info profiling) |
| 2 | Application Information & Governance | `stakeholder_identification` | `q2` | Is there a designated IT contact? (Technical lead or engineer responsible for main... | `info` | All applications (Info profiling) |
| 3 | Application Information & Governance | `stakeholder_identification` | `q3` | Is there a designated data owner? (Data steward or governance officer responsible ... | `info` | All applications (Info profiling) |
| 4 | Application Information & Governance | `stakeholder_identification` | `q4` | Is the information about stakeholders updated in LeanIX / CMDB? (Stakeholder assig... | `info` | All applications (Info profiling) |
| 5 | Application Information & Governance | `data_classification` | `q1` | What is the maximum classification level handled? (Public, Internal, Confidential,... | `info` | All applications (Info profiling - Confidentiality) |
| 6 | Application Information & Governance | `hosting` | `q1` | What is the delivery and hosting model of the application? | `info` | All applications (Info profiling - Hosting model) |
| 7 | Application Information & Governance | `network_exposure` | `q1` | What is the network exposure of the application? | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 8 | Identity, Authentication & Access Control | `authentication_and_mfa` | `q1` | How do users authenticate to the application? | `baseline, custom_app, cots_app, saas_app` | **All applications** (Custom, COTS, SaaS) - Mandatory SSO |
| 9 | Identity, Authentication & Access Control | `authentication_and_mfa` | `q2` | If direct authentication is used, are strong password policies and brute-force loc... | `baseline, custom_app, cots_app, saas_app` | All applications (If direct auth used - Password policy) |
| 10 | Identity, Authentication & Access Control | `authentication_and_mfa` | `q3` | If direct authentication is used, is Multi-Factor Authentication (MFA) enforced fo... | `baseline, custom_app, cots_app, saas_app` | All applications (If direct auth used - Admin MFA) |
| 11 | Identity, Authentication & Access Control | `access_control_and_rbac` | `q1` | Have you defined roles and permissions for the application? (Is access controlled ... | `baseline, custom_app, cots_app, saas_app` | **All applications** (Baseline - RBAC least privilege) |
| 12 | Identity, Authentication & Access Control | `access_control_and_rbac` | `q2` | Is the application integrated with the enterprise Identity Governance and Administ... | `baseline, custom_app, cots_app, saas_app` | **All applications** (Baseline - SailPoint IGA integration) |
| 13 | Identity, Authentication & Access Control | `access_control_and_rbac` | `q3` | Are user entitlements and privileged permissions reviewed and recertified on a per... | `baseline, custom_app, cots_app, saas_app` | **All applications** (Baseline - Periodic recertifications) |
| 14 | Identity, Authentication & Access Control | `session_management` | `q1` | Are session tokens cryptographically secure, transmitted with secure cookie flags ... | `custom_app` |  |
| 15 | Application Vulnerability Defense & Code Hygiene | `input_validation_and_injection_defense` | `q1` | Are all user-supplied inputs validated on the server side using strict allow-lists... | `custom_app` |  |
| 16 | Application Vulnerability Defense & Code Hygiene | `input_validation_and_injection_defense` | `q2` | Are database interactions executed via parameterized queries, prepared statements,... | `custom_app` |  |
| 17 | Application Vulnerability Defense & Code Hygiene | `output_encoding_and_web_defenses` | `q1` | Is context-aware output encoding enforced across all dynamic responses to prevent ... | `custom_app` |  |
| 18 | Application Vulnerability Defense & Code Hygiene | `output_encoding_and_web_defenses` | `q2` | Are standard HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Opt... | `custom_app` |  |
| 19 | Application Vulnerability Defense & Code Hygiene | `error_handling_and_info_leakage` | `q1` | Are debug modes and detailed stack traces disabled in production environments with... | `custom_app` |  |
| 20 | Application Vulnerability Defense & Code Hygiene | `ssrf_and_cloud_metadata_defense` | `q1` | Are outbound HTTP requests initiated by the application strictly validated using d... | `custom_app` |  |
| 21 | Application Vulnerability Defense & Code Hygiene | `ssrf_and_cloud_metadata_defense` | `q2` | Are cloud instance metadata protections enforced (e.g. IMDSv2 token-backed metadat... | `custom_app` |  |
| 22 | Application Vulnerability Defense & Code Hygiene | `file_upload_security` | `q1` | Are uploaded files validated via server-side magic byte inspection, assigned rando... | `custom_app` |  |
| 23 | Application Vulnerability Defense & Code Hygiene | `file_upload_security` | `q2` | Are uploaded files scanned for malware and stored exclusively in dedicated, non-ex... | `custom_app` |  |
| 24 | Cryptography & Secrets Management | `secrets_management` | `q1` | Are application credentials, API keys, and cryptographic secrets stored exclusivel... | `baseline, custom_app, cots_app` |  |
| 25 | Cryptography & Secrets Management | `data_in_transit` | `q1` | Is data encrypted during transit? (Specify protocols, algorithms and methods: e.g.... | `baseline, custom_app, cots_app` |  |
| 26 | Cryptography & Secrets Management | `data_at_rest` | `q1` | Is data encrypted at rest? (Specify algorithms and key management: e.g., AES-256 /... | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 27 | Secure SDLC & DevSecOps Automation | `automated_security_testing` | `q1` | Is automated Static Application Security Testing (SAST) integrated into the CI/CD ... | `custom_app` |  |
| 28 | Secure SDLC & DevSecOps Automation | `automated_security_testing` | `q2` | Is Dynamic Application Security Testing (DAST) or API security scanning performed ... | `custom_app` |  |
| 29 | Secure SDLC & DevSecOps Automation | `supply_chain_and_dependencies` | `q1` | Is Software Composition Analysis (SCA) automated in the CI/CD pipeline to detect k... | `custom_app` |  |
| 30 | Secure SDLC & DevSecOps Automation | `supply_chain_and_dependencies` | `q2` | Is an accurate Software Bill of Materials (SBOM) maintained and audited for all re... | `custom_app` |  |
| 31 | Secure SDLC & DevSecOps Automation | `code_review_and_ci_cd_integrity` | `q1` | Are mandatory peer code reviews and branch protection rules enforced before any me... | `custom_app` |  |
| 32 | Secure SDLC & DevSecOps Automation | `vendor_secure_development` | `q1` | Does the third-party COTS software vendor adhere to recognized secure coding stand... | `cots_app` | **COTS Only** (Vendor secure coding guidelines) |
| 33 | API Security & Edge Protections | `api_security_and_rate_limiting` | `q1` | Are exposed web and API endpoints protected against abusive traffic via an edge We... | `internet_facing` | **Self-Hosted Internet-Facing only** (Edge WAF & DDoS) |
| 34 | API Security & Edge Protections | `api_security_and_rate_limiting` | `q2` | Are API payloads strictly validated against documented API specifications (e.g. Op... | `internet_facing` | **Self-Hosted Internet-Facing only** (API schema validation) |
| 35 | Data Protection & Lifecycle Governance | `data_exchange` | `q1` | Are there data exchanges beyond the group? (e.g., transfers, automated API integra... | `baseline, custom_app, cots_app` |  |
| 36 | Data Protection & Lifecycle Governance | `data_exchange` | `q2` | Is there a data exchange contract with the appropriate confidentiality clauses? (e... | `baseline, custom_app, cots_app` |  |
| 37 | Data Protection & Lifecycle Governance | `non_prod_data` | `q1` | Are real production data records, live customer databases, or personal data utiliz... | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 38 | Data Protection & Lifecycle Governance | `non_prod_data` | `q2` | How do you protect them? (Which sanitization or protection method is applied: cryp... | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS - if non-prod data used) |
| 39 | Data Protection & Lifecycle Governance | `non_prod_data` | `q3` | Do you clean the prod data after use in non-prod? (e.g., securely purging, sanitiz... | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS - if non-prod data used) |
| 40 | Data Protection & Lifecycle Governance | `data_destruction` | `q1` | Is there a data destruction process for this application? (e.g., documented data r... | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 41 | Data Protection & Lifecycle Governance | `data_destruction` | `q2` | Is the process compliant with the policy (responsibilities, methods, reporting)? (... | `baseline, custom_app, cots_app` | Self-Hosted only (Custom & COTS - if destruction process exists) |
| 42 | Security Logging & Monitoring | `security_event_logging` | `q1` | Does the application log key security events (failed logins, privilege escalation,... | `baseline, custom_app, cots_app` |  |
| 43 | Security Logging & Monitoring | `security_event_logging` | `q2` | Are sensitive data fields (passwords, payment cards, tokens, PII) systematically s... | `baseline, custom_app, cots_app` |  |
| 44 | Security Logging & Monitoring | `centralized_monitoring_and_alerting` | `q1` | Are application logs forwarded in near-real-time to a central SIEM/SOC platform wi... | `baseline, custom_app, cots_app` |  |
| 45 | Penetration Testing & Resilience | `penetration_testing_and_vulnerability_management` | `q1` | Is independent penetration testing conducted on the application and underlying inf... | `internet_facing` | **Self-Hosted Internet-Facing only** (Annual pentesting) |
| 46 | Penetration Testing & Resilience | `penetration_testing_and_vulnerability_management` | `q2` | Are identified vulnerabilities remediated within defined SLAs (e.g. Critical withi... | `internet_facing` | **Self-Hosted Internet-Facing only** (Remediation SLAs) |
| 47 | Penetration Testing & Resilience | `backup_and_disaster_recovery` | `q1` | Are automated and encrypted backups maintained for application state and databases... | `baseline, custom_app, cots_app` |  |
| 48 | Penetration Testing & Resilience | `cots_deployment_hardening` | `q1` | Are default vendor credentials changed, sample modules removed, and configuration ... | `cots_app` |  |
| 49 | Penetration Testing & Resilience | `cots_deployment_hardening` | `q2` | Does the COTS software actively receive security patches and vulnerability updates... | `cots_app` |  |
| 50 | Penetration Testing & Resilience | `cots_deployment_hardening` | `q3` | Are published vendor security patches, hotfixes, and critical vulnerability update... | `cots_app` |  |
| 51 | SaaS Requirements & Vendor Security Exhibit | `saas_contract_compliance` | `q1` | Is there a signed SaaS contract and binding Security Schedule? (e.g., legally exec... | `saas_app` |  |
| 52 | SaaS Requirements & Vendor Security Exhibit | `saas_governance_and_policy` | `q1` | Does the contract require and does the provider maintain an Information Security P... | `saas_app` |  |
| 53 | SaaS Requirements & Vendor Security Exhibit | `saas_governance_and_policy` | `q2` | Does the contract require and does the provider maintain an active Information Sec... | `saas_app` |  |
| 54 | SaaS Requirements & Vendor Security Exhibit | `saas_confidentiality_and_data_protection` | `q1` | Does the contract enforce strict vendor personnel access governance (e.g. Customer... | `saas_app` |  |
| 55 | SaaS Requirements & Vendor Security Exhibit | `saas_confidentiality_and_data_protection` | `q2` | Does the contract require and are cryptographic keys and certificates governed by ... | `saas_app` |  |
| 56 | SaaS Requirements & Vendor Security Exhibit | `saas_security_awareness` | `q1` | Does the contract require and are vendor personnel trained and sensitized to cyber... | `saas_app` |  |
| 57 | SaaS Requirements & Vendor Security Exhibit | `saas_security_awareness` | `q2` | Does the contract require and are formal security incident reporting procedures di... | `saas_app` |  |
| 58 | SaaS Requirements & Vendor Security Exhibit | `saas_iam` | `q1` | Does root, administrative, and break-glass access to the SaaS tenant management co... | `saas_app` | **SaaS only** (Admin console mandatory MFA) |
| 59 | SaaS Requirements & Vendor Security Exhibit | `saas_entitlements_and_privileges` | `q1` | Does the contract require and does the provider apply least privilege and Role-Bas... | `saas_app` | **SaaS only** (Provider staff least privilege & RBAC) |
| 60 | SaaS Requirements & Vendor Security Exhibit | `saas_entitlements_and_privileges` | `q2` | Does the contract mandate and does the provider conduct periodic access reviews an... | `saas_app` | **SaaS only** (Provider staff periodic access reviews) |
| 61 | SaaS Requirements & Vendor Security Exhibit | `saas_logging_and_incidents` | `q1` | Does the contract require and does the SaaS solution record tamper-resistant logs ... | `saas_app` |  |
| 62 | SaaS Requirements & Vendor Security Exhibit | `saas_logging_and_incidents` | `q2` | Does the contract legally bind the provider to notify the client of any security i... | `saas_app` |  |
| 63 | SaaS Requirements & Vendor Security Exhibit | `saas_workstation_security` | `q1` | Does the contract require and are provider workstations protected by session auto-... | `saas_app` |  |
| 64 | SaaS Requirements & Vendor Security Exhibit | `saas_workstation_security` | `q2` | Does the contract require and are all workstations and removable media fully encry... | `saas_app` |  |
| 65 | SaaS Requirements & Vendor Security Exhibit | `saas_mobile_security` | `q1` | Does the contract require and are mobile devices accessing the service governed by... | `saas_app` |  |
| 66 | SaaS Requirements & Vendor Security Exhibit | `saas_network_security` | `q1` | Does the contract mandate and does the provider enforce a formal network security ... | `saas_app` |  |
| 67 | SaaS Requirements & Vendor Security Exhibit | `saas_environment_isolation` | `q1` | Does the contract require and does the SaaS architecture enforce robust logical or... | `saas_app` |  |
| 68 | SaaS Requirements & Vendor Security Exhibit | `saas_environment_isolation` | `q2` | Does the SaaS architecture support tenant-specific cryptographic sovereignty, such... | `saas_app` |  |
| 69 | SaaS Requirements & Vendor Security Exhibit | `saas_secure_development` | `q1` | Does the contract require and is source code stored in secure repositories with ma... | `saas_app` |  |
| 70 | SaaS Requirements & Vendor Security Exhibit | `saas_secure_development` | `q2` | Does the contract mandate that the provider adheres to formal secure SDLC standard... | `saas_app` |  |
| 71 | SaaS Requirements & Vendor Security Exhibit | `saas_web_app_security` | `q1` | Does the contract require and are web services protected with TLS 1.2+ minimum, ne... | `saas_app` |  |
| 72 | SaaS Requirements & Vendor Security Exhibit | `saas_penetration_testing_and_vulnerability_management` | `q1` | How is independent penetration testing governed and performed on the SaaS platform? | `saas_app` |  |
| 73 | SaaS Requirements & Vendor Security Exhibit | `saas_penetration_testing_and_vulnerability_management` | `q2` | Does the SaaS contract commit the provider to formal vulnerability remediation SLA... | `saas_app` |  |
| 74 | SaaS Requirements & Vendor Security Exhibit | `saas_data_hosting_and_residency` | `q1` | Does the contract mandate and is all customer data (including primary databases, p... | `saas_app` |  |
| 75 | SaaS Requirements & Vendor Security Exhibit | `saas_physical_security` | `q1` | Does the contract require and are provider facilities and datacenters secured with... | `saas_app` |  |
| 76 | SaaS Requirements & Vendor Security Exhibit | `saas_backup_and_business_continuity` | `q1` | Does the contract require and are automated backups encrypted, immutable, and veri... | `saas_app` |  |
| 77 | SaaS Requirements & Vendor Security Exhibit | `saas_backup_and_business_continuity` | `q2` | Does the contract mandate and does the provider maintain documented BCP/DRP plans ... | `saas_app` |  |
| 78 | SaaS Requirements & Vendor Security Exhibit | `saas_subcontractor_management` | `q1` | Does the contract mandate and does the vendor maintain a formal subcontractor vett... | `saas_app` |  |
| 79 | SaaS Requirements & Vendor Security Exhibit | `saas_audit_and_compliance` | `q1` | Does the contract legally grant the client (or an authorized third party) the righ... | `saas_app` |  |
| 80 | SaaS Requirements & Vendor Security Exhibit | `saas_pci_dss` | `q1` | Does the application process, store, or transmit payment card data? | `saas_app` |  |
| 81 | SaaS Requirements & Vendor Security Exhibit | `saas_pci_dss` | `q2` | If payment card data is processed, does the contract require and does the provider... | `saas_app` |  |
| 82 | SaaS Requirements & Vendor Security Exhibit | `saas_non_conformity_remediation` | `q1` | Does the contract mandate formal remediation plans and compensatory measures for i... | `saas_app` |  |

---

## 3. Detailed Questions by Chapter


<a id="info"></a>
### Application Information & Governance (`info`)

*Basic application profiling, ownership, hosting, exposure, and architecture context.*

#### Node: Stakeholder identification (`stakeholder_identification`)
Action - None
- **Implementation Groups**: `info`, `baseline`
- **Description**: Stakeholders have been identified for the application

##### Q1. `stakeholder_identification:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1`
- **Question**: Is there a designated business contact? (Designated business owner or product sponsor accountable for business processes, functionality, and risk acceptance)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (25 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling)

##### Q2. `stakeholder_identification:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:stakeholder_identification:q2`
- **Question**: Is there a designated IT contact? (Technical lead or engineer responsible for maintenance, infrastructure, deployment, and operational support)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (25 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling)

##### Q3. `stakeholder_identification:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:stakeholder_identification:q3`
- **Question**: Is there a designated data owner? (Data steward or governance officer responsible for information classification, access authorization, and regulatory compliance)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (25 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling)

##### Q4. `stakeholder_identification:q4`
- **URN**: `urn:intuitem:risk:req_node:appsec:stakeholder_identification:q4`
- **Question**: Is the information about stakeholders updated in LeanIX / CMDB? (Stakeholder assignments registered and kept current in the enterprise inventory or service catalog)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (25 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling)

#### Node: Data classification (`data_classification`)
Action - None
- **Implementation Groups**: `info`, `baseline`
- **Description**: Classify data handled by the application according to organizational policy.

##### Q5. `data_classification:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_classification:q1`
- **Question**: What is the maximum classification level handled? (Public, Internal, Confidential, or Secret according to organizational data classification policy)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Public`
  - `Internal`
  - `Confidential`
  - `Secret`
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling - Confidentiality)

#### Node: Application Delivery & Hosting Model (`hosting`)
Action - None
- **Implementation Groups**: `info`, `baseline`
- **Description**: Determine the application delivery and hosting model: Custom software created and deployed by internal teams, Bought software deployed by internal teams, or third-party SaaS.

##### Q6. `hosting:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:hosting:q1`
- **Question**: What is the delivery and hosting model of the application?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Custom software created and deployed by my teams (In-house development)`
  - `Bought software deployed by my teams (COTS / Vendor package)`
  - `SaaS (Third-party software hosted and operated by a vendor)`
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling - Hosting model)

#### Node: Application Network Exposure (`network_exposure`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Determine whether self-hosted applications (Custom or COTS) are accessible from the public Internet or restricted to private internal networks. (Third-party SaaS applications are unconditionally assumed to be externally exposed and bypass this requirement).

##### Q7. `network_exposure:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:network_exposure:q1`
- **Question**: What is the network exposure of the application?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Internal / Restricted Network only` (100 pts, compute_result: true)
  - `Internet-facing (Public Web / Mobile API)` (100 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS)


<a id="iam_chapter"></a>
### Identity, Authentication & Access Control (`iam_chapter`)

*Enforce strong authentication, Multi-Factor Authentication (MFA), federated SSO, and granular authorization controls.*

#### Node: Centralized Identity, Authentication & MFA (`authentication_and_mfa`)
Action - All apps must use SSO so ask for all apps
- **Implementation Groups**: `baseline`, `custom_app`, `cots_app`, `saas_app`
- **Description**: Enforce centralized enterprise Identity Provider (SSO), strong credential hygiene, and Multi-Factor Authentication (MFA) for administrative and privileged access.

##### Q8. `authentication_and_mfa:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1`
- **Question**: How do users authenticate to the application?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Enterprise SSO (SAML 2.0 / OIDC federated IdP)` (100 pts, compute_result: true)
  - `Direct / Local application authentication (Username & Password)` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **All applications** (Custom, COTS, SaaS) - Mandatory SSO

##### Q9. `authentication_and_mfa:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q2`
- **Question**: If direct authentication is used, are strong password policies and brute-force lockout protections implemented?
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (If direct auth used - Password policy)

##### Q10. `authentication_and_mfa:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q3`
- **Question**: If direct authentication is used, is Multi-Factor Authentication (MFA) enforced for all administrative and privileged access?
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (If direct auth used - Admin MFA)

#### Node: Authorization, RBAC, IGA & Access Recertifications (`access_control_and_rbac`)
Action - All apps must use RBAC and IGA for my employees, ask for all apps (Put in baseline for all apps)
- **Implementation Groups**: `baseline`, `custom_app`, `cots_app`, `saas_app`
- **Description**: Enforce least privilege via granular RBAC/ABAC, integrate with enterprise Identity Governance & Administration (SailPoint), and perform periodic access recertifications.

##### Q11. `access_control_and_rbac:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q1`
- **Question**: Have you defined roles and permissions for the application? (Is access controlled via granular roles (RBAC/ABAC) enforcing least privilege across all business functions and APIs?)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **All applications** (Baseline - RBAC least privilege)

##### Q12. `access_control_and_rbac:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q2`
- **Question**: Is the application integrated with the enterprise Identity Governance and Administration (IGA) solution (such as SailPoint) for centralized user lifecycle, role management, and automated provisioning/deprovisioning?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (25 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **All applications** (Baseline - SailPoint IGA integration)

##### Q13. `access_control_and_rbac:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:access_control_and_rbac:q3`
- **Question**: Are user entitlements and privileged permissions reviewed and recertified on a periodic basis via formal recertification campaigns (e.g., SailPoint certification campaigns at least annually for standard users, biannually for privileged accounts)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (25 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **All applications** (Baseline - Periodic recertifications)

#### Node: Secure Session Management (`session_management`)
- **Implementation Groups**: `custom_app`
- **Description**: Enforce cryptographically secure session generation, idle timeouts, secure cookie flags (HttpOnly, Secure, SameSite), and server-side token invalidation on logout.

##### Q14. `session_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:session_management:q1`
- **Question**: Are session tokens cryptographically secure, transmitted with secure cookie flags (HttpOnly, Secure, SameSite), and invalidated on logout or inactivity?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="app_defenses_chapter"></a>
### Application Vulnerability Defense & Code Hygiene (`app_defenses_chapter`)

*Protect custom applications against OWASP Top 10 injection flaws, cross-site scripting, SSRF, insecure file uploads, and information disclosure through secure programming and input/output handling.*

#### Node: Input Validation & Injection Prevention (`input_validation_and_injection_defense`)
- **Implementation Groups**: `custom_app`
- **Description**: Enforce strict server-side input schema validation and parameterized queries (or ORMs) to eliminate SQL, NoSQL, and command injection flaws.

##### Q15. `input_validation_and_injection_defense:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:input_validation_and_injection_defense:q1`
- **Question**: Are all user-supplied inputs validated on the server side using strict allow-lists and schema rules?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q16. `input_validation_and_injection_defense:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:input_validation_and_injection_defense:q2`
- **Question**: Are database interactions executed via parameterized queries, prepared statements, or ORMs to prevent SQL and NoSQL injections?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Output Encoding & Web Security Headers (`output_encoding_and_web_defenses`)
- **Implementation Groups**: `custom_app`
- **Description**: Enforce context-aware output encoding across dynamic templates and configure modern HTTP security headers to prevent Cross-Site Scripting (XSS).

##### Q17. `output_encoding_and_web_defenses:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:output_encoding_and_web_defenses:q1`
- **Question**: Is context-aware output encoding enforced across all dynamic responses to prevent Cross-Site Scripting (XSS)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q18. `output_encoding_and_web_defenses:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:output_encoding_and_web_defenses:q2`
- **Question**: Are standard HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) configured in application middleware or response handlers?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Error Handling & Debug Protection (`error_handling_and_info_leakage`)
- **Implementation Groups**: `custom_app`
- **Description**: Disable debug modes, detailed stack traces, and internal server paths in production responses via generic error handlers.

##### Q19. `error_handling_and_info_leakage:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:error_handling_and_info_leakage:q1`
- **Question**: Are debug modes and detailed stack traces disabled in production environments with generic error handlers configured?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: SSRF & Cloud Metadata Defense (`ssrf_and_cloud_metadata_defense`)
- **Implementation Groups**: `custom_app`
- **Description**: Prevent Server-Side Request Forgery (SSRF) by validating outbound HTTP requests and enforcing cloud instance metadata protections (IMDSv2).

##### Q20. `ssrf_and_cloud_metadata_defense:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:ssrf_and_cloud_metadata_defense:q1`
- **Question**: Are outbound HTTP requests initiated by the application strictly validated using destination allow-lists with connections to RFC 1918 private subnets and localhost blocked?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q21. `ssrf_and_cloud_metadata_defense:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:ssrf_and_cloud_metadata_defense:q2`
- **Question**: Are cloud instance metadata protections enforced (e.g. IMDSv2 token-backed metadata with hop-limit=1 on AWS, or Azure/GCP metadata header requirements) to prevent credential theft via SSRF?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: File Upload Security & Malware Hygiene (`file_upload_security`)
- **Implementation Groups**: `custom_app`
- **Description**: Enforce strict file upload validation (magic bytes, path isolation, randomized filenames) and segregated storage with automated malware scanning.

##### Q22. `file_upload_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:file_upload_security:q1`
- **Question**: Are uploaded files validated via server-side magic byte inspection, assigned randomized filenames (UUIDs), and stripped of path traversal characters?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q23. `file_upload_security:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:file_upload_security:q2`
- **Question**: Are uploaded files scanned for malware and stored exclusively in dedicated, non-executable private object storage (e.g. private S3 with presigned URLs)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="crypto_chapter"></a>
### Cryptography & Secrets Management (`crypto_chapter`)

*Enforce cryptographic protection for data in transit and at rest, and maintain centralized secrets management.*

#### Node: Centralized Secrets Management (`secrets_management`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Eliminate hardcoded credentials and store all API keys, database tokens, and certificates in dedicated secrets vaults.

##### Q24. `secrets_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:secrets_management:q1`
- **Question**: Are application credentials, API keys, and cryptographic secrets stored exclusively in a dedicated secrets manager rather than in code or configuration files?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Encryption in Transit (`data_in_transit`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Encrypt data in transit across internal and external network boundaries.

##### Q25. `data_in_transit:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_in_transit:q1`
- **Question**: Is data encrypted during transit? (Specify protocols, algorithms and methods: e.g., TLS 1.2 / TLS 1.3 with AES-GCM or ChaCha20, HTTPS with HSTS, mTLS for service APIs, SSHv2, or IPsec across external and internal boundaries)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Encryption at Rest (`data_at_rest`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Encrypt data at rest in databases, file systems, and backups.

##### Q26. `data_at_rest:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_at_rest:q1`
- **Question**: Is data encrypted at rest? (Specify algorithms and key management: e.g., AES-256 / AES-GCM across databases, object storage, file systems, disk volumes, and backups with centralized KMS, HSM, or TDE)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="sdlc_chapter"></a>
### Secure SDLC & DevSecOps Automation (`sdlc_chapter`)

*Integrate security automation into CI/CD pipelines, track dependencies and SBOMs, and verify vendor secure coding practices.*

#### Node: Automated Security Testing (SAST & DAST) (`automated_security_testing`)
- **Implementation Groups**: `custom_app`
- **Description**: Integrate automated Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) into CI/CD build pipelines.

##### Q27. `automated_security_testing:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:automated_security_testing:q1`
- **Question**: Is automated Static Application Security Testing (SAST) integrated into the CI/CD pipeline with blocking quality gates?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q28. `automated_security_testing:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:automated_security_testing:q2`
- **Question**: Is Dynamic Application Security Testing (DAST) or API security scanning performed automatically prior to release?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Software Supply Chain & Component Inventory (SCA & SBOM) (`supply_chain_and_dependencies`)
- **Implementation Groups**: `custom_app`
- **Description**: Continuously scan open-source dependencies (SCA) and maintain an auditable Software Bill of Materials (SBOM).

##### Q29. `supply_chain_and_dependencies:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:supply_chain_and_dependencies:q1`
- **Question**: Is Software Composition Analysis (SCA) automated in the CI/CD pipeline to detect known vulnerabilities in open-source dependencies?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q30. `supply_chain_and_dependencies:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:supply_chain_and_dependencies:q2`
- **Question**: Is an accurate Software Bill of Materials (SBOM) maintained and audited for all released application artifacts?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Peer Code Review & Branch Protection (`code_review_and_ci_cd_integrity`)
- **Implementation Groups**: `custom_app`
- **Description**: Enforce mandatory peer code reviews and protected branch policies before merging into deployment branches.

##### Q31. `code_review_and_ci_cd_integrity:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:code_review_and_ci_cd_integrity:q1`
- **Question**: Are mandatory peer code reviews and branch protection rules enforced before any merge into deployment branches?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Vendor Secure Development & Coding Guidelines (`vendor_secure_development`)
Action - For COTS, ask if vendor follows secure coding guidelines without going into specifics (SaaS is governed under Chapter 10)
- **Implementation Groups**: `cots_app`
- **Description**: Verify that third-party COTS software vendors adhere to recognized secure coding standards and development guidelines.

##### Q32. `vendor_secure_development:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:vendor_secure_development:q1`
- **Question**: Does the third-party COTS software vendor adhere to recognized secure coding standards and software development security guidelines (e.g., OWASP, ISO/IEC 27034, NIST SSDF)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **COTS Only** (Vendor secure coding guidelines)


<a id="api_chapter"></a>
### API Security & Edge Protections (`api_chapter`)

*Protect application interfaces and APIs against abuse, volumetric attacks, and automated bots for self-hosted internet-facing applications.*

#### Node: API Gateway, Edge WAF, Rate Limiting & Bot Protection (`api_security_and_rate_limiting`)
- **Implementation Groups**: `internet_facing`
- **Description**: Protect exposed web and API endpoints against abusive traffic, automated bots, and volumetric attacks via an edge Web Application Firewall (WAF, e.g., Cloudflare), rate limiting, and schema validation. (Applicable to self-hosted applications exposed to the public Internet; SaaS edge WAF and DDoS defenses are evaluated under Chapter 10 Section 9).

##### Q33. `api_security_and_rate_limiting:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting:q1`
- **Question**: Are exposed web and API endpoints protected against abusive traffic via an edge Web Application Firewall (WAF, e.g., Cloudflare, AWS WAF), bot protection, and automated rate limiting / throttling controls?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Edge WAF, bot protection & rate limiting)

##### Q34. `api_security_and_rate_limiting:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting:q2`
- **Question**: Are API payloads strictly validated against documented API specifications (e.g. OpenAPI / JSON schema)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (OpenAPI / Schema validation) 


<a id="data_lifecycle_chapter"></a>
### Data Protection & Lifecycle Governance (`data_lifecycle_chapter`)

*Govern cross-organizational data transfers (DPAs), enforce non-production data protection, and mandate compliant data retention and destruction.*

#### Node: Control of Data Exchange (`data_exchange`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Govern external data exchanges, API integrations, webhooks, and third-party data flows via formal agreements (DPA/DTA) and secure transmission for self-hosted applications.

##### Q35. `data_exchange:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_exchange:q1`
- **Question**: Are there data exchanges beyond the group? (e.g., transfers, automated API integrations, or webhooks with external partners, third-party vendors, or public services)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No` (100 pts, compute_result: true)
  - `Yes` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q36. `data_exchange:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_exchange:q2`
- **Question**: Is there a data exchange contract with the appropriate confidentiality clauses? (e.g., formal Data Processing Agreement / DPA, Data Transfer Agreement / DTA, or NDA)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:data_exchange:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:data_exchange:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `No contract` (0 pts)
  - `Contract! (Formal Data Transfer Agreement / DPA in place)` (100 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Non-Production Data Protection (`non_prod_data`)
Action - Ask if non prod environments (if used) are secure identically as prod. If yes, subsequent questions do not really matter 
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Enforce strict governance over the use of production customer data in non-production environments (development, staging, QA) and mandate data sanitization and post-test purging for self-hosted applications.

##### Q37. `non_prod_data:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:non_prod_data:q1`
- **Question**: Are real production data records, live customer databases, or personal data utilized in non-production environments? (e.g., development/staging environments or QA databases)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No - Synthetic, generated, or mock test data is used exclusively` (100 pts, compute_result: true)
  - `Yes - Production data is copied or utilized for testing/staging` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q38. `non_prod_data:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:non_prod_data:q2`
- **Question**: How do you protect them? (Which sanitization or protection method is applied: cryptographic hashing, pseudonymisation/anonymization, or field-level encryption prior to ingestion)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:non_prod_data:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:non_prod_data:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `No, no protection` (0 pts)
  - `Hashing` (90 pts, compute_result: true)
  - `Pseudonymisation` (90 pts, compute_result: true)
  - `Encryption` (90 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q39. `non_prod_data:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:non_prod_data:q3`
- **Question**: Do you clean the prod data after use in non-prod? (e.g., securely purging, sanitizing, or deleting production data once testing or troubleshooting activities conclude in non-production environments)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:non_prod_data:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:non_prod_data:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `No` (0 pts)
  - `Yes` (10 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Compliant Data Destruction (`data_destruction`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Enforce compliant data retention schedules, end-of-life purging, and certified cryptographic erasure for self-hosted applications.

##### Q40. `data_destruction:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_destruction:q1`
- **Question**: Is there a data destruction process for this application? (e.g., documented data retention schedule and end-of-life purging procedures for self-hosted systems)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No` (0 pts)
  - `Yes` (50 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q41. `data_destruction:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_destruction:q2`
- **Question**: Is the process compliant with the policy (responsibilities, methods, reporting)? (e.g., defined stakeholder roles, approved cryptographic erasure or disposal methods, and verification certificates)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:data_destruction:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:data_destruction:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `No, not compliant` (0 pts)
  - `Yes, compliant! (Compliant data destruction schedule and procedures operational)` (50 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="logging_chapter"></a>
### Security Logging & Monitoring (`logging_chapter`)

*Log security-relevant events, mask sensitive fields, and forward telemetry to a central SIEM.*

#### Node: Security Event Logging & Data Masking (`security_event_logging`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Log authentication, authorization, and administrative events while systematically masking sensitive fields.

##### Q42. `security_event_logging:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:security_event_logging:q1`
- **Question**: Does the application log key security events (failed logins, privilege escalation, administrative changes, access to sensitive assets)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q43. `security_event_logging:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:security_event_logging:q2`
- **Question**: Are sensitive data fields (passwords, payment cards, tokens, PII) systematically sanitized/masked from log outputs?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Centralized SIEM Forwarding & Security Alerting (`centralized_monitoring_and_alerting`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Stream application logs in real-time to a centralized SIEM/SOC with anomaly detection and automated alerting.

##### Q44. `centralized_monitoring_and_alerting:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:centralized_monitoring_and_alerting:q1`
- **Question**: Are application logs forwarded in near-real-time to a central SIEM/SOC platform with alerting rules for suspicious activities?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="resilience_chapter"></a>
### Penetration Testing & Resilience (`resilience_chapter`)

*Perform independent penetration testing, enforce patch remediation SLAs, and maintain disaster recovery readiness.*

#### Node: Penetration Testing & Vulnerability Remediation (`penetration_testing_and_vulnerability_management`)
- **Implementation Groups**: `internet_facing`
- **Description**: Conduct independent penetration tests at least annually on self-hosted applications and infrastructure, and remediate identified vulnerabilities within defined SLAs. (Applicable to self-hosted applications exposed to the public Internet; SaaS penetration testing is governed under Chapter 10 Section 13).

##### Q45. `penetration_testing_and_vulnerability_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:penetration_testing_and_vulnerability_management:q1`
- **Question**: Is independent penetration testing conducted on the application and underlying infrastructure at least annually by qualified internal or external penetration testers?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Annual pentesting)

##### Q46. `penetration_testing_and_vulnerability_management:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:penetration_testing_and_vulnerability_management:q2`
- **Question**: Are identified vulnerabilities remediated within defined SLAs (e.g. Critical within 7 days, High within 30 days)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Remediation SLAs) 

#### Node: Backup Strategy & Disaster Recovery (`backup_and_disaster_recovery`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Maintain automated encrypted backups and test restoration drills against documented RTO and RPO targets.

##### Q47. `backup_and_disaster_recovery:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:backup_and_disaster_recovery:q1`
- **Question**: Are automated and encrypted backups maintained for application state and databases, with restoration tests performed at least annually?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: COTS Deployment Hardening, Vendor Support & Patch SLAs (`cots_deployment_hardening`)
- **Implementation Groups**: `cots_app`
- **Description**: Enforce vendor hardening benchmarks, verify that COTS software actively receives vendor security patches (not End-of-Life / EOL), and deploy updates within strict patch SLAs.

##### Q48. `cots_deployment_hardening:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:cots_deployment_hardening:q1`
- **Question**: Are default vendor credentials changed, sample modules removed, and configuration hardened against vendor or CIS benchmarks?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (40 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q49. `cots_deployment_hardening:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:cots_deployment_hardening:q2`
- **Question**: Does the COTS software actively receive security patches and vulnerability updates from the vendor (under an active maintenance/support contract, not End-of-Life / EOL or End-of-Support / EOS)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q50. `cots_deployment_hardening:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:cots_deployment_hardening:q3`
- **Question**: Are published vendor security patches, hotfixes, and critical vulnerability updates deployed within formal SLAs (Critical <= 14 days)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="saas_chapter"></a>
### SaaS Requirements & Vendor Security Exhibit (`saas_chapter`)

*Baseline contractual security requirements applicable to all SaaS providers processing customer data (Security Schedule / Exhibit).*

#### Node: SaaS Master Contract & Security Schedule Execution (`saas_contract_compliance`)
- **Implementation Groups**: `saas_app`
- **Description**: Ensure a signed Master Services Agreement (MSA) and binding Security Exhibit govern the SaaS service.

##### Q51. `saas_contract_compliance:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_contract_compliance:q1`
- **Question**: Is there a signed SaaS contract and binding Security Schedule? (e.g., legally executed Master Services Agreement / MSA and Security Exhibit with the provider)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Security Governance & Policy (`saas_governance_and_policy`)
- **Implementation Groups**: `saas_app`
- **Description**: Maintain an ISO 27001-based security policy, an active ISMS, and conduct annual risk analyses and policy updates.

##### Q52. `saas_governance_and_policy:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_governance_and_policy:q1`
- **Question**: Does the contract require and does the provider maintain an Information Security Policy based on a recognized framework (such as ISO 27001), updated at least annually?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q53. `saas_governance_and_policy:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_governance_and_policy:q2`
- **Question**: Does the contract require and does the provider maintain an active Information Security Management System (ISMS) and perform risk analyses at least annually?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Confidentiality & Data Protection (`saas_confidentiality_and_data_protection`)
- **Implementation Groups**: `saas_app`
- **Description**: Enforce vendor personnel access governance (Customer Lockbox), contractual employee NDAs, and state-of-the-art key/certificate management.

##### Q54. `saas_confidentiality_and_data_protection:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_confidentiality_and_data_protection:q1`
- **Question**: Does the contract enforce strict vendor personnel access governance (e.g. Customer Lockbox / explicit client approval workflows before vendor support or engineering can access customer tenant data), supported by binding confidentiality agreements (NDAs) and employee security charters?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q55. `saas_confidentiality_and_data_protection:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_confidentiality_and_data_protection:q2`
- **Question**: Does the contract require and are cryptographic keys and certificates governed by documented lifecycle procedures using state-of-the-art algorithms and protocols?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Security Awareness & Training (`saas_security_awareness`)
- **Implementation Groups**: `saas_app`
- **Description**: Conduct annual cybersecurity training for all personnel, covering risks, data breaches, and incident escalation procedures.

##### Q56. `saas_security_awareness:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_security_awareness:q1`
- **Question**: Does the contract require and are vendor personnel trained and sensitized to cybersecurity risks, data breaches, and non-compliance consequences at least annually?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q57. `saas_security_awareness:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_security_awareness:q2`
- **Question**: Does the contract require and are formal security incident reporting procedures disseminated and maintained accessible to all staff?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Identity & Access Management (`saas_iam`)
Action - Simplify, admin access to SaaS platform must use MFA
- **Implementation Groups**: `saas_app`
- **Description**: Enforce Multi-Factor Authentication (MFA) for administrative and privileged access to the SaaS management console and tenant platform.

##### Q58. `saas_iam:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_iam:q1`
- **Question**: Does root, administrative, and break-glass access to the SaaS tenant management console strictly enforce Multi-Factor Authentication (MFA) independently of standard user SSO?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **SaaS only** (Admin console mandatory MFA)

#### Node: Privilege Governance, IGA & Access Recertifications (`saas_entitlements_and_privileges`)
Action - Simplify, RBAC and periodic reviews are enough
- **Implementation Groups**: `saas_app`
- **Description**: Apply least privilege, restrict administrator rights, and conduct periodic access reviews for provider personnel accessing tenant infrastructure.

##### Q59. `saas_entitlements_and_privileges:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q1`
- **Question**: Does the contract require and does the provider apply least privilege and Role-Based Access Control (RBAC), restricting admin rights and maintaining an inventory of privileged accounts across its internal personnel?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **SaaS only** (Provider staff least privilege & RBAC)

##### Q60. `saas_entitlements_and_privileges:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q2`
- **Question**: Does the contract mandate and does the provider conduct periodic access reviews and recertifications of its internal personnel granted privileged or operational access to tenant data and infrastructure?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **SaaS only** (Provider staff periodic access reviews)

#### Node: Logging & Incident Management (`saas_logging_and_incidents`)
- **Implementation Groups**: `saas_app`
- **Description**: Log user and admin actions, ensure log tamper-resistance, continuously monitor security events, and notify incidents within 48 hours.

##### Q61. `saas_logging_and_incidents:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_logging_and_incidents:q1`
- **Question**: Does the contract require and does the SaaS solution record tamper-resistant logs of logins, logouts, access, and administrative actions, with continuous monitoring and audit telemetry export into the client SIEM?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q62. `saas_logging_and_incidents:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_logging_and_incidents:q2`
- **Question**: Does the contract legally bind the provider to notify the client of any security incident or anomaly within a maximum of 48 hours of discovery, and is a formal incident notification and escalation procedure operational?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Workstation & Endpoint Security (`saas_workstation_security`)
- **Implementation Groups**: `saas_app`
- **Description**: Enforce auto-lock, local firewalls, EDR/antivirus, secure system configuration, vulnerability/patch management, full-disk encryption, and lost equipment procedures.

##### Q63. `saas_workstation_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_workstation_security:q1`
- **Question**: Does the contract require and are provider workstations protected by session auto-lock after inactivity, active local firewalls, hardened configurations, and updated EDR/antivirus?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q64. `saas_workstation_security:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_workstation_security:q2`
- **Question**: Does the contract require and are all workstations and removable media fully encrypted, governed by patch management and a formal lost/compromised equipment procedure?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Mobile Device Security (`saas_mobile_security`)
- **Implementation Groups**: `saas_app`
- **Description**: Govern mobile devices via a formal policy, MDM solution, remote wipe capability, mobile data encryption, and controlled synchronization.

##### Q65. `saas_mobile_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_mobile_security:q1`
- **Question**: Does the contract require and are mobile devices accessing the service governed by a formal MDM policy with mandatory device encryption, remote wipe capabilities, and controlled data synchronization?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Network Security & Traffic Control (`saas_network_security`)
- **Implementation Groups**: `saas_app`
- **Description**: Enforce formalized network security policy, control inbound/outbound traffic, secure Wi-Fi, and protect remote access connections.

##### Q66. `saas_network_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_network_security:q1`
- **Question**: Does the contract mandate and does the provider enforce a formal network security policy with strict ingress/egress filtering, anti-DDoS and WAF protections (e.g. Cloudflare, or competitor services such as AWS WAF & Shield, Google Cloud Armor, Azure WAF, Akamai, Fastly, Imperva), secure Wi-Fi, and protected remote access (VPN/ZTNA)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Environment Security & Tenant Isolation (`saas_environment_isolation`)
- **Implementation Groups**: `saas_app`
- **Description**: Ensure multi-tenant environment isolation, network traffic filtering, and customer-managed cryptographic sovereignty (BYOK/HYOK).

##### Q67. `saas_environment_isolation:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_environment_isolation:q1`
- **Question**: Does the contract require and does the SaaS architecture enforce robust logical or physical client environment isolation, traffic filtering, and antimalware defenses?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q68. `saas_environment_isolation:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_environment_isolation:q2`
- **Question**: Does the SaaS architecture support tenant-specific cryptographic sovereignty, such as dedicated tenant encryption keys, Bring-Your-Own-Key (BYOK/HYOK), or KMS envelope isolation to prevent vendor-level access to at-rest customer data?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Development Security & Secure SDLC (`saas_secure_development`)
- **Implementation Groups**: `saas_app`
- **Description**: Manage source code in secure repositories, mandate peer code reviews, separate dev/test/prod, and enforce secure SDLC and supply chain gates.

##### Q69. `saas_secure_development:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_secure_development:q1`
- **Question**: Does the contract require and is source code stored in secure repositories with mandatory peer reviews and strict segregation between development, test, and production environments?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q70. `saas_secure_development:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_secure_development:q2`
- **Question**: Does the contract mandate that the provider adheres to formal secure SDLC standards (e.g., OWASP SAMM, ISO/IEC 27034), with mandatory developer secure coding training, automated pipeline security gates (SAST/SCA), and software supply chain integrity controls?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Web Application & Transport Security (`saas_web_app_security`)
- **Implementation Groups**: `saas_app`
- **Description**: Enforce TLS 1.2+, network port restrictions, and administrative interface access controls.

##### Q71. `saas_web_app_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_web_app_security:q1`
- **Question**: Does the contract require and are web services protected with TLS 1.2+ minimum, network ports restricted to the strict minimum, and administrative interfaces strictly controlled?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: SaaS Penetration Testing & Vulnerability Remediation (`saas_penetration_testing_and_vulnerability_management`)
- **Implementation Groups**: `saas_app`
- **Description**: Verify SaaS contractual authorization for penetration testing (or vendor annual third-party pentest audit reports) and contractual commitment to vulnerability remediation SLAs.

##### Q72. `saas_penetration_testing_and_vulnerability_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_penetration_testing_and_vulnerability_management:q1`
- **Question**: How is independent penetration testing governed and performed on the SaaS platform?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `We are allowed to pentest (SaaS contract authorizes customer-led penetration testing)` (50 pts, compute_result: true)
  - `The SaaS vendor does the pentest (contract mandates that the vendor undergoes annual independent penetration tests and provides audit reports/attestations)` (50 pts, compute_result: true)
  - `They refuse (the SaaS vendor refuses penetration testing and provides no reports)` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q73. `saas_penetration_testing_and_vulnerability_management:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_penetration_testing_and_vulnerability_management:q2`
- **Question**: Does the SaaS contract commit the provider to formal vulnerability remediation SLAs (e.g. Critical within 7 days, High within 30 days)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Data Hosting & European Residency (`saas_data_hosting_and_residency`)
- **Implementation Groups**: `saas_app`
- **Description**: Host data primarily within the European Union (EU) or European Economic Area (EEA) when required by regulation.

##### Q74. `saas_data_hosting_and_residency:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_data_hosting_and_residency:q1`
- **Question**: Does the contract mandate and is all customer data (including primary databases, processing pipelines, and backups) hosted primarily within the European Union (EU) or European Economic Area (EEA)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Physical & Environmental Security (`saas_physical_security`)
- **Implementation Groups**: `saas_app`
- **Description**: Control physical access to premises, protect sensitive zones, retain access traces, protect IT equipment, and regularly review authorizations.

##### Q75. `saas_physical_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_physical_security:q1`
- **Question**: Does the contract require and are provider facilities and datacenters secured with badge access controls, sensitive zone restrictions, trace logging, and regular physical access reviews?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Backup & Business Continuity (`saas_backup_and_business_continuity`)
- **Implementation Groups**: `saas_app`
- **Description**: Maintain regular backups with verified restore tests, immutable/encrypted storage, documented and annually tested BCP/DRP plans, and defined RTO/RPO.

##### Q76. `saas_backup_and_business_continuity:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_backup_and_business_continuity:q1`
- **Question**: Does the contract require and are automated backups encrypted, immutable, and verified through regular documented restoration tests?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q77. `saas_backup_and_business_continuity:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_backup_and_business_continuity:q2`
- **Question**: Does the contract mandate and does the provider maintain documented BCP/DRP plans tested at least annually, with contractually defined RTO and RPO targets?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Subcontractor & Sub-Processor Management (`saas_subcontractor_management`)
- **Implementation Groups**: `saas_app`
- **Description**: Select subcontractors with sufficient security guarantees, verify their compliance, and preserve full vendor liability.

##### Q78. `saas_subcontractor_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_subcontractor_management:q1`
- **Question**: Does the contract mandate and does the vendor maintain a formal subcontractor vetting process with documented compliance verification, while assuming full liability for all downstream subcontractors?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Audit Rights & Compliance Verification (`saas_audit_and_compliance`)
- **Implementation Groups**: `saas_app`
- **Description**: Perform annual compliance checks, provide compliance evidence, maintain gap remediation plans, and grant client/third-party audit rights.

##### Q79. `saas_audit_and_compliance:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q1`
- **Question**: Does the contract legally grant the client (or an authorized third party) the right to audit (e.g., review independent annual SOC 2 Type II or ISO 27001 reports), and does the provider perform annual compliance checks and actively provide audit evidence and remediation plans?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: PCI DSS Payment Security (`saas_pci_dss`)
- **Implementation Groups**: `saas_app`
- **Description**: Maintain PCI DSS certification for payment data environments, provide annual AOCs, implement dedicated cardholder incident procedures, and immediately notify payment incidents.

##### Q80. `saas_pci_dss:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_pci_dss:q1`
- **Question**: Does the application process, store, or transmit payment card data?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No - Out of scope / Not applicable` (100 pts, compute_result: true)
  - `Yes - Payment data is processed` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q81. `saas_pci_dss:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_pci_dss:q2`
- **Question**: If payment card data is processed, does the contract require and does the provider maintain active PCI DSS certification, provide an annual AOC, and enforce dedicated payment incident procedures with immediate notification?
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:saas_pci_dss:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:saas_pci_dss:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Non-Conformity Management & Contractual Remedies (`saas_non_conformity_remediation`)
- **Implementation Groups**: `saas_app`
- **Description**: Implement corrective actions for breaches, deliver documented remediation plans, establish compensatory controls, and grant rights of access suspension or contract termination for severe breaches.

##### Q82. `saas_non_conformity_remediation:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_non_conformity_remediation:q1`
- **Question**: Does the contract mandate formal remediation plans and compensatory measures for identified security gaps, with explicit rights to suspend access or terminate for repeated breaches?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

