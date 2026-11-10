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
| 0a | Application Information & Governance | `application_description` | `q1` | What is the primary functional domain and business purpose of the application? | `info` | All applications (Functional & business domain profiling) |
| 0b | Application Information & Governance | `application_description` | `q2` | Who are the primary intended users or consumers of the application? | `info` | All applications (User audience & consumer scope profiling) |
| 1 | Application Information & Governance | `stakeholder_identification` | `q1` | Is there a designated business contact? (Designated business owner or product spon... | `info` | All applications (Info profiling) |
| 2 | Application Information & Governance | `stakeholder_identification` | `q2` | Is there a designated IT contact? (Technical lead or engineer responsible for main... | `info` | All applications (Info profiling) |
| 3 | Application Information & Governance | `stakeholder_identification` | `q3` | Is there a designated data owner? (Data steward or governance officer responsible ... | `info` | All applications (Info profiling) |
| 4 | Application Information & Governance | `stakeholder_identification` | `q4` | Is the information about stakeholders updated in LeanIX / CMDB? (Stakeholder assig... | `info` | All applications (Info profiling) |
| 5a | Application Information & Governance | `data_classification` | `q1` | What is the primary operational data category handled? (Retail storefront, warehouse/operations, confidential customer/commercial, or critical financial/secrets) | `info` | All applications (Data classification refinement - Category) |
| 5b | Application Information & Governance | `data_classification` | `q2` | What is the adverse impact severity of unauthorized disclosure? (Negligible, minor friction, moderate/severe, or catastrophic) | `info` | All applications (Data classification refinement - Impact severity) |
| 5c | Application Information & Governance | `data_classification` | `q3` | What category of personal data is processed by the application under GDPR? | `info` | All applications (GDPR profiling - Personal data type) |
| 5d | Application Information & Governance | `data_classification` | `q4` | What is the volume of data subjects (individuals) whose personal data is processed? | `info` | Applications processing personal data (depends on `data_classification:q3`) |
| 6 | Application Information & Governance | `hosting` | `q1` | What is the delivery and hosting model of the application? | `info` | All applications (Info profiling - Hosting model) |
| 7 | Application Information & Governance | `hosting` | `q2` | What is the network exposure of the application? | `info` | Self-Hosted only (Custom & COTS - depends on `hosting:q1`) |
| 7b | Application Information & Governance | `hosting` | `q3` | Is the SaaS vendor certified under ISO/IEC 27001 or SOC 2 Type II? | `info` | SaaS only (depends on `hosting:q1 == SaaS`) |
| 8 | Identity, Authentication & Access Control | `authentication_and_mfa` | `q1` | How do users authenticate to the application? (Exclusive SSO [+100], Hybrid [+40], Direct [+0], M2M API [+100]) | `baseline` | **All applications** (Custom, COTS, SaaS) - Mandatory SSO / Hybrid |
| 9 | Identity, Authentication & Access Control | `authentication_and_mfa` | `q2` | If direct or hybrid authentication is used, are strong password policies and brute-force lockout protections implemented for local accounts? | `baseline` | All applications (If direct or hybrid auth used - Password policy, +30 pts) |
| 10 | Identity, Authentication & Access Control | `authentication_and_mfa` | `q3` | If direct or hybrid authentication is used, is Multi-Factor Authentication (MFA) enforced for all administrative, privileged, and break-glass access? | `baseline` | All applications (If direct or hybrid auth used - Admin MFA, +30 pts) |
| 11 | Identity, Authentication & Access Control | `access_control_and_rbac` | `q1` | Have you defined roles and permissions for the application? (Is access controlled ... | `baseline` | **All applications** (Baseline - RBAC least privilege) |
| 12 | Identity, Authentication & Access Control | `access_control_and_rbac` | `q2` | Is the application integrated with the enterprise Identity Governance and Administ... | `baseline` | **All applications** (Baseline - SailPoint IGA integration) |
| 13 | Identity, Authentication & Access Control | `access_control_and_rbac` | `q3` | Are user entitlements and privileged permissions reviewed and recertified on a per... | `baseline` | **All applications** (Baseline - Periodic recertifications) |
| 14 | Identity, Authentication & Access Control | `session_management` | `q1` | Are session identifiers and API bearer tokens cryptographically secure, protected in transit/storage, and invalidated upon logout, expiration, or inactivity? | `custom_app` | Custom applications and APIs (+100 pts) |
| 15 | Application Vulnerability Defense & Code Hygiene | `owasp_top_10_defenses` | `q1` | Are server-side input validation and parameterized queries/ORMs enforced to prevent injection flaws (SQLi, command injection, SSRF)? | `custom_app` | Custom applications (+50 pts) |
| 15b | Application Vulnerability Defense & Code Hygiene | `owasp_top_10_defenses` | `q2` | Are context-aware output encoding, security headers (CSP), and generic production error handlers enforced to prevent XSS and stack-trace leakage? | `custom_app` | Custom applications (+50 pts) |
| 16 | Application Vulnerability Defense & Code Hygiene | `ssrf_and_cloud_metadata_defense` | `q1` | Are outbound HTTP requests initiated by the application strictly validated using d... | `custom_app` |  |
| 17 | Application Vulnerability Defense & Code Hygiene | `ssrf_and_cloud_metadata_defense` | `q2` | Are cloud instance metadata protections enforced (e.g. IMDSv2 token-backed metadat... | `custom_app` |  |
| 18 | Application Vulnerability Defense & Code Hygiene | `file_upload_security` | `q1` | Can files be uploaded to the application? (e.g., user attachments, documents, images, media, or data imports) | `custom_app` | Custom App only (Gating question) |
| 19 | Application Vulnerability Defense & Code Hygiene | `file_upload_security` | `q2` | Are uploaded files validated via server-side magic byte inspection, assigned rando... | `custom_app` | Custom App only (if files uploaded - Magic bytes / UUIDs) |
| 20 | Application Vulnerability Defense & Code Hygiene | `file_upload_security` | `q3` | Are uploaded files scanned for malware and stored exclusively in dedicated, non-ex... | `custom_app` | Custom App only (if files uploaded - Malware scanning & isolated storage) |
| 21 | Cryptography & Secrets Management | `secrets_management` | `q1` | Are application credentials, API keys, and cryptographic secrets stored exclusivel... | `infra` | Self-Hosted only (Custom & COTS) |
| 21b | Cryptography & Secrets Management | `data_in_transit` | `q1` | Is data encrypted during transit? (Specify protocols, algorithms and methods: e.g.... | `infra` | Self-Hosted only (Custom & COTS) |
| 22 | Cryptography & Secrets Management | `data_at_rest` | `q1` | Is data encrypted at rest? (Specify algorithms and key management: e.g., AES-256 /... | `infra` | Self-Hosted only (Custom & COTS) |
| 23 | Secure SDLC & DevSecOps Automation | `automated_security_testing` | `q1` | Is automated Static Application Security Testing (SAST) integrated into the CI/CD ... | `custom_app` |  |
| 24 | Secure SDLC & DevSecOps Automation | `automated_security_testing` | `q2` | Is Dynamic Application Security Testing (DAST) or API security scanning performed ... | `custom_app` |  |
| 25 | Secure SDLC & DevSecOps Automation | `supply_chain_and_dependencies` | `q1` | Is Software Composition Analysis (SCA) automated in the CI/CD pipeline to detect k... | `custom_app` |  |
| 26 | Secure SDLC & DevSecOps Automation | `supply_chain_and_dependencies` | `q2` | Is an accurate Software Bill of Materials (SBOM) maintained and audited for all re... | `custom_app` |  |
| 27 | Secure SDLC & DevSecOps Automation | `code_review_and_ci_cd_integrity` | `q1` | Are mandatory peer code reviews enforced prior to merging changes into deployment branches? | `custom_app` | Custom applications (+50 pts) |
| 27b | Secure SDLC & DevSecOps Automation | `code_review_and_ci_cd_integrity` | `q2` | Do repository branch protection rules block direct commits, force-pushes, and failing CI status checks on deployment branches? | `custom_app` | Custom applications (+50 pts) |
| 28 | Secure SDLC & DevSecOps Automation | `vendor_secure_development` | `q1` | Does the third-party COTS software vendor adhere to recognized secure coding stand... | `cots_app` | **COTS Only** (Vendor secure coding guidelines) |
| 29 | API Security & Edge Protections | `api_security_and_rate_limiting` | `q1` | Are internet-facing endpoints fronted by an Edge WAF and anti-DDoS / bot protection (e.g. Cloudflare, AWS WAF)? | `internet_facing` | **Self-Hosted Internet-Facing only** (Edge WAF & DDoS, +50 pts) |
| 30 | API Security & Edge Protections | `api_security_and_rate_limiting` | `q2` | Are API rate limiting, throttling, and payload size quotas enforced to prevent scraping and resource exhaustion? | `internet_facing` | **Self-Hosted Internet-Facing only** (Rate limiting & quotas, +50 pts) |
| 31 | Data Protection & Lifecycle Governance | `data_exchange` | `q1` | Does the application exchange data externally? (e.g., transfers, automated API int... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 32 | Data Protection & Lifecycle Governance | `data_exchange` | `q2` | Is there a data exchange contract with the appropriate confidentiality clauses? (e... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS - if data exchanged) |
| 33 | Data Protection & Lifecycle Governance | `non_prod_data` | `q1` | Are real production data records, live customer databases, or personal data utiliz... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 34 | Data Protection & Lifecycle Governance | `non_prod_data` | `q2` | How do you protect them? (Which sanitization or protection method is applied: cryp... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS - if non-prod data used) |
| 35 | Data Protection & Lifecycle Governance | `non_prod_data` | `q3` | Do you clean the prod data after use in non-prod? (e.g., securely purging, sanitiz... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS - if non-prod data used) |
| 36 | Data Protection & Lifecycle Governance | `data_destruction` | `q1` | Is there a data destruction process for this application? (e.g., documented data r... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS) |
| 37 | Data Protection & Lifecycle Governance | `data_destruction` | `q2` | Is the process compliant with the policy (responsibilities, methods, reporting)? (... | `custom_app, cots_app` | Self-Hosted only (Custom & COTS - if destruction process exists) |
| 38 | Security Logging & Monitoring | `security_event_logging` | `q1` | Does the application log key security events (failed logins, privilege escalation,... | `infra` | Self-Hosted only (Custom & COTS) |
| 39 | Security Logging & Monitoring | `security_event_logging` | `q2` | Are sensitive data fields (passwords, payment cards, tokens, PII) systematically s... | `infra` | Self-Hosted only (Custom & COTS) |
| 40 | Security Logging & Monitoring | `centralized_monitoring_and_alerting` | `q1` | Are application logs forwarded in near-real-time to a central SIEM/SOC platform wi... | `infra` | Self-Hosted only (Custom & COTS) |
| 41 | Penetration Testing & Resilience | `penetration_testing_and_vulnerability_management` | `q1` | Is independent penetration testing conducted on the application and underlying inf... | `internet_facing` | **Self-Hosted Internet-Facing only** (Annual pentesting) |
| 42 | Penetration Testing & Resilience | `penetration_testing_and_vulnerability_management` | `q2` | Are identified vulnerabilities remediated within defined SLAs (e.g. Critical withi... | `internet_facing` | **Self-Hosted Internet-Facing only** (Remediation SLAs) |
| 43 | Penetration Testing & Resilience | `backup_and_disaster_recovery` | `q1` | Are automated and encrypted backups maintained for application state and databases? | `infra` | Self-Hosted only (Custom & COTS, +50 pts) |
| 43a | Penetration Testing & Resilience | `backup_and_disaster_recovery` | `q2` | Are backup restoration and disaster recovery drills tested at least annually against documented RTO/RPO targets? | `infra` | Self-Hosted only (Custom & COTS - depends on `backup_and_disaster_recovery:q1 == Yes`, +50 pts) |
| 43b | Penetration Testing & Resilience | `os_patching` | `q1` | Are operating system (OS) security patches, kernel updates, and host/container sec... | `infra` | Self-Hosted only (Custom & COTS - Automatic OS patching) |
| 43c | Penetration Testing & Resilience | `os_patching` | `q2` | If OS patching is not automatic, is there a formal patching schedule compliant wit... | `infra` | Self-Hosted only (Custom & COTS - if `os_patching:q1 == No`) |
| 43d | Penetration Testing & Resilience | `os_patching` | `q3` | Does the application and infrastructure architecture allow no-downtime patching fr... | `infra` | Self-Hosted only (Custom & COTS - High availability / no-downtime patching) |
| 44 | Penetration Testing & Resilience | `cots_deployment_hardening` | `q1` | Are default vendor credentials changed, sample modules removed, and configuration ... | `cots_app` |  |
| 45 | Penetration Testing & Resilience | `cots_deployment_hardening` | `q2` | Does the COTS software actively receive security patches and vulnerability updates... | `cots_app` |  |
| 46 | Penetration Testing & Resilience | `cots_deployment_hardening` | `q3` | Are published vendor security patches, hotfixes, and critical vulnerability update... | `cots_app` |  |
| 47 | SaaS Requirements & Vendor Security Exhibit | `saas_contract_compliance` | `q1` | Is there a signed SaaS contract and binding Security Schedule? (e.g., legally exec... | `saas_app` |  |
| 48 | SaaS Requirements & Vendor Security Exhibit | `saas_governance_and_policy` | `q1` | Does the contract require and does the provider maintain an Information Security P... | `saas_app` |  |
| 49 | SaaS Requirements & Vendor Security Exhibit | `saas_governance_and_policy` | `q2` | Does the contract require and does the provider maintain an active Information Sec... | `saas_app` |  |
| 50 | SaaS Requirements & Vendor Security Exhibit | `saas_confidentiality_and_data_protection` | `q1` | Does the contract require vendor personnel to sign confidentiality agreements (NDAs... | `saas_app` |  |
| 51 | SaaS Requirements & Vendor Security Exhibit | `saas_confidentiality_and_data_protection` | `q2` | Does the contract mandate data encryption for all customer data, both in transit... | `saas_app` |  |
| 52 | SaaS Requirements & Vendor Security Exhibit | `saas_security_awareness` | `q1` | Does the contract require and are vendor personnel trained and sensitized to cyber... | `saas_app` |  |
| 53 | SaaS Requirements & Vendor Security Exhibit | `saas_security_awareness` | `q2` | Does the contract require and are formal security incident reporting procedures di... | `saas_app` |  |
| 54 | SaaS Requirements & Vendor Security Exhibit | `saas_iam` | `q1` | Does root, administrative, and break-glass access to the SaaS tenant management co... | `saas_app` | **SaaS only** (Admin console mandatory MFA) |
| 55 | SaaS Requirements & Vendor Security Exhibit | `saas_entitlements_and_privileges` | `q1` | Does the contract require and does the provider apply least privilege and Role-Bas... | `saas_app` | **SaaS only** (Provider staff least privilege & RBAC) |
| 56 | SaaS Requirements & Vendor Security Exhibit | `saas_entitlements_and_privileges` | `q2` | Does the contract mandate and does the provider conduct periodic access reviews an... | `saas_app` | **SaaS only** (Provider staff periodic access reviews) |
| 57 | SaaS Requirements & Vendor Security Exhibit | `saas_logging_and_incidents` | `q1` | Does the contract require and does the SaaS solution record tamper-resistant logs ... | `saas_app` |  |
| 58 | SaaS Requirements & Vendor Security Exhibit | `saas_logging_and_incidents` | `q2` | Does the contract legally bind the provider to notify the client of any security i... | `saas_app` |  |
| 59 | SaaS Requirements & Vendor Security Exhibit | `saas_workstation_security` | `q1` | Does the contract require and are provider workstations protected by session auto-... | `saas_app` |  |
| 60 | SaaS Requirements & Vendor Security Exhibit | `saas_workstation_security` | `q2` | Does the contract require and are all workstations and removable media fully encry... | `saas_app` |  |
| 61 | SaaS Requirements & Vendor Security Exhibit | `saas_mobile_security` | `q1` | Does the contract require and are mobile devices accessing the service governed by... | `saas_app` |  |
| 62 | SaaS Requirements & Vendor Security Exhibit | `saas_network_security` | `q1` | Does the contract mandate and does the provider enforce a formal network security ... | `saas_app` |  |
| 63 | SaaS Requirements & Vendor Security Exhibit | `saas_environment_isolation` | `q1` | Does the contract require and does the SaaS architecture enforce robust logical or... | `saas_app` |  |
| 64 | SaaS Requirements & Vendor Security Exhibit | `saas_secure_development` | `q1` | Does the contract require and is source code stored in secure repositories with ma... | `saas_app` |  |
| 65 | SaaS Requirements & Vendor Security Exhibit | `saas_secure_development` | `q2` | Does the contract mandate that the provider adheres to formal secure SDLC standard... | `saas_app` |  |
| 66 | SaaS Requirements & Vendor Security Exhibit | `saas_web_app_security` | `q1` | Does the contract require and are web services protected with TLS 1.2+ minimum, ne... | `saas_app` |  |
| 68 | SaaS Requirements & Vendor Security Exhibit | `saas_vulnerability_remediation_sla` | `q1` | Does the SaaS contract commit the provider to formal vulnerability remediation SLA... | `saas_uncertified` |  |
| 69 | SaaS Requirements & Vendor Security Exhibit | `saas_data_hosting_and_residency` | `q1` | Does the contract mandate that all customer data be hosted primarily within the EU/EEA? | `saas_app` | SaaS applications (EU/EEA Data Hosting) |
| 69b | SaaS Requirements & Vendor Security Exhibit | `saas_data_hosting_and_residency` | `q2` | Is a formal Data Processing Agreement (DPA) executed incorporating Article 28 clauses? | `saas_app` | SaaS applications (GDPR DPA Article 28) |
| 69c | SaaS Requirements & Vendor Security Exhibit | `saas_data_hosting_and_residency` | `q3` | Does the contract mandate prior authorization/notice for sub-processors with objection rights? | `saas_app` | SaaS applications (Sub-processor Governance) |
| 69d | SaaS Requirements & Vendor Security Exhibit | `saas_data_hosting_and_residency` | `q4` | Does the contract establish a strict personal data breach notification SLA (24-48h)? | `saas_app` | SaaS applications (Breach Notification SLA) |
| 69e | SaaS Requirements & Vendor Security Exhibit | `saas_data_hosting_and_residency` | `q5` | Does the vendor provide Data Subject Rights (DSR) assistance and certified exit data deletion? | `saas_app` | SaaS applications (DSR & Exit Deletion) |
| 70 | SaaS Requirements & Vendor Security Exhibit | `saas_physical_security` | `q1` | Does the contract require and are provider facilities and datacenters secured with... | `saas_uncertified` |  |
| 71 | SaaS Requirements & Vendor Security Exhibit | `saas_backup_and_business_continuity` | `q1` | Does the contract require and are automated backups encrypted, immutable, and veri... | `saas_uncertified` |  |
| 72 | SaaS Requirements & Vendor Security Exhibit | `saas_backup_and_business_continuity` | `q2` | Does the contract mandate and does the provider maintain documented BCP/DRP plans ... | `saas_uncertified` |  |
| 73 | SaaS Requirements & Vendor Security Exhibit | `saas_subcontractor_management` | `q1` | Does the contract mandate and does the vendor maintain a formal subcontractor vett... | `saas_uncertified` |  |
| 74 | SaaS Requirements & Vendor Security Exhibit | `saas_audit_and_compliance` | `q1` | Does the contract legally grant the client (or an authorized independent third pa... | `saas_app` |  |
| 74b | SaaS Requirements & Vendor Security Exhibit | `saas_audit_and_compliance` | `q2` | How is independent penetration testing governed and performed on the SaaS platform? | `saas_app` |  |
| 75 | SaaS Requirements & Vendor Security Exhibit | `saas_pci_dss` | `q1` | Does the application process, store, or transmit payment card data? | `saas_app` |  |
| 76 | SaaS Requirements & Vendor Security Exhibit | `saas_pci_dss` | `q2` | If payment card data is processed, does the contract require and does the provider... | `saas_app` |  |
| 77 | SaaS Requirements & Vendor Security Exhibit | `saas_non_conformity_remediation` | `q1` | Does the contract mandate formal remediation plans and compensatory measures for i... | `saas_app` |  |

---

## 3. Detailed Questions by Chapter


<a id="info"></a>
### Application Information & Governance (`info`)

*Basic application profiling, ownership, hosting, exposure, and architecture context.*

#### Node: Application Description & Business Purpose (`application_description`)
- **Implementation Groups**: `info`
- **Description**: Describe what the application is doing, including its primary functional domain, business capabilities, intended users, and operational scope.

##### Q1. `application_description:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:application_description:q1`
- **Question**: What is the primary functional domain and business purpose of the application?
- **Type**: `unique_choice`
- **Choices**:
  - `Customer-Facing & Digital Commerce (e-commerce, customer portals, public web services, mobile apps)`
  - `Internal Operations & Enterprise Management (ERP, CRM, HR, finance, supply chain, intranet)`
  - `Data Analytics, AI & Business Intelligence (data warehouse, ETL pipelines, reporting, ML models)`
  - `Integration Middleware & Core APIs (API gateways, message brokers, microservices hub)`
  - `Infrastructure, Platform & DevOps Management (CI/CD, monitoring, ITSM, security tooling)`
  - `Other / Specialized Functional Purpose`
- **Applicable Cases / Situations**:
  - [x] All applications (Functional & business domain profiling)

##### Q2. `application_description:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:application_description:q2`
- **Question**: Who are the primary intended users or consumers of the application?
- **Type**: `unique_choice`
- **Choices**:
  - `Internal workforce (employees, internal contractors)`
  - `Business partners and vendors (B2B suppliers, distributors, affiliates)`
  - `External public consumers and customers (B2C)`
  - `Automated systems / Machine-to-Machine clients only (APIs, daemons, backend services)`
- **Applicable Cases / Situations**:
  - [x] All applications (User audience & consumer scope profiling)

#### Node: Stakeholder identification (`stakeholder_identification`)
Action - None
- **Implementation Groups**: `info`
- **Description**: Stakeholders have been identified for the application

##### Q1. `stakeholder_identification:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:stakeholder_identification:q1`
- **Question**: Is there a designated business contact? (Designated business owner or product sponsor accountable for business processes, functionality, and risk acceptance)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling)

##### Q2. `stakeholder_identification:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:stakeholder_identification:q2`
- **Question**: Is there a designated IT contact? (Technical lead or engineer responsible for maintenance, infrastructure, deployment, and operational support)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
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
  - `Yes` (15 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (Info profiling)

#### Node: Data classification (`data_classification`)
Action - None
- **Implementation Groups**: `info`
- **Description**: Classify data handled by the application through multi-dimensional criteria narrowing down business classification, disclosure harm, and GDPR personal data profiling.
- **Policy Reference**: See detailed classification standards and examples in [Data Classification Policy & Guidance](file:///home/python/ciso-assistant/docs/data_classification_policy_guide.md).

##### Q5a. `data_classification:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_classification:q1`
- **Question**: What is the primary operational data category handled by the application?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Public storefront & published brand content (Published product descriptions, size guides, retail prices, delivery/return policies, public marketing collateral)`
  - `Internal operations, logistics & non-sensitive enterprise workflows (Warehouse operating procedures, staff training materials, aggregated order-volume dashboards, org charts, sales figures)`
  - `Confidential commercial, supplier & customer operational records (Customer PII/contact details & delivery addresses, customer order/return/refund histories, support tickets, supplier costs/margins, unreleased campaign plans, inventory forecasts)`
  - `Critical financial, cryptographic secrets, cardholder data & anti-fraud rules (Customer payment-card data / PAN / CVV, refund bank accounts / IBANs, production admin credentials / API secrets / TLS keys, anti-fraud rules & evasion thresholds)`
- **Applicable Cases / Situations**:
  - [x] All applications (Data classification refinement - Category)

##### Q5b. `data_classification:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_classification:q2`
- **Question**: What would be the adverse impact severity of unauthorized disclosure or breach of the data handled?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Negligible / None (Data is intended for public consumption; unauthorized disclosure causes zero harm)`
  - `Minor operational friction (Internal workforce inconvenience, minor productivity delay, no external customer or financial harm)`
  - `Moderate to severe harm (Damage to customer trust, competitive disadvantage, significant operational disruption, or GDPR regulatory notifications)`
  - `Catastrophic or existential impact (Systemic payment fraud, loss of merchant processing agreement, severe GDPR/PCI-DSS fines, root cloud account compromise)`
- **Applicable Cases / Situations**:
  - [x] All applications (Data classification refinement - Disclosure impact)

##### Q5c. `data_classification:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_classification:q3`
- **Question**: What category of personal data is processed by the application under GDPR?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No personal data` (Green - `#33a745`)
  - `Contact data of employees` (Yellow - `#ffc107`)
  - `Contact and order details about customers` (Orange - `#fd7e14`)
  - `HR and financial details about employees and customer payment data` (Red - `#dc3545`)
- **Applicable Cases / Situations**:
  - [x] All applications (GDPR profiling - Personal data type)

##### Q5d. `data_classification:q4`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_classification:q4`
- **Question**: What is the volume of data subjects (individuals) whose personal data is processed?
- **Type**: `unique_choice`
- **Depends On**: `data_classification:q3` (answers: employee contact data, customer contact/order details, or HR/financial/payment data)
- **Choices & Scoring**:
  - `Low volume (Fewer than 1,000 individuals / data subjects)` (Impact multiplier: `1.0`)
  - `Medium volume (1,000 to 100,000 individuals / data subjects)` (Impact multiplier: `1.0`)
  - `High volume / Large scale processing under GDPR (More than 100,000 individuals, or systemic nationwide monitoring)` (Impact multiplier: `1.5`)
- **Applicable Cases / Situations**:
  - [x] Applications processing personal data (GDPR profiling - Volume)

#### Node: Application Delivery & Network Exposure (`hosting`)
Action - None
- **Implementation Groups**: `info`
- **Description**: Determine the application delivery and hosting model (Custom software, Bought COTS, or third-party SaaS), its network exposure (Internal restricted network or Internet-facing), and SaaS vendor certification status.

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

##### Q7. `hosting:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:hosting:q2`
- **Question**: What is the network exposure of the application?
- **Depends on**: `hosting:q1` in `[Custom software, Bought software]`
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Internal / Restricted Network only` (100 pts, compute_result: true)
  - `Internet-facing (Public Web / Mobile API)` (100 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS; hidden for SaaS)

##### Q7b. `hosting:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:hosting:q3`
- **Question**: Is the SaaS vendor certified under ISO/IEC 27001 or SOC 2 Type II?
- **Depends on**: `hosting:q1` == `SaaS`
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes - Vendor holds an active ISO/IEC 27001 certification or SOC 2 Type II report` (100 pts, compute_result: true)
  - `No - Vendor is not ISO/IEC 27001 or SOC 2 Type II certified` (100 pts, compute_result: true; activates `saas_uncertified`)
- **Applicable Cases / Situations**:
  - [x] SaaS only (triggers `saas_uncertified` when `No`)


<a id="iam_chapter"></a>
### Identity, Authentication & Access Control (`iam_chapter`)

*Enforce strong authentication, Multi-Factor Authentication (MFA), federated SSO, and granular authorization controls.*

#### Node: Centralized Identity, Authentication & MFA (`authentication_and_mfa`)
Action - All apps must use SSO so ask for all apps
- **Implementation Groups**: `baseline`
- **Description**: Enforce centralized enterprise Identity Provider (SSO), strong credential hygiene, and Multi-Factor Authentication (MFA) for administrative and privileged access.

##### Q8. `authentication_and_mfa:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1`
- **Question**: How do users authenticate to the application?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Enterprise SSO exclusively (SAML 2.0 / OIDC federated IdP, with no local accounts)` (100 pts, compute_result: true)
  - `Hybrid: Enterprise SSO for users, with local admin / break-glass or external accounts` (40 pts, compute_result: true)
  - `Direct / Local application authentication only (Username & Password)` (0 pts, compute_result: false)
  - `Machine-to-Machine / API only (mTLS, OAuth2 Client Credentials, or signed tokens; no interactive user login)` (100 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [x] **All applications** (Custom, COTS, SaaS) - Mandatory SSO / Hybrid Auth

##### Q9. `authentication_and_mfa:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q2`
- **Question**: If direct or hybrid authentication is used, are strong password policies and brute-force lockout protections implemented for local accounts?
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1', 'answers': ['...:c2', '...:c3'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (If direct or hybrid auth used - Password policy)

##### Q10. `authentication_and_mfa:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q3`
- **Question**: If direct or hybrid authentication is used, is Multi-Factor Authentication (MFA) enforced for all administrative, privileged, and break-glass access?
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:authentication_and_mfa:q1', 'answers': ['...:c2', '...:c3'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] All applications (If direct or hybrid auth used - Admin & Break-Glass MFA)

#### Node: Authorization, RBAC, IGA & Access Recertifications (`access_control_and_rbac`)
Action - All apps must use RBAC and IGA for my employees, ask for all apps (Put in baseline for all apps)
- **Implementation Groups**: `baseline`
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
- **Description**: Enforce cryptographically secure session identifiers and API bearer tokens, idle timeouts, secure cookie flags (HttpOnly, Secure, SameSite), and token invalidation on logout.

##### Q14. `session_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:session_management:q1`
- **Question**: Are session identifiers and API bearer tokens cryptographically secure, protected in transit/storage (e.g. HttpOnly, Secure, SameSite cookie flags or secure token storage), and invalidated upon logout, expiration, or inactivity?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Custom applications and APIs (Secure cookie flags, Bearer token lifecycle, timeout invalidation)


<a id="app_defenses_chapter"></a>
### Application Vulnerability Defense & Code Hygiene (`app_defenses_chapter`)

*Protect custom applications against OWASP Top 10 injection flaws, cross-site scripting, SSRF, insecure file uploads, and information disclosure through secure programming and input/output handling.*

#### Node: OWASP Top 10 Secure Coding & Defenses (`owasp_top_10_defenses`)
- **Implementation Groups**: `custom_app`
- **Description**: Enforce secure coding guidelines and defenses against OWASP Top 10 vulnerabilities, including input validation, parameterized queries, context-aware output encoding, and secure error handling.

##### Q15. `owasp_top_10_defenses:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:owasp_top_10_defenses:q1`
- **Question**: Are server-side input validation and parameterized queries/ORMs enforced to prevent injection flaws (SQLi, command injection, SSRF)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Custom applications (Server-side input validation & parameterized queries/ORMs)

##### Q15b. `owasp_top_10_defenses:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:owasp_top_10_defenses:q2`
- **Question**: Are context-aware output encoding, security headers (CSP), and generic production error handlers enforced to prevent XSS and stack-trace leakage?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Custom applications (Context-aware output encoding, CSP & error masking) 

#### Node: SSRF & Cloud Metadata Defense (`ssrf_and_cloud_metadata_defense`)
- **Implementation Groups**: `custom_app`
- **Description**: Prevent Server-Side Request Forgery (SSRF) by validating outbound HTTP requests and enforcing cloud instance metadata protections (IMDSv2).

##### Q16. `ssrf_and_cloud_metadata_defense:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:ssrf_and_cloud_metadata_defense:q1`
- **Question**: Are outbound HTTP requests initiated by the application strictly validated using destination allow-lists with connections to RFC 1918 private subnets and localhost blocked?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q17. `ssrf_and_cloud_metadata_defense:q2`
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

##### Q18. `file_upload_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:file_upload_security:q1`
- **Question**: Can files be uploaded to the application? (e.g., user attachments, documents, images, media, or data imports)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No` (100 pts, compute_result: true)
  - `Yes` (0 pts)
- **Applicable Cases / Situations**:
  - Custom applications that do not allow file uploads receive 100 points immediately.
  - If `Yes`, conditionally activates `q2` and `q3`.

##### Q19. `file_upload_security:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:file_upload_security:q2`
- **Question**: Are uploaded files validated via server-side magic byte inspection, assigned randomized filenames (UUIDs), and stripped of path traversal characters?
- **Type**: `unique_choice`
- **Depends On**: `file_upload_security:q1` (`Yes`)
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q20. `file_upload_security:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:file_upload_security:q3`
- **Question**: Are uploaded files scanned for malware and stored exclusively in dedicated, non-executable private object storage (e.g. private S3 with presigned URLs)?
- **Type**: `unique_choice`
- **Depends On**: `file_upload_security:q1` (`Yes`)
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="crypto_chapter"></a>
### Cryptography & Secrets Management (`crypto_chapter`)

*Enforce cryptographic protection for data in transit and at rest, and maintain centralized secrets management.*

#### Node: Centralized Secrets Management (`secrets_management`)
- **Implementation Groups**: `infra`
- **Description**: Eliminate hardcoded credentials and store all API keys, database tokens, and certificates in dedicated secrets vaults.

##### Q20. `secrets_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:secrets_management:q1`
- **Question**: Are application credentials, API keys, and cryptographic secrets stored exclusively in a dedicated secrets manager rather than in code or configuration files?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS)

#### Node: Encryption in Transit (`data_in_transit`)
- **Implementation Groups**: `infra`
- **Description**: Enforce cryptographic protection (TLS 1.2+, HTTPS, mTLS) for all data in transit across external and internal boundaries.

##### Q21. `data_in_transit:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_in_transit:q1`
- **Question**: Is data encrypted during transit? (Specify protocols, algorithms and methods: e.g., TLS 1.2 / TLS 1.3 with AES-GCM or ChaCha20, HTTPS with HSTS, mTLS for service APIs, SSHv2, or IPsec across external and internal boundaries)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS)

#### Node: Encryption at Rest (`data_at_rest`)
- **Implementation Groups**: `infra`
- **Description**: Encrypt data at rest in databases, file systems, and backups.

##### Q22. `data_at_rest:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_at_rest:q1`
- **Question**: Is data encrypted at rest? (Specify algorithms and key management: e.g., AES-256 / AES-GCM across databases, object storage, file systems, disk volumes, and backups with centralized KMS, HSM, or TDE)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS)


<a id="sdlc_chapter"></a>
### Secure SDLC & DevSecOps Automation (`sdlc_chapter`)

*Integrate security automation into CI/CD pipelines, track dependencies and SBOMs, and verify vendor secure coding practices.*

#### Node: Automated Security Testing (SAST & DAST) (`automated_security_testing`)
- **Implementation Groups**: `custom_app`
- **Description**: Integrate automated Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) into CI/CD build pipelines.

##### Q23. `automated_security_testing:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:automated_security_testing:q1`
- **Question**: Is automated Static Application Security Testing (SAST) integrated into the CI/CD pipeline with blocking quality gates?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q24. `automated_security_testing:q2`
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

##### Q25. `supply_chain_and_dependencies:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:supply_chain_and_dependencies:q1`
- **Question**: Is Software Composition Analysis (SCA) automated in the CI/CD pipeline to detect known vulnerabilities in open-source dependencies?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q26. `supply_chain_and_dependencies:q2`
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

##### Q27. `code_review_and_ci_cd_integrity:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:code_review_and_ci_cd_integrity:q1`
- **Question**: Are mandatory peer code reviews enforced prior to merging changes into deployment branches?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Custom applications (Mandatory peer code review prior to merge)

##### Q27b. `code_review_and_ci_cd_integrity:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:code_review_and_ci_cd_integrity:q2`
- **Question**: Do repository branch protection rules block direct commits, force-pushes, and failing CI status checks on deployment branches?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Custom applications (Branch protection rules & CI quality gate enforcement)

#### Node: Vendor Secure Development & Coding Guidelines (`vendor_secure_development`)
Action - For COTS, ask if vendor follows secure coding guidelines without going into specifics (SaaS is governed under Chapter 10)
- **Implementation Groups**: `cots_app`
- **Description**: Verify that third-party COTS software vendors adhere to recognized secure coding standards and development guidelines.

##### Q28. `vendor_secure_development:q1`
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
- **Description**: Protect exposed web and API endpoints against abusive traffic, automated bots, and volumetric attacks via an edge Web Application Firewall (WAF, e.g., Cloudflare), and automated rate limiting / throttling controls. (Applicable strictly to self-hosted applications exposed to the public Internet; excluded from the SaaS questionnaire as provider implicitly manages edge protections and rate limiting; SaaS contractual network security is evaluated under Chapter 10 Section 9).

##### Q29. `api_security_and_rate_limiting:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting:q1`
- **Question**: Are internet-facing endpoints fronted by an Edge WAF and anti-DDoS / bot protection (e.g. Cloudflare, AWS WAF)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Edge WAF, anti-DDoS & bot protection)

##### Q30. `api_security_and_rate_limiting:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:api_security_and_rate_limiting:q2`
- **Question**: Are API rate limiting, throttling, and payload size quotas enforced to prevent scraping and resource exhaustion?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Rate limiting, throttling & payload quotas) 


<a id="data_lifecycle_chapter"></a>
### Data Protection & Lifecycle Governance (`data_lifecycle_chapter`)

*Govern cross-organizational data transfers (DPAs), enforce non-production data protection, and mandate compliant data retention and destruction.*

#### Node: Control of External Data Exchange (`data_exchange`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Govern external B2B data exchanges, API integrations, webhooks, and third-party data flows via formal agreements (DPA/DTA) for self-hosted applications (excluding B2C interactions, as customers do not receive data the same way B2B partners do).

##### Q31. `data_exchange:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_exchange:q1`
- **Question**: Does the application exchange data externally? (e.g., B2B transfers, automated API integrations, webhooks, or network communications with external partners, third-party vendors, or external services; Note: this excludes B2C interactions, as customers do not receive data the same way B2B partners do)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No` (100 pts, compute_result: true)
  - `Yes` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS)

##### Q32. `data_exchange:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_exchange:q2`
- **Question**: Is there a data exchange contract with the appropriate confidentiality clauses? (e.g., formal Data Processing Agreement / DPA, Data Transfer Agreement / DTA, or NDA)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:data_exchange:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:data_exchange:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `No` (0 pts)
  - `Yes` (100 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS - if data exchanged)

#### Node: Non-Production Data Protection (`non_prod_data`)
Action - Ask if non prod environments (if used) are secure identically as prod. If yes, subsequent questions do not really matter 
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Enforce strict governance over the use of production customer data in non-production environments (development, staging, QA) and mandate data sanitization and post-test purging for self-hosted applications.

##### Q33. `non_prod_data:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:non_prod_data:q1`
- **Question**: Are real production data records, live customer databases, or personal data utilized in non-production environments? (e.g., development/staging environments or QA databases)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No - Synthetic, generated, or mock test data is used exclusively` (100 pts, compute_result: true)
  - `Yes - Production data is copied or utilized for testing/staging` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q34. `non_prod_data:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:non_prod_data:q2`
- **Question**: How do you protect them? (Which sanitization or protection method is applied: cryptographic hashing, pseudonymisation/anonymization, or field-level encryption prior to ingestion)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:non_prod_data:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:non_prod_data:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `No, no protection` (0 pts)
  - `Hashing` (60 pts, compute_result: true)
  - `Pseudonymisation` (60 pts, compute_result: true)
  - `Encryption` (60 pts, compute_result: true)
  - `Masking / Anonymization` (60 pts, compute_result: true)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q35. `non_prod_data:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:non_prod_data:q3`
- **Question**: Do you clean the prod data after use in non-prod? (e.g., securely purging, sanitizing, or deleting production data once testing or troubleshooting activities conclude in non-production environments)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:non_prod_data:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:non_prod_data:q1:c2'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (40 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Compliant Data Destruction (`data_destruction`)
- **Implementation Groups**: `custom_app`, `cots_app`
- **Description**: Enforce compliant data retention schedules, end-of-life purging, and certified cryptographic erasure for self-hosted applications.

##### Q36. `data_destruction:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_destruction:q1`
- **Question**: Is there a data destruction process for this application? (e.g., documented data retention schedule and end-of-life purging procedures for self-hosted systems)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q37. `data_destruction:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:data_destruction:q2`
- **Question**: Is the process compliant with the policy (responsibilities, methods, reporting)? (e.g., defined stakeholder roles, approved cryptographic erasure or disposal methods, and verification certificates)
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:data_destruction:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:data_destruction:q1:c1'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 


<a id="logging_chapter"></a>
### Security Logging & Monitoring (`logging_chapter`)

*Log security-relevant events, mask sensitive fields, and forward telemetry to a central SIEM.*

#### Node: Security Event Logging & Data Masking (`security_event_logging`)
- **Implementation Groups**: `infra`
- **Description**: Log authentication, authorization, and administrative events while systematically masking sensitive fields.

##### Q38. `security_event_logging:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:security_event_logging:q1`
- **Question**: Does the application log key security events (failed logins, privilege escalation, administrative changes, access to sensitive assets)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q39. `security_event_logging:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:security_event_logging:q2`
- **Question**: Are sensitive data fields (passwords, payment cards, tokens, PII) systematically sanitized/masked from application, diagnostic, and error log outputs?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Centralized SIEM Forwarding & Security Alerting (`centralized_monitoring_and_alerting`)
- **Implementation Groups**: `infra`
- **Description**: Stream application logs in real-time to a centralized SIEM/SOC with anomaly detection and automated alerting.

##### Q40. `centralized_monitoring_and_alerting:q1`
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

##### Q41. `penetration_testing_and_vulnerability_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:penetration_testing_and_vulnerability_management:q1`
- **Question**: Is independent penetration testing conducted on the application and underlying infrastructure at least annually by qualified internal or external penetration testers?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Annual pentesting)

##### Q42. `penetration_testing_and_vulnerability_management:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:penetration_testing_and_vulnerability_management:q2`
- **Question**: Are identified vulnerabilities remediated within defined SLAs (e.g. Critical within 7 days, High within 30 days)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **Self-Hosted Internet-Facing only** (Remediation SLAs) 

#### Node: Backup Strategy & Disaster Recovery (`backup_and_disaster_recovery`)
- **Implementation Groups**: `infra`
- **Description**: Maintain automated encrypted backups and test restoration drills against documented RTO and RPO targets.

##### Q43. `backup_and_disaster_recovery:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:backup_and_disaster_recovery:q1`
- **Question**: Are automated and encrypted backups maintained for application state and databases?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS - Automated encrypted backups)

##### Q43a. `backup_and_disaster_recovery:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:backup_and_disaster_recovery:q2`
- **Question**: Are backup restoration and disaster recovery drills tested at least annually against documented RTO/RPO targets?
- **Type**: `unique_choice`
- **Conditional Dependency (`depends_on`)**: `{'question': 'urn:intuitem:risk:req_node:appsec:backup_and_disaster_recovery:q1', 'answers': ['urn:intuitem:risk:req_node:appsec:backup_and_disaster_recovery:q1:c1'], 'condition': 'any'}`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS - Annual DR drills & restoration testing)

#### Node: Operating System Patching & High Availability (`os_patching`)
- **Implementation Groups**: `infra`
- **Description**: Maintain operating system and platform patch hygiene within defined SLAs, and ensure system architecture allows no-downtime patching from a business perspective.

##### Q43a. `os_patching:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:os_patching:q1`
- **Question**: Are operating system (OS) security patches, kernel updates, and host/container security updates applied automatically within formal SLAs? (e.g. Critical <= 14 days, High <= 30 days)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes - OS patching is automatic` (50 pts, compute_result: true)
  - `No - OS patching is not automatic` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS - `infra`)

##### Q43b. `os_patching:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:os_patching:q2`
- **Question**: If OS patching is not automatic, is there a formal patching schedule compliant with requirements? (e.g. documented recurring maintenance windows adhering to Critical <= 14 days, High <= 30 days)
- **Type**: `unique_choice`
- **Depends On**: `os_patching:q1` == `No - OS patching is not automatic`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS - `infra`, if OS patching is not automatic)

##### Q43c. `os_patching:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:os_patching:q3`
- **Question**: Does the application and infrastructure architecture allow no-downtime patching from a business perspective? (e.g., high-availability clusters, rolling updates, or blue-green deployments preventing business downtime during maintenance)
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] Self-Hosted only (Custom & COTS - `infra`)

#### Node: COTS Deployment Hardening, Vendor Support & Patch SLAs (`cots_deployment_hardening`)
- **Implementation Groups**: `cots_app`
- **Description**: Enforce vendor hardening benchmarks, verify that COTS software actively receives vendor security patches (not End-of-Life / EOL), and deploy updates within strict patch SLAs.

##### Q44. `cots_deployment_hardening:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:cots_deployment_hardening:q1`
- **Question**: Are default vendor credentials changed, sample modules removed, and configuration hardened against vendor or CIS benchmarks?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (40 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q45. `cots_deployment_hardening:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:cots_deployment_hardening:q2`
- **Question**: Does the COTS software actively receive security patches and vulnerability updates from the vendor (under an active maintenance/support contract, not End-of-Life / EOL or End-of-Support / EOS)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (30 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q46. `cots_deployment_hardening:q3`
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

##### Q47. `saas_contract_compliance:q1`
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

##### Q48. `saas_governance_and_policy:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_governance_and_policy:q1`
- **Question**: Does the contract require and does the provider maintain an Information Security Policy based on a recognized framework (such as ISO 27001), updated at least annually?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q49. `saas_governance_and_policy:q2`
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
- **Description**: Enforce vendor personnel confidentiality (NDAs), customer data access controls, and data encryption mandated in the contract (in transit and at rest).

##### Q50. `saas_confidentiality_and_data_protection:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_confidentiality_and_data_protection:q1`
- **Question**: Does the contract require vendor personnel to sign confidentiality agreements (NDAs) and restrict access to customer data (e.g. requiring client approval before vendor support or engineering can access tenant data)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q51. `saas_confidentiality_and_data_protection:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_confidentiality_and_data_protection:q2`
- **Question**: Does the contract mandate data encryption for all customer data, both in transit (e.g. TLS/HTTPS) and at rest (e.g. AES-256)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Security Awareness & Training (`saas_security_awareness`)
- **Implementation Groups**: `saas_app`
- **Description**: Conduct annual cybersecurity training for all personnel, covering risks, data breaches, and incident escalation procedures.

##### Q52. `saas_security_awareness:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_security_awareness:q1`
- **Question**: Does the contract require and are vendor personnel trained and sensitized to cybersecurity risks, data breaches, and non-compliance consequences at least annually?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q53. `saas_security_awareness:q2`
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

##### Q54. `saas_iam:q1`
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

##### Q55. `saas_entitlements_and_privileges:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_entitlements_and_privileges:q1`
- **Question**: Does the contract require and does the provider apply least privilege and Role-Based Access Control (RBAC), restricting admin rights and maintaining an inventory of privileged accounts across its internal personnel?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] **SaaS only** (Provider staff least privilege & RBAC)

##### Q56. `saas_entitlements_and_privileges:q2`
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

##### Q57. `saas_logging_and_incidents:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_logging_and_incidents:q1`
- **Question**: Does the contract require and does the SaaS solution record tamper-resistant logs of logins, logouts, access, and administrative actions, with continuous monitoring and audit telemetry export into the client SIEM?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q58. `saas_logging_and_incidents:q2`
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

##### Q59. `saas_workstation_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_workstation_security:q1`
- **Question**: Does the contract require and are provider workstations protected by session auto-lock after inactivity, active local firewalls, hardened configurations, and updated EDR/antivirus?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q60. `saas_workstation_security:q2`
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

##### Q61. `saas_mobile_security:q1`
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

##### Q62. `saas_network_security:q1`
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
- **Description**: Ensure multi-tenant environment isolation, logical data segregation, and network traffic filtering.

##### Q63. `saas_environment_isolation:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_environment_isolation:q1`
- **Question**: Does the contract require and does the SaaS architecture enforce robust logical or physical client environment isolation, traffic filtering, and antimalware defenses?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Development Security & Secure SDLC (`saas_secure_development`)
- **Implementation Groups**: `saas_app`
- **Description**: Manage source code in secure repositories, mandate peer code reviews, separate dev/test/prod, and enforce secure SDLC and supply chain gates.

##### Q64. `saas_secure_development:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_secure_development:q1`
- **Question**: Does the contract require and is source code stored in secure repositories with mandatory peer reviews and strict segregation between development, test, and production environments?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q65. `saas_secure_development:q2`
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

##### Q66. `saas_web_app_security:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_web_app_security:q1`
- **Question**: Does the contract require and are web services protected with TLS 1.2+ minimum, network ports restricted to the strict minimum, and administrative interfaces strictly controlled?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: SaaS Contractual Vulnerability Remediation SLAs (`saas_vulnerability_remediation_sla`)
- **Implementation Groups**: `saas_uncertified`
- **Description**: Enforce contractually binding vulnerability remediation SLAs for security flaws discovered in the SaaS platform.

##### Q68. `saas_vulnerability_remediation_sla:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_vulnerability_remediation_sla:q1`
- **Question**: Does the SaaS contract commit the provider to formal vulnerability remediation SLAs (e.g. Critical within 7 days, High within 30 days)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Data Hosting, European Residency & GDPR Compliance (`saas_data_hosting_and_residency`)
- **Implementation Groups**: `saas_app`
- **Description**: Host data primarily within the European Union (EU) or European Economic Area (EEA) and ensure comprehensive contractual GDPR compliance under Article 28.

##### Q69. `saas_data_hosting_and_residency:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_data_hosting_and_residency:q1`
- **Question**: Does the contract mandate that all customer data (including primary databases, processing pipelines, and backups) be hosted primarily within the European Union (EU) or European Economic Area (EEA)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (20 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] SaaS applications (EU/EEA Data Hosting)

##### Q69b. `saas_data_hosting_and_residency:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_data_hosting_and_residency:q2`
- **Question**: Is a formal Data Processing Agreement (DPA) executed with the vendor that incorporates all mandatory GDPR Article 28 clauses (processing only on documented instructions, personnel confidentiality commitments, and statutory security measures)?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (20 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] SaaS applications (GDPR DPA & Article 28 mandatory clauses)

##### Q69c. `saas_data_hosting_and_residency:q3`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_data_hosting_and_residency:q3`
- **Question**: Does the contract mandate prior written authorization or advance notice before engaging or replacing sub-processors, granting the customer a legally enforceable right to object or terminate?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (20 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] SaaS applications (Sub-processor change notification & objection rights)

##### Q69d. `saas_data_hosting_and_residency:q4`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_data_hosting_and_residency:q4`
- **Question**: Does the contract or DPA establish a binding obligation for the vendor to notify the customer without undue delay (within 24 to 48 hours maximum) following the discovery of a suspected or confirmed personal data breach?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (20 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] SaaS applications (Personal data breach notification SLA)

##### Q69e. `saas_data_hosting_and_residency:q5`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_data_hosting_and_residency:q5`
- **Question**: Does the vendor provide technical mechanisms or contractual commitments to assist the customer in fulfilling Data Subject Rights (access, rectification, erasure, portability) and ensure complete data deletion or return upon contract termination?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (20 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [x] SaaS applications (Data subject rights assistance & post-termination data return/deletion) 

#### Node: Physical & Environmental Security (`saas_physical_security`)
- **Implementation Groups**: `saas_app`
- **Description**: Control physical access to premises, protect sensitive zones, retain access traces, protect IT equipment, and regularly review authorizations.

##### Q70. `saas_physical_security:q1`
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

##### Q71. `saas_backup_and_business_continuity:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_backup_and_business_continuity:q1`
- **Question**: Does the contract require and are automated backups encrypted, immutable, and verified through regular documented restoration tests?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q72. `saas_backup_and_business_continuity:q2`
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

##### Q73. `saas_subcontractor_management:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_subcontractor_management:q1`
- **Question**: Does the contract mandate and does the vendor maintain a formal subcontractor vetting process with documented compliance verification, while assuming full liability for all downstream subcontractors?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: Audit Rights, Penetration Testing & Compliance Verification (`saas_audit_and_compliance`)
- **Implementation Groups**: `saas_app`
- **Description**: Contractually grant the client (or an independent auditor mandated by the client) the right to audit the provider, obtain compliance evidence verifying adherence to contractual security obligations, and govern independent penetration testing of the SaaS platform.

##### Q74. `saas_audit_and_compliance:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q1`
- **Question**: Does the contract legally grant the client (or an authorized independent third party) the right to audit the provider and obtain compliance evidence to verify adherence to contractual security obligations?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (50 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q74b. `saas_audit_and_compliance:q2`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_audit_and_compliance:q2`
- **Question**: How is independent penetration testing governed and performed on the SaaS platform?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `We are allowed to pentest (SaaS contract authorizes customer-led penetration testing)` (50 pts, compute_result: true)
  - `The SaaS vendor does the pentest (contract mandates that the vendor undergoes annual independent penetration tests and provides audit reports/attestations)` (50 pts, compute_result: true)
  - `They refuse (the SaaS vendor refuses penetration testing and provides no reports)` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

#### Node: PCI DSS Payment Security (`saas_pci_dss`)
- **Implementation Groups**: `saas_app`
- **Description**: Maintain PCI DSS certification for payment data environments, provide annual AOCs, implement dedicated cardholder incident procedures, and immediately notify payment incidents.

##### Q75. `saas_pci_dss:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_pci_dss:q1`
- **Question**: Does the application process, store, or transmit payment card data?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `No - Out of scope / Not applicable` (100 pts, compute_result: true)
  - `Yes - Payment data is processed` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

##### Q76. `saas_pci_dss:q2`
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

##### Q77. `saas_non_conformity_remediation:q1`
- **URN**: `urn:intuitem:risk:req_node:appsec:saas_non_conformity_remediation:q1`
- **Question**: Does the contract mandate formal remediation plans and compensatory measures for identified security gaps, with explicit rights to suspend access or terminate for repeated breaches?
- **Type**: `unique_choice`
- **Choices & Scoring**:
  - `Yes` (100 pts, compute_result: true)
  - `No` (0 pts)
- **Applicable Cases / Situations**:
  - [ ] 

