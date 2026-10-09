# Application Security Policy & Contextual Requirements Applicability Matrix

## 1. Executive Summary & Policy Scope

This document establishes the **Application Security Policy (AppSec)** and the **Contextual Applicability Matrix** governing all software applications across the organization.

The objective of this framework is to enforce defense-in-depth while eliminating irrelevant security requirements based on the application's operational context. Requirements are dynamically tailored according to four primary context dimensions:
1. **Software Delivery & Hosting Model**: Custom software (In-house) vs. Bought software (COTS deployed internally) vs. SaaS (Third-party hosted).
2. **Data Classification**: Public, Internal, Confidential, or Secret.
3. **Network Exposure**: Internal/Restricted vs. Internet-Facing.
4. **Authentication Architecture**: Enterprise SSO Federation vs. Direct Application Authentication.

---

## 2. Software Delivery & Hosting Responsibility Model

The operational boundary between software development and infrastructure hosting determines which technical controls are enforceable:

```
+---------------------------------------------------------------------------------------+
| SHARED RESPONSIBILITY ARCHITECTURE                                                   |
+--------------------------+------------------------------+-----------------------------+
| Delivery Model           | Software Development Tier    | Infrastructure Hosting Tier |
+--------------------------+------------------------------+-----------------------------+
| Custom Software          | Internal Engineering Teams   | Internal Infrastructure     |
| (In-House Development)   | (Full Code & Pipeline Scope) | (Full Hosting Scope)        |
+--------------------------+------------------------------+-----------------------------+
| Bought Software (COTS)   | Third-Party Vendor           | Internal Infrastructure     |
| (Deployed by my teams)   | (No source code access)      | (Full Hosting Scope)        |
+--------------------------+------------------------------+-----------------------------+
| SaaS Platform            | Third-Party Vendor           | Third-Party Cloud           |
| (Vendor Operated)        | (Contractual & SOC 2 Scope)  | (Contractual & SOC 2 Scope) |
+--------------------------+------------------------------+-----------------------------+
```

### Responsibility Principles
- **Custom Software (In-House)**: The organization controls **both development and hosting**. Subject to full shift-left DevSecOps (SAST, DAST, SCA, SBOM, peer reviews), code hygiene (parameterized queries, input schemas, output encoding, debug suppression), and infrastructure hardening.
- **Bought Software (COTS)**: The organization controls **only hosting**, not development. Requirements regarding internal source-code programming, session token generation algorithms, and CI/CD development pipelines are strictly **out of scope**. Security focuses on IAM federation/MFA, secrets manager injection, TLS in transit, database encryption at rest, centralized SIEM logging, backup/DR resilience, and external penetration testing.
- **SaaS Platforms**: The organization controls **neither development nor hosting**. Technical questions across Chapters 2 through 9 are superseded by **Chapter 10 (SaaS Vendor Security Exhibit)**, verifying vendor commitments via contracts (MSA/DPA), SOC 2 Type II reports, ISO 27001 certifications, and independent penetration testing summaries.

---

## 3. Dynamic Selection Mechanisms in CISO Assistant

The framework evaluates context through two complementary mechanisms:

### A. Implementation Groups (IGs) — Node-Level Scoping
Requirement nodes are assigned to native CISO Assistant Implementation Groups, ensuring clean inclusion or complete exclusion without blank/empty questionnaire forms:
- `info`: Application profiling and governance (active by default).
- `custom_app`: Custom software track (in-house development: session management, Chapter 3 code hygiene, Chapter 5 DevSecOps).
- `cots_app`: Bought software track (COTS / vendor package deployment).
- `saas_app`: SaaS application track (Chapter 10 contractual governance).
- `baseline`: Application security technical baseline applicable to self-hosted applications (Custom & COTS).
- `confidential_app`: Triggered when Data Classification is **Confidential** or **Secret**.
- `secret_app`: Triggered exclusively when Data Classification is **Secret**.
- `internet_facing`: Triggered when Network Exposure is **Internet-Facing**.

Profiling triggers in `hosting:q1` dynamically activate the tracks:
- **Custom Software**: Activates `custom_app` and `baseline`.
- **Bought Software (COTS)**: Activates `cots_app` and `baseline`.
- **SaaS**: Activates `saas_app`.

### B. Dynamic Dependencies (`depends_on`) — Question-Level Scoping
Within active requirement nodes, questions are dynamically conditioned using intra-node dependencies:
- **SSO vs. Direct Auth Dependency**: When Enterprise SSO is active, questions regarding direct password complexity and direct MFA are automatically hidden.
- **Sub-process Dependencies**: Secondary questions (e.g., non-prod data sanitization methods, DPA contract verification, PCI DSS AOC) only appear if the respondent confirms the primary activity.

---

## 4. Policy Rules & Requirements by Chapter

### Chapter 1: Application Information, Governance & Scoping
- **`instructions_splash`**: Guidance splash screen detailing assessment expectations.
- **`stakeholder_identification`**: Mandatory documentation of Business Owner, Technical Owner, and Information Security Officer (CISO/SecOps delegate).
- **`data_classification`**: Formally categorizes data assets into Public, Internal, Confidential, or Secret.
- **`hosting`**: Discriminates between Custom (In-house), Bought (COTS), and SaaS.
- **`network_exposure`**: Identifies whether the application is restricted to internal corporate networks or exposed to the public Internet.

### Chapter 2: Identity, Authentication & Access Control (IAM)
- **`authentication_and_mfa`** (`baseline`, `custom_app`, `cots_app`):
  - `q1`: Mandates Enterprise SSO federation (SAML 2.0 / OIDC) as primary authentication standard.
  - `q2`: If Direct Authentication is used, enforces strong password complexity and brute-force lockout.
  - `q3`: If Direct Authentication is used, enforces Multi-Factor Authentication (MFA) for administrative and privileged users.
- **`access_control_and_rbac`** (`baseline`, `custom_app`, `cots_app`):
  - `q1`: Enforces granular Role-Based / Attribute-Based Access Control (RBAC/ABAC) and least privilege across business functions and APIs.
  - `q2`: Mandates integration with Enterprise Identity Governance & Administration (IGA / SailPoint).
  - `q3`: Enforces periodic access recertifications (annual standard, semi-annual privileged).
- **`session_management`** (`custom_app` only):
  - `q1`: Enforces cryptographically secure session tokens, `HttpOnly`, `Secure`, `SameSite` cookie flags, and idle session timeouts.

### Chapter 3: Application Vulnerability Defense & Code Hygiene
- **`input_validation_and_injection_defense`** (`custom_app` only):
  - `q1`: Strict server-side schema validation and allow-lists.
  - `q2`: Parameterized queries, prepared statements, or ORMs preventing SQL/NoSQL injection.
- **`output_encoding_and_web_defenses`** (`custom_app` only):
  - `q1`: Context-aware output encoding across dynamic UI templates preventing XSS.
  - `q2`: Standard HTTP security response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) in application middleware.
- **`error_handling_and_info_leakage`** (`custom_app` only):
  - `q1`: Production debug modes (`DEBUG=False`) and detailed stack traces disabled with generic error handlers.

### Chapter 4: Cryptography & Secrets Management
- **`secrets_management`** (`baseline`, `custom_app`, `cots_app`):
  - `q1`: Application secrets, API keys, and database credentials stored in a dedicated secrets manager (Vault, AWS Secrets Manager); zero hardcoded secrets.
- **`data_in_transit`** (`confidential_app`, `secret_app`):
  - `q1`: Mandates TLS 1.2+ with strong cipher suites (AES-GCM, ChaCha20) across all external and internal transmission channels.
- **`data_at_rest`** (`confidential_app`, `secret_app`):
  - `q1`: Mandates AES-256 encryption at rest across databases, block storage, and object stores.
- **`data_exchange`** (`confidential_app`, `secret_app`):
  - `q1`: Formally controls external data exchanges and API integrations.
  - `q2`: Enforces formal data transfer agreements (DPA/DTA/NDA) when external exchange is active.

### Chapter 5: Secure SDLC & DevSecOps
- **`automated_security_testing`** (`custom_app` only):
  - `q1`: Automated Static Application Security Testing (SAST) in CI/CD with blocking quality gates.
  - `q2`: Automated Dynamic Application Security Testing (DAST) or API scanning prior to release.
- **`supply_chain_and_dependencies`** (`custom_app` only):
  - `q1`: Automated Software Composition Analysis (SCA) for open-source libraries.
  - `q2`: Generation and auditing of Software Bill of Materials (SBOM) for releases.
- **`code_review_and_ci_cd_integrity`** (`custom_app` only):
  - `q1`: Mandatory peer code review and protected branch policies before merging.

### Chapter 6: API Security & Gateway Protections
- **`api_security_and_rate_limiting`** (`baseline`, `custom_app`, `cots_app`, `internet_facing`):
  - `q1`: Edge Web Application Firewall (WAF, e.g., Cloudflare, AWS WAF), bot protection, and automated rate limiting / throttling controls.
  - `q2`: API payload strict validation against documented API specifications (OpenAPI / JSON schema).

### Chapter 7: Data Lifecycle & Sanitization
- **`non_prod_data`** (`confidential_app`, `secret_app`):
  - `q0`: Identifies if production data is copied or utilized in non-production environments.
  - `q1`: Restricts production data use to authorized testing scopes.
  - `q2`: Enforces cryptographic masking, pseudonymisation, or field-level encryption on non-prod data.
  - `q3`: Enforces prompt post-testing data deletion.
- **`data_destruction`** (`confidential_app`, `secret_app`):
  - `q1`: Formally verifies application data retention and certified destruction requirements.
  - `q2`: Enforces compliance with certified cryptographic erasure methods and disposal certificates.

### Chapter 8: Security Logging & Monitoring
- **`security_event_logging`** (`baseline`, `custom_app`, `cots_app`):
  - `q1`: Comprehensive audit logging of authentication, authorization, and administrative actions.
  - `q2`: Systematic masking of sensitive fields (passwords, tokens, card numbers) from log outputs.
- **`centralized_monitoring_and_alerting`** (`baseline`, `custom_app`, `cots_app`):
  - `q1`: Near-real-time streaming of security telemetry to corporate SIEM/SOC with active alerting rules.

### Chapter 9: Penetration Testing & Operational Resilience
- **`penetration_testing_and_vulnerability_management`** (`baseline`, `custom_app`, `cots_app`, `internet_facing`, `saas_app`):
  - `q1`: Independent annual penetration testing governed contractually for SaaS (we are allowed to pentest, SaaS vendor does the pentest, or they refuse) or conducted annually for internal apps.
  - `q2`: Strict vulnerability remediation SLAs (Critical <= 7d, High <= 30d, contractually committed for SaaS).
- **`backup_and_disaster_recovery`** (`baseline`, `custom_app`, `cots_app`):
  - `q1`: Automated, encrypted backups, annual restoration testing, and documented RTO/RPO targets.

### Chapter 10: SaaS Requirements & Vendor Security Exhibit
- **`saas_contract_compliance`**: Execution of Master Agreement and Security Schedules (SaaS MSA and binding Security Exhibit). Detailed technical clauses (audit, incidents, IAM, confidentiality) are merged into their respective sections.
- **`saas_governance_and_policy`**: Documented Information Security Policy and formal annual management reviews.
- **`saas_confidentiality_and_data_protection`**: Vendor employee NDAs and tenant-isolated encryption.
- **`saas_security_awareness`**: Mandatory annual cybersecurity training for vendor personnel.
- **`saas_iam`**: Mandatory Enterprise SSO federation or robust tenant identity policies.
- **`saas_entitlements_and_privileges`**: Vendor least privilege, administrative account inventory, and support for enterprise IGA (SailPoint).
- **`saas_logging_and_incidents`**: Immutable vendor audit logs, 48h breach notification SLA, and SIEM streaming API.
- **`saas_workstation_security`**: Hardened vendor laptops, EDR, full-disk encryption, and patch compliance.
- **`saas_mobile_security`**: Mobile Device Management (MDM) on vendor devices accessing customer tenant data.
- **`saas_network_security`**: Vendor WAF, anti-DDoS protection (Cloudflare, AWS WAF, etc.), and network segregation.
- **`saas_environment_isolation`**: Strict logical tenant isolation preventing cross-tenant data leakage.
- **`saas_secure_development`**: Vendor DevSecOps, peer review, and secure coding practices.
- **`saas_web_app_security`**: Annual vendor third-party penetration testing letters and remediation SLAs.
- **`saas_data_exchange_security`**: TLS 1.2+ encryption on vendor external APIs and data transfers.
- **`saas_data_hosting_and_residency`**: Documented cloud hosting regions and European data residency compliance.
- **`saas_physical_security`**: Tier III+ datacenter physical security and environmental protections.
- **`saas_backup_and_business_continuity`**: Daily immutable vendor backups and tested Disaster Recovery plans.
- **`saas_secure_data_destruction`**: Certified post-contract data purge and destruction certificates.
- **`saas_subcontractor_management`**: Sub-Processor auditing, security flow-down clauses, and prior notification of changes.
- **`saas_audit_and_compliance`**: Annual SOC 2 Type II / ISO 27001 third-party audit reports provided to customer.
- **`saas_pci_dss`**: Valid PCI DSS Attestation of Compliance (AOC) if payment card data is processed.
- **`saas_non_conformity_remediation`**: Contractual remediation timeframes and termination rights for security non-compliance.

---

## 5. Requirements Applicability Matrix

The table below defines the exact applicability criteria for every requirement and question in the framework:

| Chapter | Requirement Ref ID | Requirement Name | Implementation Groups | Delivery Scope | Sensitivity Scope | Exposure Scope | Dynamic Condition (`depends_on`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **0. Splash** | `instructions_splash` | Instructions & Guidance | `info` | All | All | All | None (Always visible) |
| **1. Profile** | `stakeholder_identification` | Stakeholder Identification | `info` | All | All | All | None |
| **1. Profile** | `data_classification` | Application Data Classification | `info` | All | All | All | None |
| **1. Profile** | `hosting` | Delivery & Hosting Model | `info` | All | All | All | None |
| **1. Profile** | `network_exposure` | Application Network Exposure | `info` | All | All | All | None |
| **2. IAM** | `authentication_and_mfa` (q1) | Authentication Mode (SSO vs Direct) | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **2. IAM** | `authentication_and_mfa` (q2) | Password Policy & Lockout | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | `q1 == Direct Authentication` |
| **2. IAM** | `authentication_and_mfa` (q3) | Admin MFA Enforcement | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | `q1 == Direct Authentication` |
| **2. IAM** | `access_control_and_rbac` (q1) | Granular RBAC & Least Privilege | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **2. IAM** | `access_control_and_rbac` (q2) | Enterprise IGA (SailPoint) Connector | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **2. IAM** | `access_control_and_rbac` (q3) | Periodic Access Recertifications | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **2. IAM** | `session_management` (q1) | Cryptographic Session Tokens & Cookies | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **3. Defenses** | `input_validation_and_injection_defense` (q1) | Server-Side Input Schema Validation | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **3. Defenses** | `input_validation_and_injection_defense` (q2) | Parameterized Queries / ORMs | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **3. Defenses** | `output_encoding_and_web_defenses` (q1) | Context-Aware Output Encoding (XSS) | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **3. Defenses** | `output_encoding_and_web_defenses` (q2) | HTTP Security Headers (CSP, HSTS) | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **3. Defenses** | `error_handling_and_info_leakage` (q1) | Debug Modes & Stack Traces Disabled | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **4. Crypto** | `secrets_management` (q1) | Centralized Secrets Vault | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **4. Crypto** | `data_in_transit` (q1) | Encryption in Transit (TLS 1.2+) | `confidential_app`, `secret_app` | All | **Confidential, Secret** | All | Active if Data Class >= Confidential |
| **4. Crypto** | `data_at_rest` (q1) | Encryption at Rest (AES-256) | `confidential_app`, `secret_app` | All | **Confidential, Secret** | All | Active if Data Class >= Confidential |
| **4. Crypto** | `data_exchange` (q1) | External Data Exchange Tracking | `confidential_app`, `secret_app` | All | **Confidential, Secret** | All | Active if Data Class >= Confidential |
| **4. Crypto** | `data_exchange` (q2) | Data Exchange Contract (DPA/DTA) | `confidential_app`, `secret_app` | All | **Confidential, Secret** | All | `data_exchange:q1 == Yes` |
| **5. SDLC** | `automated_security_testing` (q1) | Automated SAST in CI/CD | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **5. SDLC** | `automated_security_testing` (q2) | Automated DAST / API Scanning | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **5. SDLC** | `supply_chain_and_dependencies` (q1) | Automated SCA for Dependencies | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **5. SDLC** | `supply_chain_and_dependencies` (q2) | Audited Release Artifact SBOM | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **5. SDLC** | `code_review_and_ci_cd_integrity` (q1) | Peer Code Review & Branch Protection | `custom_app` | **Custom Only** | All | All | **Active exclusively if custom_app is selected** |
| **6. API** | `api_security_and_rate_limiting` (q1) | Edge WAF, Bot Protection & Rate Limiting | `baseline`, `custom_app`, `cots_app`, `internet_facing` | Custom, COTS | All | **Internet-Facing** | Active if Network Exposure == Internet |
| **6. API** | `api_security_and_rate_limiting` (q2) | OpenAPI / Schema Validation | `baseline`, `custom_app`, `cots_app`, `internet_facing` | Custom, COTS | All | **Internet-Facing** | Active if Network Exposure == Internet |
| **7. Lifecycle**| `non_prod_data` (q0) | Production Data in Non-Prod Use | `confidential_app`, `secret_app` | Custom, COTS | **Confidential, Secret** | All | Active if Data Class >= Confidential |
| **7. Lifecycle**| `non_prod_data` (q1-q3) | Non-Prod Masking & Data Purging | `confidential_app`, `secret_app` | Custom, COTS | **Confidential, Secret** | All | `non_prod_data:q0 == Yes` |
| **7. Lifecycle**| `data_destruction` (q1) | Certified Data Destruction Policy | `confidential_app`, `secret_app` | All | **Confidential, Secret** | All | Active if Data Class >= Confidential |
| **7. Lifecycle**| `data_destruction` (q2) | Destruction Process & Certificate | `confidential_app`, `secret_app` | All | **Confidential, Secret** | All | `data_destruction:q1 == Yes` |
| **8. Logging** | `security_event_logging` (q1-q2) | Security Event Logging & Data Masking | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **8. Logging** | `centralized_monitoring_and_alerting` (q1)| Real-Time SIEM/SOC Forwarding | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **9. Resilience**| `penetration_testing_and_vulnerability_management` (q1-q2)| Annual Pentesting Governance & Remediation SLAs | `baseline`, `custom_app`, `cots_app`, `internet_facing`, `saas_app` | Custom, COTS, SaaS | All | **Internet-Facing** | Active if Network Exposure == Internet (or SaaS) |
| **9. Resilience**| `backup_and_disaster_recovery` (q1) | Immutable Backups & DR Testing | `baseline`, `custom_app`, `cots_app` | Custom, COTS | All | All | None |
| **10. SaaS** | `saas_contract_compliance` (q1)| SaaS Agreement & Schedules | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_governance_and_policy` | Security Policy & Management Review | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_confidentiality_and_data_protection` | Staff NDAs & Tenant Encryption | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_security_awareness` | Annual Security Awareness Training | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_iam` (q1-q4) | SSO / Password / MFA Controls | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_entitlements_and_privileges` | Privilege Governance & IGA | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_logging_and_incidents` | 48h Breach SLA & Audit Telemetry | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_workstation_security` | Vendor Endpoint EDR & Encryption | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_mobile_security` | Vendor MDM & Containerization | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_network_security` | Edge Anti-DDoS & WAF Protection | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_environment_isolation` | Multi-Tenant Data Isolation | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_secure_development` | Vendor DevSecOps & SDLC Guarantees | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_web_app_security` | Vendor Pentest Letters & Bug Bounty | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_data_exchange_security` | Vendor TLS 1.2+ Transport Security | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_data_hosting_and_residency` | EU Residency & Cloud Boundaries | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_physical_security` | Datacenter Physical Security | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_backup_and_business_continuity` | Daily Backups & Tested DR | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_secure_data_destruction` | Certified Post-Contract Purge | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_subcontractor_management` | Sub-Processor Auditing & Notice | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_audit_and_compliance` | SOC 2 Type II / ISO 27001 Audit Reports| `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **10. SaaS** | `saas_pci_dss` (q1-q2) | PCI DSS AOC (if payment cards) | `saas_app` | **SaaS Only** | All | All | `saas_pci_dss:q1 == Card data processed` |
| **10. SaaS** | `saas_non_conformity_remediation` | Contractual Remedies & SLAs | `saas_app` | **SaaS Only** | All | All | **Active exclusively if saas_app is selected** |
| **End** | `thank_you_splash` | Assessment Completion Splash | `info` | All | All | All | None (Always visible) |

---

## 6. Auditor Quick Verification Checklist

When reviewing an assessment in CISO Assistant, verify the questionnaire selection with this checklist:

1. **If assessing a Custom In-House Application (`hosting:q1 == Custom`):**
   - [x] Chapter 2 `session_management` is **VISIBLE** (code-level cryptographic token generation, idle timeout, secure cookie flags).
   - [x] Chapter 3 `input_validation`, `output_encoding`, and `error_handling` are **VISIBLE** (server-side schemas, parameterized queries, and code `DEBUG=False`).
   - [x] Chapter 5 `automated_security_testing`, `supply_chain_and_dependencies`, and `code_review_and_ci_cd_integrity` are **VISIBLE** (CI/CD SAST/DAST, SCA/SBOM, and branch protection).
   - [x] Shared hosting chapters (Chapter 2 IAM SSO/MFA/RBAC, Chapter 4 Secrets, Chapter 8 Logging, Chapter 9 Backups/DR) are **VISIBLE**.
   - [x] Chapter 10 (SaaS Track) is **EXCLUDED**.

2. **If assessing a Bought Software / COTS Application (`hosting:q1 == Bought`):**
   - [x] Chapter 2 `session_management` is **EXCLUDED** (source-code session generation out of scope for COTS).
   - [x] Chapter 3 code hygiene (`input_validation`, `output_encoding`, `error_handling`) is **EXCLUDED** (source-code programming out of scope for COTS).
   - [x] Chapter 5 SDLC (`automated_security_testing`, `supply_chain_and_dependencies`, `code_review`) is **EXCLUDED** (source-code CI/CD pipelines out of scope for COTS).
   - [x] Shared hosting chapters (Chapter 2 IAM SSO/MFA/RBAC, Chapter 4 Secrets, Chapter 8 Logging, Chapter 9 Backups/DR) are **VISIBLE**.
   - [x] Chapter 10 (SaaS Track) is **EXCLUDED**.

3. **If assessing a SaaS Platform (`hosting:q1 == SaaS`):**
   - [x] Chapter 10 (SaaS Track, 22 requirement nodes) is **ACTIVATED and VISIBLE** (governed via MSA/DPA/SLA contracts, SOC 2 Type II reports, and third-party pentest attestations).
   - [x] Internal hosting and development chapters (Chapters 2, 3, 5, 8, 9) are **EXCLUDED**.

4. **If assessing an Application handling Public or Internal data (`Data Classification <= Internal`):**
   - [x] Encryption in transit (`data_in_transit`) is **EXCLUDED**.
   - [x] Encryption at rest (`data_at_rest`) is **EXCLUDED**.
   - [x] Non-production data sanitization (`non_prod_data`) is **EXCLUDED**.
   - [x] Certified data destruction (`data_destruction`) is **EXCLUDED**.

5. **If assessing an Application handling Confidential or Secret data (`Data Classification >= Confidential`):**
   - [x] Encryption in transit, encryption at rest, data exchange governance, non-prod data masking, and certified destruction are **ACTIVATED and VISIBLE**.
