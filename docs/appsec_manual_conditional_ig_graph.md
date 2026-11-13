# Conditional Implementation Group (IG) Graph & Application Example Suite — Merged AppSec Framework

This document details the complete conditional Implementation Group (IG) state machine, intra-node question dependencies (`depends_on`), requirement scoping, and risk scenario scoping for **`YML/appsec.yml`** and **`YML/appsec_manual.yml`** (**Application Security Assessment Framework - Merged Model**).

> [!NOTE]
> **Unified Framework Model**: Both `appsec.yml` and `appsec_manual.yml` share the exact same conditional logic:
> - **Profiling Questions (`hosting:q1`–`q2`)**: Determine the delivery model and network exposure without directly activating implementation groups.
> - **Dynamic Track Assignment Questions (`hosting:q4`–`q9` in Chapter 1, `saas_contract_compliance:q3` in Chapter 10)**: Unlocked via intra-node `depends_on`.
>   - If respondent selects `c1` (*"I can answer this track"*): CISO Assistant triggers the Implementation Group dynamically via `select_implementation_groups: ["<track>"]`. The track is active and omitted from `pending_dependencies`.
>   - If respondent selects `c2` (*"Somebody else has to answer this track"*): `select_implementation_groups` is absent. Dedicated text field (`_delegate`) appears dynamically so the respondent can designate who can answer (name, email, or team). The track remains pending in the orchestrator under `pending_dependencies`, enriched with the delegate contact information for dispatching.

---

## 1. Implementation Groups Overview (8 Total)

| IG `ref_id` | IG Name | `default_selected` | Activation Mode | Assessable Nodes |
| :--- | :--- | :---: | :--- | :---: |
| `info` | **Application information & Governance** | `true` | Always active initially (`always_selectable_groups`) | **3** |
| `baseline` | **Application Security Baseline** | `false` | Triggered by `hosting:q1` $\in \{c_1, c_2, c_3\}$ | **2** |
| `custom_app` | **Custom Software Track (In-house Development)** | `false` | Triggered by `hosting:q1` $= c_1$ | **9** *(6 exclusive + 3 shared with `cots_app`)* |
| `cots_app` | **Bought Software Track (COTS / Vendor Package)** | `false` | Triggered by `hosting:q1` $= c_2$ | **5** *(2 exclusive + 3 shared with `custom_app`)* |
| `infra` | **Infrastructure & Hosting Security Track** | `false` | Triggered by `hosting:q1` $\in \{c_1, c_2\}$ | **7** |
| `internet_facing` | **Internet-Facing Application Track** | `false` | Triggered by `hosting:q2` $= c_2$ (when `hosting:q1` $\in \{c_1, c_2\}$) | **2** |
| `saas_app` | **SaaS Application Track** | `false` | Triggered by `hosting:q1` $= c_3$ | **7** |
| `saas_uncertified` | **Uncertified SaaS Vendor Track (Detailed Security Assessment)** | `false` | Triggered by `saas_contract_compliance:q2` $= c_2$ (in `saas_app`) | **14** |

> [!NOTE]
> Three requirement nodes (`data_exchange`, `non_prod_data`, and `data_destruction`) belong to both `custom_app` and `cots_app` (`implementation_groups: ["custom_app", "cots_app"]`). Therefore, the total number of distinct assessable requirement nodes across all 8 Implementation Groups is $3 + 2 + 6 + 2 + 3 + 7 + 2 + 7 + 14 = 46$.

---

## 2. Conditional IG Decision & Dependency Graph

Framework-level `implementation_groups_dependencies` rules originate from the **`hosting`** requirement node (`urn:intuitem:risk:req_node:appsec_manual:hosting`) inside the initial **`info`** Implementation Group, and from **`saas_contract_compliance`** (`urn:intuitem:risk:req_node:appsec_manual:saas_contract_compliance`) in the **`saas_app`** Implementation Group:

```mermaid
flowchart TD
    Start(["Audit Initialized<br/>Active IG: <b>info</b> (3 nodes)<br/>Hidden IGs: 7"]) --> Q1

    subgraph INFO_IG ["Initial Profiling IG: info"]
        Q1{"<b>hosting:q1</b><br/>What is the delivery and<br/>hosting model of the application?"}
        Q2{"<b>hosting:q2</b><br/>What is the network exposure?<br/><i>(depends_on: q1 in [c1, c2])</i>"}
    end

    subgraph SAAS_TRACK ["SaaS Track IG: saas_app"]
        Q3{"<b>saas_contract_compliance:q2</b><br/>Is the SaaS vendor ISO 27001<br/>or SOC 2 Type II certified?"}
    end

    %% Branch 1: Custom Software (c1)
    Q1 -->|"c1: Custom software<br/>(In-house development)"| TrigCustom["Triggers IGs:<br/>+ <b>baseline</b><br/>+ <b>custom_app</b><br/>+ <b>infra</b>"]
    TrigCustom --> Q2

    %% Branch 2: COTS Software (c2)
    Q1 -->|"c2: Bought software<br/>(COTS / Vendor package)"| TrigCOTS["Triggers IGs:<br/>+ <b>baseline</b><br/>+ <b>cots_app</b><br/>+ <b>infra</b>"]
    TrigCOTS --> Q2

    %% Branch 3: SaaS (c3)
    Q1 -->|"c3: SaaS<br/>(Third-party hosted)"| TrigSaaS["Triggers IGs:<br/>+ <b>baseline</b><br/>+ <b>saas_app</b>"]
    TrigSaaS --> Q3

    %% Exposure outcomes for Custom & COTS
    Q2 -->|"c1: Internal / Restricted<br/>Network only"| NoExtraNet["No additional IG triggered"]
    Q2 -->|"c2: Internet-facing<br/>(Public Web / Mobile API)"| TrigInternet["Triggers IG:<br/>+ <b>internet_facing</b>"]

    %% Certification outcomes for SaaS
    Q3 -->|"c1: Yes (ISO 27001 /<br/>SOC 2 Type II certified)"| NoExtraSaaS["No additional IG triggered"]
    Q3 -->|"c2: No (Uncertified<br/>SaaS vendor)"| TrigUncert["Triggers IG:<br/>+ <b>saas_uncertified</b>"]

    %% 6 Leaf Combinations
    TrigCustom -.-> Case1
    NoExtraNet --> Case1(["<b>CASE 1: Custom + Internal</b><br/>Active IGs (4): info, baseline, custom_app, infra<br/>Hidden IGs (4): cots_app, internet_facing, saas_app, saas_uncertified<br/>21 Requirements | 15 Risk Scenarios"])

    TrigCustom -.-> Case2
    TrigInternet --> Case2(["<b>CASE 2: Custom + Internet-Facing</b><br/>Active IGs (5): info, baseline, custom_app, infra, internet_facing<br/>Hidden IGs (3): cots_app, saas_app, saas_uncertified<br/>23 Requirements | 17 Risk Scenarios"])

    TrigCOTS -.-> Case3
    NoExtraNet --> Case3(["<b>CASE 3: COTS + Internal</b><br/>Active IGs (4): info, baseline, cots_app, infra<br/>Hidden IGs (4): custom_app, internet_facing, saas_app, saas_uncertified<br/>17 Requirements | 13 Risk Scenarios"])

    TrigCOTS -.-> Case4
    TrigInternet --> Case4(["<b>CASE 4: COTS + Internet-Facing</b><br/>Active IGs (5): info, baseline, cots_app, infra, internet_facing<br/>Hidden IGs (3): custom_app, saas_app, saas_uncertified<br/>19 Requirements | 15 Risk Scenarios"])

    TrigSaaS -.-> Case5
    NoExtraSaaS --> Case5(["<b>CASE 5: SaaS + Certified</b><br/>Active IGs (3): info, baseline, saas_app<br/>Hidden IGs (5): custom_app, cots_app, infra, internet_facing, saas_uncertified<br/>12 Requirements | 7 Risk Scenarios"])

    TrigSaaS -.-> Case6
    TrigUncert --> Case6(["<b>CASE 6: SaaS + Uncertified</b><br/>Active IGs (4): info, baseline, saas_app, saas_uncertified<br/>Hidden IGs (4): custom_app, cots_app, infra, internet_facing<br/>26 Requirements | 10 Risk Scenarios"])
```

---

## 3. All 10 `implementation_groups_dependencies` Rules

| # | Dependency `ref_id` | Source IG | Trigger Question | Trigger Choice | Target IG (`target_implementation_group`) |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | `dep_custom_app` | `info` | `hosting:q1` | `c1` (*Custom software...*) | `custom_app` |
| **2** | `dep_custom_infra` | `info` | `hosting:q1` | `c1` (*Custom software...*) | `infra` |
| **3** | `dep_custom_baseline` | `info` | `hosting:q1` | `c1` (*Custom software...*) | `baseline` |
| **4** | `dep_cots_app` | `info` | `hosting:q1` | `c2` (*Bought software...*) | `cots_app` |
| **5** | `dep_cots_infra` | `info` | `hosting:q1` | `c2` (*Bought software...*) | `infra` |
| **6** | `dep_cots_baseline` | `info` | `hosting:q1` | `c2` (*Bought software...*) | `baseline` |
| **7** | `dep_saas_app` | `info` | `hosting:q1` | `c3` (*SaaS...*) | `saas_app` |
| **8** | `dep_saas_baseline` | `info` | `hosting:q1` | `c3` (*SaaS...*) | `baseline` |
| **9** | `dep_saas_uncertified` | `saas_app` | `saas_contract_compliance:q2` | `c2` (*No - Not certified*) | `saas_uncertified` |
| **10** | `dep_internet_facing` | `info` | `hosting:q2` | `c2` (*Internet-facing...*) | `internet_facing` |

---

## 3.1 Initial Respondent Assignment Questions & Delegate Form Fields for Each Triggered IG (`hosting:q4`–`q9_delegate` & `saas_contract_compliance:q3`–`q3_delegate`)

Inside the initial profiling requirement node **`hosting`** (`urn:intuitem:risk:req_node:appsec_manual:hosting`) and the SaaS contract compliance node **`saas_contract_compliance`** (`urn:intuitem:risk:req_node:appsec_manual:saas_contract_compliance`), the respondent is asked for each triggered implementation group whether they can answer that track directly or if somebody else has to. When *"Somebody else has to answer this track"* is selected, a dedicated free text form field (`type: text`) is dynamically displayed so the respondent can record who should answer (name, email, or team):

| Question ID | Target Triggered IG | Trigger Condition (`depends_on`) | Question Text / Delegate Text Field | Type & Choices |
| :---: | :--- | :--- | :--- | :--- |
| **`hosting:q4`** | `baseline` (Application Security Baseline) | `hosting:q1` $\in \{c_1, c_2, c_3\}$ | *"Can you answer the Application Security Baseline track (SSO federation, administrative MFA, and Role-Based Access Control [RBAC]), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`hosting:q4_delegate`** | `baseline` (Assignee Designation) | `hosting:q4` $= c_2$ (*Somebody else*) | *"Application Security Baseline track: please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |
| **`hosting:q5`** | `custom_app` (Custom Software Track) | `hosting:q1` $= c_1$ (*Custom software*) | *"Can you answer the Custom Software Track (code-level session management, input validation, output encoding, debug suppression, and CI/CD SAST/DAST/SCA pipelines), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`hosting:q5_delegate`** | `custom_app` (Assignee Designation) | `hosting:q5` $= c_2$ (*Somebody else*) | *"Custom Software Track: please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |
| **`hosting:q6`** | `cots_app` (Bought Software Track) | `hosting:q1` $= c_2$ (*Bought software*) | *"Can you answer the Bought Software Track (COTS deployment configuration hardening, vendor maintenance/support contracts, and patch SLAs), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`hosting:q6_delegate`** | `cots_app` (Assignee Designation) | `hosting:q6` $= c_2$ (*Somebody else*) | *"Bought Software Track (COTS): please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |
| **`hosting:q7`** | `infra` (Infrastructure & Hosting Security Track) | `hosting:q1` $\in \{c_1, c_2\}$ (*Self-hosted*) | *"Can you answer the Infrastructure & Hosting Security Track (secrets vault management, encryption at rest/transit, SIEM logging, backup & DR, and host OS patching), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`hosting:q7_delegate`** | `infra` (Assignee Designation) | `hosting:q7` $= c_2$ (*Somebody else*) | *"Infrastructure & Hosting Security Track: please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |
| **`hosting:q8`** | `internet_facing` (Internet-Facing Application Track) | `hosting:q2` $= c_2$ (*Internet-facing*) | *"Can you answer the Internet-Facing Application Track (edge Web Application Firewall [WAF], anti-DDoS, API rate limiting, and external penetration testing), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`hosting:q8_delegate`** | `internet_facing` (Assignee Designation) | `hosting:q8` $= c_2$ (*Somebody else*) | *"Internet-Facing Application Track: please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |
| **`hosting:q9`** | `saas_app` (SaaS Application Track) | `hosting:q1` $= c_3$ (*SaaS*) | *"Can you answer the SaaS Application Track (Master SaaS Agreement, confidentiality & encryption clauses, tenant admin MFA, EU data residency, audit rights, and non-conformity remedies), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`hosting:q9_delegate`** | `saas_app` (Assignee Designation) | `hosting:q9` $= c_2$ (*Somebody else*) | *"SaaS Application Track: please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |
| **`saas_contract_compliance:q3`** | `saas_uncertified` (Uncertified SaaS Vendor Track) | `saas_contract_compliance:q2` $= c_2$ (*Uncertified SaaS*) | *"Can you answer the Uncertified SaaS Vendor Track (detailed vendor security assessment: ISMS, awareness, workstation/mobile security, network isolation, secure development, penetration testing, physical security, and subcontractor governance), or does somebody else have to?"* | `unique_choice`<br>`c1`: I can answer this track<br>`c2`: Somebody else has to answer this track |
| **`saas_contract_compliance:q3_delegate`** | `saas_uncertified` (Assignee Designation) | `saas_contract_compliance:q3` $= c_2$ (*Somebody else*) | *"Uncertified SaaS Vendor Track: please specify who can answer (name, email address, or team):"* | `text` *(free text input, optional)* |

> [!TIP]
> When the respondent selects *"Somebody else has to answer this track"*, the corresponding `_delegate` free text form field expands immediately below the choice question via intra-node `depends_on`. If the respondent answers *"I can answer this track"*, the text field remains hidden to keep the questionnaire streamlined.

---

## 4. Exhaustive Matrix of the 6 Conditional IG Combinations & Example Profiles

| Case | Example Profile (`test_data/*.yml`) | Delivery (`hosting:q1`) | Exposure (`hosting:q2`) | Certification (`saas_contract_compliance:q2`) | Active IGs (`visible_groups`) | Hidden IGs (`hidden_groups`) | Scoped Reqs | Scoped Scenarios | Classification |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| **0** | *(Initial Audit State)* | *(Unanswered)* | *(Hidden)* | *(Hidden)* | `info` (1) | `baseline`, `custom_app`, `cots_app`, `infra`, `saas_app`, `saas_uncertified`, `internet_facing` (7) | **4** | **0** | N/A |
| **1** | `app_manual_custom_internal.yml` | `c1` (Custom) | `c1` (Internal) | *(Hidden)* | `info`, `baseline`, `custom_app`, `infra` (4) | `cots_app`, `internet_facing`, `saas_app`, `saas_uncertified` (4) | **22** | **15** | `Internal` |
| **2** | `app_manual_custom_internet.yml` | `c1` (Custom) | `c2` (Internet) | *(Hidden)* | `info`, `baseline`, `custom_app`, `infra`, `internet_facing` (5) | `cots_app`, `saas_app`, `saas_uncertified` (3) | **25** | **17** | `Secret` |
| **3** | `app_manual_cots_internal.yml` | `c2` (COTS) | `c1` (Internal) | *(Hidden)* | `info`, `baseline`, `cots_app`, `infra` (4) | `custom_app`, `internet_facing`, `saas_app`, `saas_uncertified` (4) | **18** | **13** | `Confidential` |
| **4** | `app_manual_cots_internet.yml` | `c2` (COTS) | `c2` (Internet) | *(Hidden)* | `info`, `baseline`, `cots_app`, `infra`, `internet_facing` (5) | `custom_app`, `saas_app`, `saas_uncertified` (3) | **21** | **15** | `Confidential` |
| **5** | `app_manual_saas_certified.yml` | `c3` (SaaS) | *(Hidden)* | `c1` (Yes) | `info`, `baseline`, `saas_app` (3) | `custom_app`, `cots_app`, `infra`, `internet_facing`, `saas_uncertified` (5) | **13** | **7** | `Confidential` |
| **6** | `app_manual_saas_uncertified.yml` | `c3` (SaaS) | *(Hidden)* | `c2` (No) | `info`, `baseline`, `saas_app`, `saas_uncertified` (4) | `custom_app`, `cots_app`, `infra`, `internet_facing` (4) | **27** | **10** | `Secret` |

---

## 5. Intra-Node Question Dependencies (`depends_on`) Coverage Across the 6 Examples

In addition to framework-level IG dependencies, `appsec_manual.yml` contains **8 requirement nodes with intra-node conditional questions (`depends_on`)**. The 6 application examples are designed so that **both the skipped ("No/SSO/Automatic") and triggered ("Yes/Direct/Manual") branches of every conditional question are tested**:

```mermaid
flowchart LR
    subgraph IntraNode ["Intra-Node Conditional Question Branches (depends_on)"]
        direction TB
        A["<b>authentication_and_mfa:q1</b><br/>c1 (Exclusive SSO) / c4 (M2M API) &#8594; skips q2, q3 <i>[Cases 1, 3, 5]</i><br/>c2 (Hybrid SSO) / c3 (Direct Auth) &#8594; unlocks q2, q3 <i>[Cases 2, 4, 6]</i>"]
        B["<b>file_upload_security:q1</b><br/>c1 (No uploads) &#8594; skips q2, q3 <i>[Case 1]</i><br/>c2 (Yes uploads) &#8594; unlocks q2, q3 <i>[Case 2]</i>"]
        C["<b>data_exchange:q1</b><br/>c1 (No external exchange) &#8594; skips q2 <i>[Case 1]</i><br/>c2 (Yes external exchange) &#8594; unlocks q2 <i>[Cases 2, 3, 4]</i>"]
        D["<b>non_prod_data:q1</b><br/>c1 (Synthetic/mock only) &#8594; skips q2, q3 <i>[Cases 1, 4]</i><br/>c2 (Prod data in non-prod) &#8594; unlocks q2, q3 <i>[Cases 2, 3]</i>"]
        E["<b>data_destruction:q1</b><br/>c1 (Yes destruction process) &#8594; unlocks q2 <i>[Cases 1, 3, 4]</i><br/>c2 (No destruction process) &#8594; skips q2 <i>[Case 2]</i>"]
        F["<b>os_patching:q1</b><br/>c1 (Automatic OS patching) &#8594; skips q2 <i>[Case 1]</i><br/>c2 (Manual OS patching) &#8594; unlocks q2 <i>[Cases 2, 3, 4]</i>"]
        G["<b>saas_pci_dss:q1</b><br/>c1 (Out of scope for PCI DSS) &#8594; skips q2, q3 <i>[Case 6]</i><br/>c2 (In scope for PCI DSS) &#8594; unlocks q2, q3 <i>[Case 5]</i>"]
        H["<b>backup_and_disaster_recovery:q1</b><br/>c1 (Yes automated backups) &#8594; unlocks q2 (DR drills) <i>[Cases 1, 2, 3, 4]</i><br/>c2 (No automated backups) &#8594; skips q2"]
    end
```

---

## 6. Requirement Node Applicability Matrix Across All 6 Cases (48 Assessable Nodes)

| # | Requirement `ref_id` | Implementation Group(s) | Case 1 (Custom+Int) | Case 2 (Custom+Ext) | Case 3 (COTS+Int) | Case 4 (COTS+Ext) | Case 5 (SaaS+Cert) | Case 6 (SaaS+Uncert) |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | `application_description` | `info` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ |
| 2 | `stakeholder_identification` | `info` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ |
| 3 | `data_classification` | `info` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ |
| 4 | `hosting` | `info` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ |
| 5 | `authentication_and_mfa` | `baseline` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ |
| 6 | `access_control_and_rbac` | `baseline` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ |
| 7 | `session_management` | `custom_app` | $\checkmark$ | $\checkmark$ | — | — | — | — |
| 8 | `owasp_top_10_defenses` | `custom_app` | $\checkmark$ | $\checkmark$ | — | — | — | — |
| 9 | `file_upload_security` | `custom_app` | $\checkmark$ | $\checkmark$ | — | — | — | — |
| 10 | `automated_security_testing` | `custom_app` | $\checkmark$ | $\checkmark$ | — | — | — | — |
| 11 | `supply_chain_and_dependencies` | `custom_app` | $\checkmark$ | $\checkmark$ | — | — | — | — |
| 12 | `code_review_and_ci_cd_integrity` | `custom_app` | $\checkmark$ | $\checkmark$ | — | — | — | — |
| 13 | `vendor_secure_development` | `cots_app` | — | — | $\checkmark$ | $\checkmark$ | — | — |
| 14 | `cots_deployment_hardening` | `cots_app` | — | — | $\checkmark$ | $\checkmark$ | — | — |
| 15 | `data_exchange` | `custom_app`, `cots_app` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 16 | `non_prod_data` | `custom_app`, `cots_app` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 17 | `data_destruction` | `custom_app`, `cots_app` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 18 | `secrets_management` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 19 | `data_in_transit` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 20 | `data_at_rest` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 21 | `security_event_logging` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 22 | `centralized_monitoring_and_alerting` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 23 | `backup_and_disaster_recovery` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 24 | `os_patching` | `infra` | $\checkmark$ | $\checkmark$ | $\checkmark$ | $\checkmark$ | — | — |
| 25 | `edge_network_protection` | `internet_facing` | — | $\checkmark$ | — | $\checkmark$ | — | — |
| 26 | `api_security_and_rate_limiting` | `internet_facing` | — | $\checkmark$ | — | $\checkmark$ | — | — |
| 27 | `penetration_testing_and_vulnerability_management` | `internet_facing` | — | $\checkmark$ | — | $\checkmark$ | — | — |
| 28 | `saas_contract_compliance` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 29 | `saas_confidentiality_and_data_protection` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 30 | `saas_iam` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 31 | `saas_data_hosting_and_residency` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 32 | `saas_audit_and_compliance` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 33 | `saas_pci_dss` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 34 | `saas_non_conformity_remediation` | `saas_app` | — | — | — | — | $\checkmark$ | $\checkmark$ |
| 35 | `saas_governance_and_policy` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 36 | `saas_security_awareness` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 37 | `saas_entitlements_and_privileges` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 38 | `saas_logging_and_incidents` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 39 | `saas_workstation_security` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 40 | `saas_mobile_security` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 41 | `saas_network_security` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 42 | `saas_environment_isolation` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 43 | `saas_secure_development` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 44 | `saas_web_app_security` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 45 | `saas_vulnerability_remediation_sla` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 46 | `saas_physical_security` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 47 | `saas_backup_and_business_continuity` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| 48 | `saas_subcontractor_management` | `saas_uncertified` | — | — | — | — | — | $\checkmark$ |
| | **Total Active Assessable Nodes** | | **22** | **25** | **18** | **21** | **13** | **27** |
