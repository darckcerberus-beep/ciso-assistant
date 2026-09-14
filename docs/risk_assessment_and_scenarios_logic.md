# Risk Assessment and Scenarios Logic Documentation

This document provides a comprehensive technical reference for the Risk Assessment and Risk Scenario modeling engine implemented across [`classes/core/risk.py`](file:///home/romain/ciso-assistant/classes/core/risk.py), [`classes/audits/compliance.py`](file:///home/romain/ciso-assistant/classes/audits/compliance.py), [`classes/controls/applied.py`](file:///home/romain/ciso-assistant/classes/controls/applied.py), and [`YML/newDPP.yml`](file:///home/romain/ciso-assistant/YML/newDPP.yml).

---

## 1. Overview and Core Philosophy

In CISO Assistant, risk assessments and scenarios are **dynamically derived from compliance audit results**:
- A **Compliance Assessment** captures questionnaire responses against framework requirements.
- The **Risk Engine** translates questionnaire scores (0–100%) and classification choices into quantitative **Likelihood** and **Impact** metrics.
- Scenarios link directly to **Perimeter Assets**, **Asset Owners**, and **Applied Controls** (categorized into *existing/implemented* vs. *planned/mitigating*).
- Scenario risk levels dynamically drive **Control Priorities** (Priority 1 = Urgent down to Priority 4 = Low).

```
+--------------------------+
|  Compliance Assessment   |
|  (Audit Questionnaires)  |
+------------+-------------+
             |
             v
+--------------------------+       +-------------------------+
|   Parent Risk Assess.    | <---> |   4x4 Risk Matrix       |
|  (Tied to Perimeter/Lib) |       |  (Likelihood x Impact)  |
+------------+-------------+       +-------------------------+
             |
             v
+------------------------------------------------------------+
|                       Risk Scenarios                       |
|  - Likelihood Node: Evaluated from requirement score (0-100)|
|  - Impact Node: Evaluated from data classification answer  |
|  - Controls: Existing (Active) vs Planned (To Do)          |
|  - Assets & Owners: Inherited from Perimeter               |
+----------------------------+-------------------------------+
                             |
                             v
+------------------------------------------------------------+
|                 Applied Control Priority                   |
|  Current Scenario Level (1-4) -> Control Priority (1-4)     |
+------------------------------------------------------------+
```

---

## 2. Architecture & Data Structures

### 2.1 Core Classes (`classes/core/risk.py`)

| Class | Description | Key Responsibilities |
| :--- | :--- | :--- |
| [`RiskAssessment`](file:///home/romain/ciso-assistant/classes/core/risk.py#L16) | High-level risk assessment container | Wraps single `/api/risk-assessments/{id}/` record tied to a domain, perimeter, and risk matrix. |
| [`RiskAssessmentDict`](file:///home/romain/ciso-assistant/classes/core/risk.py#L48) | Collection & factory for risk assessments | Fetches all risk assessments; creates new ones idempotently if not already present. |
| [`RiskScenario`](file:///home/romain/ciso-assistant/classes/core/risk.py#L97) | Concrete risk realization model | Stores probability, impact, residual risk, linked controls, assets, and owners; performs non-destructive relationship updates via `PATCH`. |
| [`RiskScenarioDict`](file:///home/romain/ciso-assistant/classes/core/risk.py#L154) | Collection & scenario evaluation manager | Handles 0-based API conversion, scenario `POST`/`PATCH` updates, and cleanup of obsolete scenarios (`delete_risk_scenario`). |
| [`RiskMatrix`](file:///home/romain/ciso-assistant/classes/core/risk.py#L273) | Risk matrix definition | Wraps 4x4 or custom probability/impact matrix structures and risk level color scales. |
| [`RiskMatrixDict`](file:///home/romain/ciso-assistant/classes/core/risk.py#L288) | Collection of risk matrices | Resolves risk matrix IDs by framework library ID (`get_risk_matrix_id_by_library_id`). |
| [`Vulnerability`](file:///home/romain/ciso-assistant/classes/core/risk.py#L316) | Threat vulnerability model | Wraps weaknesses defined in the library. |
| [`VulnerabilityDict`](file:///home/romain/ciso-assistant/classes/core/risk.py#L337) | Collection of vulnerabilities | Fetches and manages vulnerability payloads from `/api/vulnerabilities/`. |

---

## 3. End-to-End Workflow

The risk synchronization pipeline is executed during Step 7 of [`main.py`](file:///home/romain/ciso-assistant/main.py#L54-L64) via `ComplianceAssessmentDict.create_risk_assessments(...)`.

### Step 1: Pre-Qualification (Answer Check)
Before creating risk objects, the system checks whether the compliance assessment has at least one answered requirement:
```python
if not requirement_assessment_dict.has_answers_for_compliance_assessment(ca.get_id()):
    utils.log(f"Skipping risk creation for compliance assessment {ca.get_name()}: no answered requirements", level=20)
    continue
```
*Rationale: Prevents empty placeholder risk assessments for unassessed perimeters.*

### Step 2: Parent Risk Assessment Creation
A parent `RiskAssessment` object is created or loaded for the compliance assessment:
- **Name**: `"{Compliance Assessment Name} Risk Assessment"`
- **Domain**: Domain / Framework ID (`ca.get_framework_id()`)
- **Perimeter**: Perimeter UUID (`ca.get_perimeter_id()`)
- **Risk Matrix**: Resolved from the framework library via `risk_matrix_dict.get_risk_matrix_id_by_library_id(...)`

### Step 3: Scenario Evaluation & Stale Cleanup
For each scenario defined under `objects.risk_scenarios` in [`YML/newDPP.yml`](file:///home/romain/ciso-assistant/YML/newDPP.yml):
1. **Likelihood Node Resolution**: Finds the requirement assessment matching `risk_scenario.get("likelihood")`.
2. **Answer Check**:
   - If the likelihood requirement has **no selected answer** (`not likelihood_assessment.has_selected_answer()`):
     - The scenario is considered non-applicable.
     - Any previously created scenario under this assessment is deleted via `risk_scenario_dict.delete_risk_scenario(name, risk_assessment_id)`.
     - Processing for this scenario stops.

### Step 4: Likelihood and Impact Calculation

#### Likelihood Calculation (Inverse Relationship)
The compliance audit score is a percentage between $0$ and $100$ representing control implementation maturity.
Because **higher compliance implies lower risk**, the likelihood scaling is inverted:

$$\text{scaled\_likelihood} = \min\left(4, \max\left(1, 4 - \left\lfloor\frac{\text{score} - 1}{25}\right\rfloor\right)\right)$$

| Compliance Score (%) | Compliance State | Scaled Likelihood (1-based) | Likelihood Level Name | API Value (0-based) |
| :---: | :---: | :---: | :---: | :---: |
| **76 – 100** | High Compliance / Implemented | **1** | Unlikely | `0` |
| **51 – 75** | Moderate / In Progress | **2** | Rather unlikely | `1` |
| **26 – 50** | Partial / Minor Implementation | **3** | Likely | `2` |
| **0 – 25** | Non-compliant / Not started | **4** | Very likely | `3` |

#### Impact Calculation (Data Classification Mapping)
Impact is determined by the classification level of data handled by the perimeter:
1. Looks up the requirement assessment corresponding to `risk_scenario.get("impact")` (typically `urn:intuitem:risk:req_node:mls:data_classification`).
2. Checks selected answers against `criticality_mapping.confidentiality` in `newDPP.yml`:
   - `urn:intuitem:risk:choice:mls:public` $\to$ Level `0` ($+1 \to \mathbf{1}$ / Minor)
   - `urn:intuitem:risk:choice:mls:internal` $\to$ Level `1` ($+1 \to \mathbf{2}$ / Significant)
   - `urn:intuitem:risk:choice:mls:confidential` $\to$ Level `2` ($+1 \to \mathbf{3}$ / Serious)
   - `urn:intuitem:risk:choice:mls:secret` $\to$ Level `3` ($+1 \to \mathbf{4}$ / Critical)
3. **Fallback**: If no answer choice matches the map, the raw compliance score of the impact node is used (`max(1, int(impact))`).

#### Residual Risk Formulation
- **Residual Probability**: Initialized to `1` (Unlikely), representing the target risk state once planned controls are implemented.
- **Residual Impact**: Maintained equal to `scaled_impact` (inherent impact remains consistent).

### Step 5: Mitigating Control Classification
Applied controls linked to the scenario's likelihood requirement (the specific mitigating security controls) are segregated based on their `status`:
```python
# Identify requirement assessment IDs associated with this scenario's likelihood (mitigating controls)
requirement_assessment_ids = [
    requirement_assessment.get_id()
    for requirement_assessment in requirement_assessments.values()
    if requirement_assessment.get_compliance_assessment_id() == ca.get_id()
    and requirement_assessment.get_urn() == risk_scenario.get('likelihood', '')
]

controls_by_status = applied_control_dict.get_control_ids_by_status_for_requirement_assessments(
    requirement_assessment_ids
)
```
- `existing_applied_controls` (`status == "active"`): Controls currently in place.
- `applied_controls` (`status == "to_do"`): Planned mitigating controls.

*(Note: The impact node, such as `data_classification`, reflects asset sensitivity rather than a risk-reducing security control and is therefore excluded from scenario mitigating controls to avoid falsely attributing classification as a mitigation for unaddressed threats).*

### Step 6: Asset and Owner Linkage
- **Assets**: Extracted directly from the compliance assessment's perimeter (`ca.get_asset_id_list()`).
- **Owners**: Resolved via `asset_dict.get_owner_ids_for_assets(asset_ids)` from the associated asset owner definitions.

### Step 7: API Submission & Idempotency
[`RiskScenarioDict.create_risk_scenario`](file:///home/romain/ciso-assistant/classes/core/risk.py#L188) automatically converts 1-based values to 0-based API values:
- `current_proba = scaled_likelihood - 1`
- `current_impact = scaled_impact - 1`
- `residual_proba = residual_proba - 1`
- `residual_impact = residual_impact - 1`

If a scenario with the same name already exists under the parent `risk_assessment`, a `PATCH` request updates modified attributes. Otherwise, a `POST` creates the new scenario and registers it in memory.

---

## 4. Scenario Definitions in `newDPP.yml`

The 7 standard risk scenarios configured in [`YML/newDPP.yml`](file:///home/romain/ciso-assistant/YML/newDPP.yml) are:

| Ref ID | Scenario Name | Likelihood Requirement Node | Impact Requirement Node |
| :--- | :--- | :--- | :--- |
| `unencrypted_data_in_transit` | Exposure of unencrypted data in transit | `data_in_transit` | `data_classification` |
| `unencrypted_data_at_rest` | Exposure of unencrypted data at rest | `data_at_rest` | `data_classification` |
| `nonprod_data_disclosure` | Disclosure of production data in non-production environments | `non_prod_data` | `data_classification` |
| `third_party_data_leakage` | Third-party data leakage | `data_exchange` | `data_classification` |
| `saas_provider_data_leakage` | SaaS provider data leakage | `saas_contract` | `data_classification` |
| `missing_stakeholders` | Missing application stakeholders | `stakeholder_identification` | `data_classification` |
| `improper_data_retention` | Excessive retention of sensitive data | `data_destruction` | `data_classification` |

---

## 5. Downstream Applied Control Priority Derivation

The calculated risk scenario level directly drives the priority of remediation controls via [`AppliedControlDict.get_priority_for_compliance_assessment_id`](file:///home/romain/ciso-assistant/classes/controls/applied.py#L161):

```
Risk Level 4 (Critical)  --->  Control Priority 1 (Urgent)
Risk Level 3 (High)      --->  Control Priority 2 (High)
Risk Level 2 (Medium)    --->  Control Priority 3 (Medium)
Risk Level 1 (Low)       --->  Control Priority 4 (Low)
```

If any compliance assessment, risk assessment, or risk scenario is missing, execution halts with a descriptive `LookupError` or `ValueError`, preventing inconsistent states or invalid fallbacks.

