# TO-DO: Conditional Questions for Network Exposure & Criticality (AppSec Framework)

**Date**: October 8, 2026  
**Status**: Ready to Implement  
**Branch**: `main`  
**Current Baseline**: All 201 automated unit tests pass (`python3 -m unittest discover tests`).

---

## 1. Goal & Context

When assessing whether an application is externally exposed or not (both for in-house applications and SaaS solutions), implement **conditional questions** (`depends_on:`) so that:
- **Non-exposed apps** (restricted to internal networks/VPN) and **non-critical apps** (handling low sensitivity data) are **not asked irrelevant questions** (such as external Web Application Firewalls, public DDoS mitigation, external API rate limiting, and third-party external penetration tests).
- **Internet-facing and/or critical apps** are prompted with the necessary deep-dive questions and scored accordingly.
- Compliance scoring integrity is strictly maintained (`add_score > 0` $\leftrightarrow$ `compute_result: true`).

---

## 2. Completed Discovery & Architecture Decisions

1. **Target Framework**: `YML/appsec.yml` (Application Security Assessment Framework - AppSec).
2. **Conditional Branching Schema**:
   In CISO Assistant schema and YAML libraries, question-level branching uses `depends_on:` referencing sibling question URNs:
   ```yaml
   depends_on:
     question: urn:intuitem:risk:req_node:appsec:network_exposure:q1
     answers: ["urn:intuitem:risk:req_node:appsec:network_exposure:q1:c2"]
     condition: any
   ```
3. **Scoring Integrity Rules** (`tests/test_yaml_integrity.py`):
   - Choices with `add_score > 0` must have `compute_result: true`.
   - Choices with `add_score == 0` must have `compute_result: false`.
   - Sum of applicable questions for a requirement node should scale to 100 points.
4. **Risk Scenario Independence**:
   - `network_exposure` is not directly mapped as a likelihood requirement node in risk scenarios, meaning adding conditional questions to it will **not** break risk matrix evaluations across the 16 risk scenarios in `test_application_scenarios.py`.

---

## 3. Remaining Implementation Steps

### Step 1: Update `YML/appsec.yml`

#### A. Node `urn:intuitem:risk:req_node:appsec:network_exposure` (Chapter 1 `info`)
- **Keep `q1`** as the exposure discriminator:
  - Text: `"What is the network exposure of the application?"`
  - Choice `c1` ("Internal / Restricted Network only"): `add_score: 50` (or `100`), `compute_result: true`.
  - Choice `c2` ("Internet-facing (Public Web / Mobile API)"): `add_score: 25`, `compute_result: true`, selects `internet_facing`.
- **Add conditional follow-up questions** that activate **only** if `q1 == c2` (`Internet-facing`):
  - **`q2`** (WAF & DDoS Mitigation):
    - Text: *"Are Internet-facing endpoints protected by a Web Application Firewall (WAF) and automated anti-DDoS mitigation?"*
    - `depends_on`: depends on `q1:c2`.
    - `choices`: Yes (`add_score: 25`, `compute_result: true`), No (`add_score: 0`, `compute_result: false`).
  - **`q3`** (Public API Rate Limiting & Abuse Prevention):
    - Text: *"Are public API endpoints protected against abuse via IP rate limiting, token throttling, or bot mitigation?"*
    - `depends_on`: depends on `q1:c2`.
    - `choices`: Yes (`add_score: 25`, `compute_result: true`), No (`add_score: 0`, `compute_result: false`).
  - **`q4`** (External Penetration Testing):
    - Text: *"Has the externally exposed attack surface undergone an external penetration test within the last 12 months?"*
    - `depends_on`: depends on `q1:c2`.
    - `choices`: Yes (`add_score: 25`, `compute_result: true`), No (`add_score: 0`, `compute_result: false`).

#### B. Node `urn:intuitem:risk:req_node:appsec:saas_web_app_security` (Chapter 10 `saas_chapter`)
- Currently, `q2` unconditionally mandates external penetration testing for all SaaS apps, even internal-only or non-critical SaaS tools.
- **Refactor `saas_web_app_security`**:
  - **`q1`**: TLS 1.2+ & administrative interface restrictions (`add_score: 50`).
  - **`q2` (Gatekeeper)**:
    - Text: *"Is the SaaS platform externally exposed to the public Internet, or processing critical data (Confidential or Secret)?"*
    - Choice `c1` (*"No - Restricted internal/private access only and non-critical data"*): `add_score: 50`, `compute_result: true`. (Skips pentest requirement, awarding full points).
    - Choice `c2` (*"Yes - Externally exposed or processing critical data"*): `add_score: 0`, `compute_result: false`.
  - **`q3` (Conditional External Pentest)**:
    - `depends_on`: depends on `q2:c2`.
    - Text: *"Does the provider undergo an independent external penetration test pre-production and at least annually thereafter, with monthly vulnerability scans and formal remediation SLAs?"*
    - Choice `c1` (*"Yes"*): `add_score: 50`, `compute_result: true`.
    - Choice `c2` (*"No"*): `add_score: 0`, `compute_result: false`.

#### C. Baseline Nodes `api_security_and_rate_limiting` & `penetration_testing_and_vulnerability_management` (Optional / Recommended)
- Provide explicit *"Not applicable (Internal / non-exposed and non-critical)"* choice (`add_score: 50`, `compute_result: true`) for applications with zero external attack surface.

---

### Step 2: Update Test Data Profiles in `test_data/`

Update the following application profiles to include answers for the new conditional questions:
1. `test_data/app_appsec_secure_api.yml`:
   - An Internet-facing SaaS app handling Secret data.
   - Add answers for `network_exposure`: `q2` ("Yes"), `q3` ("Yes"), `q4` ("Yes").
2. `test_data/app_appsec_hybrid_saas.yml`:
   - An Internet-facing SaaS app handling Confidential data.
   - Add answers for `network_exposure`: `q2`, `q3`, `q4`.
3. `test_data/app_appsec_vulnerable_legacy.yml`:
   - An Internal on-premises app.
   - Keep `network_exposure` answering `"Internal / Restricted Network only"` to verify non-exposed apps cleanly bypass `q2-q4`.

---

### Step 3: Add Unit Tests in `tests/test_yaml_integrity.py`

Add a new test method `test_appsec_network_exposure_and_conditional_branching`:
- Verify `network_exposure` defines `q1` with `Internal` and `Internet-facing` choices.
- Verify conditional follow-up questions (`q2`, `q3`, `q4`) have `depends_on` pointing to `urn:intuitem:risk:req_node:appsec:network_exposure:q1:c2`.
- Verify `saas_web_app_security` defines gatekeeper branching so non-exposed and non-critical SaaS apps skip external penetration testing without score penalties.
- Verify `compute_result` is strictly consistent with `add_score`.

---

### Step 4: Verification & Test Execution

Run the full automated test suite to confirm zero regressions:
```bash
# Run integrity tests
python3 -m unittest tests/test_yaml_integrity.py

# Run application profile & risk scenario tests
python3 -m unittest tests/test_application_scenarios.py

# Run all tests
python3 -m unittest discover tests
```

---

## 4. Quick Resume Instructions for Next Session
1. Open this file `TODO.md` and `YML/appsec.yml`.
2. Apply changes to `YML/appsec.yml` (`network_exposure` and `saas_web_app_security`).
3. Update `test_data/app_appsec_*.yml` profiles.
4. Add the assertions to `tests/test_yaml_integrity.py`.
5. Run `python3 -m unittest discover tests`.

