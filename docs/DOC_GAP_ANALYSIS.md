# Documentation Gap Analysis

**Date**: 2026-04-22  
**Scope**: Full audit of `docs/` and `README.md` against the actual source code  
**Status**: Open — work tracked in GitHub issue

---

## Overview

This document records all gaps, inaccuracies, and missing coverage identified by comparing the existing documentation to the implemented codebase. It is the reference for the documentation update work.

---

## 1. Incorrect / Outdated Content

### 1.1 `docs/CLI.md` — `generate --template` lists wrong values

| | Detail |
|---|---|
| **Doc says** | `(talos-security, pqc-transition, custom)` — 3 values |
| **Code** (`_ALL_TEMPLATES`) | `talos-security`, `pqc-transition`, `cis-azure`, `security`, `network`, `registry`, `strict`, `talos`, `pqc`, `all` — 10 values |
| **Missing** | `cis-azure` template and all 7 Kyverno profile names |
| **Fix** | Update the `--template` option description and examples to list all 10 valid choices, grouped as: 3 bundles + 7 Kyverno profile names |

### 1.2 `docs/CLI.md` + `docs/MULTI_FORMAT_GENERATION.md` — `--style custom` marked as "planned/future"

| | Detail |
|---|---|
| **Doc says** | "Framework for future policy formats" / "Planned support: HashiCorp Sentinel, OPA Rego, ..." |
| **Code** | `--style` is `click.Choice(["kyverno", "azure", "custom"])` — `custom` is a valid, implemented option today |
| **Fix** | Remove the "planned/future" language. Document what `--style custom` currently produces. |

### 1.3 `docs/CLI.md` — `deploy --target both` scope is ambiguous

| | Detail |
|---|---|
| **Doc** | Shows `--target both` without clarifying which targets are combined |
| **Code** | `both` = kubernetes + itl-api **only**. Azure requires an explicit `--target azure`. |
| **Fix** | Add a note clarifying that `both` means kubernetes + itl-api, and Azure must be targeted separately. |

### 1.4 `docs/CLI.md` — `validate` credential handling not documented

| | Detail |
|---|---|
| **Doc** | Lists options but does not mention that credential flags are absent for `itl-api` and `azure` validation |
| **Code** | `validate --target itl-api` reads `ITL_API_ENDPOINT` / `ITL_API_KEY` from environment; no CLI flags |
| **Fix** | Add a note that `validate --target itl-api` and `validate --target azure` use environment variables only. |

---

## 2. Missing Documentation

### 2.1 Kyverno profile system (`templates/kyverno.py`)

- 7 named profiles: `security`, `network`, `registry`, `strict`, `talos`, `pqc`, `all`
- `KYVERNO_PROFILE_CATEGORIES`, `KyvernoProfileBuilder`, `KyvernoProfileDefinition` are public API
- **Action**: Create `docs/KYVERNO_PROFILES.md` documenting all profiles, what policies each includes, and how to use them via `--template <profile>`.

### 2.2 Bicep export (`export/bicep.py`)

- `export/bicep.py` exists alongside `export/arm.py` and `export/kyverno.py`
- `README.md` and `docs/MULTI_FORMAT_GENERATION.md` only mention ARM export
- **Action**: Document Bicep export in `README.md` and `docs/MULTI_FORMAT_GENERATION.md`.

### 2.3 Builder classes (`builders/`)

Five builder modules with no documentation:
- `builders/policy.py`
- `builders/assignment.py`
- `builders/exemption.py`
- `builders/initiative.py`
- `builders/remediation.py`

**Action**: Create `docs/PYTHON_API.md` documenting the builder API for users who use the library programmatically.

### 2.4 Conditions DSL (`conditions/dsl.py`)

- No documentation exists for the conditions DSL
- **Action**: Document in `docs/PYTHON_API.md`.

### 2.5 Policy evaluator (`evaluation/evaluator.py`)

- `PolicyEvaluator` is not mentioned in any doc
- **Action**: Document in `docs/PYTHON_API.md`.

### 2.6 Testing helpers (`testing/helpers.py`)

- `PolicyTestHelper` and `PolicyAssertionError` not mentioned anywhere
- **Action**: Create `docs/TESTING.md` documenting the test helpers for contributors and library extenders.

### 2.7 Enums module (`enums/__init__.py`)

Public enums with no documentation:
`Effect`, `PolicyMode`, `PolicyType`, `ComplianceState`, `RemediationState`, `AssignmentScope`, `ExemptionCategory`, `ParameterType`

**Action**: Include enum reference in `docs/PYTHON_API.md`.

### 2.8 ITL API deployment integration

- `README.md` prominently lists ITL Control Plane as a deploy target
- No doc explains the integration, required API contract, or authentication details beyond env vars
- **Action**: Add an ITL API integration section to `docs/CLI.md` or create `docs/ITL_INTEGRATION.md`.

---

## 3. Content to Remove or Archive

### 3.1 Non-technical files in `docs/archive/`

The following files have no technical value and should be removed from the repository:

| File | Reason to remove |
|---|---|
| `docs/archive/LINKEDIN_ARTIKEL_PQC.md` | Marketing article draft |
| `docs/archive/MONETISATIE_STRATEGIE.md` | Commercialisation strategy, Dutch |
| `docs/archive/PQC_ACTION_PLAN.md` | Strategic planning, not technical |
| `docs/archive/PQC_RISK_ASSESSMENT.md` | Strategic planning, not technical |
| `docs/archive/PQC_TRANSITIE_STAPPENPLAN.md` | Migration strategy, Dutch |

### 3.2 Superseded implementation notes in `docs/archive/`

The following files are implementation notes from a past development phase, now superseded by `docs/CLI.md` and `docs/MULTI_FORMAT_GENERATION.md`:

- `docs/archive/CLI_IMPLEMENTATION_SUMMARY.md`
- `docs/archive/KYVERNO_INTEGRATION_SUMMARY.md`

**Action**: Remove, or add a clear `> ⚠️ Archived — superseded by docs/CLI.md` banner at the top of each file.

---

## 4. Verification Needed

### 4.1 ITL Serialiser in `README.md` architecture diagram

The `README.md` mermaid diagram shows `ITL Serialiser → ITL Control Plane`. No `export/itl.py` module was found in the source tree — only `export/arm.py`, `export/bicep.py`, and `export/kyverno.py`.

**Action**: Verify whether an ITL serialiser export path exists. If not, remove it from the architecture diagram.

---

## 5. Summary / Priority Table

| File / Area | Issue | Priority |
|---|---|---|
| `docs/CLI.md` — `generate --template` | Lists 3 values, code has 10 | **High** |
| `docs/CLI.md` + `MULTI_FORMAT_GENERATION.md` | `--style custom` marked "planned", already implemented | **High** |
| *(missing)* | Kyverno profiles documentation | **High** |
| `docs/CLI.md` | `deploy --target both` scope ambiguous | Medium |
| `docs/CLI.md` | `validate` credential handling not documented | Medium |
| `docs/MULTI_FORMAT_GENERATION.md` | Bicep export not mentioned | Medium |
| *(missing)* | Python API / builders documentation | Medium |
| `README.md` | ITL Serialiser in diagram may not exist | Medium |
| *(missing)* | Testing helpers documentation | Low |
| `docs/archive/` | 5 non-technical files to remove | Low |
| `docs/archive/` | 2 superseded implementation notes | Low |
