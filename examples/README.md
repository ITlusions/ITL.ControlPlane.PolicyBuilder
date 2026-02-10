# ITL Policy Builder - Examples Guide

This directory contains comprehensive examples demonstrating how to use the ITL Policy Builder SDK to create, customize, and deploy governance policies.

## Quick Start

### Run All Kyverno Examples
```bash
python kyverno_examples.py
```

This demonstrates:
- Pod security baseline policies
- Image security enforcement
- Custom validation rules
- PQC (Post-Quantum Cryptography) readiness
- Talos security bundle generation
- Mutation rules for auto-labeling

### Run All Azure ARM Examples
```bash
python azure_examples.py
```

This demonstrates:
- Location enforcement policies
- Tagging requirements with parameters
- Complex conditions (all_of, any_of, not_)
- Built-in policy templates
- BIO (Dutch government) compliance policies
- PQC readiness for cloud resources
- Policy assignments and initiatives
- Export to JSON and YAML formats

### Deploy to Azure (Native ARM)
```bash
# See comprehensive deployment guide
cat azure_deployment.md

# Or quick example:
itl-policy generate --template talos-security --style azure -o policies.json

itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000" \
  --action audit
```

### CLI Examples
```bash
# See CLI usage examples
cat cli_examples.md

# Run actual CLI commands
itl-policy list
itl-policy generate --template talos-security --style kyverno
itl-policy generate --template talos-security --style azure
```

---

## File Organization

### `kyverno_examples.py` — Kubernetes-Native Policies

**13 examples** showing how to build Kyverno ClusterPolicies for Talos Kubernetes clusters.

#### Kyverno Examples (1-8):
1. **Pod Security Baseline** — Enforce non-root containers with security context
2. **Image Security** — Prevent image:latest tag usage
3. **Custom Validation** — Require CPU/memory resource limits
4. **PQC Readiness** — Label workloads for quantum-safe crypto transition
5. _(skipped in output)_
6. **List Policies** — Discover available policy templates by category
7. **Mutation Rules** — Auto-add labels to all pods
8. **kubectl Manifest** — Generate deployment-ready YAML manifests

#### Azure ARM Examples (9-13):
9. **Azure Location Policy** — Require West Europe location
10. **Azure Tag Policy** — Require environment tag with allowed values
11. **Comparing Styles** — Same policy in Kyverno vs Azure, side-by-side
12. **Azure PQC Policies** — PQC readiness for cloud resources
13. **Azure Initiative** — Group multiple policies into an initiative

**When to use:** If you're targeting Kubernetes/Talos environments or want to see both Kyverno and Azure approaches in one place.

### `azure_examples.py` — Azure Resource Manager Policies

**10 focused examples** showing how to build Azure ARM policies for governance at scale.

1. **Simple Location Policy** — Require resources in West Europe
2. **Tagging Policy** — Require specific tags with parameter customization
3. **Complex Conditions** — Use all_of, any_of, not_ operators
4. **Built-in Templates** — Leverage pre-built policy templates
5. **BIO Compliance** — Dutch government security baseline (17 policies)
6. **PQC Readiness** — Post-quantum cryptography policies (16 policies)
7. **Parameterized Policy** — Create flexible, reusable policies
8. **Policy Assignment** — Assign policies to subscription scopes
9. **Policy Initiative** — Group policies with logical categories
10. **Export Formats** — Convert to JSON (API) or YAML (documentation)

**When to use:** If you're targeting Azure subscriptions or need comprehensive Azure governance examples.

### `azure_deployment.md` — Azure Native Deployment Guide (NEW)

**Complete workflow guide** for deploying policies directly to Azure subscriptions.

Sections:
- Prerequisites (Azure SDK, authentication)
- CLI commands for deployment
- Scope options (subscription, resource group, management group)
- Authentication methods (CLI, environment variables, managed identity)
- Real-world deployment examples
- Troubleshooting guide
- Environment variables reference

**When to use:** If you're deploying policies to real Azure subscriptions production.

**Quick Start:**
```bash
# Install Azure SDK
pip install itl-policy-builder[azure]

# Generate policies
itl-policy generate --template talos-security --style azure -o policies.json

# Deploy (audit mode first)
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action audit
```

**27 realistic workflows** showing how to use the `itl-policy` CLI tool from the command line.

#### Section 1: Basic Operations
- List available policies
- Generate policies (Kyverno and Azure styles)
- Output formats (YAML, JSON)
- Filter by category/template

#### Section 2: Deployment
- Deploy to Kubernetes with kubeconfig
- Deploy to ITL Control Plane API
- Deployment modes: audit → enforce progression
- Dry-run before production

#### Section 3: Configuration
- Environment variables (ITL_API_ENDPOINT, ITL_API_KEY, KUBECONFIG)
- Configuration files (~/.itl-policy/config.json)
- Multi-environment setup

#### Section 4: Complete Workflows
- **Workflow 1:** Generate → Validate → Deploy to K8s (audit-first approach)
- **Workflow 2:** Azure ARM deployment with compliance checks
- **Workflow 3:** Multi-environment (dev, staging, prod)
- **Workflow 4:** Development & testing with dry-run

#### Reference Sections
- Available styles (Kyverno, Azure, Custom)
- Environment variables table
- Exit codes
- Troubleshooting guide

**When to use:** If you prefer CLI over SDK, need quick copy-paste commands, or want realistic deployment workflows.

---

## Framework Comparison

### Kyverno (Kubernetes)
**Best for:** Talos/Kubernetes environments, pod security, image control
**Deployment:** `kubectl apply -f policies.yaml`
**Effect:** Real-time admission control (blocks violations at API server)
**Example:** Prevent privileged containers, enforce resource limits

```python
# Run examples
python kyverno_examples.py
```

### Azure ARM (Control Plane)
**Best for:** Azure subscriptions, enterprise governance, compliance reporting
**Deployment:** REST API to Control Plane (`itl-policy deploy --target itl-api`)
**Effect:** Policy evaluation at resource creation time
**Example:** Enforce location restrictions, require encryption, PQC readiness

```python
# Run examples
python azure_examples.py
```

### When to Use Each

| Scenario | Framework | Example |
|----------|-----------|---------|
| "Lock down pod images" | Kyverno | Whitelist registries, block latest tags |
| "Enforce encryption" | Both | Kubernetes volume encryption, Azure storage encryption |
| "Require tagging" | Azure ARM | Enforce at subscription level |
| "Security baseline" | Kyverno | Pod security standards |
| "Compliance reporting" | Azure ARM | BIO, PQC readiness, audit trails |
| "Development & testing" | Kyverno | Fast feedback loop with kubectl |
| "Multi-cloud governance" | Both | Deploy policies to both simultaneously |

---

## Running Examples Step-by-Step

### Step 1: Install SDK with CLI
```bash
pip install itl-policy-builder[cli]
```

### Step 2: Run Kyverno Examples
```bash
cd examples/
python kyverno_examples.py | head -100  # See first 100 lines
python kyverno_examples.py > kyverno-output.txt  # Save output
```

### Step 3: Run Azure Examples
```bash
python azure_examples.py | head -100  # See first 100 lines
python azure_examples.py > azure-output.txt  # Save output
```

### Step 4: Try CLI Commands
```bash
# List available policies
itl-policy list

# Generate Kyverno policies
itl-policy generate --template talos-security --style kyverno --output my-policies.yaml

# Generate Azure policies
itl-policy generate --template talos-security --style azure --output my-policies.json

# Validate
itl-policy validate --file my-policies.yaml

# See CLI workflows
cat cli_examples.md
```

### Step 5: Deploy (if you have a cluster/environment)
```bash
# To Kubernetes
itl-policy deploy --file my-policies.yaml --target kubernetes --action audit

# To ITL Control Plane
export ITL_API_ENDPOINT=https://controlplane.example.com/api
export ITL_API_KEY=sk-your-key
itl-policy deploy --file my-policies.json --target itl-api --action audit
```

---

## SDK vs CLI Examples

### SDK Examples (Python)
**Files:** `kyverno_examples.py`, `azure_examples.py`

**Advantages:**
- See internal structures and details
- Understand field operators and conditions
- Build custom policies programmatically
- Integrate into applications

**Example:**
```python
from itl_policy_builder import PolicyBuilder, field, Effect

policy = (
    PolicyBuilder("my-policy")
    .display_name("My Policy")
    .with_rule(
        if_=field("location").not_equals("westeurope"),
        then=Effect.DENY,
    )
    .build()
)
```

### CLI Examples (Command Line)
**File:** `cli_examples.md`

**Advantages:**
- Quick copy-paste commands
- No Python knowledge required
- Template-based generation
- Realistic deployment workflows

**Example:**
```bash
itl-policy generate \
  --template talos-security \
  --style kyverno \
  --output policies.yaml

itl-policy deploy \
  --file policies.yaml \
  --target kubernetes \
  --action audit
```

---

## Learning Path

1. **Beginner:** Start with `cli_examples.md` to understand workflows
   ```bash
   itl-policy generate --template talos-security --style kyverno
   ```

2. **Intermediate:** Run `kyverno_examples.py` to see SDK patterns
   ```bash
   python kyverno_examples.py | grep -A 20 "Example 3"
   ```

3. **Advanced:** Run `azure_examples.py` to understand policy structures
   ```bash
   python azure_examples.py | grep -A 20 "Example 7"
   ```

4. **Expert:** Combine both, build custom policies
   ```python
   from itl_policy_builder import *
   # Create your own policies
   ```

---

## Troubleshooting Examples

### "ModuleNotFoundError: No module named 'itl_policy_builder'"
**Solution:** Install the SDK
```bash
pip install itl-policy-builder
```

### "Click is required for CLI support"
**Solution:** Install CLI extras
```bash
pip install itl-policy-builder[cli]
```

### Example script takes too long
**Solution:** Run specific example by opening the file and calling functions directly
```python
# In Python interpreter
from kyverno_examples import example_1_pod_security
example_1_pod_security()
```

### CLI command not found: "itl-policy: command not found"
**Solution:** Install with CLI tools and check PATH
```bash
pip install itl-policy-builder[cli]
which itl-policy
```

---

## Next Steps

### 1. Explore Built-in Templates
```bash
itl-policy list
itl-policy list --category security
itl-policy list --category pqc
```

### 2. Generate Your First Policy
```bash
itl-policy generate \
  --template talos-security \
  --style kyverno \
  --output my-first-policy.yaml
```

### 3. Customize and Deploy
```bash
# Edit my-first-policy.yaml as needed
itl-policy validate --file my-first-policy.yaml
itl-policy deploy --file my-first-policy.yaml --target kubernetes --action audit
```

### 4. Build Custom Policies
```python
from itl_policy_builder import PolicyBuilder, field, Effect

# Create your custom policy
my_policy = (
    PolicyBuilder("my-custom-policy")
    .display_name("My Custom Policy")
    .with_rule(
        if_=field("tags.environment").equals("production"),
        then=Effect.AUDIT,
        message="Audit production resources",
    )
    .build()
)
```

---

## References

- **SDK Documentation:** [../src/itl_policy_builder/](../src/itl_policy_builder/)
- **CLI Guide:** [../docs/CLI.md](../docs/CLI.md)
- **Multi-Format Generation:** [../docs/MULTI_FORMAT_GENERATION.md](../docs/MULTI_FORMAT_GENERATION.md)
- **README:** [../README.md](../README.md)
- **API Reference:** [../docs/API_REFERENCE.md](../docs/API_REFERENCE.md) (if available)

---

## Contributing New Examples

To add new examples:

1. **For Kyverno:** Add new example function to `kyverno_examples.py`
2. **For Azure ARM:** Add new example function to `azure_examples.py`
3. **For CLI:** Add new workflow to `cli_examples.md`
4. **Update this guide:** Document the new example here

Format: Keep examples under 50 lines, with clear comments and outputs.

---

**Last Updated:** February 2026
**Examples Included:** 31 total (13 Kyverno, 10 Azure ARM, 8 CLI workflows)
