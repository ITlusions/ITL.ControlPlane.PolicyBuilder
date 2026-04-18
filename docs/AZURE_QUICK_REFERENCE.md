# Azure Deployment — Quick Reference

**Feature:** Deploy ITL Policy Builder policies directly to Azure subscriptions using native Azure Resource Manager APIs.

---

## Installation

```bash
pip install itl-policy-builder[azure]
```

---

## Quick Start (5 Minutes)

### 1. Generate Policies
```bash
itl-policy generate \
  --template talos-security \
  --style azure \
  --format json \
  --output policies.json
```

### 2. Login to Azure
```bash
az login
```

### 3. Deploy (Audit Mode First)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "YOUR-SUBSCRIPTION-ID" \
  --assignment-scope "/subscriptions/YOUR-SUBSCRIPTION-ID" \
  --action audit \
  --dry-run
```

### 4. Review and Enforce
```bash
# Check Azure Portal for violations
# Policy → Compliance → Non-Compliant Resources

# Once approved, switch to enforce
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "YOUR-SUBSCRIPTION-ID" \
  --assignment-scope "/subscriptions/YOUR-SUBSCRIPTION-ID" \
  --action enforce
```

---

## Common Commands

### Get Subscription ID
```bash
az account show --query id -o tsv
# Output: 00000000-0000-0000-0000-000000000000
```

### Deploy to Subscription (All Resources)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id"
```

### Deploy to Resource Group (Scoped)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id/resourceGroups/my-rg"
```

### Deploy Multiple Policies
```bash
itl-policy deploy \
  --file all-policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id"
```

### Dry-Run (Test Without Deploying)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --dry-run
```

### Audit Mode (Log Violations)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action audit
```

### Enforce Mode (Block Violations)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action enforce
```

---

## Authentication

### Azure CLI (Easiest)
```bash
az login
itl-policy deploy --file policies.json --target azure --subscription-id "sub-id" --assignment-scope "/subscriptions/sub-id"
```

### Service Principal (CI/CD)
```bash
export AZURE_CLIENT_ID="client-id"
export AZURE_CLIENT_SECRET="client-secret"
export AZURE_TENANT_ID="tenant-id"

itl-policy deploy --file policies.json --target azure --subscription-id "sub-id" --assignment-scope "/subscriptions/sub-id" --azure-auth env
```

### Managed Identity (Azure VMs)
```bash
# No setup needed, uses VM's managed identity automatically
itl-policy deploy --file policies.json --target azure --subscription-id "sub-id" --assignment-scope "/subscriptions/sub-id"
```

---

## Policy Styles

### Generate for Azure
```bash
itl-policy generate --style azure --format json
```

### Available Styles
```bash
itl-policy list              # All policies
itl-policy list --category security   # By category
itl-policy list --category pqc        # PQC policies
itl-policy list --category talos      # Talos policies
```

---

## Verification

### Check Deployment
```bash
# Azure Portal → Policy → Definitions
# Look for policies created by "itl-policy-builder"
```

### Check Compliance
```bash
# Azure Portal → Policy → Compliance
# View non-compliant resources
```

### Check via Azure CLI
```bash
az policy definition list --query "[?displayName.contains('Talos')]"
az policy assignment list --scope "/subscriptions/sub-id"
```

---

## Environment Variables

```bash
export AZURE_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
export AZURE_ASSIGNMENT_SCOPE="/subscriptions/00000000-0000-0000-0000-000000000000"

# Then use simplified commands:
itl-policy deploy --file policies.json --target azure
```

---

## Deployment Scopes

| Scope | Example |
|-------|---------|
| Subscription | `/subscriptions/sub-id` |
| Resource Group | `/subscriptions/sub-id/resourceGroups/rg-name` |
| Management Group | `/providers/ITL.Core/managementGroups/mg-name` |

---

## Policy Sets (Initiatives)

Group multiple policies into an initiative and deploy them as one unit:

```python
from itl_policy_builder import PolicySetBuilder
from itl_policy_builder.deploy import PolicyDeployer, DeployConfig, DeployTarget, DeployAction

initiative = (
    PolicySetBuilder("itl-security-baseline")
    .display_name("ITL Security Baseline")
    .description("Core security policies for all environments")
    .category("Security")
    .version("1.0.0")
    .add_group("Security", "Security-related policies")
    .add_policy(
        "/providers/ITL.Authorization/policyDefinitions/require-tag-environment",
        groups=["Security"],
    )
    .add_policy(
        "/providers/ITL.Authorization/policyDefinitions/deny-public-ip",
        parameters={"effect": {"value": "Deny"}},
        groups=["Security"],
    )
)

# Serialize to ARM-compatible dict
arm_dict = initiative.to_azure_dict()  # or: initiative.build_dict()

config = DeployConfig(
    target=DeployTarget.AZURE,
    azure_subscription_id="sub-id",
    azure_assignment_scope="/subscriptions/sub-id",
    azure_credential="cli",
    action=DeployAction.AUDIT,
)

# The deployer auto-detects initiatives (policyDefinitions present) vs. individual policies
import asyncio
deployer = PolicyDeployer(configs=[config])
results = asyncio.run(deployer.deploy([arm_dict]))
```

The deployer auto-detects whether a payload is a **policy definition** or a **policy set (initiative)** based on the presence of `policyDefinitions` in the properties, or the `type` field being `ITL.Authorization/policySetDefinitions` or `Microsoft.Authorization/policySetDefinitions`.

### Use a Built-in Initiative

```python
from itl_policy_builder.templates import get_bio_initiative, get_pqc_initiative

# BIO (Dutch government security baseline) — 17 policies bundled
bio = get_bio_initiative()
arm_dict = bio.to_azure_dict()

# PQC (Post-Quantum Cryptography) — 16 policies bundled
pqc = get_pqc_initiative()
arm_dict = pqc.to_azure_dict()
```

### Generate Initiatives via CLI

```bash
# Generate BIO security initiative (Azure ARM format)
itl-policy generate --template talos-security --style azure --format json --output bio-initiative.json

# Generate PQC transition initiative
itl-policy generate --template pqc-transition --style azure --format json --output pqc-initiative.json

# Deploy initiative
itl-policy deploy \
  --file bio-initiative.json \
  --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID"
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Azure SDK not installed` | `pip install itl-policy-builder[azure]` |
| `Subscription not found` | `az account set --subscription "sub-id"` |
| `Permission denied` | Assign "Policy Contributor" role (scope: subscription) |
| `Authentication failed` | Run `az login` or set env vars |
| `azure-mgmt-authorization not found` | Dependency fixed — use `azure-mgmt-resource` |

---

## Complete Workflow

```bash
# Step 1: Generate policies
itl-policy generate \
  --template talos-security \
  --style azure \
  --output my-policies.json

# Step 2: Get subscription ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# Step 3: Dry-run test
itl-policy deploy \
  --file my-policies.json \
  --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID" \
  --action audit \
  --dry-run

# Step 4: Deploy in audit mode
itl-policy deploy \
  --file my-policies.json \
  --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID" \
  --action audit

# Step 5: Review in Azure Portal (2-7 days)
echo "Review Policy → Compliance in Azure Portal"

# Step 6: Switch to enforce mode
itl-policy deploy \
  --file my-policies.json \
  --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID" \
  --action enforce
```

---

## See Also

- **Full Guide:** `examples/azure_deployment.md`
- **SDK Examples:** `examples/azure_examples.py`
- **CLI Docs:** `docs/CLI.md`
- **Implementation:** `AZURE_DEPLOYMENT_SUMMARY.md`
