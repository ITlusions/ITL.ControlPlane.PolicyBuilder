# Azure Policy Deployment Examples

This guide shows how to deploy ITL Policy Builder-generated policies directly to **Azure subscriptions** using native Azure Resource Manager (ARM) APIs.

## Prerequisites

### 1. Install Azure SDK
```bash
pip install itl-policy-builder[azure]
```

This installs:
- `azure-mgmt-authorization` — Azure Policy management
- `azure-identity` — Azure authentication

### 2. Authenticate with Azure
```bash
# Login with Azure CLI
az login

# Or set environment variables
export AZURE_SUBSCRIPTION_ID="subscription-id-here"
export AZURE_TENANT_ID="tenant-id-here"
```

### 3. Set Required Parameters
```bash
export AZURE_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
export AZURE_ASSIGNMENT_SCOPE="/subscriptions/00000000-0000-0000-0000-000000000000"
```

---

## Using the CLI

### 1. Generate Azure Policies
```bash
# Generate policies from template
itl-policy generate \
  --template talos-security \
  --style azure \
  --format json \
  --output azure-policies.json
```

**Output:** `azure-policies.json` containing Azure PolicyDefinitions

### 2. Deploy to Azure (Dry Run First)
```bash
itl-policy deploy \
  --file azure-policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000" \
  --action audit \
  --dry-run
```

**Output:**
```
📋 Loaded 5 policies from azure-policies.json
🚀 Deploying 5 policies...
   (DRY RUN MODE)
✅ 5 policies deployed to azure (details: ...)
```

### 3. Deploy in Audit Mode
```bash
# Create policies but don't enforce yet (audit mode)
itl-policy deploy \
  --file azure-policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000" \
  --action audit
```

Monitor violations in Azure Portal:
- Go to **Policy** → **Compliance**
- Check which resources violate policies
- Review violations for 7-14 days

### 4. Switch to Enforce Mode
```bash
# Once you've reviewed violations, enforce policies
itl-policy deploy \
  --file azure-policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000" \
  --action enforce
```

Now violations will be **blocked** at resource creation time.

---

## Authentication Methods

### Azure CLI (Recommended for Development)
```bash
az login
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --azure-auth cli
```

Automatically uses your `az login` credentials.

### Environment Variables
```bash
export AZURE_CLIENT_ID="client-id"
export AZURE_CLIENT_SECRET="client-secret"
export AZURE_TENANT_ID="tenant-id"
export AZURE_SUBSCRIPTION_ID="subscription-id"

itl-policy deploy \
  --file policies.json \
  --target azure \
  --assignment-scope "/subscriptions/sub-id" \
  --azure-auth env
```

### Managed Identity (Azure VMs, App Service)
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --azure-auth default
```

Uses the VM/App Service managed identity automatically.

---

## Scope Options

### Subscription-Level Policies
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000"
```

Applies to all resources in the subscription.

### Resource Group-Level Policies
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg"
```

Applies only to resources in `my-rg`.

### Management Group-Level Policies
```bash
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/providers/Microsoft.Management/managementGroups/my-mg"
```

Applies to all subscriptions under the management group.

---

## Policy Types and Examples

### Example 1: Location Policy
```bash
# Generate location-restricted policies
itl-policy generate \
  --template allowed-locations \
  --style azure \
  --output location-policy.json

# Deploy
itl-policy deploy \
  --file location-policy.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action enforce
```

**Effect:** Resources can only be created in specified locations (e.g., westeurope, northeurope)

### Example 2: Encryption Policy
```bash
# Generate encryption policies
itl-policy generate \
  --template encryption-baseline \
  --style azure \
  --output encryption-policy.json

# Deploy
itl-policy deploy \
  --file encryption-policy.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action enforce
```

**Effect:** Storage accounts and databases must have encryption enabled

### Example 3: Tagging Policy
```bash
# Generate tagging policies
itl-policy generate \
  --template tag-enforcement \
  --style azure \
  --output tagging-policy.json

# Deploy with audit first
itl-policy deploy \
  --file tagging-policy.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action audit

# After monitoring, enforce
itl-policy deploy \
  --file tagging-policy.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action enforce
```

**Effect:** All resources must have required tags (e.g., environment, owner, cost-center)

### Example 4: PQC Readiness Policy
```bash
# Generate PQC readiness policies
itl-policy generate \
  --template pqc-readiness \
  --style azure \
  --output pqc-policy.json

# Deploy in audit mode to plan transition
itl-policy deploy \
  --file pqc-policy.json \
  --target azure \
  --subscription-id "sub-id" \
  --assignment-scope "/subscriptions/sub-id" \
  --action audit
```

**Effect:** Audit current cryptography state, plan quantum-safe migration

---

## Complete Workflow Example

### Step 1: Generate Policies
```bash
itl-policy generate \
  --template talos-security \
  --style azure \
  --format json \
  --output production-policies.json
```

### Step 2: Test in Non-Prod
```bash
# Deploy to dev subscription first
itl-policy deploy \
  --file production-policies.json \
  --target azure \
  --subscription-id "dev-sub-id" \
  --assignment-scope "/subscriptions/dev-sub-id" \
  --action audit \
  --dry-run

# See what would be deployed
# Then remove --dry-run to actually deploy
itl-policy deploy \
  --file production-policies.json \
  --target azure \
  --subscription-id "dev-sub-id" \
  --assignment-scope "/subscriptions/dev-sub-id" \
  --action audit
```

### Step 3: Review in Azure Portal
- Navigate to **Policy** → **Compliance**
- Check **Non-Compliant Resources**
- Review violations with teams
- Adjust policies if needed

### Step 4: Deploy to Production
```bash
# Once satisfied with audit results, deploy to production
itl-policy deploy \
  --file production-policies.json \
  --target azure \
  --subscription-id "prod-sub-id" \
  --assignment-scope "/subscriptions/prod-sub-id" \
  --action audit

# Monitor for 2-3 weeks, then enforce
itl-policy deploy \
  --file production-policies.json \
  --target azure \
  --subscription-id "prod-sub-id" \
  --assignment-scope "/subscriptions/prod-sub-id" \
  --action enforce
```

---

## Environment Variables Reference

| Variable | Purpose | Example |
|----------|---------|---------|
| `AZURE_SUBSCRIPTION_ID` | Subscription for deployment | `00000000-0000-0000-0000-000000000000` |
| `AZURE_TENANT_ID` | Tenant ID (optional) | `00000000-0000-0000-0000-000000000000` |
| `AZURE_ASSIGNMENT_SCOPE` | Scope for policy assignment | `/subscriptions/sub-id` |
| `AZURE_RESOURCE_GROUP` | Resource group (optional) | `my-resource-group` |
| `AZURE_CLIENT_ID` | Service principal client ID | (for env auth) |
| `AZURE_CLIENT_SECRET` | Service principal secret | (for env auth) |

---

## Troubleshooting

### "Azure SDK not installed"
**Error:** `Azure SDK not installed. Install with: pip install azure-mgmt-authorization azure-identity`

**Solution:**
```bash
pip install itl-policy-builder[azure]
```

### "Authentication failed"
**Error:** `DefaultAzureCredential failed to authenticate`

**Solution:** Try these in order:
1. Run `az login` for Azure CLI authentication
2. Set environment variables for service principal
3. Use managed identity on Azure resources
4. Pass `--azure-auth cli` or `--azure-auth env`

### "Subscription not found"
**Error:** `The specified subscription could not be found`

**Solution:**
```bash
# List available subscriptions
az account list -o table

# Set the correct subscription
az account set --subscription "subscription-id"

# Pass to CLI
itl-policy deploy \
  --file policies.json \
  --target azure \
  --subscription-id "subscription-id" \
  --assignment-scope "/subscriptions/subscription-id"
```

### "Permission denied"
**Error:** `InvalidClientTokenError: Unable to create policy definitions. Insufficient permissions.`

**Solution:** Ensure your user/service principal has these roles:
- **Policy Contributor** (for creating policy definitions)
- **Resource Policy Contributor** (for creating assignments)

Assign via:
```bash
az role assignment create \
  --role "Policy Contributor" \
  --assignee "your-principal-id" \
  --scope "/subscriptions/subscription-id"
```

---

## CLI Flags Reference

```bash
itl-policy deploy \
  --file <path>                      # Policy file (required)
  --target azure                     # Deployment target
  --subscription-id <sub-id>         # Azure subscription (required)
  --tenant-id <tenant-id>            # Optional: Azure tenant
  --resource-group <rg-name>         # Optional: resource group
  --assignment-scope <scope>         # Scope for assignment (required)
  --azure-auth {default,cli,env}     # Auth method (default: default)
  --action {audit,enforce}           # Effect mode (default: audit)
  --dry-run                          # Simulate without deploying
```

---

## Next Steps

1. **Set up Managed Identity** — Use Azure RBAC for production deployments
2. **Create Policy Initiatives** — Group related policies with `PolicySetBuilder`
3. **Automate with CI/CD** — Deploy policies via Azure DevOps or GitHub Actions
4. **Monitor Compliance** — Check **Policy** → **Compliance** in Azure Portal
5. **Scale to Management Groups** — Deploy across multiple subscriptions

---

## See Also

- [CLI Guide](../docs/CLI.md) — Complete CLI documentation
- [Azure Examples](azure_examples.py) — SDK code examples
- [Multi-Format Generation](../docs/MULTI_FORMAT_GENERATION.md) — Kyverno vs Azure
- [README](../README.md) — Full project overview
