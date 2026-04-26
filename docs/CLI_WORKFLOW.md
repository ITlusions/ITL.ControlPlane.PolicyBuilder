# CLI Workflow — YaRM Policies met PolicyBuilder

## Overzicht

De PolicyBuilder CLI ondersteunt nu **volledige managed identity policies** met on-the-fly YAML/JSON conversie en Azure deployment.

## Quick Start

### 1. Genereer Policies (YAML — "YaRM")

```powershell
# Genereer managed identity policy suite als YAML
itl-policy generate `
  --template managed-identity `
  --style azure `
  --format yaml `
  --output policies.yaml

# Output: 6 policies (5 policies + 1 initiative) in clean YAML
```

### 2. Genereer Policies (JSON)

```powershell
# Converteer on-the-fly naar JSON voor Azure deployment
itl-policy generate `
  --template managed-identity `
  --style azure `
  --format json `
  --output policies.json
```

### 3. Deploy naar Azure

```powershell
# Dry-run eerst (test zonder daadwerkelijk te deployen)
itl-policy deploy `
  --file policies.yaml `
  --target azure `
  --subscription-id "your-sub-id" `
  --assignment-scope "/subscriptions/your-sub-id" `
  --action audit `
  --dry-run

# Daadwerkelijk deployen (audit mode)
itl-policy deploy `
  --file policies.yaml `
  --target azure `
  --subscription-id "your-sub-id" `
  --assignment-scope "/subscriptions/your-sub-id" `
  --action audit

# Enforce mode (policies worden afgedwongen)
itl-policy deploy `
  --file policies.yaml `
  --target azure `
  --subscription-id "your-sub-id" `
  --assignment-scope "/subscriptions/your-sub-id" `
  --action enforce
```

### 4. Deployment met Environment Variables

```powershell
# Stel Azure credentials in
$env:AZURE_SUBSCRIPTION_ID = "your-sub-id"
$env:AZURE_ASSIGNMENT_SCOPE = "/subscriptions/your-sub-id"

# Deploy zonder command-line args
itl-policy deploy `
  --file policies.yaml `
  --target azure `
  --action audit
```

## Wat Krijg Je?

De `managed-identity` template genereert:

### 5 Policies:
1. **deny-sp-password-credentials** — Blokkeert password-based service principals
2. **deny-sp-certificate-credentials** — Blokkeert certificate-based authentication  
3. **audit-legacy-sp-credentials** — Audit bestaande credentials (discovery mode)
4. **require-managed-identity-resources** — Vereist managed identities op resources
5. **allow-workload-identity** — Documeert compliant workload identities

### 1 Initiative:
- **managed-identity-enforcement** — Bundelt alle 5 policies

## Format Conversie Matrix

| Van  | Naar | CLI Commando |
|------|------|--------------|
| Code | YAML | `itl-policy generate --format yaml` |
| Code | JSON | `itl-policy generate --format json` |
| YAML | Azure | `itl-policy deploy --file *.yaml --target azure` |
| JSON | Azure | `itl-policy deploy --file *.json --target azure` |

## Advanced: Multi-Target Deployment

```powershell
# Deploy naar zowel Kubernetes als Azure
itl-policy deploy `
  --file policies.yaml `
  --target both `
  --kubeconfig ~/.kube/config `
  --subscription-id "your-sub-id" `
  --assignment-scope "/subscriptions/your-sub-id"
```

## Tips

### ✅ Gebruik YAML als Source of Truth
```powershell
# Genereer eenmalig YAML
itl-policy generate --template managed-identity --style azure --format yaml -o policies.yaml

# Deploy direct vanuit YAML (CLI converteert automatisch naar JSON voor Azure API)
itl-policy deploy --file policies.yaml --target azure
```

### ✅ Dry-Run Eerst
```powershell
# Test deployment zonder wijzigingen
itl-policy deploy --file policies.yaml --target azure --dry-run
```

### ✅ Start met Audit Mode
```powershell
# Ontdek eerst wat er non-compliant is
itl-policy deploy --file policies.yaml --target azure --action audit

# Later overschakelen naar enforce
itl-policy deploy --file policies.yaml --target azure --action enforce
```

### ✅ Resource Group Scoped Deployment
```powershell
# Deploy op resource group niveau
itl-policy deploy `
  --file policies.yaml `
  --target azure `
  --subscription-id "your-sub-id" `
  --resource-group "my-rg" `
  --assignment-scope "/subscriptions/your-sub-id/resourceGroups/my-rg"
```

## Beschikbare Templates

| Template | Style | Beschrijving |
|----------|-------|--------------|
| `managed-identity` | azure | Passwordless authentication enforcement |
| `cis-azure` | azure | CIS Microsoft Azure Foundations Benchmark |
| `pqc-transition` | azure | Post-quantum cryptography readiness |
| `talos-security` | kyverno | Kubernetes security voor Talos |
| `security` | kyverno | General Kubernetes security |

## CLI Commands Overzicht

```powershell
# Help
itl-policy --help
itl-policy generate --help
itl-policy deploy --help

# Lijst templates
itl-policy list

# Genereer
itl-policy generate --template <name> --style <azure|kyverno> --format <yaml|json>

# Deploy
itl-policy deploy --file <path> --target <azure|kubernetes|both>

# Validate
itl-policy validate --file <path> --target azure
```

## Troubleshooting

### "PyYAML required" Error
```powershell
pip install "itl-policy-builder[cli]"
```

### Azure Authentication Failed
```powershell
# Login met Azure CLI
az login
az account set --subscription "your-sub-id"

# Of gebruik environment variables
$env:AZURE_SUBSCRIPTION_ID = "your-sub-id"
$env:AZURE_TENANT_ID = "your-tenant-id"
```

### Deployment Permissions
Je Azure identity heeft deze permissions nodig:
- `Microsoft.Authorization/policyDefinitions/write`
- `Microsoft.Authorization/policySetDefinitions/write`
- `Microsoft.Authorization/policyAssignments/write`

Rol: **Resource Policy Contributor** of **Owner**

---

**Version**: 1.0.0  
**Last Updated**: 25 april 2026
