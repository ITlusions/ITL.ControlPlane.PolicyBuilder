# Multi-Format Policy Generation

The ITL Policy Builder CLI now supports generating policies in multiple formats, allowing you to use the same policy templates across different platforms and frameworks.

## Supported Styles

### 1. **Kyverno** (Kubernetes-native)
Generate policies for **Kubernetes admission control** using Kyverno.

```bash
itl-policy generate --template talos-security --style kyverno
```

**Best for:**
- Kubernetes clusters (especially Talos)
- Pod security enforcement
- Image validation
- Network policy enforcement
- Runtime compliance checking

**Output:** Kyverno `ClusterPolicy` YAML/JSON

**Example:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: pod-security-baseline
spec:
  validationFailureAction: audit
  rules:
  - name: check-security-context
    # ...
```

---

### 2. **Azure ARM** (Azure Resource Manager)
Generate policies for **Azure governance** using PolicyDefinitions.

```bash
itl-policy generate --template talos-security --style azure
```

**Best for:**
- Azure subscription governance
- Compliance with Azure security baselines
- Azure Policy enforcement
- Resource Manager deployments
- Multi-cloud strategy with Azure

**Output:** Azure `PolicyDefinition` JSON/YAML

**Example:**
```json
{
  "type": "ITL.Authorization/policyDefinitions",
  "properties": {
    "displayName": "Require Resource Location",
    "policyType": "Custom",
    "policyRule": {
      "if": {
        "field": "location",
        "notEquals": "westeurope"
      },
      "then": {
        "effect": "Deny"
      }
    }
  }
}
```

---

### 3. **Custom** (Extensible)
Framework for future policy formats.

```bash
itl-policy generate --template talos-security --style custom
```

**Planned support:**
- HashiCorp Sentinel
- Cloud Foundry policies
- Custom JSON schemas
- OpenPolicyAgent (Rego)

---

## Output Formats

Each style can be serialized in multiple formats:

```bash
# YAML (default)
itl-policy generate --template talos-security --style kyverno --format yaml

# JSON
itl-policy generate --template talos-security --style kyverno --format json

# YAML (for Azure)
itl-policy generate --template talos-security --style azure --format yaml

# JSON (for Azure)
itl-policy generate --template talos-security --style azure --format json
```

---

## Available Templates

### talos-security
**Security hardening policies for Talos Kubernetes.**

**Includes:**
- Pod security baseline (non-root, read-only filesystem options)
- Image registry whitelisting
- Privileged container blocking
- Resource limit enforcement
- Capability dropping
- SELinux enforcement

**Available as:**
- Kyverno policies (YAML/JSON)
- Azure ARM policies (YAML/JSON)

**Deploy to Kubernetes:**
```bash
itl-policy generate --template talos-security --style kyverno -o talos-k8s.yaml
itl-policy deploy --file talos-k8s.yaml --target kubernetes --action audit
```

**Deploy to Azure:**
```bash
itl-policy generate --template talos-security --style azure -o talos-azure.json
itl-policy deploy --file talos-azure.json --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID"
```

---

### pqc-transition
**Post-Quantum Cryptography readiness policies.**

**Includes:**
- Certificate validation rules
- Algorithm recommendations
- PQC migration tracking
- Compliance checkpoints

**Available as:**
- Kyverno policies (YAML/JSON)
- Azure ARM policies (YAML/JSON)

---

## Real-World Workflows

### Multi-Environment Enforcement

Deploy the same logical policies across different platforms:

```bash
# 1. Generate both styles from single template
itl-policy generate --template talos-security --style kyverno -o k8s.yaml
itl-policy generate --template talos-security --style azure -o azure.json

# 2. Deploy to Kubernetes
itl-policy deploy --file k8s.yaml --target kubernetes --action enforce

# 3. Deploy to Azure
itl-policy deploy --file azure.json --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID" \
  --action enforce
```

### Compliance Across Platforms

Ensure consistent security posture:

```bash
# 1. Generate for all platforms
itl-policy generate --template talos-security --style kyverno -o policies/k8s.yaml
itl-policy generate --template talos-security --style azure -o policies/azure.json

# 2. Commit to version control
git add policies/
git commit -m "Security baseline v1.0"

# 3. Deploy in audit mode first
itl-policy deploy --file policies/k8s.yaml --target kubernetes --action audit &
itl-policy deploy --file policies/azure.json --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID" \
  --action audit &
wait

# 4. Review violations
# ... check audit logs, compliance dashboards ...

# 5. Enforce
itl-policy deploy --file policies/k8s.yaml --target kubernetes --action enforce
itl-policy deploy --file policies/azure.json --target azure \
  --subscription-id "$SUBSCRIPTION_ID" \
  --assignment-scope "/subscriptions/$SUBSCRIPTION_ID" \
  --action enforce
```

---

## Command Syntax

### Basic
```bash
itl-policy generate --template <template> --style <style> [--format <format>] [--output <file>]
```

### Options
- `--template` — Template name (talos-security, pqc-transition, custom)
- `--style` — Output style (kyverno, azure, custom)
- `--format` — Serialization (yaml, json; default: yaml)
- `--output, -o` — File path (default: stdout)

### Examples
```bash
# Kyverno to stdout
itl-policy generate --template talos-security --style kyverno

# Kyverno to file
itl-policy generate --template talos-security --style kyverno -o k8s.yaml

# Azure as JSON
itl-policy generate --template talos-security --style azure --format json

# Azure to file
itl-policy generate --template talos-security --style azure -o azure.json

# All combinations
itl-policy generate --template pqc-transition --style kyverno --format json -o pqc-k8s.json
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Template (e.g., talos-security)             │
│  Logical policies independent of platform               │
└────┬──────────────────────────────────────┬──────────────┘
     │                                       │
     ├─ --style kyverno ──→ KyvernoPolicies ├─ --format yaml  ──→ YAML
     │                     (ClusterPolicy)   ├─ --format json  ──→ JSON
     │
     └─ --style azure ───→ ARMPolicies      ├─ --format yaml  ──→ YAML
                          (PolicyDefinition)├─ --format json  ──→ JSON
```

---

## Comparison Table

| Aspect | Kyverno | Azure ARM |
|--------|---------|-----------|
| **Platform** | Kubernetes | Azure |
| **Scope** | Pod/Deployment | Subscription/Resource Group |
| **Enforcement** | Kubelet webhook | Resource Manager |
| **Speed** | Milliseconds | Seconds (deployment time) |
| **Use Case** | Runtime security | Governance at scale |
| **Best For** | Talos, K8s clusters | Azure resource management |

---

## Next Steps

1. **Deploy to your environment:**
   ```bash
   itl-policy generate --template talos-security --style kyverno -o policies.yaml
   itl-policy deploy --file policies.yaml --target kubernetes --action audit
   ```

2. **Monitor violations:**
   - Kyverno: `kubectl get policyreport -A`
   - Azure: Azure Portal → Policy → Compliance

3. **Enforce when ready:**
   ```bash
   itl-policy deploy --file policies.yaml --action enforce
   ```

4. **Add to CI/CD:**
   ```bash
   # GitHub Actions example
   - run: itl-policy validate --file policies.yaml
   - run: itl-policy deploy --file policies.yaml --target kubernetes --action enforce
   ```

---

## Troubleshooting

### "Unknown style: foo"
```bash
# Use one of: kyverno, azure, custom
itl-policy generate --template talos-security --style kyverno
```

### "PolicyBuilder (ARM policies) required"
```bash
# Install core policy builder
pip install itl-policy-builder
```

### "Kyverno style not working"
```bash
# Ensure Kyverno templates are available
itl-policy list --category talos
```

---

## See Also

- [CLI Guide](../docs/CLI.md)
- [Kyverno Integration](../README.md#kyverno-kubernetes-policies)
- [Deployment Module](../src/itl_policy_builder/deploy/deployer.py)
