# ITL Policy Builder CLI Examples

The **ITL Policy Builder CLI** provides a command-line interface for managing governance policies. Install with:

```bash
pip install itl-policy-builder[cli]
```

Once installed, use the `itl-policy` command:

---

## Basic Operations

### 1. List Available Policies

```bash
# List all templates
itl-policy list

# List policies by category
itl-policy list --category security
itl-policy list --category pqc
itl-policy list --category talos
```

**Output:**
```
Available policies (20):

  • pod-security-baseline
  • pod-security-restricted
  • require-image-signature
  • require-resource-limits
  • ...

Categories: security, image, network, pqc, talos, governance
```

---

### 2. Generate Policies from Templates

The CLI supports generating policies in multiple formats. Choose your target environment:

#### Kubernetes (Kyverno) Format

```bash
# Default: Output to stdout (YAML)
itl-policy generate --template talos-security

# Explicitly set Kyverno style
itl-policy generate --template talos-security --style kyverno --output talos-policies.yaml

# Generate as JSON
itl-policy generate --template talos-security --style kyverno --format json --output talos-policies.json

# Generate PQC transition policies
itl-policy generate --template pqc-transition --style kyverno --output pqc-policies.yaml
```

#### Azure ARM Format

```bash
# Generate Azure Resource Manager policies (JSON)
itl-policy generate --template talos-security --style azure --format json --output azure-policies.json

# Generate Azure ARM policies (YAML representation)
itl-policy generate --template talos-security --style azure --format yaml --output azure-policies.yaml

# Generate PQC policies for Azure
itl-policy generate --template pqc-transition --style azure --format json --output pqc-azure.json
```

#### Generate to Different Formats

```bash
# Kyverno as YAML (most common)
itl-policy generate --template talos-security --style kyverno --format yaml

# Kyverno as JSON (programmatic processing)
itl-policy generate --template talos-security --style kyverno --format json

# Azure as JSON (Azure Portal import)
itl-policy generate --template talos-security --style azure --format json

# Azure as YAML (documentation/review)
itl-policy generate --template talos-security --style azure --format yaml
```

---

### 3. Validate Policies

Validate policies before deploying to ensure they're correct:

```bash
# Validate for Kubernetes deployment
itl-policy validate --file policies.yaml --target kubernetes

# Validate for ITL API deployment
itl-policy validate --file policies.yaml --target itl-api \
  --api-endpoint https://controlplane.example.com

# Validate for both targets
itl-policy validate --file policies.yaml --target both
```

---

## Deployment

### 4. Deploy to Kubernetes

#### Deploy with Default Kubeconfig

```bash
itl-policy deploy \
  --file talos-policies.yaml \
  --target kubernetes
```

#### Deploy with Custom Kubeconfig

```bash
itl-policy deploy \
  --file talos-policies.yaml \
  --target kubernetes \
  --kubeconfig /path/to/kubeconfig.yaml
```

#### Deploy with Audit Mode (Default)

```bash
# Audit mode (records violations without enforcement)
itl-policy deploy \
  --file talos-policies.yaml \
  --target kubernetes \
  --action audit
```

#### Deploy with Enforcement

```bash
# Enforce mode (blocks violations)
itl-policy deploy \
  --file talos-policies.yaml \
  --target kubernetes \
  --action enforce
```

#### Dry Run

```bash
# See what would be deployed without making changes
itl-policy deploy \
  --file talos-policies.yaml \
  --target kubernetes \
  --dry-run
```

---

### 5. Deploy to ITL Control Plane

#### Using Command Line Arguments

```bash
itl-policy deploy \
  --file policies.yaml \
  --target itl-api \
  --api-endpoint https://controlplane.example.com/api \
  --api-key sk-xxxxxxxxxxxxxxxxxxxx
```

#### Using Environment Variables

```bash
export ITL_API_ENDPOINT=https://controlplane.example.com/api
export ITL_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx

itl-policy deploy \
  --file policies.yaml \
  --target itl-api
```

#### Deploy to Both Targets Simultaneously

```bash
itl-policy deploy \
  --file policies.yaml \
  --target both \
  --kubeconfig ~/.kube/config \
  --api-endpoint https://controlplane.example.com/api \
  --api-key sk-xxxxxxxxxxxxxxxxxxxx
```

---

### 6. Initialize Configuration

Create a configuration file for reuse:

```bash
itl-policy init \
  --api-endpoint https://controlplane.example.com/api \
  --api-key sk-xxxxxxxxxxxxxxxxxxxx
```

This creates `~/.itl-policy/config.json`:

```json
{
  "api_endpoint": "https://controlplane.example.com/api",
  "api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
  "kubeconfig": "/home/user/.kube/config"
}
```

---

## Complete Workflows

### Workflow 1: Generate → Validate → Deploy to Kubernetes

```bash
# Step 1: Generate policies
itl-policy generate \
  --template talos-security \
  --output my-policies.yaml

# Step 2: Validate
itl-policy validate \
  --file my-policies.yaml \
  --target kubernetes

# Step 3: Deploy in audit mode first
itl-policy deploy \
  --file my-policies.yaml \
  --target kubernetes \
  --action audit

# Step 4: Review violations, then enforce
itl-policy deploy \
  --file my-policies.yaml \
  --target kubernetes \
  --action enforce
```

### Workflow 2: Azure Resource Manager Deployment

```bash
# Step 1: Generate Azure ARM policies
itl-policy generate \
  --template talos-security \
  --style azure \
  --format json \
  --output azure-policies.json

# Step 2: Validate ARM policies
itl-policy validate \
  --file azure-policies.json \
  --target itl-api

# Step 3: Deploy to ITL API (acts as Azure ARM provider)
export ITL_API_ENDPOINT=https://controlplane.example.com/api
export ITL_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx

itl-policy deploy \
  --file azure-policies.json \
  --target itl-api \
  --action audit

# Step 4: After review, enforce
itl-policy deploy \
  --file azure-policies.json \
  --target itl-api \
  --action enforce
```

### Workflow 3: Multi-Environment Deployment

```bash
# Generate policies once
itl-policy generate \
  --template talos-security \n  --style kyverno \
  --output policies.yaml

# Deploy to development Kubernetes
export KUBECONFIG=~/.kube/dev-config.yaml
itl-policy deploy \
  --file policies.yaml \
  --target kubernetes \
  --action audit

# Deploy to production Kubernetes
export KUBECONFIG=~/.kube/prod-config.yaml
itl-policy deploy \
  --file policies.yaml \
  --target kubernetes \
  --action enforce

# Deploy to ITL Control Plane
export ITL_API_ENDPOINT=https://prod-controlplane.com/api
export ITL_API_KEY=sk-prod-key
itl-policy deploy \
  --file policies.yaml \
  --target itl-api \
  --action enforce
```

### Workflow 4: Development & Testing

```bash
# Create policies file
cat > dev-policies.yaml << 'EOF'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: audit
  rules:
  - name: check-image
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Image signature required"
      pattern:
        spec:
          containers:
          - image: "*/signatures/*"
EOF

# Validate locally
itl-policy validate --file dev-policies.yaml

# Test with dry-run
itl-policy deploy \
  --file dev-policies.yaml \
  --target kubernetes \
  --dry-run

# Deploy in audit mode
itl-policy deploy \
  --file dev-policies.yaml \
  --target kubernetes \
  --action audit

# Monitor violations, then promote to enforce
itl-policy deploy \
  --file dev-policies.yaml \
  --target kubernetes \
  --action enforce
```

---

## Help & Advanced Options

```bash
# Show general help
itl-policy --help

# Show command help
itl-policy generate --help      # Includes --style and --format options
itl-policy deploy --help
itl-policy validate --help

# Check version
itl-policy --version
```

## Available Styles & Formats

### Style: Kyverno (Kubernetes-native admission controller)
**Best for:** Talos Kubernetes clusters, pod security, image validation
**Generates:** ClusterPolicy and ClusterRole resources
**Formats:** YAML (default), JSON (for programmatic processing)

```bash
# Kyverno format (default)
itl-policy generate --template talos-security --style kyverno --format yaml

# Kyverno as JSON
itl-policy generate --template talos-security --style kyverno --format json
```

**Use Cases:**
- Enforce pod security standards on Talos/Kubernetes clusters
- Implement image registry whitelisting
- Require resource limits on workloads
- Enforce network policies
- PQC readiness labeling for containerized workloads

### Style: Azure ARM (Azure Resource Manager)
**Best for:** Azure subscriptions, compliance reporting, governance at scale
**Generates:** PolicyDefinition and PolicyAssignment resources
**Formats:** JSON (native), YAML (documentation)

```bash
# Azure ARM format as JSON (native)
itl-policy generate --template talos-security --style azure --format json

# Azure ARM format as YAML (for documentation)
itl-policy generate --template talos-security --style azure --format yaml
```

**Use Cases:**
- Enforce compliance across Azure subscriptions
- Require encryption on storage accounts
- Enforce tagging requirements at scale
- Compliance reporting to audit logs
- Policy initiatives for regulatory compliance (BIO, PQC standards)

### Style: Custom (extensible for future frameworks)
**Best for:** Custom policy engines, future frameworks, organization-specific needs

```bash
# Custom format (scaffold for implementation)
itl-policy generate --template talos-security --style custom
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ITL_API_ENDPOINT` | ITL Control Plane API endpoint (for ITL API deployments) |
| `ITL_API_KEY` | API key for ITL Control Plane authentication |
| `KUBECONFIG` | Path to Kubernetes config file (overridable with `--kubeconfig`) |

---

## Exit Codes

- **0** — Success
- **1** — General error (validation, deployment failed, missing arguments)
- **2** — Config error (missing kubeconfig, invalid API endpoint)

---

## Troubleshooting

### "Click is required for CLI support"

**Error:** `ImportError: Click is required for CLI support`

**Solution:** Install CLI extras:
```bash
pip install itl-policy-builder[cli]
pip install click>=8.1.0
```

### "Kubeconfig not found"

**Error:** `Error: Kubeconfig not found at ~/.kube/config`

**Solution:** Specify kubeconfig explicitly:
```bash
itl-policy deploy \
  --file policies.yaml \
  --kubeconfig /path/to/kubeconfig.yaml
```

### "API authentication failed"

**Error:** `❌ Invalid for itl-api: 401 Unauthorized`

**Solution:** Check API key:
```bash
export ITL_API_KEY=$(kubectl get secret api-credentials -o jsonpath='{.data.key}' | base64 -d)
itl-policy deploy --file policies.yaml --target itl-api
```

### "Policy validation failed"

**Error:** `❌ Invalid for kubernetes: policy syntax error`

**Debugging:**
```bash
# Validate the YAML first
itl-policy validate --file policies.yaml

# Check policy format manually
kubectl apply --dry-run=client -f policies.yaml
```

---

## Next Steps

- **For Programmatic Use:** See [SDK examples](./kyverno_examples.py)
- **For Platform Integration:** See [Deployment Module Docs](../src/itl_policy_builder/deploy/deployer.py)
- **For Templates:** Use `itl-policy list` to discover available policies
