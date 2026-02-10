# ITL Policy Builder CLI

A complete command-line tool for managing governance policies on the ITL Control Plane and Kubernetes clusters.

## Installation

**Core SDK (without CLI):**
```bash
pip install itl-policy-builder
```

**With CLI tools:**
```bash
pip install itl-policy-builder[cli]
```

**With Kubernetes deployment support:**
```bash
pip install itl-policy-builder[kubernetes]
```

**With Azure deployment support:**
```bash
pip install itl-policy-builder[azure]
```

**Everything (recommended for development):**
```bash
pip install itl-policy-builder[all]
```

---

## Quick Start

### 1. List Available Policies

```bash
itl-policy list
itl-policy list --category security
```

### 2. Generate Policies

```bash
# Generate Talos security bundle to stdout
itl-policy generate --template talos-security

# Save to file
itl-policy generate --template talos-security --output policies.yaml
```

### 3. Validate Policies

```bash
itl-policy validate --file policies.yaml
```

### 4. Deploy Policies

```bash
# Deploy to Kubernetes (audit mode)
itl-policy deploy --file policies.yaml --target kubernetes --action audit

# Deploy to Kubernetes (enforce mode)
itl-policy deploy --file policies.yaml --target kubernetes --action enforce

# Deploy to ITL Control Plane
export ITL_API_KEY=sk-xxxxxxxxxxxx
itl-policy deploy --file policies.yaml --target itl-api \
  --api-endpoint https://controlplane.example.com
```

---

## Commands

### `list` — List Available Policies

**Usage:**
```bash
itl-policy list [OPTIONS]
```

**Options:**
- `--category TEXT` — Filter by category (security, image, network, pqc, talos, governance)

**Example:**
```bash
itl-policy list --category talos
```

### `generate` — Generate Policies from Templates

**Usage:**
```bash
itl-policy generate [OPTIONS]
```

**Options:**
- `--template TEXT` — Template name (talos-security, pqc-transition, custom) **[default: talos-security]**
- `--style TEXT` — Policy style/format:
  - `kyverno` — Kubernetes-native Kyverno policies **[default]**
  - `azure` — Azure ARM Resource Manager policies
  - `custom` — Other formats (extensible)
- `--output, -o PATH` — Output file (default: stdout)
- `--format TEXT` — Serialization format (yaml, json; default: yaml)

**Examples:**

Generate Kyverno policies for Kubernetes:
```bash
itl-policy generate --template talos-security --style kyverno
itl-policy generate --template talos-security --style kyverno --output k8s-policies.yaml
```

Generate Azure ARM policies:
```bash
itl-policy generate --template talos-security --style azure
itl-policy generate --template talos-security --style azure --format json --output azure-policies.json
```

### `validate` — Validate Policies

**Usage:**
```bash
itl-policy validate [OPTIONS]
```

**Options:**
- `--file, -f PATH` — Policy file (YAML/JSON) **[required]**
- `--target TEXT` — Validation target (kubernetes, itl-api, both; default: kubernetes)

**Example:**
```bash
itl-policy validate --file policies.yaml --target kubernetes
```

### `deploy` — Deploy Policies

**Usage:**
```bash
itl-policy deploy [OPTIONS]
```

**Options:**
- `--file, -f PATH` — Policy file (YAML/JSON) **[required]**
- `--target TEXT` — Deployment target (kubernetes, itl-api, azure, both; default: kubernetes)
- `--kubeconfig PATH` — Kubeconfig path (for Kubernetes; default: ~/.kube/config)
- `--api-endpoint TEXT` — ITL API endpoint (for itl-api)
- `--api-key TEXT` — ITL API key (or use ITL_API_KEY env var)
- `--subscription-id TEXT` — Azure subscription ID (for Azure)
- `--tenant-id TEXT` — Azure tenant ID (optional for Azure)
- `--assignment-scope TEXT` — Azure assignment scope (for Azure; e.g., /subscriptions/{sub-id})
- `--azure-auth TEXT` — Azure auth method (default, cli, env; default: default)
- `--action TEXT` — Deployment action (audit, enforce; default: audit)
- `--dry-run` — Simulate deployment without making changes

**Examples:**
```bash
# Deploy to Kubernetes in audit mode
itl-policy deploy --file policies.yaml --action audit

# Deploy to Azure subscription
itl-policy deploy --file azure-policies.json --target azure \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --assignment-scope "/subscriptions/00000000-0000-0000-0000-000000000000"

# Deploy to ITL Control Plane with dry-run
itl-policy deploy --file policies.yaml --target itl-api \
  --api-endpoint https://controlplane.example.com \
  --dry-run

# Deploy to both Kubernetes and ITL API
itl-policy deploy --file policies.yaml --target both
```

### `init` — Initialize Configuration

**Usage:**
```bash
itl-policy init [OPTIONS]
```

**Options:**
- `--api-endpoint TEXT` — ITL API endpoint
- `--api-key TEXT` — ITL API key

**Example:**
```bash
itl-policy init --api-endpoint https://controlplane.example.com \
  --api-key sk-xxxxxxxxxxxx
```

This creates `~/.itl-policy/config.json` for persistent configuration.

---

## Environment Variables

| Variable | Usage |
|----------|-------|
| `ITL_API_ENDPOINT` | ITL Control Plane API endpoint |
| `ITL_API_KEY` | API authentication key |
| `KUBECONFIG` | Path to Kubernetes config file |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID for deployments |
| `AZURE_TENANT_ID` | Azure tenant ID (optional) |
| `AZURE_ASSIGNMENT_SCOPE` | Azure policy assignment scope |
| `AZURE_RESOURCE_GROUP` | Azure resource group (optional) |
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |

---

## Workflows

### Workflow: Generate → Validate → Deploy

```bash
# Step 1: Generate policies
itl-policy generate --template talos-security --output my-policies.yaml

# Step 2: Validate them
itl-policy validate --file my-policies.yaml

# Step 3: Deploy in audit mode first
itl-policy deploy --file my-policies.yaml --action audit

# Step 4: Monitor violations, then enforce
itl-policy deploy --file my-policies.yaml --action enforce
```

### Workflow: Multi-Environment Deployment

```bash
# Generate once
itl-policy generate --template talos-security --output policies.yaml

# Deploy to dev (audit)
export KUBECONFIG=~/.kube/dev-config.yaml
itl-policy deploy --file policies.yaml --action audit

# Deploy to prod (enforce)
export KUBECONFIG=~/.kube/prod-config.yaml
itl-policy deploy --file policies.yaml --action enforce

# Deploy to ITL Control Plane
export ITL_API_ENDPOINT=https://prod-controlplane.com/api
export ITL_API_KEY=sk-prod-key
itl-policy deploy --file policies.yaml --target itl-api --action enforce
```

---

## Output Modes

### Audit Mode (Default)

```bash
itl-policy deploy --file policies.yaml --action audit
```

- **Kyverno:** Logs policy violations without blocking
- **ITL API:** Records violations in compliance database
- **Use case:** Initial rollout, monitoring compliance gaps

### Enforce Mode

```bash
itl-policy deploy --file policies.yaml --action enforce
```

- **Kyverno:** Blocks policy violations
- **ITL API:** Blocks resource creation/updates that violate policies
- **Use case:** Production enforcement, security hardening

### Dry Run

```bash
itl-policy deploy --file policies.yaml --dry-run
```

- Simulates deployment without making changes
- Useful for testing and validation pipelines

---

## Return Values

Commands return exit codes:

- **0** — Success
- **1** — Error (validation failed, deployment failed, missing required args)
- **2** — Configuration error (missing file, invalid kubeconfig)

---

## Troubleshooting

### "Click is required"
```bash
pip install itl-policy-builder[cli]
```

### "Kubeconfig not found"
```bash
itl-policy deploy --file policies.yaml --kubeconfig /path/to/config.yaml
```

### "API authentication failed"
Check your API key:
```bash
export ITL_API_KEY=$(kubectl get secret api-key -o jsonpath='{.data.key}' | base64 -d)
itl-policy deploy --file policies.yaml --target itl-api
```

### "Policy validation failed"
Validate the YAML syntax first:
```bash
itl-policy validate --file policies.yaml
kubectl apply --dry-run=client -f policies.yaml
```

---

## Full Examples

See [CLI Examples](./examples/cli_examples.md) for comprehensive workflow examples.

---

## Architecture

The CLI is built with:

- **Click 8.1+** — Command-line framework
- **httpx** — Async HTTP client for ITL API
- **kubernetes** — Optional, for Kubernetes deployments
- **PyYAML** — Policy serialization

The CLI is **optional** and can be installed separately from the core SDK:

```
pip install itl-policy-builder          # Just SDK, no CLI
pip install itl-policy-builder[cli]     # SDK + CLI tools
```

This keeps the core SDK lightweight for programmatic use.

---

## Core SDK Integration

The CLI is built on top of the core SDK:

```python
from itl_policy_builder import KyvernoPolicyBuilder
from itl_policy_builder.deploy import PolicyDeployer, DeployConfig, DeployTarget

# programmatic usage still works
builder = KyvernoPolicyBuilder("my-policy")
deployer = PolicyDeployer(...)
```

---

## Next Steps

- **Examples:** [CLI Examples](./examples/cli_examples.md)
- **SDK Docs:** [Kyverno Integration](../README.md#kyverno-kubernetes-policies)
- **Deployment Module:** [PolicyDeployer API](../src/itl_policy_builder/deploy/deployer.py)
