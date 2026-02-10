# ITL Policy Builder CLI — Quick Reference

## Installation

```bash
pip install itl-policy-builder[cli]
```

## Essential Commands

### Discover Policies
```bash
itl-policy list                          # All policies
itl-policy list --category security      # By category
```

### Generate Policies

#### Kyverno (Kubernetes)
```bash
itl-policy generate --template talos-security --style kyverno              # Kyverno YAML
itl-policy generate --template talos-security --style kyverno -o k8s.yaml   # Save file
itl-policy generate --template talos-security --style kyverno --format json # JSON format
```

#### Azure ARM
```bash
itl-policy generate --template talos-security --style azure               # Azure YAML
itl-policy generate --template talos-security --style azure -o azure.yaml  # Save file
itl-policy generate --template talos-security --style azure --format json  # JSON format
```

### Validate Policies
```bash
itl-policy validate --file policies.yaml
itl-policy validate --file policies.yaml --target kubernetes
```

### Deploy Policies

#### To Kubernetes
```bash
# Audit mode (records violations)
itl-policy deploy --file policies.yaml --target kubernetes --action audit

# Enforce mode (blocks violations)
itl-policy deploy --file policies.yaml --target kubernetes --action enforce

# Dry-run (preview without changes)
itl-policy deploy --file policies.yaml --target kubernetes --dry-run
```

#### To ITL Control Plane
```bash
# Using env vars
export ITL_API_KEY=sk-xxxxxxxxxxxx
itl-policy deploy --file policies.yaml --target itl-api \
  --api-endpoint https://controlplane.example.com

# Using command args
itl-policy deploy --file policies.yaml --target itl-api \
  --api-endpoint https://controlplane.example.com \
  --api-key sk-xxxxxxxxxxxx
```

#### To Both Targets
```bash
itl-policy deploy --file policies.yaml --target both \
  --api-endpoint https://controlplane.example.com \
  --api-key sk-xxxxxxxxxxxx
```

### Setup Configuration
```bash
itl-policy init --api-endpoint https://controlplane.example.com \
  --api-key sk-xxxxxxxxxxxx
```

Creates `~/.itl-policy/config.json` for persistent settings.

---

## Common Workflows

### 1. First-Time Setup
```bash
itl-policy init --api-endpoint https://api.example.com --api-key sk-xxx
```

### 2. Audit Existing Cluster
```bash
itl-policy generate --template talos-security -o policies.yaml
itl-policy validate --file policies.yaml
itl-policy deploy --file policies.yaml --action audit
# Monitor violations in Kubernetes event logs / ITL dashboard
```

### 3. Enforce Policies in Production
```bash
itl-policy deploy --file policies.yaml --action enforce
```

### 4. Test Before Deploying
```bash
itl-policy deploy --file policies.yaml --dry-run
```

---

## Environment Variables

```bash
ITL_API_ENDPOINT=https://controlplane.example.com   # API endpoint
ITL_API_KEY=sk-xxxxxxxxxxxx                         # API key
KUBECONFIG=~/.kube/prod-config.yaml                # Kubernetes config
```

---

## Options Cheat Sheet

### Global
- `--help` — Help text
- `--version` — Show version

### list
- `--category {security,image,network,pqc,talos,governance}` — Filter

### generate
- `--template {talos-security,pqc-transition}` — Template name **[default: talos-security]**
- `--style {kyverno,azure,custom}` — Policy format **[default: kyverno]**
  - `kyverno` — Kubernetes-native policies
  - `azure` — Azure ARM policies
- `-o`, `--output PATH` — Output file
- `--format {yaml,json}` — Serialization format **[default: yaml]**

### validate
- `-f`, `--file PATH` — Policy file (**required**)
- `--target {kubernetes,itl-api,both}` — Target

### deploy
- `-f`, `--file PATH` — Policy file (**required**)
- `--target {kubernetes,itl-api,both}` — Target
- `--kubeconfig PATH` — Kubernetes config
- `--api-endpoint URL` — ITL API URL
- `--api-key KEY` — ITL API key
- `--action {audit,enforce}` — Policy action
- `--dry-run` — Preview without changes

### init
- `--api-endpoint URL` — API endpoint
- `--api-key KEY` — API key

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |

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
Check environment variables:
```bash
echo $ITL_API_KEY
echo $ITL_API_ENDPOINT
```

Or pass explicitly:
```bash
itl-policy deploy --file policies.yaml --target itl-api \
  --api-endpoint https://... --api-key sk-...
```

### "Policy validation failed"
Test the YAML:
```bash
itl-policy validate --file policies.yaml
kubectl apply --dry-run=client -f policies.yaml
```

---

## Examples

### Generate + Deploy in One Go
```bash
itl-policy generate --template talos-security -o /tmp/policies.yaml && \
itl-policy deploy --file /tmp/policies.yaml --action audit
```

### Multi-Environment
```bash
# Dev
KUBECONFIG=~/.kube/dev.yaml \
itl-policy deploy --file policies.yaml --action audit

# Prod
KUBECONFIG=~/.kube/prod.yaml \
itl-policy deploy --file policies.yaml --action enforce
```

### Check Available Talos Policies
```bash
itl-policy list --category talos
```

### Test Without Making Changes
```bash
itl-policy deploy --file policies.yaml --dry-run
```

---

## More Information

- Full docs: `itl-policy --help`
- Examples: See [examples/cli_examples.md](examples/cli_examples.md)
- Guide: See [docs/CLI.md](docs/CLI.md)
