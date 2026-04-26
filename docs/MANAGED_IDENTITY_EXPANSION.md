# Managed Identity Policy Expansion — Roadmap

## Huidige Template (v1.0)

✅ **5 Core Policies**:
1. `deny-sp-password-credentials` — Blokkeert password-based service principals
2. `deny-sp-certificate-credentials` — Blokkeert certificate credentials
3. `audit-legacy-sp-credentials` — Audit existing credentials
4. `require-managed-identity-resources` — Vereist managed identity op 7 resource types
5. `allow-workload-identity` — Documeert workload identities

## Uitbreidingen — Categorieën

### 1. Storage & Data Access Policies

**Rationale**: Storage accounts en databases zijn vaak targets voor credential leaks. Managed identities elimineren de noodzaak voor connection strings met secrets.

#### Potential Policies:
```yaml
deny-storage-account-keys:
  displayName: "Deny Storage Account Key Access"
  description: "Prevent storage account key regeneration and usage. Use managed identity with RBAC instead."
  resourceType: Microsoft.Storage/storageAccounts
  effect: Deny
  condition: |
    If storage account key operation (regenerateKey, listKeys)
    Then deny with message

require-storage-rbac:
  displayName: "Require Storage RBAC Instead of Keys"
  description: "Enforce RBAC-based access to storage accounts using managed identities."
  resourceType: Microsoft.Storage/storageAccounts
  effect: Audit
  condition: |
    If storage account exists
    And no RBAC assignments with managed identity
    Then audit

deny-sql-authentication:
  displayName: "Deny SQL Authentication for Azure SQL"
  description: "Prevent SQL username/password authentication. Use Azure AD (managed identity) only."
  resourceType: Microsoft.Sql/servers
  effect: Deny
  condition: |
    If administratorLogin exists (SQL auth enabled)
    Then deny

require-cosmos-rbac:
  displayName: "Require Cosmos DB RBAC"
  description: "Enforce RBAC data plane access instead of connection strings."
  resourceType: Microsoft.DocumentDB/databaseAccounts
  effect: Audit
```

### 2. Key Vault & Secrets Management

**Rationale**: Key Vault moet de centrale secrets store zijn, niet hardcoded credentials. Access moet via managed identity gebeuren.

#### Potential Policies:
```yaml
require-keyvault-for-secrets:
  displayName: "Require Key Vault for Application Secrets"
  description: "Applications must use Key Vault references, not inline secrets."
  resourceType: 
    - Microsoft.Web/sites
    - Microsoft.Logic/workflows
    - Microsoft.DataFactory/factories
  effect: Audit
  condition: |
    If app settings contain secrets pattern (key=, password=, token=)
    And no Key Vault reference (@Microsoft.KeyVault...)
    Then audit

require-keyvault-managed-identity:
  displayName: "Key Vault Must Use Managed Identity Access"
  description: "Key Vault access policies must prefer managed identities over service principals."
  resourceType: Microsoft.KeyVault/vaults
  effect: Audit
  condition: |
    If accessPolicies contain objectId
    And objectId is not managed identity
    Then audit

deny-keyvault-secrets-in-code:
  displayName: "Deny Hardcoded Key Vault Secrets"
  description: "Prevent direct secret values in ARM templates. Use secretUri references."
  resourceType: ALL
  effect: Deny
  condition: |
    If template contains Microsoft.KeyVault/vaults/secrets/value
    Then deny
```

### 3. Network & Private Endpoints

**Rationale**: Managed identities werken best met private connectivity. Public endpoints verhogen attack surface.

#### Potential Policies:
```yaml
require-private-endpoint-storage:
  displayName: "Require Private Endpoints for Storage Accounts"
  description: "Storage accounts with managed identity should use private endpoints."
  resourceType: Microsoft.Storage/storageAccounts
  effect: Audit
  condition: |
    If publicNetworkAccess = Enabled
    And no privateEndpointConnections
    Then audit

require-private-endpoint-keyvault:
  displayName: "Require Private Endpoints for Key Vault"
  description: "Key Vault must use private endpoints when accessed via managed identity."
  resourceType: Microsoft.KeyVault/vaults
  effect: Audit

deny-public-network-sql:
  displayName: "Deny Public Network Access for Azure SQL"
  description: "Azure SQL using managed identity must disable public access."
  resourceType: Microsoft.Sql/servers
  effect: Deny
  condition: |
    If publicNetworkAccess = Enabled
    And azureAdOnlyAuthentication = true
    Then deny
```

### 4. AKS & Container Workload Identities

**Rationale**: Kubernetes workloads moeten workload identity gebruiken, niet pod-managed identity of service account tokens.

#### Potential Policies:
```yaml
require-aks-workload-identity:
  displayName: "Require AKS Workload Identity"
  description: "AKS clusters must enable workload identity for pod authentication."
  resourceType: Microsoft.ContainerService/managedClusters
  effect: Deny
  condition: |
    If oidcIssuerProfile.enabled != true
    Or securityProfile.workloadIdentity.enabled != true
    Then deny

require-aks-managed-identity:
  displayName: "Require System-Assigned Identity for AKS"
  description: "AKS clusters must use system-assigned managed identity, not service principal."
  resourceType: Microsoft.ContainerService/managedClusters
  effect: Deny
  condition: |
    If identity.type != SystemAssigned
    Or servicePrincipalProfile exists
    Then deny

audit-pod-identity-deprecated:
  displayName: "Audit Deprecated Pod Identity Usage"
  description: "AAD Pod Identity is deprecated. Use workload identity instead."
  resourceType: Microsoft.ContainerService/managedClusters
  effect: Audit
  condition: |
    If addon podIdentity exists
    Then audit with migration message
```

### 5. API Management & Service Integration

**Rationale**: API backends en integrations moeten managed identity gebruiken voor authenticatie.

#### Potential Policies:
```yaml
require-apim-managed-identity-backends:
  displayName: "Require Managed Identity for APIM Backends"
  description: "API Management backends must authenticate with managed identity."
  resourceType: Microsoft.ApiManagement/service/backends
  effect: Audit
  condition: |
    If credentials.authorization or credentials.certificate
    Then audit

require-function-app-managed-identity:
  displayName: "Require Managed Identity for Function Apps"
  description: "Function apps must use managed identity for outbound connections."
  resourceType: Microsoft.Web/sites (kind: functionapp)
  effect: Audit
  condition: |
    If app settings contain connection strings with secrets
    Then audit
```

### 6. Monitoring & Compliance

**Rationale**: Visibility en compliance checking voor managed identity adoption.

#### Potential Policies:
```yaml
tag-managed-identity-compliant:
  displayName: "Tag Resources Using Managed Identity"
  description: "Automatically tag resources that properly use managed identity."
  resourceType: ALL
  effect: Modify
  condition: |
    If identity.type exists
    And identity.type != None
    Then add tag: ManagedIdentity=Compliant

audit-resources-without-identity:
  displayName: "Audit Resources Without Identity"
  description: "Find resources that should use managed identity but don't."
  resourceType: 
    - Microsoft.Web/*
    - Microsoft.Compute/*
    - Microsoft.Logic/*
    - Microsoft.DataFactory/*
  effect: Audit
  condition: |
    If identity not exists or identity.type = None
    Then audit

require-diagnostic-settings-managed-identity:
  displayName: "Require Managed Identity for Diagnostic Settings"
  description: "Log Analytics workspace connections should use managed identity."
  resourceType: Microsoft.Insights/diagnosticSettings
  effect: Audit
```

### 7. Service Bus, Event Hub & Messaging

**Rationale**: Messaging services moeten RBAC gebruiken, niet SAS tokens of connection strings.

#### Potential Policies:
```yaml
deny-servicebus-sas-tokens:
  displayName: "Deny Service Bus SAS Token Creation"
  description: "Prevent creation of Shared Access Signatures. Use managed identity with RBAC."
  resourceType: Microsoft.ServiceBus/namespaces/AuthorizationRules
  effect: Deny
  condition: |
    If creating new authorization rule (SAS)
    Then deny

require-eventhub-managed-identity:
  displayName: "Require Managed Identity for Event Hub Clients"
  description: "Event Hub consumers/producers must use managed identity."
  resourceType: Microsoft.EventHub/namespaces
  effect: Audit
  condition: |
    If authorizationRules exist (SAS keys)
    Then audit

deny-eventhub-connection-strings:
  displayName: "Deny Event Hub Connection String Usage"
  description: "Applications must not use connection strings. Use DefaultAzureCredential."
  resourceType: Microsoft.Web/sites, Microsoft.Logic/workflows
  effect: Audit
  condition: |
    If app settings contain EventHubConnectionString
    Then audit
```

## Implementatie Prioriteit

### Phase 1 (Immediate Value) — 🔥 High Impact
1. ✅ **deny-storage-account-keys** — Storage is grootste credential leak vector
2. ✅ **deny-sql-authentication** — SQL passwords zijn veelvoorkomend security risk
3. ✅ **require-keyvault-managed-identity** — Key Vault is critical secrets store
4. ✅ **require-aks-workload-identity** — AKS workloads zijn groeiende use case

### Phase 2 (Strong Governance) — 📊 Compliance
5. **require-private-endpoint-storage** — Network isolation
6. **tag-managed-identity-compliant** — Visibility en compliance tracking
7. **audit-resources-without-identity** — Discovery van non-compliant resources
8. **deny-servicebus-sas-tokens** — Messaging security

### Phase 3 (Advanced) — 🚀 Ecosystem Integration
9. **require-apim-managed-identity-backends** — API security
10. **require-function-app-managed-identity** — Serverless security
11. **require-cosmos-rbac** — NoSQL data plane security
12. **deny-keyvault-secrets-in-code** — Template security

## Code Structure Uitbreiding

### Nieuwe Template Files
```
src/itl_policy_builder/templates/
├── managed_identity.py              # Bestaand (5 policies)
├── managed_identity_storage.py      # Nieuw (4 policies)
├── managed_identity_keyvault.py     # Nieuw (3 policies)
├── managed_identity_aks.py          # Nieuw (3 policies)
├── managed_identity_network.py      # Nieuw (3 policies)
├── managed_identity_messaging.py    # Nieuw (3 policies)
├── managed_identity_monitoring.py   # Nieuw (3 policies)
└── managed_identity_complete.py     # Nieuw (All 24 policies)
```

### CLI Template Options
```powershell
# Bestaand
itl-policy generate --template managed-identity --style azure

# Nieuw — Specifieke categorieën
itl-policy generate --template managed-identity-storage --style azure
itl-policy generate --template managed-identity-aks --style azure
itl-policy generate --template managed-identity-complete --style azure

# Nieuw — Custom selectie
itl-policy generate --template managed-identity --categories storage,keyvault,aks --style azure
```

## Resource Types Coverage

### Huidige Coverage (7 types):
- Microsoft.AAD/servicePrincipals ✅
- Microsoft.Compute/virtualMachines ✅
- Microsoft.Web/sites ✅
- Microsoft.ContainerInstance/containerGroups ✅
- Microsoft.ContainerService/managedClusters ✅
- Microsoft.Logic/workflows ✅
- Microsoft.Automation/automationAccounts ✅
- Microsoft.DataFactory/factories ✅

### Nieuwe Coverage (12+ types):
- Microsoft.Storage/storageAccounts 🆕
- Microsoft.KeyVault/vaults 🆕
- Microsoft.Sql/servers 🆕
- Microsoft.DocumentDB/databaseAccounts 🆕
- Microsoft.DBforPostgreSQL/servers 🆕
- Microsoft.DBforMySQL/servers 🆕
- Microsoft.ServiceBus/namespaces 🆕
- Microsoft.EventHub/namespaces 🆕
- Microsoft.ApiManagement/service 🆕
- Microsoft.Insights/diagnosticSettings 🆕
- Microsoft.Network/privateEndpoints 🆕
- Microsoft.OperationalInsights/workspaces 🆕

### Totaal: **20+ resource types** gedekt

## Testing Strategy

Voor elke nieuwe policy:
1. **Schema Validation** — Azure policy schema compliance
2. **Logic Testing** — Condition evaluation met mock resources
3. **Integration Testing** — Deploy naar test subscription
4. **Negative Testing** — Verify deny/audit triggers correct
5. **Documentation** — Examples met compliant vs non-compliant scenarios

## Documentation Updates

Bij elke uitbreiding:
- ✅ Update `templates/__init__.py` exports
- ✅ Update `cli/main.py` template list
- ✅ Update `docs/CLI_WORKFLOW.md` voorbeelden
- ✅ Create `examples/managed_identity_<category>.py`
- ✅ Add tests in `tests/test_managed_identity_<category>_schema.py`
- ✅ Update `README.md` feature matrix

## Estimated Effort

| Phase | Policies | Development | Testing | Total |
|-------|----------|-------------|---------|-------|
| Phase 1 | 4 policies | 4 hours | 2 hours | 6 hours |
| Phase 2 | 4 policies | 4 hours | 2 hours | 6 hours |
| Phase 3 | 4 policies | 4 hours | 2 hours | 6 hours |
| **Total** | **12 policies** | **12 hours** | **6 hours** | **18 hours** |

## Next Steps

1. **Prioritize** — Which phase do you want to implement first?
2. **Validate** — Review policy logic with stakeholders
3. **Implement** — Create template files
4. **Test** — Schema validation + integration testing
5. **Document** — Update docs en examples
6. **Deploy** — Roll out to production subscriptions

---

**Version**: 1.0.0  
**Last Updated**: 25 april 2026  
**Status**: Roadmap — Awaiting prioritization
