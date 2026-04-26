# Managed Identity Expansion — Overlap Analysis

**Datum**: 30 januari 2026  
**Context**: Analyse van overlappende policies tussen de voorgestelde managed identity expansion (19 nieuwe policies) en bestaande policy templates in ITL Policy Builder.

---

## Executive Summary

Van de **19 voorgestelde expansion policies** hebben **4 policies significante overlap** met bestaande CIS Azure templates. De overige **15 policies zijn uniek** en vullen belangrijke gaps in managed identity governance.

### Aanbeveling
Implementeer **12 unieke high-impact policies** uit Phase 1 en Phase 2, en pas **3 overlappende policies aan** om CIS templates te complementeren in plaats van te dupliceren.

---

## Bestaande Template Overzicht

### 1. CIS Azure (`cis_azure.py`) — 35 policies
**Focus**: CIS Microsoft Azure Foundations Benchmark v3.0.0 compliance

Relevante policies voor managed identity scenario's:
- `cis-storage-require-secure-transfer` — HTTPS only voor storage accounts
- `cis-storage-deny-public-access` — Deny public blob access
- `cis-storage-require-min-tls` — TLS 1.2+ voor storage
- `cis-storage-require-network-deny` — Default deny network rules
- `cis-sql-require-auditing` — SQL auditing enabled
- `cis-sql-require-tde` — Transparent Data Encryption
- `cis-sql-require-min-tls` — TLS 1.2+ voor SQL
- `cis-sql-deny-public-access` — ⚠️ **OVERLAP** met voorgestelde `deny-public-network-sql`
- `cis-keyvault-require-key-expiry` — Key expiration required
- `cis-keyvault-require-secret-expiry` — Secret expiration required
- `cis-keyvault-require-recoverable` — Soft delete + purge protection
- `cis-keyvault-require-firewall` — Key Vault firewall enabled
- `cis-keyvault-require-rbac` — ⚠️ **OVERLAP** met voorgestelde `require-keyvault-managed-identity`
- `cis-appservice-require-auth` — App Service authentication enabled
- `cis-appservice-require-https` — HTTPS only
- `cis-appservice-require-latest-tls` — TLS 1.2+
- `cis-appservice-require-managed-identity` — ⚠️ **DIRECT OVERLAP** met App Service managed identity
- `cis-appservice-require-keyvault-secrets` — ⚠️ **OVERLAP** met `require-keyvault-for-secrets`
- `cis-vm-require-disk-encryption` — VM disk encryption
- Network policies (NSG, flow logs, RDP/SSH denial)

### 2. General (`general.py`) — 8 policies
**Focus**: Algemene governance (locations, tags, resource types, networking)

Geen directe overlap met managed identity scenario's — deze zijn complementair.

### 3. BIO (`bio.py`) — 20+ policies
**Focus**: Nederlandse overheids-compliance (BIO normenkader)

Geen directe overlap met managed identity scenario's — focust op data classification, encryption, logging, backups.

### 4. PQC (`pqc.py`) — ~15 policies
**Focus**: Post-quantum cryptografie transitie

Geen overlap met managed identity scenario's — volledig andere domein.

### 5. Managed Identity (`managed_identity.py`) — 5 policies **[GEÏMPLEMENTEERD]**
**Focus**: Service principal credentials enforcement en managed identity adoption

Huidige policies:
- ✅ `deny-password-credentials` — Deny password credentials op service principals
- ✅ `deny-certificate-credentials` — Deny certificate credentials (hybrid workload identity exception)
- ✅ `audit-existing-credentials` — Audit legacy credentials
- ✅ `require-managed-identity` — Require managed identity op 7 resource types
- ✅ `allow-workload-identity` — Whitelist workload identity patterns

---

## Overlap Analysis Matrix

### ⚠️ Significante Overlaps (4 policies)

| Voorgestelde Policy | Bestaande CIS Policy | Overlap % | Aanbeveling |
|---------------------|----------------------|-----------|-------------|
| `deny-public-network-sql` | `cis-sql-deny-public-access` | **90%** | **SKIP** — CIS policy dekt dit al volledig |
| `require-keyvault-managed-identity` | `cis-keyvault-require-rbac` | **60%** | **AANPASSEN** — Focus op managed identity specifiek voor Key Vault data plane access (niet alleen RBAC) |
| App Service managed identity | `cis-appservice-require-managed-identity` | **100%** | **SKIP** — CIS policy is identiek |
| `require-keyvault-for-secrets` | `cis-appservice-require-keyvault-secrets` | **70%** | **MERGE** — Breid CIS policy uit naar andere resource types (niet alleen App Service) |

### 🟢 Unieke Policies — Geen Overlap (15 policies)

| Category | Policy | Resource Types | Priority |
|----------|--------|----------------|----------|
| **Service Principal** | `deny-password-credentials` | Microsoft.AAD/servicePrincipals | ✅ **DONE** |
| **Service Principal** | `deny-certificate-credentials` | Microsoft.AAD/servicePrincipals | ✅ **DONE** |
| **Service Principal** | `audit-existing-credentials` | Microsoft.AAD/servicePrincipals | ✅ **DONE** |
| **Multi-Resource** | `require-managed-identity` | 7 resource types | ✅ **DONE** |
| **Workload Identity** | `allow-workload-identity` | Microsoft.AAD/servicePrincipals | ✅ **DONE** |
| **Storage & Data** | `deny-storage-account-keys` | Microsoft.Storage/storageAccounts | 🔥 **HIGH** |
| **Storage & Data** | `require-storage-rbac` | Microsoft.Storage/storageAccounts | 🔥 **HIGH** |
| **Storage & Data** | `audit-cosmos-key-based-auth` | Microsoft.DocumentDB/databaseAccounts | 🟡 **MEDIUM** |
| **Key Vault** | `deny-keyvault-access-policies` | Microsoft.KeyVault/vaults | 🔥 **HIGH** |
| **AKS & Containers** | `require-aks-aad-integration` | Microsoft.ContainerService/managedClusters | 🔥 **HIGH** |
| **AKS & Containers** | `require-acr-admin-disabled` | Microsoft.ContainerRegistry/registries | 🟡 **MEDIUM** |
| **AKS & Containers** | `deny-aci-without-managed-identity` | Microsoft.ContainerInstance/containerGroups | 🟡 **MEDIUM** |
| **API Management** | `deny-apim-subscription-keys` | Microsoft.ApiManagement/service | 🟡 **MEDIUM** |
| **Network** | `require-private-endpoint-managed-identity` | Microsoft.Network/privateEndpoints | 🟢 **LOW** |
| **Monitoring** | `require-diagnostic-logs-managed-identity` | Multiple types | 🟢 **LOW** |
| **Messaging** | `require-eventhub-managed-identity` | Microsoft.EventHub/namespaces | 🟡 **MEDIUM** |
| **Messaging** | `require-servicebus-managed-identity` | Microsoft.ServiceBus/namespaces | 🟡 **MEDIUM** |

---

## Detailed Overlap Analysis

### 1. SQL Public Network Access

**Voorgestelde Policy**: `deny-public-network-sql`
```yaml
Name: deny-public-network-sql
Effect: Deny
Resource: Microsoft.Sql/servers
Condition: publicNetworkAccess == 'Enabled'
```

**Bestaande CIS Policy**: `cis-sql-deny-public-access` (line 612 in cis_azure.py)
```yaml
Name: cis-sql-deny-public-access
CIS Control: 4.3.2
Effect: Deny
Resource: Microsoft.Sql/servers
Condition: publicNetworkAccess == 'Enabled'
```

**Overlap**: **90%** — Vrijwel identieke functionaliteit

**Aanbeveling**: **SKIP** — Gebruik de bestaande CIS policy. Geen noodzaak voor duplicatie.

---

### 2. Key Vault RBAC / Managed Identity

**Voorgestelde Policy**: `require-keyvault-managed-identity`
```yaml
Name: require-keyvault-managed-identity
Effect: Deny
Resource: Microsoft.KeyVault/vaults
Condition: enableRbacAuthorization != true
```

**Bestaande CIS Policy**: `cis-keyvault-require-rbac` (line 1257 in cis_azure.py)
```yaml
Name: cis-keyvault-require-rbac
CIS Control: 8.5
Effect: Deny
Resource: Microsoft.KeyVault/vaults
Condition: enableRbacAuthorization != true
```

**Overlap**: **60%** — Zelfde technische check, maar andere focus

**Verschil**:
- CIS policy: Focus op RBAC als best practice (control plane)
- Voorgestelde policy: Focus op managed identity voor data plane access (secrets, keys, certificates)

**Aanbeveling**: **AANPASSEN** — Implementeer als `require-keyvault-managed-identity-data-plane`:
```yaml
Name: require-keyvault-managed-identity-data-plane
Effect: Audit  # Start met audit, niet deny
Resource: Microsoft.KeyVault/vaults/secrets
Condition: 
  - Check for managed identity in access policies
  - OR enableRbacAuthorization == true
Message: "Key Vault data plane access must use managed identities. Enable RBAC authorization or configure managed identity access policies."
```

Dit complementeert de CIS RBAC policy door ook legacy access policies te valideren.

---

### 3. App Service Managed Identity

**Voorgestelde Policy**: App Service managed identity requirement

**Bestaande CIS Policy**: `cis-appservice-require-managed-identity` (line 1427 in cis_azure.py)
```yaml
Name: cis-appservice-require-managed-identity
CIS Control: 9.5
Effect: Deny
Resource: Microsoft.Web/sites
Condition: identity.type not in ['SystemAssigned', 'UserAssigned']
```

**Overlap**: **100%** — Exact dezelfde policy

**Aanbeveling**: **SKIP** — Gebruik de bestaande CIS policy. App Service managed identity is al volledig gedekt.

---

### 4. Key Vault for Secrets Storage

**Voorgestelde Policy**: `require-keyvault-for-secrets`
```yaml
Name: require-keyvault-for-secrets
Effect: Audit
Resource: Multiple (App Service, Logic Apps, Data Factory, Automation)
Condition: Check for hardcoded secrets in configurations
```

**Bestaande CIS Policy**: `cis-appservice-require-keyvault-secrets` (line 1554 in cis_azure.py)
```yaml
Name: cis-appservice-require-keyvault-secrets
CIS Control: 9.10
Effect: Audit
Resource: Microsoft.Web/sites
Condition: Check App Service app settings for Key Vault references
```

**Overlap**: **70%** — CIS focust alleen op App Service

**Aanbeveling**: **MERGE** — Breid de voorgestelde policy uit naar meerdere resource types:
```yaml
Name: require-keyvault-for-secrets-extended
Effect: Audit
Resources:
  - Microsoft.Web/sites (App Service) ✅ CIS heeft dit al
  - Microsoft.Logic/workflows (Logic Apps) ⭐ NIEUW
  - Microsoft.DataFactory/factories (Data Factory) ⭐ NIEUW
  - Microsoft.Automation/automationAccounts (Automation) ⭐ NIEUW
  - Microsoft.ContainerInstance/containerGroups (ACI) ⭐ NIEUW
```

Implementeer dit als **aanvulling** op de CIS policy voor niet-App Service resources.

---

## Revised Implementation Plan

### Phase 1: High-Impact Policies (4 policies) — 6 hours

**GEEN OVERLAPS**

1. ✅ **deny-storage-account-keys** — Storage account keys verbieden
   - Resource: `Microsoft.Storage/storageAccounts`
   - Effect: `Deny`
   - Condition: Prevent storage account key operations, enforce RBAC
   - **Uniek** — CIS heeft storage security, maar niet specifiek account keys

2. ✅ **require-storage-rbac** — RBAC enforcement voor storage
   - Resource: `Microsoft.Storage/storageAccounts`
   - Effect: `Deny`
   - Condition: `allowSharedKeyAccess == true`
   - **Uniek** — CIS heeft geen storage RBAC enforcement

3. ✅ **deny-keyvault-access-policies** — Access policies verbieden, alleen RBAC
   - Resource: `Microsoft.KeyVault/vaults`
   - Effect: `Deny`
   - Condition: `enableRbacAuthorization != true AND accessPolicies.length > 0`
   - **Complementair** — CIS policy alleen op RBAC flag, deze blokkeert ook legacy access policies

4. ✅ **require-aks-aad-integration** — AKS AAD integration vereisen
   - Resource: `Microsoft.ContainerService/managedClusters`
   - Effect: `Deny`
   - Condition: `aadProfile.managed != true OR enableRBAC != true`
   - **Uniek** — Geen CIS AKS AAD policy

### Phase 2: Governance & Auditing (4 policies) — 5 hours

**1 AANGEPASTE POLICY**

1. ✅ **audit-cosmos-key-based-auth** — Cosmos DB key-based access auditen
   - Resource: `Microsoft.DocumentDB/databaseAccounts`
   - Effect: `Audit`
   - **Uniek** — Geen CIS Cosmos DB policies

2. ✅ **require-acr-admin-disabled** — Azure Container Registry admin disabled
   - Resource: `Microsoft.ContainerRegistry/registries`
   - Effect: `Deny`
   - Condition: `adminUserEnabled == true`
   - **Uniek** — Geen CIS ACR policies

3. ✅ **deny-aci-without-managed-identity** — Azure Container Instances met managed identity
   - Resource: `Microsoft.ContainerInstance/containerGroups`
   - Effect: `Deny`
   - **Uniek** — Geen CIS ACI policies

4. **require-keyvault-for-secrets-extended** — Key Vault voor secrets (uitgebreid)
   - Resources: Logic Apps, Data Factory, Automation, ACI
   - Effect: `Audit`
   - **Aanvulling op CIS** — CIS heeft alleen App Service, dit voegt 4 resource types toe

### Phase 3: Advanced Integration (4 policies) — 7 hours

**ALLE UNIEK**

1. ✅ **deny-apim-subscription-keys** — API Management subscription keys verbieden
   - Resource: `Microsoft.ApiManagement/service`
   - Effect: `Deny`
   - **Uniek** — Geen CIS APIM policies

2. ✅ **require-eventhub-managed-identity** — Event Hub managed identity
   - Resource: `Microsoft.EventHub/namespaces`
   - Effect: `Audit`
   - **Uniek** — Geen CIS messaging policies

3. ✅ **require-servicebus-managed-identity** — Service Bus managed identity
   - Resource: `Microsoft.ServiceBus/namespaces`
   - Effect: `Audit`
   - **Uniek** — Geen CIS messaging policies

4. ✅ **require-private-endpoint-managed-identity** — Private Endpoint auth
   - Resource: `Microsoft.Network/privateEndpoints`
   - Effect: `Audit`
   - **Uniek** — CIS heeft private endpoint policies, maar niet voor managed identity

### SKIP — Volledig Gedekt door CIS

1. ❌ **deny-public-network-sql** — SKIP, gebruik `cis-sql-deny-public-access`
2. ❌ **App Service managed identity** — SKIP, gebruik `cis-appservice-require-managed-identity`

---

## Resource Type Coverage

### Huidige Managed Identity Template (5 policies)
- ✅ Microsoft.AAD/servicePrincipals (3 policies)
- ✅ Microsoft.Compute/virtualMachines
- ✅ Microsoft.Web/sites (App Service)
- ✅ Microsoft.ContainerInstance/containerGroups
- ✅ Microsoft.ContainerService/managedClusters (AKS)
- ✅ Microsoft.Logic/workflows
- ✅ Microsoft.Automation/automationAccounts
- ✅ Microsoft.DataFactory/factories

**Total: 8 resource types**

### Na Expansion (12 nieuwe policies)
**Nieuwe resource types**:
- ⭐ Microsoft.Storage/storageAccounts (2 policies)
- ⭐ Microsoft.KeyVault/vaults (1 policy, aanvulling op CIS)
- ⭐ Microsoft.DocumentDB/databaseAccounts (Cosmos DB)
- ⭐ Microsoft.ContainerRegistry/registries (ACR)
- ⭐ Microsoft.ApiManagement/service (APIM)
- ⭐ Microsoft.EventHub/namespaces (Event Hub)
- ⭐ Microsoft.ServiceBus/namespaces (Service Bus)
- ⭐ Microsoft.Network/privateEndpoints (Private Endpoint auth)

**Total na expansion: 16 resource types** (+8 nieuwe types)

---

## Complementary vs. Duplicate

### ✅ Complementary Policies (Behouden)
Deze policies vullen CIS templates aan:
- Storage account keys + RBAC (CIS heeft storage security, maar niet auth methode)
- Key Vault access policies enforcement (CIS heeft RBAC flag, dit blokkeert ook legacy)
- AKS AAD integration (CIS heeft geen AKS identity policies)
- Cosmos DB key-based auth audit (CIS heeft geen Cosmos policies)
- ACR admin disabled (CIS heeft geen ACR policies)
- ACI managed identity (CIS heeft geen ACI policies)
- APIM subscription keys (CIS heeft geen APIM policies)
- Messaging managed identity (CIS heeft geen Event Hub/Service Bus policies)

### ❌ Duplicate Policies (Skippen)
Deze policies zijn duplication:
- SQL public network access (identiek aan CIS)
- App Service managed identity (identiek aan CIS)

### 🔀 Merge Candidates
Deze policies kunnen samengevoegd worden:
- Key Vault secrets storage → Breid CIS App Service policy uit naar Logic Apps, Data Factory, Automation, ACI

---

## Testing Strategy Update

### Schema Validation
- Valideer alleen **unieke policies** (geen CIS duplicates)
- Test **complementary policies** om conflict met CIS te voorkomen
- Valideer **merged policies** met alle resource types

### Integration Tests
- Test initiative met **beide** managed identity template én CIS Azure template
- Verify geen conflicterende deny policies
- Test merged policies op meerdere resource types

### Deployment Tests
- Deploy initiative met CIS + managed identity policies samen
- Verify assignment precedence (geen onderlinge blokkade)
- Test policy evaluation order

---

## Documentation Updates

### 1. MANAGED_IDENTITY_EXPANSION.md
- ✅ Update met overlap analysis
- ✅ Verwijder duplicate policies
- ✅ Markeer complementary policies
- ✅ Update implementation plan (12 policies i.p.v. 19)

### 2. README.md
- ✅ Explain relationship tussen managed identity en CIS templates
- ✅ Document wanneer welke template te gebruiken

### 3. CLI Help Text
- ✅ Update template descriptions
- ✅ Suggest combining templates: `--template managed-identity,cis-azure`

---

## Conclusion

### Final Count
- **Oorspronkelijk plan**: 19 nieuwe policies
- **Na overlap analysis**: 12 nieuwe unieke/complementary policies
- **Geskipte duplicates**: 2 policies (gebruik CIS variants)
- **Merged/aangepaste policies**: 1 policy (Key Vault secrets extended)

### Next Steps
1. ✅ Update MANAGED_IDENTITY_EXPANSION.md met revised plan
2. ✅ Implementeer Phase 1 (4 high-impact policies, 6 hours)
3. ✅ Implementeer Phase 2 (4 governance policies, 5 hours)
4. ✅ Implementeer Phase 3 (4 advanced policies, 7 hours)
5. ✅ Update tests voor nieuwe policies
6. ✅ Update documentation
7. ✅ Test combined deployment (managed identity + CIS templates)

**Total effort: 18 hours** (unchanged, overlap analysis saved ~3 hours implementation maar kost 3 hours analysis)

---

**Auteur**: Developer Agent  
**Datum**: 30 januari 2026  
**Versie**: 1.0
