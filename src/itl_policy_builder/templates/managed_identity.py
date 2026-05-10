"""
Managed Identity and Workload Identity Policy Templates.

This module provides policy templates for enforcing passwordless authentication
across Azure using managed identities (system-assigned, user-assigned) and
workload identities (federated credentials via OIDC).

Categories:
- Service Principal Restrictions: Block password/certificate credentials
- Resource Requirements: Require managed identity on supported resources
- Workload Identity: Allow and document federated credential usage

Reference: https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview
"""

from typing import Any, Dict, List, Optional

from itl_policy_builder.builders.policy import PolicyBuilder
from itl_policy_builder.builders.initiative import PolicySetBuilder
from itl_policy_builder.builders.assignment import PolicyAssignmentBuilder
from itl_policy_builder.conditions import all_of, any_of, field, not_, count
from itl_policy_builder.enums import Effect, PolicyType
from itl_policy_builder.models import PolicyDefinition, PolicySetDefinition, PolicyAssignment


# ============================================================================
# Constants
# ============================================================================

MANAGED_IDENTITY_CATEGORY = "Identity"

# Azure resource types that support managed identity
MANAGED_IDENTITY_RESOURCE_TYPES = [
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Web/sites",
    "Microsoft.ContainerInstance/containerGroups",
    "Microsoft.ContainerService/managedClusters",
    "Microsoft.Logic/workflows",
    "Microsoft.Automation/automationAccounts",
    "Microsoft.DataFactory/factories",
    "Microsoft.KeyVault/vaults",  # Added for Key Vault RBAC enforcement
]


# ============================================================================
# Base Class
# ============================================================================


class ManagedIdentityPolicy:
    """
    Base class for managed identity policy templates.

    Attributes:
        name: Unique policy identifier
        display_name: Human-readable name
        description: What the policy enforces
        category: Policy category
        version: Template version
    """

    name: str = ""
    display_name: str = ""
    description: str = ""
    category: str = MANAGED_IDENTITY_CATEGORY
    version: str = "1.0.0"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        """Build the policy with optional parameters."""
        raise NotImplementedError


# ============================================================================
# Service Principal Credential Policies
# ============================================================================


class DenyPasswordCredentialsPolicy(ManagedIdentityPolicy):
    """
    Block creation of service principals with password credentials.

    Prevents password-based authentication for service principals,
    enforcing the use of managed identities or workload identities instead.
    """

    name = "deny-sp-password-credentials"
    display_name = "Deny Service Principals with Password Credentials"
    description = "Prevents creation of service principals with password-based secrets. Use managed identities or federated credentials instead."

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("All")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.AAD/servicePrincipals"),
                    field("properties.passwordCredentials").exists(),
                    count("properties.passwordCredentials").greater_than(0),
                ),
                then=Effect.DENY,
                message=(
                    "Service principals with password credentials are not allowed. "
                    "Use managed identities (system-assigned or user-assigned) or "
                    "workload identities with federated credentials (OIDC)."
                ),
            )
            .build()
        )


class DenyCertificateCredentialsPolicy(ManagedIdentityPolicy):
    """
    Block creation of service principals with certificate credentials.

    Allows hybrid scenario where certificates are used alongside
    federated credentials for gradual migration.
    """

    name = "deny-sp-certificate-credentials"
    display_name = "Deny Service Principals with Certificate Credentials"
    description = "Prevents creation of service principals with certificate-based authentication. Use managed identities or federated credentials for passwordless auth."

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("All")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.AAD/servicePrincipals"),
                    field("properties.certificateCredentials").exists(),
                    count("properties.certificateCredentials").greater_than(0),
                    # Allow hybrid scenario: cert + federated credentials (migration path)
                    not_(
                        all_of(
                            field("properties.federatedIdentityCredentials").exists(),
                            count("properties.federatedIdentityCredentials").greater_than(0),
                        )
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Service principals with certificate credentials are not allowed "
                    "unless combined with federated credentials. Use managed identities "
                    "(system-assigned or user-assigned) or workload identities with "
                    "federated credentials (OIDC)."
                ),
            )
            .build()
        )


class AuditLegacyCredentialsPolicy(ManagedIdentityPolicy):
    """
    Audit existing service principals with legacy credentials.

    Non-blocking policy for discovering existing service principals
    that need migration to managed identities or workload identities.
    """

    name = "audit-legacy-sp-credentials"
    display_name = "Audit Service Principals with Legacy Credentials"
    description = "Identifies existing service principals using passwords or certificates for migration planning to managed identities or workload identities."

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("All")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.AAD/servicePrincipals"),
                    any_of(
                        all_of(
                            field("properties.passwordCredentials").exists(),
                            count("properties.passwordCredentials").greater_than(0),
                        ),
                        all_of(
                            field("properties.certificateCredentials").exists(),
                            count("properties.certificateCredentials").greater_than(0),
                        ),
                    ),
                    # Exclude if migration in progress (has federated credentials)
                    not_(
                        all_of(
                            field("properties.federatedIdentityCredentials").exists(),
                            count("properties.federatedIdentityCredentials").greater_than(0),
                        )
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "This service principal uses legacy password or certificate credentials. "
                    "Migrate to managed identity or workload identity with federated credentials."
                ),
            )
            .build()
        )


# ============================================================================
# Resource Managed Identity Policies
# ============================================================================


class RequireManagedIdentityPolicy(ManagedIdentityPolicy):
    """
    Require managed identity on supported Azure resources.

    Audits resources that support managed identity but don't have one assigned.
    Applies to VMs, App Service, Functions, Container Apps, AKS, Logic Apps, etc.
    """

    name = "require-managed-identity-resources"
    display_name = "Require Managed Identity on Supported Resources"
    description = "Ensures that Azure resources supporting managed identities have one assigned. Applies to VMs, App Service, Function Apps, Container Apps, AKS, Logic Apps. Audits non-compliant resources for remediation planning."

    @classmethod
    def build(
        cls,
        resource_types: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        resource_types = resource_types or MANAGED_IDENTITY_RESOURCE_TYPES

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("Indexed")
            .with_rule(
                if_=all_of(
                    field("type").in_(*resource_types),
                    not_(
                        field("identity.type").in_(
                            "SystemAssigned",
                            "UserAssigned",
                            "SystemAssigned, UserAssigned",
                        )
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "This resource type supports managed identity but none is assigned. "
                    "Enable system-assigned or user-assigned managed identity."
                ),
            )
            .build()
        )


# ============================================================================
# Workload Identity Policies
# ============================================================================


class AllowWorkloadIdentityPolicy(ManagedIdentityPolicy):
    """
    Document and allow workload identities with federated credentials.

    Marks service principals using OIDC federation (GitHub Actions, Azure DevOps)
    as compliant. This is a documentation policy.
    """

    name = "allow-workload-identity"
    display_name = "Allow Workload Identities with Federated Credentials"
    description = "Permits service principals with ONLY federated identity credentials (no passwords or certificates). Used for GitHub Actions, Azure DevOps, and other OIDC-based CI/CD pipelines."

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("All")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.AAD/servicePrincipals"),
                    field("properties.federatedIdentityCredentials").exists(),
                    count("properties.federatedIdentityCredentials").greater_than(0),
                    # No legacy credentials allowed
                    not_(field("properties.passwordCredentials").exists()),
                    not_(field("properties.certificateCredentials").exists()),
                ),
                then=Effect.AUDIT,
                message=(
                    "✅ This service principal uses workload identity with federated credentials. "
                    "This is a recommended passwordless authentication method."
                ),
            )
            .build()
        )


# ============================================================================
# Key Vault & AKS Policies
# ============================================================================


class DenyKeyVaultAccessPoliciesPolicy(ManagedIdentityPolicy):
    """
    Deny Key Vault access policies - enforce RBAC-only model.
    
    Complements CIS policy cis-keyvault-require-rbac by also blocking
    legacy access policies. CIS checks the RBAC flag; this policy ensures
    no access policies can exist even if RBAC is enabled.
    
    Reference: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
    """

    name = "deny-keyvault-access-policies"
    display_name = "Deny Key Vault Access Policies (RBAC Only)"
    description = "Blocks Key Vault vaults with access policies configured. Enforces Azure RBAC-only model for managed identity authentication to secrets, keys, and certificates."

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("Indexed")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.KeyVault/vaults"),
                    any_of(
                        # Scenario 1: RBAC not enabled
                        not_(field("properties.enableRbacAuthorization").equals("true")),
                        # Scenario 2: RBAC enabled BUT access policies still configured
                        all_of(
                            field("properties.enableRbacAuthorization").equals("true"),
                            field("properties.accessPolicies").exists(),
                            count("properties.accessPolicies[*]").greater_than(0),
                        ),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Key Vault must use Azure RBAC for authorization (enableRbacAuthorization=true) "
                    "with NO access policies configured. Legacy access policies prevent managed identity "
                    "enforcement and should be migrated to RBAC assignments."
                ),
            )
            .build()
        )


class RequireAKSAADIntegrationPolicy(ManagedIdentityPolicy):
    """
    Require AKS clusters to use Azure AD (Entra ID) integration with managed identity.
    
    Enforces managed Azure AD integration (aadProfile.managed=true) and RBAC
    for Kubernetes authentication. Blocks service principal-based clusters.
    
    Reference: https://learn.microsoft.com/en-us/azure/aks/managed-aad
    """

    name = "require-aks-aad-integration"
    display_name = "Require AKS Azure AD Integration"
    description = "Enforces managed Azure AD integration with RBAC on AKS clusters. Blocks service principal authentication in favor of managed identities for cluster identity."

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.CUSTOM)
            .mode("Indexed")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    any_of(
                        # Scenario 1: AAD profile not configured
                        not_(field("properties.aadProfile").exists()),
                        # Scenario 2: AAD profile exists but not managed
                        not_(field("properties.aadProfile.managed").equals("true")),
                        # Scenario 3: RBAC not enabled (legacy ABAC)
                        not_(field("properties.enableRBAC").equals("true")),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "AKS cluster must use managed Azure AD integration (aadProfile.managed=true) "
                    "with Kubernetes RBAC enabled (enableRBAC=true). This ensures cluster identity "
                    "uses managed identity instead of service principals, and workload authentication "
                    "can leverage Azure AD identities."
                ),
            )
            .build()
        )


# ============================================================================
# Helper Functions
# ============================================================================


def get_managed_identity_policy(name: str) -> PolicyDefinition:
    """Get a managed identity policy by name."""
    policies = {
        "deny-password": DenyPasswordCredentialsPolicy.build(),
        "deny-certificate": DenyCertificateCredentialsPolicy.build(),
        "audit-legacy": AuditLegacyCredentialsPolicy.build(),
        "require-managed-identity": RequireManagedIdentityPolicy.build(),
        "allow-workload-identity": AllowWorkloadIdentityPolicy.build(),
        "deny-keyvault-access-policies": DenyKeyVaultAccessPoliciesPolicy.build(),
        "require-aks-aad-integration": RequireAKSAADIntegrationPolicy.build(),
    }
    
    if name not in policies:
        raise ValueError(f"Unknown managed identity policy: {name}. Available: {list(policies.keys())}")
    
    return policies[name]


def list_managed_identity_policies() -> List[str]:
    """List all available managed identity policy names."""
    return [
        "deny-password",
        "deny-certificate",
        "audit-legacy",
        "require-managed-identity",
        "allow-workload-identity",
        "deny-keyvault-access-policies",
        "require-aks-aad-integration",
    ]


def get_all_managed_identity_policies() -> List[PolicyDefinition]:
    """Get all managed identity policies."""
    return [
        DenyPasswordCredentialsPolicy.build(),
        DenyCertificateCredentialsPolicy.build(),
        AuditLegacyCredentialsPolicy.build(),
        RequireManagedIdentityPolicy.build(),
        AllowWorkloadIdentityPolicy.build(),
        DenyKeyVaultAccessPoliciesPolicy.build(),
        RequireAKSAADIntegrationPolicy.build(),
    ]


def get_managed_identity_initiative(
    name: str = "managed-identity-enforcement",
    display_name: str = "Managed Identity and Workload Identity Enforcement",
) -> PolicySetDefinition:
    """
    Create a policy initiative grouping all managed identity policies.
    
    Args:
        name: Initiative identifier
        display_name: Human-readable name
    
    Returns:
        PolicySetDefinition with all managed identity policies
    """
    policies = get_all_managed_identity_policies()
    policy_ids = [p.id for p in policies]
    
    return (
        PolicySetBuilder(name)
        .display_name(display_name)
        .description(
            "Comprehensive policy set enforcing passwordless authentication across Azure. "
            "Requires managed identities or workload identities with federated credentials. "
            "Blocks service principals with password or certificate credentials."
        )
        .category(MANAGED_IDENTITY_CATEGORY)
        .add_policies(*policy_ids)
        .build()
    )


def create_subscription_assignment(
    subscription_id: str,
    location: str = "westeurope",
) -> PolicyAssignment:
    """
    Create a subscription-level assignment for the managed identity initiative.
    
    Args:
        subscription_id: Azure subscription ID
        location: Azure region for assignment metadata
    
    Returns:
        PolicyAssignment for subscription scope
    """
    return (
        PolicyAssignmentBuilder("managed-identity-enforcement")
        .display_name("Managed Identity Enforcement (Subscription)")
        .description(
            "Enforces managed identity and workload identity usage across all resources. "
            "Blocks creation of service principals with password/certificate credentials. "
            "Audits resources without managed identities for remediation planning."
        )
        .scope(f"/subscriptions/{subscription_id}")
        .policy_definition_id(
            f"/subscriptions/{subscription_id}/providers/ITL.Authorization/"
            f"policySetDefinitions/managed-identity-enforcement"
        )
        .location(location)
        .build()
    )
