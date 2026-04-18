"""
CIS Microsoft Azure Foundations Benchmark Policy Templates.

This module provides policy templates based on the CIS Microsoft Azure
Foundations Benchmark v3.0.0 (2024) — the industry-standard baseline
for securing Azure subscriptions.

CIS Sections:
- Section 1:  Identity and Access Management (IAM)
- Section 2:  Microsoft Defender for Cloud
- Section 3:  Storage Accounts
- Section 4:  Database Services
- Section 5:  Logging and Monitoring
- Section 6:  Networking
- Section 7:  Virtual Machines
- Section 8:  Key Vault
- Section 9:  App Service

Reference: https://www.cisecurity.org/benchmark/azure
Benchmark:  CIS Microsoft Azure Foundations Benchmark v3.0.0
Mapping:    https://learn.microsoft.com/en-us/azure/governance/policy/samples/cis-azure-1-4-0
"""

from typing import Any, Dict, List, Optional, Tuple, Type

from itl_policy_builder.builder import PolicyBuilder
from itl_policy_builder.conditions import all_of, any_of, field, not_
from itl_policy_builder.enums import Effect, PolicyType
from itl_policy_builder.initiative import PolicySetBuilder
from itl_policy_builder.models import PolicyDefinition, PolicySetDefinition


# ============================================================================
# CIS Categories (Benchmark Sections)
# ============================================================================

CIS_SECTIONS = {
    "CIS-1": "Identity and Access Management",
    "CIS-2": "Microsoft Defender for Cloud",
    "CIS-3": "Storage Accounts",
    "CIS-4": "Database Services",
    "CIS-5": "Logging and Monitoring",
    "CIS-6": "Networking",
    "CIS-7": "Virtual Machines",
    "CIS-8": "Key Vault",
    "CIS-9": "App Service",
    # Custom extended sections
    "AKS": "Azure Kubernetes Service",
    "ACR": "Container Registry",
    "WAF": "Application Gateway & WAF",
    "Backup": "Backup & Recovery",
    "LogAnalytics": "Log Analytics",
    "CosmosDB": "Cosmos DB",
    "Governance": "Governance & Tagging",
}

CIS_BENCHMARK_VERSION = "3.0.0"
CIS_BENCHMARK_REFERENCE = "https://www.cisecurity.org/benchmark/azure"


# ============================================================================
# Base Class
# ============================================================================


class CISPolicy:
    """
    Base class for CIS Azure Foundations Benchmark policy templates.

    Attributes:
        name:           Unique policy identifier
        display_name:   Human-readable name
        description:    What the policy enforces
        cis_control:    CIS control reference (e.g., "3.1")
        cis_section:    CIS section code (e.g., "CIS-3")
        severity:       Severity level: "High" | "Medium" | "Low"
        version:        Policy template version
    """

    name: str = ""
    display_name: str = ""
    description: str = ""
    cis_control: str = ""
    cis_section: str = ""
    severity: str = "Medium"
    version: str = "1.0.0"

    @classmethod
    def _base_builder(cls) -> PolicyBuilder:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.cis_section)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "cis_control": cls.cis_control,
                "cis_section": cls.cis_section,
                "cis_benchmark": f"CIS Azure Foundations v{CIS_BENCHMARK_VERSION}",
                "severity": cls.severity,
                "compliance_standard": "CIS",
            })
        )

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        raise NotImplementedError


# ============================================================================
# Section 1 — Identity and Access Management
# ============================================================================


class RequireSecurityContactEmailPolicy(CISPolicy):
    """
    CIS 1.1 — Ensure that security contact details are registered.

    Azure Security Center can notify security contacts when a security
    incident or vulnerability is detected.
    """

    name = "cis-require-security-contact"
    display_name = "CIS 1.1 — Require Security Contact Email Tag"
    description = (
        "Resources and subscriptions should have a 'securityContact' tag "
        "set to a valid email address for incident notifications (CIS 1.1)."
    )
    cis_control = "1.1"
    cis_section = "CIS-1"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=field("tags.securityContact").exists(False),
                then=Effect.AUDIT,
                message="Resources should have a 'securityContact' tag with a valid email address.",
            )
            .build()
        )


class DenyGuestUserOwnerRolePolicy(CISPolicy):
    """
    CIS 1.3 — Guest accounts with Owner role should not exist.

    Guest users with elevated roles could pose significant security risks
    if their home tenant is compromised.
    """

    name = "cis-deny-guest-owner-role"
    display_name = "CIS 1.3 — Deny Guest Owner Role"
    description = (
        "Guest user accounts should not have Owner or Contributor roles "
        "assigned at subscription scope (CIS 1.3)."
    )
    cis_control = "1.3"
    cis_section = "CIS-1"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .mode("All")
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Authorization/roleAssignments"),
                    field("properties.principalType").equals("Guest"),
                    any_of(
                        # Owner
                        field("properties.roleDefinitionId").contains(
                            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                        ),
                        # Contributor
                        field("properties.roleDefinitionId").contains(
                            "b24988ac-6180-42a0-ab88-20f7382dd24c"
                        ),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Guest user accounts must not have Owner or Contributor role assignments. "
                    "Review access and reduce to least-privilege (CIS 1.3)."
                ),
            )
            .build()
        )


class RequireMFATagPolicy(CISPolicy):
    """
    CIS 1.2 — Audit subscriptions where MFA enforcement cannot be confirmed.

    Tags privileged resources for MFA-required access review.
    """

    name = "cis-require-mfa-tag"
    display_name = "CIS 1.2 — Require MFA Tag on Privileged Resources"
    description = (
        "Privileged resources (VMs, Key Vaults, databases) should carry "
        "a 'mfaRequired' tag to confirm MFA enforcement (CIS 1.2)."
    )
    cis_control = "1.2"
    cis_section = "CIS-1"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").like("Microsoft.Compute/*"),
                        field("type").like("Microsoft.KeyVault/*"),
                        field("type").like("Microsoft.Sql/*"),
                    ),
                    field("tags.mfaRequired").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Privileged resources should carry a 'mfaRequired' tag confirming "
                    "MFA is enforced for administrative access (CIS 1.2)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 2 — Microsoft Defender for Cloud
# ============================================================================


class RequireDefenderForServersPolicy(CISPolicy):
    """
    CIS 2.1 — Ensure Microsoft Defender for Servers is enabled.

    Defender for Servers provides threat detection and vulnerability
    assessments for virtual machines.
    """

    name = "cis-require-defender-servers"
    display_name = "CIS 2.1 — Require Defender for Servers"
    description = (
        "Virtual Machines must have Microsoft Defender for Servers "
        "enabled via the 'defenderForServers' tag or security profile (CIS 2.1)."
    )
    cis_control = "2.1"
    cis_section = "CIS-2"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Compute/virtualMachines"),
                    field("properties.securityProfile.securityType").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Virtual Machines should have Defender for Servers enabled. "
                    "Enable via Microsoft Defender for Cloud plans (CIS 2.1)."
                ),
            )
            .build()
        )


class RequireDefenderTagPolicy(CISPolicy):
    """
    CIS 2.3 — Audit resources not enrolled in Defender for Cloud.

    Tags workloads to confirm Defender for Cloud plan coverage.
    """

    name = "cis-require-defender-tag"
    display_name = "CIS 2.3 — Audit Defender for Cloud Enrollment"
    description = (
        "Resources should carry a 'defenderEnabled' tag confirming "
        "Microsoft Defender for Cloud is active (CIS 2.3)."
    )
    cis_control = "2.3"
    cis_section = "CIS-2"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").like("Microsoft.Compute/*"),
                        field("type").like("Microsoft.Web/*"),
                        field("type").like("Microsoft.Sql/*"),
                        field("type").like("Microsoft.Storage/*"),
                        field("type").like("Microsoft.KeyVault/*"),
                        field("type").like("Microsoft.ContainerService/*"),
                    ),
                    field("tags.defenderEnabled").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Resources should carry a 'defenderEnabled' tag to confirm "
                    "Defender for Cloud coverage (CIS 2.3)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 3 — Storage Accounts
# ============================================================================


class RequireStorageSecureTransferPolicy(CISPolicy):
    """
    CIS 3.1 — Ensure secure transfer to storage accounts is enabled.

    Secure transfer forces all requests to use HTTPS, preventing
    man-in-the-middle attacks on storage operations.
    """

    name = "cis-storage-require-secure-transfer"
    display_name = "CIS 3.1 — Storage: Require Secure Transfer (HTTPS)"
    description = (
        "Storage accounts must have 'Secure transfer required' enabled "
        "to enforce HTTPS for all API requests (CIS 3.1)."
    )
    cis_control = "3.1"
    cis_section = "CIS-3"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Storage/storageAccounts"),
                    any_of(
                        field("properties.supportsHttpsTrafficOnly").exists(False),
                        field("properties.supportsHttpsTrafficOnly").equals(False),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Storage accounts must have 'supportsHttpsTrafficOnly' set to true. "
                    "Enable 'Secure transfer required' in the storage account configuration (CIS 3.1)."
                ),
            )
            .build()
        )


class DenyStoragePublicBlobAccessPolicy(CISPolicy):
    """
    CIS 3.7 — Ensure that public access on storage accounts is disallowed.

    Anonymous blob access can lead to unintended data exposure.
    """

    name = "cis-storage-deny-public-access"
    display_name = "CIS 3.7 — Storage: Deny Public Blob Access"
    description = (
        "Storage accounts must have public blob access disabled to prevent "
        "unauthorized data exposure (CIS 3.7)."
    )
    cis_control = "3.7"
    cis_section = "CIS-3"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Storage/storageAccounts"),
                    any_of(
                        field("properties.allowBlobPublicAccess").exists(False),
                        field("properties.allowBlobPublicAccess").equals(True),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Storage accounts must have 'allowBlobPublicAccess' set to false. "
                    "Disable anonymous public read access (CIS 3.7)."
                ),
            )
            .build()
        )


class RequireStorageMinTLSPolicy(CISPolicy):
    """
    CIS 3.15 — Ensure the minimum TLS version is set to 1.2 for storage accounts.

    TLS 1.0 and 1.1 have known vulnerabilities. Enforce TLS 1.2 as minimum.
    """

    name = "cis-storage-require-min-tls"
    display_name = "CIS 3.15 — Storage: Minimum TLS Version 1.2"
    description = (
        "Storage accounts must use TLS 1.2 as the minimum allowed "
        "TLS version to protect data in transit (CIS 3.15)."
    )
    cis_control = "3.15"
    cis_section = "CIS-3"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Storage/storageAccounts"),
                    any_of(
                        field("properties.minimumTlsVersion").exists(False),
                        field("properties.minimumTlsVersion").not_in("TLS1_2", "TLS1_3"),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Storage accounts must have 'minimumTlsVersion' set to 'TLS1_2' or higher. "
                    "Disable TLS 1.0 and 1.1 in storage account configuration (CIS 3.15)."
                ),
            )
            .build()
        )


class RequireStorageNetworkDefaultDenyPolicy(CISPolicy):
    """
    CIS 3.9 — Ensure storage accounts use private endpoints or deny public network access.

    Default network access action should be Deny, with explicit allow rules.
    """

    name = "cis-storage-require-network-deny"
    display_name = "CIS 3.9 — Storage: Default Network Access Deny"
    description = (
        "Storage account network ACLs must have the default action set to 'Deny' "
        "to prevent unrestricted public network access (CIS 3.9)."
    )
    cis_control = "3.9"
    cis_section = "CIS-3"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Storage/storageAccounts"),
                    any_of(
                        field("properties.networkAcls.defaultAction").exists(False),
                        field("properties.networkAcls.defaultAction").equals("Allow"),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "Storage account network ACLs should have 'defaultAction' set to 'Deny'. "
                    "Use private endpoints or specific IP/VNet rules (CIS 3.9)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 4 — Database Services
# ============================================================================


class RequireSQLAuditingPolicy(CISPolicy):
    """
    CIS 4.1.1 — Ensure that Microsoft SQL server auditing is set to On.

    SQL Server auditing tracks database events and writes them to an audit log.
    """

    name = "cis-sql-require-auditing"
    display_name = "CIS 4.1.1 — SQL Server: Require Auditing"
    description = (
        "Azure SQL servers must have auditing enabled to track database "
        "access and changes for compliance (CIS 4.1.1)."
    )
    cis_control = "4.1.1"
    cis_section = "CIS-4"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Sql/servers"),
                    any_of(
                        field("properties.state").exists(False),
                        field("properties.state").not_equals("Enabled"),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "SQL servers must have auditing enabled. "
                    "Enable server-level auditing under Security in the SQL server settings (CIS 4.1.1)."
                ),
            )
            .build()
        )


class RequireSQLTDEPolicy(CISPolicy):
    """
    CIS 4.2.1 — Ensure that Transparent Data Encryption (TDE) is enabled.

    TDE encrypts data-at-rest for SQL Server databases.
    """

    name = "cis-sql-require-tde"
    display_name = "CIS 4.2.1 — SQL: Require Transparent Data Encryption"
    description = (
        "SQL Server databases must have Transparent Data Encryption (TDE) "
        "enabled to protect data at rest (CIS 4.2.1)."
    )
    cis_control = "4.2.1"
    cis_section = "CIS-4"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Sql/servers/databases/transparentDataEncryption"),
                    any_of(
                        field("properties.status").exists(False),
                        field("properties.status").not_equals("Enabled"),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "SQL databases must have Transparent Data Encryption (TDE) enabled. "
                    "Enable TDE under Security > Transparent data encryption (CIS 4.2.1)."
                ),
            )
            .build()
        )


class RequireSQLMinTLSPolicy(CISPolicy):
    """
    CIS 4.5.1 — Ensure SQL Server TLS version is set to 1.2 or higher.

    Deprecated TLS versions should not be supported for database connections.
    """

    name = "cis-sql-require-min-tls"
    display_name = "CIS 4.5.1 — SQL Server: Minimum TLS Version 1.2"
    description = (
        "SQL servers must require a minimum TLS version of 1.2 "
        "for all client connections (CIS 4.5.1)."
    )
    cis_control = "4.5.1"
    cis_section = "CIS-4"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Sql/servers"),
                    any_of(
                        field("properties.minimalTlsVersion").exists(False),
                        field("properties.minimalTlsVersion").not_in("1.2", "1.3"),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "SQL servers must have 'minimalTlsVersion' set to '1.2' or '1.3'. "
                    "Update the minimal TLS version in the SQL server networking settings (CIS 4.5.1)."
                ),
            )
            .build()
        )


class RequireSQLPublicAccessDisabledPolicy(CISPolicy):
    """
    CIS 4.1.3 — Ensure SQL server public network access is disabled.

    SQL servers should not be accessible from the public internet.
    """

    name = "cis-sql-deny-public-access"
    display_name = "CIS 4.1.3 — SQL Server: Deny Public Network Access"
    description = (
        "SQL servers must have public network access disabled. "
        "Use private endpoints for database connectivity (CIS 4.1.3)."
    )
    cis_control = "4.1.3"
    cis_section = "CIS-4"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Sql/servers"),
                    any_of(
                        field("properties.publicNetworkAccess").exists(False),
                        field("properties.publicNetworkAccess").equals("Enabled"),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "SQL servers should have 'publicNetworkAccess' set to 'Disabled'. "
                    "Use Azure Private Link for secure database connectivity (CIS 4.1.3)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 5 — Logging and Monitoring
# ============================================================================


class RequireActivityLogRetentionPolicy(CISPolicy):
    """
    CIS 5.1.1 — Ensure the activity retention log is set to at least one year.

    Activity logs provide an audit trail for subscription-level events.
    Retention must be at least 365 days.
    """

    name = "cis-require-activity-log-retention"
    display_name = "CIS 5.1.1 — Require Activity Log Retention (365 days)"
    description = (
        "Diagnostic settings for activity logs must retain data for at least "
        "365 days to meet audit and forensic requirements (CIS 5.1.1)."
    )
    cis_control = "5.1.1"
    cis_section = "CIS-5"
    severity = "Medium"

    @classmethod
    def build(
        cls,
        minimum_retention_days: int = 365,
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            cls._base_builder()
            .parameter(
                "minimumRetentionDays",
                type="Integer",
                display_name="Minimum Retention (days)",
                description="Minimum number of days to retain activity logs",
                default=minimum_retention_days,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Insights/diagnosticSettings"),
                    field("properties.logs[*].retentionPolicy.days").less_than(
                        minimum_retention_days
                    ),
                ),
                then=Effect.DENY,
                message=(
                    f"Activity log diagnostic settings must retain logs for at least "
                    f"{minimum_retention_days} days (CIS 5.1.1)."
                ),
            )
            .build()
        )


class RequireDiagnosticSettingsPolicy(CISPolicy):
    """
    CIS 5.2 — Ensure diagnostic settings are configured for all resource types.

    Diagnostic settings capture resource-level logs and metrics, enabling
    security monitoring and incident response.
    """

    name = "cis-require-diagnostic-settings"
    display_name = "CIS 5.2 — Require Diagnostic Settings"
    description = (
        "Key resource types must have diagnostic settings configured to "
        "route logs to a Log Analytics workspace or storage account (CIS 5.2)."
    )
    cis_control = "5.2"
    cis_section = "CIS-5"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("Microsoft.Compute/virtualMachines"),
                        field("type").equals("Microsoft.Sql/servers"),
                        field("type").equals("Microsoft.KeyVault/vaults"),
                        field("type").equals("Microsoft.Network/applicationGateways"),
                        field("type").equals("Microsoft.Network/azureFirewalls"),
                    ),
                    field("properties.diagnosticSettings").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Resource must have diagnostic settings configured to capture "
                    "audit logs and metrics (CIS 5.2)."
                ),
            )
            .build()
        )


class DenyPublicStorageForLogsPolicy(CISPolicy):
    """
    CIS 5.1.2 — Ensure storage container storing activity logs is not publicly accessible.

    Log storage should be private to prevent unauthorized access to audit data.
    """

    name = "cis-deny-public-log-storage"
    display_name = "CIS 5.1.2 — Deny Public Access on Log Storage"
    description = (
        "Storage accounts used for activity logs must not allow public "
        "blob access (CIS 5.1.2)."
    )
    cis_control = "5.1.2"
    cis_section = "CIS-5"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Storage/storageAccounts"),
                    field("tags.purpose").equals("activity-logs"),
                    field("properties.allowBlobPublicAccess").equals(True),
                ),
                then=Effect.DENY,
                message=(
                    "Storage accounts used for activity logs must have public "
                    "blob access disabled (CIS 5.1.2)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 6 — Networking
# ============================================================================


class DenyRDPFromInternetPolicy(CISPolicy):
    """
    CIS 6.1 / 6.3 — Ensure RDP access from the internet is blocked.

    NSG rules allowing inbound RDP (port 3389) from any source (0.0.0.0/0
    or *) expose virtual machines to brute-force attacks.
    """

    name = "cis-deny-rdp-internet"
    display_name = "CIS 6.3 — Deny Inbound RDP from Internet"
    description = (
        "Network Security Groups must not allow inbound RDP (port 3389) "
        "from the public internet (CIS 6.3)."
    )
    cis_control = "6.3"
    cis_section = "CIS-6"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/networkSecurityGroups"),
                    all_of(
                        field("properties.securityRules[*].direction").equals("Inbound"),
                        field("properties.securityRules[*].access").equals("Allow"),
                        any_of(
                            field("properties.securityRules[*].destinationPortRange").equals("3389"),
                            field("properties.securityRules[*].destinationPortRange").equals("*"),
                        ),
                        any_of(
                            field("properties.securityRules[*].sourceAddressPrefix").equals("*"),
                            field("properties.securityRules[*].sourceAddressPrefix").equals("Internet"),
                            field("properties.securityRules[*].sourceAddressPrefix").equals("0.0.0.0/0"),
                        ),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Network Security Groups must not allow inbound RDP (3389) from the internet. "
                    "Restrict access to specific IP ranges or use Azure Bastion (CIS 6.3)."
                ),
            )
            .build()
        )


class DenySSHFromInternetPolicy(CISPolicy):
    """
    CIS 6.1 / 6.2 — Ensure SSH access from the internet is blocked.

    NSG rules allowing inbound SSH (port 22) from the public internet
    expose virtual machines to brute-force and credential attacks.
    """

    name = "cis-deny-ssh-internet"
    display_name = "CIS 6.2 — Deny Inbound SSH from Internet"
    description = (
        "Network Security Groups must not allow inbound SSH (port 22) "
        "from the public internet (CIS 6.2)."
    )
    cis_control = "6.2"
    cis_section = "CIS-6"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/networkSecurityGroups"),
                    all_of(
                        field("properties.securityRules[*].direction").equals("Inbound"),
                        field("properties.securityRules[*].access").equals("Allow"),
                        any_of(
                            field("properties.securityRules[*].destinationPortRange").equals("22"),
                            field("properties.securityRules[*].destinationPortRange").equals("*"),
                        ),
                        any_of(
                            field("properties.securityRules[*].sourceAddressPrefix").equals("*"),
                            field("properties.securityRules[*].sourceAddressPrefix").equals("Internet"),
                            field("properties.securityRules[*].sourceAddressPrefix").equals("0.0.0.0/0"),
                        ),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Network Security Groups must not allow inbound SSH (22) from the internet. "
                    "Restrict access to specific IP ranges or use Azure Bastion (CIS 6.2)."
                ),
            )
            .build()
        )


class RequireNSGOnSubnetsPolicy(CISPolicy):
    """
    CIS 6.6 — Ensure NSG is applied to every subnet.

    Subnets without Network Security Groups have no layer-3/4 protection
    against lateral movement and unauthorized access.
    """

    name = "cis-require-nsg-on-subnets"
    display_name = "CIS 6.6 — Require NSG on All Subnets"
    description = (
        "All subnets must have a Network Security Group attached "
        "to control inbound and outbound traffic (CIS 6.6)."
    )
    cis_control = "6.6"
    cis_section = "CIS-6"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/virtualNetworks/subnets"),
                    field("name").not_in("GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet"),
                    field("properties.networkSecurityGroup.id").exists(False),
                ),
                then=Effect.DENY,
                message=(
                    "Subnets must have a Network Security Group attached. "
                    "GatewaySubnet, AzureFirewallSubnet and AzureBastionSubnet are excluded (CIS 6.6)."
                ),
            )
            .build()
        )


class RequireNSGFlowLogsPolicy(CISPolicy):
    """
    CIS 6.5 — Ensure NSG Flow Log retention period is greater than or equal to 90 days.

    NSG flow logs provide visibility into network traffic patterns and
    are essential for security investigations.
    """

    name = "cis-require-nsg-flow-logs"
    display_name = "CIS 6.5 — Require NSG Flow Logs (90 days retention)"
    description = (
        "NSG flow logs must be enabled and retained for at least 90 days "
        "to support security investigations (CIS 6.5)."
    )
    cis_control = "6.5"
    cis_section = "CIS-6"
    severity = "Medium"

    @classmethod
    def build(
        cls,
        minimum_retention_days: int = 90,
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            cls._base_builder()
            .parameter(
                "minimumRetentionDays",
                type="Integer",
                display_name="Minimum Retention (days)",
                description="Minimum NSG flow log retention in days",
                default=minimum_retention_days,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/networkWatchers/flowLogs"),
                    any_of(
                        field("properties.retentionPolicy.enabled").equals(False),
                        field("properties.retentionPolicy.days").less_than(minimum_retention_days),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    f"NSG flow logs must be enabled with at least {minimum_retention_days} days "
                    f"retention (CIS 6.5)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 7 — Virtual Machines
# ============================================================================


class RequireVMDiskEncryptionPolicy(CISPolicy):
    """
    CIS 7.1 — Ensure that OS disk encryption is enabled on virtual machines.

    Unencrypted OS disks expose data if physical media is compromised.
    """

    name = "cis-vm-require-disk-encryption"
    display_name = "CIS 7.1 — VM: Require OS Disk Encryption"
    description = (
        "Virtual machines must have OS disk encryption enabled "
        "to protect data at rest (CIS 7.1)."
    )
    cis_control = "7.1"
    cis_section = "CIS-7"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Compute/virtualMachines"),
                    field("properties.storageProfile.osDisk.encryptionSettings.enabled").not_equals(
                        True
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "Virtual machine OS disks must have encryption enabled. "
                    "Enable Azure Disk Encryption or Server-Side Encryption with CMK (CIS 7.1)."
                ),
            )
            .build()
        )


class RequireVMDataDiskEncryptionPolicy(CISPolicy):
    """
    CIS 7.3 — Ensure that unattached disks are encrypted.

    Data disks and unattached disks must be encrypted at rest.
    """

    name = "cis-vm-require-data-disk-encryption"
    display_name = "CIS 7.3 — VM: Require Data Disk Encryption"
    description = (
        "Virtual machine data disks must have encryption enabled "
        "to protect data at rest (CIS 7.3)."
    )
    cis_control = "7.3"
    cis_section = "CIS-7"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Compute/disks"),
                    field("properties.encryption.type").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Managed disks must have encryption configured. "
                    "Use platform-managed or customer-managed keys (CIS 7.3)."
                ),
            )
            .build()
        )


class RequireTrustedLaunchPolicy(CISPolicy):
    """
    CIS 7.7 — Ensure Trusted Launch is enabled on supported virtual machines.

    Trusted Launch provides secure boot, vTPM, and integrity monitoring
    to protect against boot-level attacks.
    """

    name = "cis-vm-require-trusted-launch"
    display_name = "CIS 7.7 — VM: Require Trusted Launch"
    description = (
        "Virtual machines should use Trusted Launch (secureBootEnabled + vTPM) "
        "to protect against boot-level attacks (CIS 7.7)."
    )
    cis_control = "7.7"
    cis_section = "CIS-7"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Compute/virtualMachines"),
                    any_of(
                        field("properties.securityProfile.secureBootEnabled").not_equals(True),
                        field("properties.securityProfile.vTpmEnabled").not_equals(True),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "Virtual machines should have Trusted Launch enabled "
                    "(secureBootEnabled and vTpmEnabled both set to true). "
                    "Use Generation 2 VM images to enable Trusted Launch (CIS 7.7)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 8 — Key Vault
# ============================================================================


class RequireKeyExpiryPolicy(CISPolicy):
    """
    CIS 8.1 — Ensure that the expiration date is set on all keys.

    Keys without expiry dates could be in use indefinitely, increasing
    the risk of key compromise.
    """

    name = "cis-keyvault-require-key-expiry"
    display_name = "CIS 8.1 — Key Vault: Require Key Expiration Date"
    description = (
        "Key Vault keys must have an expiration date set to ensure "
        "periodic key rotation (CIS 8.1)."
    )
    cis_control = "8.1"
    cis_section = "CIS-8"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.KeyVault/vaults/keys"),
                    field("properties.attributes.exp").exists(False),
                ),
                then=Effect.DENY,
                message=(
                    "Key Vault keys must have an expiration date set. "
                    "Set key expiration during key creation or update (CIS 8.1)."
                ),
            )
            .build()
        )


class RequireSecretExpiryPolicy(CISPolicy):
    """
    CIS 8.2 — Ensure that the expiration date is set on all secrets.

    Secrets without expiry dates may remain in use after compromise.
    """

    name = "cis-keyvault-require-secret-expiry"
    display_name = "CIS 8.2 — Key Vault: Require Secret Expiration Date"
    description = (
        "Key Vault secrets must have an expiration date set to enforce "
        "periodic rotation (CIS 8.2)."
    )
    cis_control = "8.2"
    cis_section = "CIS-8"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.KeyVault/vaults/secrets"),
                    field("properties.attributes.exp").exists(False),
                ),
                then=Effect.DENY,
                message=(
                    "Key Vault secrets must have an expiration date set. "
                    "Set secret expiration during creation or update (CIS 8.2)."
                ),
            )
            .build()
        )


class RequireKeyVaultRecoverablePolicy(CISPolicy):
    """
    CIS 8.3 — Ensure Key Vault is recoverable (soft delete + purge protection).

    Without soft delete and purge protection, accidental or malicious deletion
    of Key Vault data cannot be recovered.
    """

    name = "cis-keyvault-require-recoverable"
    display_name = "CIS 8.3 — Key Vault: Require Soft Delete and Purge Protection"
    description = (
        "Key Vaults must have soft delete enabled and purge protection "
        "enabled to prevent accidental or malicious data loss (CIS 8.3)."
    )
    cis_control = "8.3"
    cis_section = "CIS-8"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.KeyVault/vaults"),
                    any_of(
                        field("properties.enableSoftDelete").not_equals(True),
                        field("properties.enablePurgeProtection").not_equals(True),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Key Vaults must have both 'enableSoftDelete' and 'enablePurgeProtection' "
                    "set to true to protect against data loss (CIS 8.3)."
                ),
            )
            .build()
        )


class RequireKeyVaultFirewallPolicy(CISPolicy):
    """
    CIS 8.6 — Ensure that Azure Key Vault network access is restricted.

    Key Vaults should only be accessible from trusted networks or via
    private endpoints, not from the public internet.
    """

    name = "cis-keyvault-require-firewall"
    display_name = "CIS 8.6 — Key Vault: Require Network Firewall"
    description = (
        "Key Vaults must restrict public network access. "
        "Default network action must be 'Deny' (CIS 8.6)."
    )
    cis_control = "8.6"
    cis_section = "CIS-8"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.KeyVault/vaults"),
                    any_of(
                        field("properties.networkAcls.defaultAction").exists(False),
                        field("properties.networkAcls.defaultAction").equals("Allow"),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "Key Vaults must have 'networkAcls.defaultAction' set to 'Deny'. "
                    "Use private endpoints or specific IP/VNet allow rules (CIS 8.6)."
                ),
            )
            .build()
        )


class RequireKeyVaultRBACPolicy(CISPolicy):
    """
    CIS 8.5 — Ensure that Azure Key Vault uses RBAC instead of access policies.

    Azure RBAC provides more granular and auditable access control
    compared to legacy Key Vault access policies.
    """

    name = "cis-keyvault-require-rbac"
    display_name = "CIS 8.5 — Key Vault: Require Azure RBAC"
    description = (
        "Key Vaults must use Azure RBAC authorization model instead of "
        "legacy vault access policies (CIS 8.5)."
    )
    cis_control = "8.5"
    cis_section = "CIS-8"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.KeyVault/vaults"),
                    any_of(
                        field("properties.enableRbacAuthorization").exists(False),
                        field("properties.enableRbacAuthorization").not_equals(True),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "Key Vaults should have RBAC authorization enabled "
                    "('enableRbacAuthorization': true). "
                    "Migrate from legacy access policies to Azure RBAC (CIS 8.5)."
                ),
            )
            .build()
        )


# ============================================================================
# Section 9 — App Service
# ============================================================================


class RequireAppServiceAuthPolicy(CISPolicy):
    """
    CIS 9.1 — Ensure App Service Authentication is set to On.

    App Service Authentication prevents unauthenticated requests from reaching
    the application, reducing the attack surface.
    Official policy GUIDs: c75248c1 (Function App), 95bccee9 (Web App).
    """

    name = "cis-appservice-require-auth"
    display_name = "CIS 9.1 — App Service: Require Authentication"
    description = (
        "App Service and Function Apps must have authentication enabled to prevent "
        "unauthenticated access (CIS 9.1)."
    )
    cis_control = "9.1"
    cis_section = "CIS-9"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    any_of(
                        field("properties.siteAuthSettings.enabled").exists(False),
                        field("properties.siteAuthSettings.enabled").not_equals(True),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "App Service apps must have Authentication/Authorization enabled. "
                    "Enable authentication under Settings > Authentication (CIS 9.1)."
                ),
            )
            .build()
        )


class RequireHTTPSOnlyAppServicePolicy(CISPolicy):
    """
    CIS 9.2 — Ensure Web Application is only accessible over HTTPS.

    Enforcing HTTPS prevents data interception and man-in-the-middle attacks.
    Official policy GUID: a4af4a39-4135-47fb-b175-47fbdf85311d.
    """

    name = "cis-appservice-require-https"
    display_name = "CIS 9.2 — App Service: Require HTTPS Only"
    description = (
        "App Service apps must have HTTPS Only enabled to prevent "
        "unencrypted HTTP traffic (CIS 9.2)."
    )
    cis_control = "9.2"
    cis_section = "CIS-9"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    any_of(
                        field("properties.httpsOnly").exists(False),
                        field("properties.httpsOnly").not_equals(True),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "App Service apps must have 'httpsOnly' set to true. "
                    "Enable 'HTTPS Only' under Settings > Configuration > General settings (CIS 9.2)."
                ),
            )
            .build()
        )


class RequireLatestTLSAppServicePolicy(CISPolicy):
    """
    CIS 9.3 — Ensure Web App uses the latest version of TLS encryption.

    Outdated TLS versions (1.0, 1.1) have known vulnerabilities.
    Minimum TLS 1.2 must be enforced.
    Official policy GUIDs: f9d614c5 (Function App), f0e6e85b (Web App).
    """

    name = "cis-appservice-require-latest-tls"
    display_name = "CIS 9.3 — App Service: Require Minimum TLS 1.2"
    description = (
        "App Service apps must use TLS 1.2 or higher as the minimum "
        "TLS version for all connections (CIS 9.3)."
    )
    cis_control = "9.3"
    cis_section = "CIS-9"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    any_of(
                        field("properties.siteConfig.minTlsVersion").exists(False),
                        field("properties.siteConfig.minTlsVersion").not_in("1.2", "1.3"),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "App Service apps must have 'minTlsVersion' set to '1.2' or '1.3'. "
                    "Update the minimum TLS version under Settings > Configuration > "
                    "General settings (CIS 9.3)."
                ),
            )
            .build()
        )


class RequireManagedIdentityAppServicePolicy(CISPolicy):
    """
    CIS 9.5 — Ensure that Register with Azure Active Directory is enabled on App Service.

    Managed identities eliminate the need for hard-coded credentials and
    enable secure access to Azure resources.
    Official policy GUIDs: 0da106f2 (Function App), 2b9ad585 (Web App).
    """

    name = "cis-appservice-require-managed-identity"
    display_name = "CIS 9.5 — App Service: Require Managed Identity"
    description = (
        "App Service apps must use a managed identity (system-assigned or user-assigned) "
        "to authenticate to other Azure services without stored credentials (CIS 9.5)."
    )
    cis_control = "9.5"
    cis_section = "CIS-9"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    any_of(
                        field("identity.type").exists(False),
                        field("identity.type").equals("None"),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "App Service apps should have a managed identity enabled. "
                    "Enable system-assigned or user-assigned managed identity under "
                    "Settings > Identity (CIS 9.5)."
                ),
            )
            .build()
        )


class RequireLatestHTTPVersionAppServicePolicy(CISPolicy):
    """
    CIS 9.9 — Ensure that 'HTTP Version' is the latest for App Service.

    HTTP/2 provides improved performance and security over HTTP/1.1 through
    header compression and request multiplexing.
    Official policy GUIDs: e2c1c086 (Function App), 8c122334 (Web App).
    """

    name = "cis-appservice-require-latest-http"
    display_name = "CIS 9.9 — App Service: Require HTTP 2.0"
    description = (
        "App Service apps should use HTTP 2.0 to benefit from improved "
        "performance and security (CIS 9.9)."
    )
    cis_control = "9.9"
    cis_section = "CIS-9"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    any_of(
                        field("properties.siteConfig.http20Enabled").exists(False),
                        field("properties.siteConfig.http20Enabled").not_equals(True),
                    ),
                ),
                then=Effect.AUDIT,
                message=(
                    "App Service apps should have HTTP 2.0 enabled. "
                    "Enable HTTP version 2.0 under Settings > Configuration > "
                    "General settings (CIS 9.9)."
                ),
            )
            .build()
        )


class RequireFTPSOnlyAppServicePolicy(CISPolicy):
    """
    CIS 9.10 — Ensure FTP deployments are disabled (FTPS only or disabled).

    Plain FTP transmits credentials and data in cleartext. Only FTPS
    (encrypted FTP) or complete FTP disable should be permitted.
    Official policy GUIDs: 399b2637 (Function App), 4d24b6d4 (Web App).
    """

    name = "cis-appservice-require-ftps-only"
    display_name = "CIS 9.10 — App Service: Require FTPS Only or Disable FTP"
    description = (
        "App Service apps must have FTP state set to 'FtpsOnly' or 'Disabled'. "
        "Plain FTP transmits credentials in cleartext (CIS 9.10)."
    )
    cis_control = "9.10"
    cis_section = "CIS-9"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    any_of(
                        field("properties.siteConfig.ftpsState").exists(False),
                        field("properties.siteConfig.ftpsState").equals("AllAllowed"),
                    ),
                ),
                then=Effect.DENY,
                message=(
                    "App Service apps must have 'ftpsState' set to 'FtpsOnly' or 'Disabled'. "
                    "Disable plain FTP under Settings > Configuration > "
                    "General settings (CIS 9.10)."
                ),
            )
            .build()
        )


class RequireKeyVaultForAppSecretsPolicy(CISPolicy):
    """
    CIS 9.11 — Ensure that Azure Key Vault is used to store App Service secrets.

    Storing sensitive configuration in application settings as plain text
    increases the risk of credential exposure. Key Vault references should
    be used for all secrets.
    Official policy GUID: b8dad106-6444-5f55-307e-1e1cc9723e39.
    """

    name = "cis-appservice-require-keyvault-secrets"
    display_name = "CIS 9.11 — App Service: Require Key Vault for Secrets"
    description = (
        "App Service apps should reference secrets from Azure Key Vault "
        "rather than storing them as plain text in application settings (CIS 9.11)."
    )
    cis_control = "9.11"
    cis_section = "CIS-9"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Web/sites"),
                    field("properties.keyVaultReferenceIdentity").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "App Service apps should use Azure Key Vault references for secrets. "
                    "Configure Key Vault references in application settings and set "
                    "keyVaultReferenceIdentity to the managed identity (CIS 9.11)."
                ),
            )
            .build()
        )


# ============================================================================
# Azure Kubernetes Service (AKS)
# ============================================================================


class RequireAKSRBACPolicy(CISPolicy):
    """
    AKS-1 — Ensure RBAC is enabled on AKS clusters.

    Role-Based Access Control restricts access to Kubernetes API resources
    based on roles and role bindings, limiting the blast radius of compromised
    credentials. Official built-in GUID: ac4a19c2-fa67-49b4-be9a-67b27b64bbc3.
    """

    name = "aks-require-rbac"
    display_name = "AKS-1 — Require RBAC on AKS Clusters"
    description = (
        "AKS clusters must have Kubernetes RBAC enabled to enforce "
        "least-privilege access to the Kubernetes API (AKS-1)."
    )
    cis_control = "AKS-1"
    cis_section = "AKS"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    field("properties.enableRBAC").equals(False),
                ),
                then=Effect.DENY,
                message=(
                    "AKS clusters must have RBAC enabled. "
                    "Set enableRBAC: true in the cluster properties (AKS-1)."
                ),
            )
            .build()
        )


class RequireAKSAuthorizedIPRangesPolicy(CISPolicy):
    """
    AKS-2 — Ensure authorized IP ranges are configured on the AKS API server.

    Restricting access to the Kubernetes API server to known IP ranges reduces
    the attack surface of the control plane.
    Official built-in GUID: 0e246bcf-5f6f-4f87-bc6f-775d4712c7ea.
    """

    name = "aks-require-authorized-ip-ranges"
    display_name = "AKS-2 — Require Authorized IP Ranges on AKS API Server"
    description = (
        "AKS clusters must restrict API server access to authorized IP ranges "
        "to reduce Kubernetes control plane exposure (AKS-2)."
    )
    cis_control = "AKS-2"
    cis_section = "AKS"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    field("properties.apiServerAccessProfile.authorizedIPRanges").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "AKS clusters should define authorized IP ranges for API server access. "
                    "Configure authorizedIPRanges in apiServerAccessProfile (AKS-2)."
                ),
            )
            .build()
        )


class RequireAKSPrivateClusterPolicy(CISPolicy):
    """
    AKS-3 — Ensure AKS clusters use a private API server endpoint.

    A private cluster ensures the Kubernetes API server is not exposed to the
    public internet, significantly reducing the control plane attack surface.
    Official built-in GUID: 040732e8-d947-40b8-95d6-854c95024bf8.
    """

    name = "aks-require-private-cluster"
    display_name = "AKS-3 — Require AKS Private Cluster"
    description = (
        "AKS clusters should use a private API server endpoint to prevent "
        "exposure of the Kubernetes control plane to the internet (AKS-3)."
    )
    cis_control = "AKS-3"
    cis_section = "AKS"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    field("properties.apiServerAccessProfile.enablePrivateCluster").equals(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "AKS clusters should use a private API server endpoint. "
                    "Enable enablePrivateCluster in apiServerAccessProfile (AKS-3)."
                ),
            )
            .build()
        )


class RequireAKSDefenderPolicy(CISPolicy):
    """
    AKS-4 — Ensure Microsoft Defender for Containers is enabled on AKS.

    Defender for Containers provides runtime threat detection, vulnerability
    scanning, and compliance monitoring for Kubernetes workloads.
    Official built-in GUID: 523b5cd1-3374-4e2f-8cc5-839698ca3e0c.
    """

    name = "aks-require-defender"
    display_name = "AKS-4 — Require Defender for Containers on AKS"
    description = (
        "AKS clusters must have Microsoft Defender for Containers enabled "
        "for runtime threat detection and vulnerability scanning (AKS-4)."
    )
    cis_control = "AKS-4"
    cis_section = "AKS"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    field(
                        "properties.securityProfile.defender.securityMonitoring.enabled"
                    ).equals(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "AKS clusters should have Microsoft Defender for Containers enabled. "
                    "Enable securityProfile.defender.securityMonitoring (AKS-4)."
                ),
            )
            .build()
        )


class DenyAKSPrivilegedContainersPolicy(CISPolicy):
    """
    AKS-5 — Ensure AKS clusters do not allow privileged containers.

    Privileged containers have full access to the host kernel and can be used
    to escape the container sandbox. This policy audits clusters that have not
    applied pod security standards restricting privileged workloads.
    Official built-in GUID: 1c6e92c9-99f0-4e55-9cf2-0c234dc48f99.
    """

    name = "aks-deny-privileged-containers"
    display_name = "AKS-5 — Deny Privileged Containers in AKS"
    description = (
        "AKS clusters should not allow privileged containers. "
        "Privileged containers can escalate to host-level access (AKS-5)."
    )
    cis_control = "AKS-5"
    cis_section = "AKS"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    field("properties.podSecurityStandardsProfile.restricted").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "AKS clusters should restrict privileged containers using "
                    "Pod Security Admission or Azure Policy for AKS (AKS-5)."
                ),
            )
            .build()
        )


class RequireAKSNetworkPolicyPolicy(CISPolicy):
    """
    AKS-6 — Ensure AKS clusters have a network policy configured.

    Kubernetes Network Policies restrict pod-to-pod and pod-to-external traffic,
    enforcing zero-trust network segmentation within the cluster.
    Official built-in GUID: 9000cf9b-6cc4-4de3-b6b2-9ab42f6c1a6d.
    """

    name = "aks-require-network-policy"
    display_name = "AKS-6 — Require Network Policy on AKS"
    description = (
        "AKS clusters must have a Kubernetes network policy configured "
        "to enforce pod-level traffic segmentation (AKS-6)."
    )
    cis_control = "AKS-6"
    cis_section = "AKS"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerService/managedClusters"),
                    field("properties.networkProfile.networkPolicy").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "AKS clusters must have a network policy configured (Azure, Calico, or Cilium). "
                    "Set networkProfile.networkPolicy (AKS-6)."
                ),
            )
            .build()
        )


# ============================================================================
# Container Registry (ACR)
# ============================================================================


class DenyACRAdminUserPolicy(CISPolicy):
    """
    ACR-1 — Ensure the container registry admin account is disabled.

    The built-in admin account uses shared credentials and does not support
    RBAC or auditing. All registry access should use Azure AD identities.
    """

    name = "acr-deny-admin-user"
    display_name = "ACR-1 — Deny Container Registry Admin User"
    description = (
        "Container Registry admin user must be disabled. "
        "Use Azure AD identities and RBAC for registry access (ACR-1)."
    )
    cis_control = "ACR-1"
    cis_section = "ACR"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerRegistry/registries"),
                    field("properties.adminUserEnabled").equals(True),
                ),
                then=Effect.DENY,
                message=(
                    "Container Registry admin user must be disabled. "
                    "Disable adminUserEnabled and use managed identities (ACR-1)."
                ),
            )
            .build()
        )


class RequireACRPrivateEndpointPolicy(CISPolicy):
    """
    ACR-2 — Ensure container registries are not accessible from public networks.

    Public network access to a container registry allows anyone to attempt to
    pull images or authenticate. Private endpoints restrict access to known
    virtual networks only.
    """

    name = "acr-require-private-endpoint"
    display_name = "ACR-2 — Require Private Endpoint for Container Registry"
    description = (
        "Container registries must disable public network access and use "
        "private endpoints to prevent unauthorized image access (ACR-2)."
    )
    cis_control = "ACR-2"
    cis_section = "ACR"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerRegistry/registries"),
                    field("properties.publicNetworkAccess").equals("Enabled"),
                ),
                then=Effect.AUDIT,
                message=(
                    "Container registries should disable public network access. "
                    "Configure a private endpoint and set publicNetworkAccess to Disabled (ACR-2)."
                ),
            )
            .build()
        )


class RequireACRImageScanPolicy(CISPolicy):
    """
    ACR-3 — Ensure container images are scanned for vulnerabilities on push.

    Enabling quarantine policy causes images to be held until a security scanner
    approves them, preventing vulnerable images from reaching production.
    """

    name = "acr-require-image-scan"
    display_name = "ACR-3 — Require Image Scanning on Container Registry"
    description = (
        "Container registries should have image vulnerability scanning enabled "
        "to prevent deployment of vulnerable container images (ACR-3)."
    )
    cis_control = "ACR-3"
    cis_section = "ACR"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.ContainerRegistry/registries"),
                    field("properties.policies.quarantinePolicy.status").equals("disabled"),
                ),
                then=Effect.AUDIT,
                message=(
                    "Container registries should enable quarantine policy for image scanning. "
                    "Set policies.quarantinePolicy.status to 'enabled' (ACR-3)."
                ),
            )
            .build()
        )


# ============================================================================
# Application Gateway & WAF
# ============================================================================


class RequireWAFOnAppGatewayPolicy(CISPolicy):
    """
    WAF-1 — Ensure Application Gateway is deployed with Web Application Firewall.

    Application Gateways without WAF provide no L7 threat protection.
    All internet-facing Application Gateways must use the WAF_v2 SKU.
    """

    name = "waf-require-on-appgateway"
    display_name = "WAF-1 — Require WAF on Application Gateway"
    description = (
        "Application Gateways must use the WAF_v2 SKU to enable "
        "Web Application Firewall protection (WAF-1)."
    )
    cis_control = "WAF-1"
    cis_section = "WAF"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/applicationGateways"),
                    field("properties.sku.name").not_in("WAF_v2", "WAF"),
                ),
                then=Effect.DENY,
                message=(
                    "Application Gateways must use the WAF_v2 SKU. "
                    "Change the SKU to WAF_v2 to enable Web Application Firewall (WAF-1)."
                ),
            )
            .build()
        )


class RequireWAFPreventionModePolicy(CISPolicy):
    """
    WAF-2 — Ensure Web Application Firewall is in Prevention mode.

    WAF in Detection mode only logs requests but does not block attacks.
    Prevention mode is required for active threat mitigation.
    """

    name = "waf-require-prevention-mode"
    display_name = "WAF-2 — Require WAF Prevention Mode"
    description = (
        "Web Application Firewall must be set to Prevention mode to actively "
        "block malicious requests rather than only detecting them (WAF-2)."
    )
    cis_control = "WAF-2"
    cis_section = "WAF"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/applicationGateways"),
                    field(
                        "properties.webApplicationFirewallConfiguration.firewallMode"
                    ).equals("Detection"),
                ),
                then=Effect.DENY,
                message=(
                    "Web Application Firewall must be in Prevention mode. "
                    "Set webApplicationFirewallConfiguration.firewallMode to 'Prevention' (WAF-2)."
                ),
            )
            .build()
        )


class RequireWAFPolicyLinkPolicy(CISPolicy):
    """
    WAF-3 — Ensure Application Gateway has a WAF Policy attached.

    A WAF Policy provides centralized management of WAF rules, custom rules,
    and exclusions. Attaching a WAF Policy is required for fine-grained
    protection configuration.
    """

    name = "waf-require-policy-link"
    display_name = "WAF-3 — Require WAF Policy on Application Gateway"
    description = (
        "Application Gateways must have a WAF Policy attached for centralized "
        "rule management and custom protections (WAF-3)."
    )
    cis_control = "WAF-3"
    cis_section = "WAF"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Network/applicationGateways"),
                    field("properties.firewallPolicy.id").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Application Gateways should have a WAF Policy attached. "
                    "Create a WAF Policy and link it to the Application Gateway (WAF-3)."
                ),
            )
            .build()
        )


# ============================================================================
# Backup & Recovery
# ============================================================================


class RequireBackupSoftDeletePolicy(CISPolicy):
    """
    Backup-1 — Ensure soft delete is enabled on Recovery Services Vaults.

    Soft delete retains deleted backup data for 14 days, protecting against
    accidental or malicious deletion of backup items.
    """

    name = "backup-require-soft-delete"
    display_name = "Backup-1 — Require Soft Delete on Recovery Services Vault"
    description = (
        "Recovery Services Vaults must have soft delete enabled to protect "
        "backup data from accidental or malicious deletion (Backup-1)."
    )
    cis_control = "Backup-1"
    cis_section = "Backup"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.RecoveryServices/vaults"),
                    field("properties.softDeleteFeatureState").equals("Disabled"),
                ),
                then=Effect.DENY,
                message=(
                    "Recovery Services Vaults must have soft delete enabled. "
                    "Set softDeleteFeatureState to 'Enabled' (Backup-1)."
                ),
            )
            .build()
        )


class RequireVMBackupPolicy(CISPolicy):
    """
    Backup-2 — Ensure virtual machines have backup configured.

    VMs without backup are vulnerable to data loss from system failures,
    ransomware, or accidental deletion. Use the 'backup-enabled' tag as
    a governance signal alongside Azure Backup association.
    """

    name = "backup-require-vm-backup"
    display_name = "Backup-2 — Require Backup for Virtual Machines"
    description = (
        "Virtual machines must be tagged with 'backup-enabled' to indicate "
        "an Azure Backup policy is associated (Backup-2)."
    )
    cis_control = "Backup-2"
    cis_section = "Backup"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.Compute/virtualMachines"),
                    field("tags['backup-enabled']").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Virtual machines should have Azure Backup configured. "
                    "Associate the VM with a Recovery Services Vault and add the "
                    "'backup-enabled' tag (Backup-2)."
                ),
            )
            .build()
        )


class RequireBackupImmutabilityPolicy(CISPolicy):
    """
    Backup-3 — Ensure Recovery Services Vaults have immutability enabled.

    Immutable vaults prevent backup data from being modified or deleted until
    the retention period expires, protecting against ransomware targeting backups.
    """

    name = "backup-require-immutability"
    display_name = "Backup-3 — Require Immutability on Recovery Services Vault"
    description = (
        "Recovery Services Vaults should enable immutability to protect backup "
        "data from modification or premature deletion (Backup-3)."
    )
    cis_control = "Backup-3"
    cis_section = "Backup"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.RecoveryServices/vaults"),
                    field(
                        "properties.securitySettings.immutabilitySettings.state"
                    ).exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Recovery Services Vaults should enable immutability (Locked or Unlocked). "
                    "Set securitySettings.immutabilitySettings.state (Backup-3)."
                ),
            )
            .build()
        )


# ============================================================================
# Log Analytics
# ============================================================================


class RequireLogAnalyticsRetentionPolicy(CISPolicy):
    """
    LogAnalytics-1 — Ensure Log Analytics workspaces retain data for at least 90 days.

    Log data is essential for security investigations. Workspaces with insufficient
    retention may not have logs available for incident response.
    """

    name = "loganalytics-require-retention"
    display_name = "LogAnalytics-1 — Require Log Analytics Retention >= 90 Days"
    description = (
        "Log Analytics workspaces must retain data for at least 90 days "
        "to support security investigations and audit requirements (LogAnalytics-1)."
    )
    cis_control = "LogAnalytics-1"
    cis_section = "LogAnalytics"
    severity = "Medium"

    @classmethod
    def build(cls, minimum_retention_days: int = 90, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .parameter(
                "minimumRetentionDays",
                type="Integer",
                display_name="Minimum Retention (days)",
                description="Minimum Log Analytics workspace data retention in days",
                default=minimum_retention_days,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.OperationalInsights/workspaces"),
                    field("properties.retentionInDays").less_than(minimum_retention_days),
                ),
                then=Effect.DENY,
                message=(
                    f"Log Analytics workspaces must retain data for at least "
                    f"{minimum_retention_days} days. "
                    f"Increase retentionInDays (LogAnalytics-1)."
                ),
            )
            .build()
        )


class DenyLogAnalyticsPublicAccessPolicy(CISPolicy):
    """
    LogAnalytics-2 — Ensure Log Analytics workspaces block public network access.

    Workspaces accessible from public networks may receive log data or queries
    from unauthorized sources. Network isolation should be enforced.
    """

    name = "loganalytics-deny-public-access"
    display_name = "LogAnalytics-2 — Deny Public Network Access to Log Analytics"
    description = (
        "Log Analytics workspaces must disable public network access for "
        "log ingestion and queries (LogAnalytics-2)."
    )
    cis_control = "LogAnalytics-2"
    cis_section = "LogAnalytics"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.OperationalInsights/workspaces"),
                    field("properties.publicNetworkAccessForIngestion").equals("Enabled"),
                ),
                then=Effect.AUDIT,
                message=(
                    "Log Analytics workspaces should disable public network access. "
                    "Set publicNetworkAccessForIngestion to 'Disabled' (LogAnalytics-2)."
                ),
            )
            .build()
        )


class RequireLogAnalyticsCMKPolicy(CISPolicy):
    """
    LogAnalytics-3 — Ensure Log Analytics workspaces use a customer-managed key.

    Customer-managed keys give organizations full control over the encryption
    key lifecycle for log data, required for high-compliance environments.
    """

    name = "loganalytics-require-cmk"
    display_name = "LogAnalytics-3 — Require CMK for Log Analytics Workspace"
    description = (
        "Log Analytics workspaces should use customer-managed keys for "
        "encryption of stored log data (LogAnalytics-3)."
    )
    cis_control = "LogAnalytics-3"
    cis_section = "LogAnalytics"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.OperationalInsights/workspaces"),
                    field("properties.features.clusterResourceId").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Log Analytics workspaces should use a dedicated cluster with CMK encryption. "
                    "Link the workspace to a Log Analytics Cluster with a CMK (LogAnalytics-3)."
                ),
            )
            .build()
        )


# ============================================================================
# Cosmos DB
# ============================================================================


class RequireCosmosFirewallPolicy(CISPolicy):
    """
    CosmosDB-1 — Ensure Cosmos DB accounts have firewall rules configured.

    Cosmos DB accounts without IP firewall rules allow connections from any
    public IP address, exposing the database to unauthorized access.
    """

    name = "cosmosdb-require-firewall"
    display_name = "CosmosDB-1 — Require Firewall on Cosmos DB Accounts"
    description = (
        "Cosmos DB accounts must have IP firewall rules configured to "
        "restrict access to known IP ranges (CosmosDB-1)."
    )
    cis_control = "CosmosDB-1"
    cis_section = "CosmosDB"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.DocumentDB/databaseAccounts"),
                    field("properties.ipRules").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Cosmos DB accounts should have IP firewall rules configured. "
                    "Add IP filter rules or configure virtual network rules (CosmosDB-1)."
                ),
            )
            .build()
        )


class DenyCosmosPublicNetworkPolicy(CISPolicy):
    """
    CosmosDB-2 — Ensure Cosmos DB accounts disable public network access.

    Disabling public network access forces all connections through private
    endpoints, eliminating internet-facing attack surface on the database.
    """

    name = "cosmosdb-deny-public-network"
    display_name = "CosmosDB-2 — Deny Public Network Access to Cosmos DB"
    description = (
        "Cosmos DB accounts must disable public network access and use "
        "private endpoints for all connections (CosmosDB-2)."
    )
    cis_control = "CosmosDB-2"
    cis_section = "CosmosDB"
    severity = "High"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.DocumentDB/databaseAccounts"),
                    field("properties.publicNetworkAccess").equals("Enabled"),
                ),
                then=Effect.DENY,
                message=(
                    "Cosmos DB accounts must disable public network access. "
                    "Set publicNetworkAccess to 'Disabled' and configure private endpoints (CosmosDB-2)."
                ),
            )
            .build()
        )


class RequireCosmosCMKPolicy(CISPolicy):
    """
    CosmosDB-3 — Ensure Cosmos DB accounts use customer-managed keys.

    By default Cosmos DB uses Microsoft-managed keys. CMK encryption provides
    organizations with full control of the encryption key lifecycle.
    """

    name = "cosmosdb-require-cmk"
    display_name = "CosmosDB-3 — Require CMK Encryption for Cosmos DB"
    description = (
        "Cosmos DB accounts should use customer-managed keys for data "
        "encryption at rest (CosmosDB-3)."
    )
    cis_control = "CosmosDB-3"
    cis_section = "CosmosDB"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("type").equals("Microsoft.DocumentDB/databaseAccounts"),
                    field("properties.keyVaultKeyUri").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "Cosmos DB accounts should use customer-managed keys. "
                    "Configure keyVaultKeyUri with a Key Vault key URI (CosmosDB-3)."
                ),
            )
            .build()
        )


# ============================================================================
# Governance & Tagging
# ============================================================================


class RequireEnvironmentTagPolicy(CISPolicy):
    """
    Gov-1 — Ensure all resources have an 'environment' tag.

    The environment tag (e.g., production, staging, development) is essential
    for cost allocation, access scoping, and policy targeting. Resources
    without this tag cannot be reliably governed.
    """

    name = "gov-require-environment-tag"
    display_name = "Gov-1 — Require 'environment' Tag on All Resources"
    description = (
        "All resources must have an 'environment' tag to enable "
        "cost allocation, policy targeting, and lifecycle management (Gov-1)."
    )
    cis_control = "Gov-1"
    cis_section = "Governance"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("tags['environment']").exists(False),
                ),
                then=Effect.DENY,
                message=(
                    "All resources must have an 'environment' tag. "
                    "Add a tag with key 'environment' and a value such as "
                    "'production', 'staging', or 'development' (Gov-1)."
                ),
            )
            .build()
        )


class RequireCostCenterTagPolicy(CISPolicy):
    """
    Gov-2 — Ensure all resources have a 'cost-center' tag.

    Cost center tags are required for financial accountability and charge-back
    processes. Without this tag, resource costs cannot be attributed to the
    correct organizational unit.
    """

    name = "gov-require-cost-center-tag"
    display_name = "Gov-2 — Require 'cost-center' Tag on All Resources"
    description = (
        "All resources must have a 'cost-center' tag for financial "
        "accountability and charge-back attribution (Gov-2)."
    )
    cis_control = "Gov-2"
    cis_section = "Governance"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("tags['cost-center']").exists(False),
                ),
                then=Effect.AUDIT,
                message=(
                    "All resources should have a 'cost-center' tag. "
                    "Add a tag with key 'cost-center' for charge-back attribution (Gov-2)."
                ),
            )
            .build()
        )


class RequireOwnerTagGovPolicy(CISPolicy):
    """
    Gov-3 — Ensure all resources have an 'owner' tag.

    Owner tags identify the team or individual responsible for a resource,
    enabling rapid contact for security incidents, cost reviews, and
    lifecycle management.
    """

    name = "gov-require-owner-tag"
    display_name = "Gov-3 — Require 'owner' Tag on All Resources"
    description = (
        "All resources must have an 'owner' tag identifying the responsible "
        "team or individual for lifecycle and incident management (Gov-3)."
    )
    cis_control = "Gov-3"
    cis_section = "Governance"
    severity = "Medium"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("tags['owner']").exists(False),
                ),
                then=Effect.DENY,
                message=(
                    "All resources must have an 'owner' tag. "
                    "Add a tag with key 'owner' identifying the responsible team or person (Gov-3)."
                ),
            )
            .build()
        )


class RequireAllowedLocationsPolicy(CISPolicy):
    """
    Gov-4 — Ensure resources are only deployed in approved Azure regions.

    Restricting deployments to specific regions ensures data residency
    compliance, reduces latency, and limits exposure to regional risk.
    Default allowed regions: westeurope, northeurope, global.
    Customize by passing allowed_locations to build().
    """

    name = "gov-require-allowed-locations"
    display_name = "Gov-4 — Restrict Resources to Allowed Azure Regions"
    description = (
        "Resources must be deployed in approved Azure regions only. "
        "Configure allowed_locations to match your data residency requirements (Gov-4)."
    )
    cis_control = "Gov-4"
    cis_section = "Governance"
    severity = "High"

    @classmethod
    def build(
        cls,
        allowed_locations: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        locations = allowed_locations or ["westeurope", "northeurope", "global"]
        return (
            cls._base_builder()
            .with_rule(
                if_=all_of(
                    field("location").not_in(*locations),
                ),
                then=Effect.DENY,
                message=(
                    f"Resources must be deployed in approved regions: {', '.join(locations)}. "
                    f"Change the resource location to an approved region (Gov-4)."
                ),
            )
            .build()
        )


# ============================================================================
# Registry
# ============================================================================

_CIS_POLICIES: Dict[str, Type[CISPolicy]] = {
    # Section 1: IAM
    "cis-require-security-contact": RequireSecurityContactEmailPolicy,
    "cis-require-mfa-tag": RequireMFATagPolicy,
    "cis-deny-guest-owner-role": DenyGuestUserOwnerRolePolicy,
    # Section 2: Defender for Cloud
    "cis-require-defender-servers": RequireDefenderForServersPolicy,
    "cis-require-defender-tag": RequireDefenderTagPolicy,
    # Section 3: Storage
    "cis-storage-require-secure-transfer": RequireStorageSecureTransferPolicy,
    "cis-storage-deny-public-access": DenyStoragePublicBlobAccessPolicy,
    "cis-storage-require-min-tls": RequireStorageMinTLSPolicy,
    "cis-storage-require-network-deny": RequireStorageNetworkDefaultDenyPolicy,
    # Section 4: Database
    "cis-sql-require-auditing": RequireSQLAuditingPolicy,
    "cis-sql-require-tde": RequireSQLTDEPolicy,
    "cis-sql-require-min-tls": RequireSQLMinTLSPolicy,
    "cis-sql-deny-public-access": RequireSQLPublicAccessDisabledPolicy,
    # Section 5: Logging
    "cis-require-activity-log-retention": RequireActivityLogRetentionPolicy,
    "cis-require-diagnostic-settings": RequireDiagnosticSettingsPolicy,
    "cis-deny-public-log-storage": DenyPublicStorageForLogsPolicy,
    # Section 6: Networking
    "cis-deny-rdp-internet": DenyRDPFromInternetPolicy,
    "cis-deny-ssh-internet": DenySSHFromInternetPolicy,
    "cis-require-nsg-on-subnets": RequireNSGOnSubnetsPolicy,
    "cis-require-nsg-flow-logs": RequireNSGFlowLogsPolicy,
    # Section 7: Virtual Machines
    "cis-vm-require-disk-encryption": RequireVMDiskEncryptionPolicy,
    "cis-vm-require-data-disk-encryption": RequireVMDataDiskEncryptionPolicy,
    "cis-vm-require-trusted-launch": RequireTrustedLaunchPolicy,
    # Section 8: Key Vault
    "cis-keyvault-require-key-expiry": RequireKeyExpiryPolicy,
    "cis-keyvault-require-secret-expiry": RequireSecretExpiryPolicy,
    "cis-keyvault-require-recoverable": RequireKeyVaultRecoverablePolicy,
    "cis-keyvault-require-firewall": RequireKeyVaultFirewallPolicy,
    "cis-keyvault-require-rbac": RequireKeyVaultRBACPolicy,
    # Section 9: App Service
    "cis-appservice-require-auth": RequireAppServiceAuthPolicy,
    "cis-appservice-require-https": RequireHTTPSOnlyAppServicePolicy,
    "cis-appservice-require-latest-tls": RequireLatestTLSAppServicePolicy,
    "cis-appservice-require-managed-identity": RequireManagedIdentityAppServicePolicy,
    "cis-appservice-require-latest-http": RequireLatestHTTPVersionAppServicePolicy,
    "cis-appservice-require-ftps-only": RequireFTPSOnlyAppServicePolicy,
    "cis-appservice-require-keyvault-secrets": RequireKeyVaultForAppSecretsPolicy,
    # Azure Kubernetes Service (AKS)
    "aks-require-rbac": RequireAKSRBACPolicy,
    "aks-require-authorized-ip-ranges": RequireAKSAuthorizedIPRangesPolicy,
    "aks-require-private-cluster": RequireAKSPrivateClusterPolicy,
    "aks-require-defender": RequireAKSDefenderPolicy,
    "aks-deny-privileged-containers": DenyAKSPrivilegedContainersPolicy,
    "aks-require-network-policy": RequireAKSNetworkPolicyPolicy,
    # Container Registry (ACR)
    "acr-deny-admin-user": DenyACRAdminUserPolicy,
    "acr-require-private-endpoint": RequireACRPrivateEndpointPolicy,
    "acr-require-image-scan": RequireACRImageScanPolicy,
    # Application Gateway & WAF
    "waf-require-on-appgateway": RequireWAFOnAppGatewayPolicy,
    "waf-require-prevention-mode": RequireWAFPreventionModePolicy,
    "waf-require-policy-link": RequireWAFPolicyLinkPolicy,
    # Backup & Recovery
    "backup-require-soft-delete": RequireBackupSoftDeletePolicy,
    "backup-require-vm-backup": RequireVMBackupPolicy,
    "backup-require-immutability": RequireBackupImmutabilityPolicy,
    # Log Analytics
    "loganalytics-require-retention": RequireLogAnalyticsRetentionPolicy,
    "loganalytics-deny-public-access": DenyLogAnalyticsPublicAccessPolicy,
    "loganalytics-require-cmk": RequireLogAnalyticsCMKPolicy,
    # Cosmos DB
    "cosmosdb-require-firewall": RequireCosmosFirewallPolicy,
    "cosmosdb-deny-public-network": DenyCosmosPublicNetworkPolicy,
    "cosmosdb-require-cmk": RequireCosmosCMKPolicy,
    # Governance & Tagging
    "gov-require-environment-tag": RequireEnvironmentTagPolicy,
    "gov-require-cost-center-tag": RequireCostCenterTagPolicy,
    "gov-require-owner-tag": RequireOwnerTagGovPolicy,
    "gov-require-allowed-locations": RequireAllowedLocationsPolicy,
}


# ============================================================================
# Helper Functions
# ============================================================================


def list_cis_policies() -> List[Tuple[str, str, str]]:
    """
    List all available CIS Azure policies.

    Returns:
        List of (name, description, cis_control) tuples
    """
    return [
        (cls.name, cls.description, cls.cis_control)
        for cls in _CIS_POLICIES.values()
    ]


def get_cis_policy(name: str, **kwargs: Any) -> PolicyDefinition:
    """
    Get a CIS Azure policy by name.

    Args:
        name:     Policy name (e.g., "cis-storage-require-secure-transfer")
        **kwargs: Policy-specific parameters

    Returns:
        PolicyDefinition: The built policy

    Raises:
        KeyError: If policy name is not found
    """
    if name not in _CIS_POLICIES:
        available = ", ".join(_CIS_POLICIES.keys())
        raise KeyError(f"Unknown CIS policy: '{name}'. Available: {available}")

    return _CIS_POLICIES[name].build(**kwargs)


def get_all_cis_policies(**default_kwargs: Any) -> List[PolicyDefinition]:
    """
    Get all CIS Azure policies.

    Args:
        **default_kwargs: Default parameters passed to every policy

    Returns:
        List of all CIS PolicyDefinitions
    """
    return [cls.build(**default_kwargs) for cls in _CIS_POLICIES.values()]


def get_cis_policies_by_section(section: str, **kwargs: Any) -> List[PolicyDefinition]:
    """
    Get CIS Azure policies filtered by benchmark section.

    Args:
        section:  CIS section code (e.g., "CIS-3", "CIS-8")
        **kwargs: Policy-specific parameters

    Returns:
        List of PolicyDefinitions in the specified section
    """
    return [
        cls.build(**kwargs)
        for cls in _CIS_POLICIES.values()
        if cls.cis_section == section
    ]


def get_cis_policies_by_severity(severity: str, **kwargs: Any) -> List[PolicyDefinition]:
    """
    Get CIS Azure policies filtered by severity level.

    Args:
        severity: "High", "Medium", or "Low"
        **kwargs: Policy-specific parameters

    Returns:
        List of PolicyDefinitions with the specified severity
    """
    return [
        cls.build(**kwargs)
        for cls in _CIS_POLICIES.values()
        if cls.severity == severity
    ]


# ============================================================================
# CIS Initiative (Policy Set)
# ============================================================================


def get_cis_initiative(**kwargs: Any) -> PolicySetDefinition:
    """
    Get the complete CIS Microsoft Azure Foundations Benchmark initiative.

    Creates a PolicySet containing all CIS policies organized by benchmark
    section (IAM, Defender, Storage, Database, Logging, Networking, VMs,
    Key Vault).

    Args:
        **kwargs: Optional parameters forwarded to individual policy builds

    Returns:
        PolicySetDefinition: Complete CIS initiative
    """
    builder = (
        PolicySetBuilder("cis-azure-foundations-baseline")
        .display_name("CIS Microsoft Azure Foundations Benchmark v3.0.0")
        .description(
            "Complete policy set for compliance with the CIS Microsoft Azure "
            "Foundations Benchmark v3.0.0. Covers Identity & Access Management, "
            "Microsoft Defender for Cloud, Storage, Databases, Logging, "
            "Networking, Virtual Machines, Key Vault, and App Service."
        )
        .category("CIS")
        .version(CIS_BENCHMARK_VERSION)
        .metadata({
            "compliance_standard": "CIS",
            "benchmark": f"CIS Microsoft Azure Foundations Benchmark v{CIS_BENCHMARK_VERSION}",
            "author": "ITL Platform Team",
            "reference": CIS_BENCHMARK_REFERENCE,
        })
    )

    # Add benchmark section groups
    for section, section_name in CIS_SECTIONS.items():
        builder.add_group(name=section_name, display_name=section_name)

    # Add all CIS policies grouped by section
    for section, section_name in CIS_SECTIONS.items():
        policies = get_cis_policies_by_section(section, **kwargs)
        for policy in policies:
            builder.add_policy(
                policy_definition_id=(
                    f"/providers/Microsoft.Authorization/policyDefinitions/{policy.name}"
                ),
                groups=[section_name],
            )

    return builder.build()


def get_cis_high_severity_initiative(**kwargs: Any) -> PolicySetDefinition:
    """
    Get a CIS initiative containing only High severity controls.

    Useful for a focused, high-impact deployment when you want to enforce
    the most critical CIS controls first.

    Returns:
        PolicySetDefinition: High-severity CIS initiative
    """
    builder = (
        PolicySetBuilder("cis-azure-high-severity")
        .display_name("CIS Azure Foundations — High Severity Controls")
        .description(
            "CIS Microsoft Azure Foundations Benchmark v3.0.0 — High severity "
            "controls only. Deploy this first for maximum security impact."
        )
        .category("CIS")
        .version(CIS_BENCHMARK_VERSION)
        .metadata({
            "compliance_standard": "CIS",
            "severity_filter": "High",
            "benchmark": f"CIS Microsoft Azure Foundations Benchmark v{CIS_BENCHMARK_VERSION}",
            "author": "ITL Platform Team",
            "reference": CIS_BENCHMARK_REFERENCE,
        })
    )

    for section, section_name in CIS_SECTIONS.items():
        builder.add_group(name=section_name, display_name=section_name)

    high_policies = get_cis_policies_by_severity("High", **kwargs)
    for policy in high_policies:
        # Determine section from the policy class
        policy_cls = _CIS_POLICIES[policy.name]
        section_name = CIS_SECTIONS[policy_cls.cis_section]
        builder.add_policy(
            policy_definition_id=(
                f"/providers/Microsoft.Authorization/policyDefinitions/{policy.name}"
            ),
            groups=[section_name],
        )

    return builder.build()
