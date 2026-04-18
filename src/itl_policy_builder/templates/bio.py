"""
BIO (Baseline Informatiebeveiliging Overheid) Policy Templates.

Dit module bevat policy templates gebaseerd op de Baseline Informatiebeveiliging
Overheid (BIO) - de Nederlandse overheidsnorm voor informatiebeveiliging.

BIO Categorieën:
- Toegangsbeheer (9.x) - Access control policies
- Cryptografie (10.x) - Encryption requirements
- Communicatiebeveiliging (13.x) - Network security
- Logging & Monitoring (12.x) - Audit logging
- Classificatie (8.x) - Data classification
- Beheer (12.x) - Operations security

Referentie: https://www.digitaleoverheid.nl/overzicht-van-alle-onderwerpen/cybersecurity/bio-en-ensia/baseline-informatiebeveiliging-overheid/
"""

from typing import Any, Dict, List, Optional, Tuple, Type

from itl_policy_builder.builder import PolicyBuilder
from itl_policy_builder.conditions import all_of, any_of, field, not_
from itl_policy_builder.enums import Effect, PolicyType
from itl_policy_builder.initiative import PolicySetBuilder
from itl_policy_builder.models import PolicyDefinition, PolicySetDefinition


# ============================================================================
# BIO Categories
# ============================================================================

BIO_CATEGORIES = {
    "BIO-8": "Classificatie van informatie",
    "BIO-9": "Toegangsbeheer",
    "BIO-10": "Cryptografie",
    "BIO-12": "Beveiliging bedrijfsvoering",
    "BIO-13": "Communicatiebeveiliging",
}


# ============================================================================
# Base Class
# ============================================================================


class BIOPolicy:
    """
    Base class for BIO policy templates.

    Attributes:
        name: Unique policy identifier
        display_name: Human-readable name
        description: What the policy does
        bio_control: BIO control reference (e.g., "9.1.1")
        bio_category: BIO category code (e.g., "BIO-9")
    """

    name: str = ""
    display_name: str = ""
    description: str = ""
    bio_control: str = ""
    bio_category: str = ""
    version: str = "1.0.0"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        """Build the policy with optional parameters."""
        raise NotImplementedError


# ============================================================================
# BIO-8: Classificatie van informatie
# ============================================================================


class RequireDataClassificationPolicy(BIOPolicy):
    """
    BIO 8.2.1 - Vereist classificatielabel op resources.

    Resources moeten een 'dataClassification' tag hebben met een geldige
    classificatiewaarde volgens de BIV-indeling.
    """

    name = "bio-require-data-classification"
    display_name = "BIO 8.2.1 - Vereist Dataclassificatie"
    description = "Resources moeten een dataclassificatie tag hebben (BIV: Beschikbaarheid, Integriteit, Vertrouwelijkheid)"
    bio_control = "8.2.1"
    bio_category = "BIO-8"

    @classmethod
    def build(
        cls,
        allowed_classifications: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_classifications = allowed_classifications or [
            "openbaar",          # Publiek toegankelijk
            "bedrijfsvertrouwelijk",  # Intern gebruik
            "vertrouwelijk",     # Beperkte toegang
            "geheim",            # Strikt vertrouwelijk
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "bio_category": cls.bio_category,
                "compliance_standard": "BIO",
            })
            .parameter(
                "allowedClassifications",
                type="Array",
                display_name="Toegestane Classificaties",
                description="Lijst van geldige dataclassificatie waarden",
                default=allowed_classifications,
            )
            .with_rule(
                if_=any_of(
                    field("tags.dataClassification").exists(False),
                    field("tags.dataClassification").not_in(*allowed_classifications),
                ),
                then=Effect.DENY,
                message="Resources moeten een geldige 'dataClassification' tag hebben. Toegestane waarden: " + ", ".join(allowed_classifications),
            )
            .build()
        )


class AuditSensitiveDataPolicy(BIOPolicy):
    """
    BIO 8.2.2 - Audit resources met gevoelige data zonder extra beveiliging.
    """

    name = "bio-audit-sensitive-data"
    display_name = "BIO 8.2.2 - Audit Gevoelige Data"
    description = "Audit resources geclassificeerd als 'vertrouwelijk' of 'geheim' die mogelijk extra beveiliging nodig hebben"
    bio_control = "8.2.2"
    bio_category = "BIO-8"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("tags.dataClassification").equals("vertrouwelijk"),
                        field("tags.dataClassification").equals("geheim"),
                    ),
                    field("tags.encryptionEnabled").not_equals("true"),
                ),
                then=Effect.AUDIT,
                message="Resources met classificatie 'vertrouwelijk' of 'geheim' vereisen versleuteling",
            )
            .build()
        )


# ============================================================================
# BIO-9: Toegangsbeheer (Access Control)
# ============================================================================


class RequireOwnerTagPolicy(BIOPolicy):
    """
    BIO 9.1.1 - Vereist een eigenaar (owner) tag op resources.

    Elke resource moet traceerbaar zijn naar een verantwoordelijke.
    """

    name = "bio-require-owner"
    display_name = "BIO 9.1.1 - Vereist Eigenaar Tag"
    description = "Resources moeten een 'owner' tag hebben voor traceerbaarheid"
    bio_control = "9.1.1"
    bio_category = "BIO-9"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=field("tags.owner").exists(False),
                then=Effect.DENY,
                message="Resources moeten een 'owner' tag hebben met de verantwoordelijke eigenaar",
            )
            .build()
        )


class DenyAnonymousAccessPolicy(BIOPolicy):
    """
    BIO 9.1.2 - Verbied anonieme/publieke toegang tot resources.

    Storage accounts, databases en andere resources mogen geen publieke
    toegang hebben zonder authenticatie.
    """

    name = "bio-deny-anonymous-access"
    display_name = "BIO 9.1.2 - Verbied Anonieme Toegang"
    description = "Verbied publieke/anonieme toegang tot resources"
    bio_control = "9.1.2"
    bio_category = "BIO-9"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=any_of(
                    # Storage accounts
                    all_of(
                        field("type").equals("ITL.Storage/storageAccounts"),
                        field("properties.allowBlobPublicAccess").equals(True),
                    ),
                    # Databases
                    all_of(
                        field("type").equals("ITL.Sql/databases"),
                        field("properties.publicNetworkAccess").equals("Enabled"),
                    ),
                    # Key Vaults
                    all_of(
                        field("type").equals("ITL.KeyVault/vaults"),
                        field("properties.publicNetworkAccess").equals("Enabled"),
                    ),
                ),
                then=Effect.DENY,
                message="Publieke/anonieme toegang is niet toegestaan volgens BIO 9.1.2",
            )
            .build()
        )


class RequireMFATagPolicy(BIOPolicy):
    """
    BIO 9.4.2 - Resources die MFA vereisen moeten getagd zijn.

    Voor audit doeleinden moeten resources aangeven of MFA verplicht is.
    """

    name = "bio-require-mfa-tag"
    display_name = "BIO 9.4.2 - Vereist MFA Indicator"
    description = "Resources moeten aangeven of MFA verplicht is voor toegang"
    bio_control = "9.4.2"
    bio_category = "BIO-9"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("tags.dataClassification").equals("vertrouwelijk"),
                        field("tags.dataClassification").equals("geheim"),
                    ),
                    field("tags.mfaRequired").exists(False),
                ),
                then=Effect.AUDIT,
                message="Resources met gevoelige data moeten een 'mfaRequired' tag hebben",
            )
            .build()
        )


# ============================================================================
# BIO-10: Cryptografie
# ============================================================================


class RequireEncryptionAtRestPolicy(BIOPolicy):
    """
    BIO 10.1.1 - Vereist versleuteling van data at rest.

    Storage, databases en andere data-opslag resources moeten
    versleuteling hebben ingeschakeld.
    """

    name = "bio-require-encryption-at-rest"
    display_name = "BIO 10.1.1 - Vereist Versleuteling at Rest"
    description = "Data-opslag resources moeten versleuteling hebben ingeschakeld"
    bio_control = "10.1.1"
    bio_category = "BIO-10"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=any_of(
                    # Storage without encryption
                    all_of(
                        field("type").equals("ITL.Storage/storageAccounts"),
                        field("properties.encryption.services.blob.enabled").not_equals(True),
                    ),
                    # SQL databases without TDE
                    all_of(
                        field("type").equals("ITL.Sql/databases"),
                        field("properties.transparentDataEncryption").not_equals("Enabled"),
                    ),
                    # Disks without encryption
                    all_of(
                        field("type").equals("ITL.Compute/disks"),
                        field("properties.encryption.type").exists(False),
                    ),
                ),
                then=Effect.DENY,
                message="Data-opslag resources moeten versleuteling hebben ingeschakeld volgens BIO 10.1.1",
            )
            .build()
        )


class RequireEncryptionInTransitPolicy(BIOPolicy):
    """
    BIO 10.1.2 - Vereist versleuteling van data in transit.

    Alle netwerkverkeer moet versleuteld zijn (HTTPS/TLS).
    """

    name = "bio-require-encryption-in-transit"
    display_name = "BIO 10.1.2 - Vereist Versleuteling in Transit"
    description = "Netwerk resources moeten TLS/HTTPS vereisen"
    bio_control = "10.1.2"
    bio_category = "BIO-10"

    @classmethod
    def build(
        cls,
        minimum_tls_version: str = "1.2",
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .parameter(
                "minimumTlsVersion",
                type="String",
                display_name="Minimum TLS Versie",
                description="Minimale TLS versie (1.2 of 1.3)",
                default=minimum_tls_version,
                allowed_values=["1.2", "1.3"],
            )
            .with_rule(
                if_=any_of(
                    # Storage accounts without HTTPS
                    all_of(
                        field("type").equals("ITL.Storage/storageAccounts"),
                        field("properties.supportsHttpsTrafficOnly").not_equals(True),
                    ),
                    # Storage accounts with old TLS
                    all_of(
                        field("type").equals("ITL.Storage/storageAccounts"),
                        field("properties.minimumTlsVersion").not_equals(f"TLS{minimum_tls_version}"),
                    ),
                    # App Services without HTTPS
                    all_of(
                        field("type").equals("ITL.Web/sites"),
                        field("properties.httpsOnly").not_equals(True),
                    ),
                ),
                then=Effect.DENY,
                message=f"Resources moeten HTTPS/TLS {minimum_tls_version}+ vereisen volgens BIO 10.1.2",
            )
            .build()
        )


class RequireCustomerManagedKeysPolicy(BIOPolicy):
    """
    BIO 10.1.3 - Vereist customer-managed keys voor gevoelige data.

    Voor 'vertrouwelijk' en 'geheim' geclassificeerde resources moeten
    customer-managed encryption keys worden gebruikt.
    """

    name = "bio-require-cmk"
    display_name = "BIO 10.1.3 - Vereist Customer-Managed Keys"
    description = "Gevoelige resources moeten customer-managed encryption keys gebruiken"
    bio_control = "10.1.3"
    bio_category = "BIO-10"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("tags.dataClassification").equals("vertrouwelijk"),
                        field("tags.dataClassification").equals("geheim"),
                    ),
                    any_of(
                        field("type").equals("ITL.Storage/storageAccounts"),
                        field("type").equals("ITL.Sql/databases"),
                        field("type").equals("ITL.Compute/disks"),
                    ),
                    field("properties.encryption.keySource").not_equals("ITL.Keyvault"),
                ),
                then=Effect.AUDIT,
                message="Gevoelige resources moeten customer-managed keys gebruiken voor versleuteling",
            )
            .build()
        )


# ============================================================================
# BIO-12: Beveiliging bedrijfsvoering
# ============================================================================


class RequireDiagnosticLogsPolicy(BIOPolicy):
    """
    BIO 12.4.1 - Vereist diagnostische logging op resources.

    Resources moeten logging hebben ingeschakeld voor audit trail.
    """

    name = "bio-require-diagnostic-logs"
    display_name = "BIO 12.4.1 - Vereist Diagnostische Logs"
    description = "Resources moeten diagnostische logging hebben ingeschakeld"
    bio_control = "12.4.1"
    bio_category = "BIO-12"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").like("ITL.Compute/*"),
                        field("type").like("ITL.Storage/*"),
                        field("type").like("ITL.Sql/*"),
                        field("type").like("ITL.Web/*"),
                        field("type").like("ITL.KeyVault/*"),
                    ),
                    field("properties.diagnosticSettings").exists(False),
                ),
                then=Effect.AUDIT,
                message="Resources moeten diagnostische logging hebben ingeschakeld volgens BIO 12.4.1",
            )
            .build()
        )


class RequireLogRetentionPolicy(BIOPolicy):
    """
    BIO 12.4.2 - Vereist minimale log retentie periode.

    Logs moeten minimaal 90 dagen bewaard worden voor overheidsorganisaties.
    """

    name = "bio-require-log-retention"
    display_name = "BIO 12.4.2 - Vereist Log Retentie"
    description = "Logs moeten minimaal 90 dagen bewaard worden"
    bio_control = "12.4.2"
    bio_category = "BIO-12"

    @classmethod
    def build(
        cls,
        minimum_retention_days: int = 90,
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .parameter(
                "minimumRetentionDays",
                type="Integer",
                display_name="Minimum Retentie (dagen)",
                description="Minimale log retentie periode in dagen",
                default=minimum_retention_days,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.Insights/diagnosticSettings"),
                    field("properties.logs[*].retentionPolicy.days").less_than(minimum_retention_days),
                ),
                then=Effect.DENY,
                message=f"Log retentie moet minimaal {minimum_retention_days} dagen zijn volgens BIO 12.4.2",
            )
            .build()
        )


class RequireBackupPolicy(BIOPolicy):
    """
    BIO 12.3.1 - Vereist backup configuratie voor kritieke resources.
    """

    name = "bio-require-backup"
    display_name = "BIO 12.3.1 - Vereist Backup Configuratie"
    description = "Kritieke resources moeten backup hebben geconfigureerd"
    bio_control = "12.3.1"
    bio_category = "BIO-12"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("ITL.Sql/databases"),
                        field("type").equals("ITL.Compute/virtualMachines"),
                        field("type").equals("ITL.Storage/storageAccounts"),
                    ),
                    any_of(
                        field("tags.criticality").equals("high"),
                        field("tags.criticality").equals("critical"),
                    ),
                    field("properties.backupPolicy").exists(False),
                ),
                then=Effect.AUDIT,
                message="Kritieke resources moeten backup hebben geconfigureerd volgens BIO 12.3.1",
            )
            .build()
        )


# ============================================================================
# BIO-13: Communicatiebeveiliging
# ============================================================================


class DenyPublicEndpointsPolicy(BIOPolicy):
    """
    BIO 13.1.1 - Verbied publieke endpoints voor gevoelige resources.
    """

    name = "bio-deny-public-endpoints"
    display_name = "BIO 13.1.1 - Verbied Publieke Endpoints"
    description = "Gevoelige resources mogen geen publieke endpoints hebben"
    bio_control = "13.1.1"
    bio_category = "BIO-13"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("tags.dataClassification").equals("vertrouwelijk"),
                        field("tags.dataClassification").equals("geheim"),
                    ),
                    any_of(
                        field("properties.publicNetworkAccess").equals("Enabled"),
                        field("properties.networkAcls.defaultAction").equals("Allow"),
                    ),
                ),
                then=Effect.DENY,
                message="Gevoelige resources mogen geen publieke endpoints hebben volgens BIO 13.1.1",
            )
            .build()
        )


class RequirePrivateEndpointsPolicy(BIOPolicy):
    """
    BIO 13.1.2 - Vereist private endpoints voor PaaS services.
    """

    name = "bio-require-private-endpoints"
    display_name = "BIO 13.1.2 - Vereist Private Endpoints"
    description = "PaaS services moeten private endpoints gebruiken"
    bio_control = "13.1.2"
    bio_category = "BIO-13"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("ITL.Storage/storageAccounts"),
                        field("type").equals("ITL.Sql/servers"),
                        field("type").equals("ITL.KeyVault/vaults"),
                    ),
                    field("properties.privateEndpointConnections").exists(False),
                ),
                then=Effect.AUDIT,
                message="PaaS services moeten private endpoints hebben voor veilige connectiviteit",
            )
            .build()
        )


class RequireNSGPolicy(BIOPolicy):
    """
    BIO 13.1.3 - Vereist Network Security Groups op virtuele netwerken.
    """

    name = "bio-require-nsg"
    display_name = "BIO 13.1.3 - Vereist Network Security Group"
    description = "Subnets moeten een Network Security Group hebben"
    bio_control = "13.1.3"
    bio_category = "BIO-13"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.Network/virtualNetworks/subnets"),
                    field("properties.networkSecurityGroup.id").exists(False),
                ),
                then=Effect.DENY,
                message="Subnets moeten een Network Security Group hebben volgens BIO 13.1.3",
            )
            .build()
        )


class DenyRDPFromInternetPolicy(BIOPolicy):
    """
    BIO 13.1.4 - Verbied RDP/SSH toegang vanaf internet.
    """

    name = "bio-deny-rdp-ssh-internet"
    display_name = "BIO 13.1.4 - Verbied RDP/SSH vanaf Internet"
    description = "RDP (3389) en SSH (22) mogen niet open staan naar internet"
    bio_control = "13.1.4"
    bio_category = "BIO-13"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "bio_control": cls.bio_control,
                "compliance_standard": "BIO",
            })
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.Network/networkSecurityGroups"),
                    any_of(
                        # RDP from any source
                        all_of(
                            field("properties.securityRules[*].destinationPortRange").contains("3389"),
                            field("properties.securityRules[*].sourceAddressPrefix").equals("*"),
                            field("properties.securityRules[*].access").equals("Allow"),
                        ),
                        # SSH from any source
                        all_of(
                            field("properties.securityRules[*].destinationPortRange").contains("22"),
                            field("properties.securityRules[*].sourceAddressPrefix").equals("*"),
                            field("properties.securityRules[*].access").equals("Allow"),
                        ),
                    ),
                ),
                then=Effect.DENY,
                message="RDP en SSH mogen niet open staan naar internet volgens BIO 13.1.4",
            )
            .build()
        )


# ============================================================================
# BIO Overig
# ============================================================================


class RequireEnvironmentTagPolicy(BIOPolicy):
    """
    BIO Algemeen - Vereist environment tag voor DTAP scheiding.
    """

    name = "bio-require-environment"
    display_name = "BIO - Vereist Environment Tag"
    description = "Resources moeten een 'environment' tag hebben (DTAP: dev/test/acceptatie/productie)"
    bio_control = "N/A"
    bio_category = "BIO-9"

    @classmethod
    def build(
        cls,
        allowed_environments: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_environments = allowed_environments or [
            "development",
            "test",
            "acceptance",
            "production",
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "compliance_standard": "BIO",
            })
            .parameter(
                "allowedEnvironments",
                type="Array",
                display_name="Toegestane Omgevingen",
                description="Lijst van geldige environment waarden",
                default=allowed_environments,
            )
            .with_rule(
                if_=any_of(
                    field("tags.environment").exists(False),
                    field("tags.environment").not_in(*allowed_environments),
                ),
                then=Effect.DENY,
                message="Resources moeten een geldige 'environment' tag hebben (DTAP)",
            )
            .build()
        )


class AllowedLocationsNLPolicy(BIOPolicy):
    """
    BIO Soevereiniteit - Beperk resources tot Nederlandse/EU locaties.

    Voor overheidsdata moet rekening gehouden worden met data soevereiniteit.
    """

    name = "bio-allowed-locations-nl"
    display_name = "BIO - Toegestane Locaties (NL/EU)"
    description = "Resources mogen alleen in Nederlandse of EU datacenters staan"
    bio_control = "N/A"
    bio_category = "BIO-8"

    @classmethod
    def build(
        cls,
        allowed_locations: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_locations = allowed_locations or [
            "westeurope",        # Nederland
            "northeurope",       # Ierland
            "germanywestcentral", # Duitsland
            "francecentral",     # Frankrijk
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.bio_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "compliance_standard": "BIO",
            })
            .parameter(
                "allowedLocations",
                type="Array",
                display_name="Toegestane Locaties",
                description="Lijst van toegestane Azure regio's",
                default=allowed_locations,
            )
            .with_rule(
                if_=field("location").not_in(*allowed_locations),
                then=Effect.DENY,
                message="Resources voor overheidsdata moeten in NL/EU datacenters staan",
            )
            .build()
        )


# ============================================================================
# Registry
# ============================================================================

_BIO_POLICIES: Dict[str, Type[BIOPolicy]] = {
    # BIO-8: Classificatie
    "bio-require-data-classification": RequireDataClassificationPolicy,
    "bio-audit-sensitive-data": AuditSensitiveDataPolicy,
    # BIO-9: Toegangsbeheer
    "bio-require-owner": RequireOwnerTagPolicy,
    "bio-deny-anonymous-access": DenyAnonymousAccessPolicy,
    "bio-require-mfa-tag": RequireMFATagPolicy,
    # BIO-10: Cryptografie
    "bio-require-encryption-at-rest": RequireEncryptionAtRestPolicy,
    "bio-require-encryption-in-transit": RequireEncryptionInTransitPolicy,
    "bio-require-cmk": RequireCustomerManagedKeysPolicy,
    # BIO-12: Bedrijfsvoering
    "bio-require-diagnostic-logs": RequireDiagnosticLogsPolicy,
    "bio-require-log-retention": RequireLogRetentionPolicy,
    "bio-require-backup": RequireBackupPolicy,
    # BIO-13: Communicatiebeveiliging
    "bio-deny-public-endpoints": DenyPublicEndpointsPolicy,
    "bio-require-private-endpoints": RequirePrivateEndpointsPolicy,
    "bio-require-nsg": RequireNSGPolicy,
    "bio-deny-rdp-ssh-internet": DenyRDPFromInternetPolicy,
    # Overig
    "bio-require-environment": RequireEnvironmentTagPolicy,
    "bio-allowed-locations-nl": AllowedLocationsNLPolicy,
}


def list_bio_policies() -> List[Tuple[str, str, str]]:
    """
    List all available BIO policies.

    Returns:
        List of (name, description, bio_control) tuples
    """
    return [
        (cls.name, cls.description, cls.bio_control)
        for cls in _BIO_POLICIES.values()
    ]


def get_bio_policy(name: str, **kwargs: Any) -> PolicyDefinition:
    """
    Get a BIO policy by name.

    Args:
        name: Policy name (e.g., "bio-require-encryption-at-rest")
        **kwargs: Policy-specific parameters

    Returns:
        PolicyDefinition: The built policy

    Raises:
        KeyError: If policy name is not found
    """
    if name not in _BIO_POLICIES:
        available = ", ".join(_BIO_POLICIES.keys())
        raise KeyError(f"Unknown BIO policy: {name}. Available: {available}")

    return _BIO_POLICIES[name].build(**kwargs)


def get_all_bio_policies(**default_kwargs: Any) -> List[PolicyDefinition]:
    """
    Get all BIO policies.

    Args:
        **default_kwargs: Default parameters passed to all policies

    Returns:
        List of all BIO PolicyDefinitions
    """
    return [cls.build(**default_kwargs) for cls in _BIO_POLICIES.values()]


def get_bio_policies_by_category(category: str, **kwargs: Any) -> List[PolicyDefinition]:
    """
    Get BIO policies filtered by category.

    Args:
        category: BIO category (e.g., "BIO-9", "BIO-10")
        **kwargs: Policy-specific parameters

    Returns:
        List of PolicyDefinitions in the specified category
    """
    return [
        cls.build(**kwargs)
        for cls in _BIO_POLICIES.values()
        if cls.bio_category == category
    ]


# ============================================================================
# BIO Initiative (Policy Set)
# ============================================================================


def get_bio_initiative(**kwargs: Any) -> PolicySetDefinition:
    """
    Get the complete BIO compliance initiative.

    This creates a PolicySet containing all BIO policies, organized
    by category for easy compliance reporting.

    Returns:
        PolicySetDefinition: Complete BIO initiative
    """
    builder = (
        PolicySetBuilder("bio-baseline-initiative")
        .display_name("BIO Baseline Informatiebeveiliging Overheid")
        .description(
            "Complete set van policies voor compliance met de Baseline "
            "Informatiebeveiliging Overheid (BIO). Bevat controls voor "
            "classificatie, toegangsbeheer, cryptografie, logging en "
            "netwerkbeveiliging."
        )
        .metadata({
            "compliance_standard": "BIO",
            "version": "1.0",
            "author": "ITL Platform Team",
            "reference": "https://www.digitaleoverheid.nl/overzicht-van-alle-onderwerpen/cybersecurity/bio-en-ensia/baseline-informatiebeveiliging-overheid/",
        })
    )

    # Add policy definition groups
    for category, category_name in BIO_CATEGORIES.items():
        builder.add_group(name=category_name, display_name=category_name)

    # Add all BIO policies grouped by category
    for category, category_name in BIO_CATEGORIES.items():
        policies = get_bio_policies_by_category(category, **kwargs)
        for policy in policies:
            builder.add_policy(
                policy_definition_id=f"/providers/ITL.Authorization/policyDefinitions/{policy.name}",
                groups=[category_name],
            )

    return builder.build()
