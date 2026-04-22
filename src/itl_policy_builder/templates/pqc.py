"""
PQC (Post-Quantum Cryptography) Policy Templates.

Dit module bevat policy templates voor de transitie naar quantum-veilige
cryptografie, gebaseerd op NIST PQC standaarden en AIVD/NCSC richtlijnen.

PQC Categorieën:
- PQC-ALG: Algorithm requirements (CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+)
- PQC-KEY: Key management en key sizes
- PQC-TLS: Transport Layer Security met PQC
- PQC-CERT: Certificate requirements
- PQC-AUDIT: Migration auditing en compliance

Referenties:
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- AIVD/NCSC: https://www.ncsc.nl/actueel/nieuws/2023/september/6/nieuwe-richtlijnen-kwantumveilige-cryptografie
"""

from typing import Any, Dict, List, Optional, Tuple, Type

from itl_policy_builder.builders.policy import PolicyBuilder
from itl_policy_builder.conditions import all_of, any_of, field, not_
from itl_policy_builder.enums import Effect, PolicyType
from itl_policy_builder.builders.initiative import PolicySetBuilder
from itl_policy_builder.models import PolicyDefinition, PolicySetDefinition


# ============================================================================
# PQC Categories
# ============================================================================

PQC_CATEGORIES = {
    "PQC-ALG": "Quantum-Safe Algorithms",
    "PQC-KEY": "Key Management",
    "PQC-TLS": "Transport Security",
    "PQC-CERT": "Certificates",
    "PQC-AUDIT": "Migration & Audit",
}

# NIST-approved PQC algorithms (as of 2024)
NIST_PQC_KEMs = [
    "ML-KEM-512",       # CRYSTALS-Kyber (FIPS 203) - Level 1
    "ML-KEM-768",       # CRYSTALS-Kyber (FIPS 203) - Level 3
    "ML-KEM-1024",      # CRYSTALS-Kyber (FIPS 203) - Level 5
]

NIST_PQC_SIGNATURES = [
    "ML-DSA-44",        # CRYSTALS-Dilithium (FIPS 204) - Level 2
    "ML-DSA-65",        # CRYSTALS-Dilithium (FIPS 204) - Level 3
    "ML-DSA-87",        # CRYSTALS-Dilithium (FIPS 204) - Level 5
    "SLH-DSA-SHA2-128f",  # SPHINCS+ (FIPS 205) - Level 1
    "SLH-DSA-SHA2-128s",  # SPHINCS+ (FIPS 205) - Level 1
    "SLH-DSA-SHA2-192f",  # SPHINCS+ (FIPS 205) - Level 3
    "SLH-DSA-SHA2-192s",  # SPHINCS+ (FIPS 205) - Level 3
    "SLH-DSA-SHA2-256f",  # SPHINCS+ (FIPS 205) - Level 5
    "SLH-DSA-SHA2-256s",  # SPHINCS+ (FIPS 205) - Level 5
]

# Hybrid algorithms (classical + PQC)
HYBRID_KEMs = [
    "X25519-ML-KEM-768",     # Hybrid: X25519 + Kyber-768
    "P256-ML-KEM-768",       # Hybrid: P-256 + Kyber-768
    "P384-ML-KEM-1024",      # Hybrid: P-384 + Kyber-1024
]

HYBRID_SIGNATURES = [
    "Ed25519-ML-DSA-65",     # Hybrid: Ed25519 + Dilithium-65
    "P256-ML-DSA-65",        # Hybrid: P-256 + Dilithium-65
    "P384-ML-DSA-87",        # Hybrid: P-384 + Dilithium-87
]

# Deprecated classical algorithms (quantum-vulnerable)
DEPRECATED_ALGORITHMS = [
    "RSA-2048",
    "RSA-3072",
    "RSA-4096",
    "ECDSA-P256",
    "ECDSA-P384",
    "ECDH-P256",
    "ECDH-P384",
    "Ed25519",              # Still secure short-term, but not PQC
    "X25519",               # Still secure short-term, but not PQC
]


# ============================================================================
# Base Class
# ============================================================================


class PQCPolicy:
    """
    Base class for PQC policy templates.

    Attributes:
        name: Unique policy identifier
        display_name: Human-readable name
        description: What the policy does
        pqc_category: PQC category code (e.g., "PQC-ALG")
        nist_reference: NIST FIPS reference if applicable
    """

    name: str = ""
    display_name: str = ""
    description: str = ""
    pqc_category: str = ""
    nist_reference: str = ""
    version: str = "1.0.0"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        """Build the policy with optional parameters."""
        raise NotImplementedError


# ============================================================================
# PQC-ALG: Quantum-Safe Algorithms
# ============================================================================


class RequirePQCKeyExchangePolicy(PQCPolicy):
    """
    PQC-ALG-001: Vereist quantum-safe key exchange algoritmes.

    Key encapsulation moet ML-KEM (Kyber) of een hybrid variant gebruiken.
    """

    name = "pqc-require-kem"
    display_name = "PQC - Vereist Quantum-Safe Key Exchange"
    description = "Key exchange moet ML-KEM (CRYSTALS-Kyber) of hybrid algoritme gebruiken"
    pqc_category = "PQC-ALG"
    nist_reference = "FIPS 203"

    @classmethod
    def build(
        cls,
        allowed_kems: Optional[List[str]] = None,
        allow_hybrid: bool = True,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_kems = allowed_kems or NIST_PQC_KEMs.copy()
        if allow_hybrid:
            allowed_kems.extend(HYBRID_KEMs)

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "nist_reference": cls.nist_reference,
                "compliance_standard": "PQC",
            })
            .parameter(
                "allowedKEMs",
                type="Array",
                display_name="Toegestane KEM Algoritmes",
                description="Lijst van toegestane key encapsulation mechanismen",
                default=allowed_kems,
            )
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("ITL.KeyVault/vaults"),
                        field("type").equals("ITL.Network/applicationGateways"),
                        field("type").equals("ITL.Web/sites"),
                    ),
                    field("properties.cryptoConfig.keyExchangeAlgorithm").not_in(*allowed_kems),
                ),
                then=Effect.DENY,
                message=f"Key exchange moet een quantum-safe algoritme gebruiken: {', '.join(NIST_PQC_KEMs[:3])}...",
            )
            .build()
        )


class RequirePQCSignaturePolicy(PQCPolicy):
    """
    PQC-ALG-002: Vereist quantum-safe signature algoritmes.

    Digitale handtekeningen moeten ML-DSA (Dilithium) of SLH-DSA (SPHINCS+) gebruiken.
    """

    name = "pqc-require-signature"
    display_name = "PQC - Vereist Quantum-Safe Signatures"
    description = "Digitale handtekeningen moeten ML-DSA of SLH-DSA gebruiken"
    pqc_category = "PQC-ALG"
    nist_reference = "FIPS 204, FIPS 205"

    @classmethod
    def build(
        cls,
        allowed_signatures: Optional[List[str]] = None,
        allow_hybrid: bool = True,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_signatures = allowed_signatures or NIST_PQC_SIGNATURES.copy()
        if allow_hybrid:
            allowed_signatures.extend(HYBRID_SIGNATURES)

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "nist_reference": cls.nist_reference,
                "compliance_standard": "PQC",
            })
            .parameter(
                "allowedSignatures",
                type="Array",
                display_name="Toegestane Signature Algoritmes",
                description="Lijst van toegestane digitale handtekening algoritmes",
                default=allowed_signatures,
            )
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("ITL.KeyVault/keys"),
                        field("type").equals("ITL.KeyVault/certificates"),
                    ),
                    field("properties.signatureAlgorithm").not_in(*allowed_signatures),
                ),
                then=Effect.DENY,
                message="Digitale handtekeningen moeten quantum-safe algoritmes gebruiken (ML-DSA of SLH-DSA)",
            )
            .build()
        )


class DenyDeprecatedAlgorithmsPolicy(PQCPolicy):
    """
    PQC-ALG-003: Verbied quantum-kwetsbare algoritmes.

    Blokkeert het gebruik van RSA, ECDSA, en andere klassieke algoritmes
    die kwetsbaar zijn voor quantum aanvallen.
    """

    name = "pqc-deny-deprecated"
    display_name = "PQC - Verbied Quantum-Kwetsbare Algoritmes"
    description = "Verbied RSA, ECDSA en andere quantum-kwetsbare algoritmes"
    pqc_category = "PQC-ALG"
    nist_reference = "N/A"

    @classmethod
    def build(
        cls,
        deprecated_algorithms: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        deprecated_algorithms = deprecated_algorithms or DEPRECATED_ALGORITHMS

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .parameter(
                "deprecatedAlgorithms",
                type="Array",
                display_name="Verboden Algoritmes",
                description="Lijst van quantum-kwetsbare algoritmes die verboden zijn",
                default=deprecated_algorithms,
            )
            .with_rule(
                if_=any_of(
                    field("properties.cryptoConfig.algorithm").in_(*deprecated_algorithms),
                    field("properties.keyProperties.algorithm").in_(*deprecated_algorithms),
                    field("properties.signatureAlgorithm").in_(*deprecated_algorithms),
                ),
                then=Effect.DENY,
                message="Quantum-kwetsbare algoritmes (RSA, ECDSA, etc.) zijn niet toegestaan",
            )
            .build()
        )


class RequireHybridModePolicy(PQCPolicy):
    """
    PQC-ALG-004: Vereist hybrid mode (transitieperiode).

    Tijdens de transitieperiode moeten systemen hybrid mode gebruiken
    (klassiek + PQC) voor backwards compatibility.
    """

    name = "pqc-require-hybrid"
    display_name = "PQC - Vereist Hybrid Mode"
    description = "Vereist hybrid cryptografie (klassiek + PQC) tijdens transitieperiode"
    pqc_category = "PQC-ALG"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        all_hybrid = HYBRID_KEMs + HYBRID_SIGNATURES

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
                "transition_policy": True,
            })
            .with_rule(
                if_=all_of(
                    field("tags.pqcTransitionPhase").equals("hybrid"),
                    any_of(
                        field("properties.cryptoConfig.algorithm").not_in(*all_hybrid),
                        field("properties.keyExchangeAlgorithm").not_in(*all_hybrid),
                    ),
                ),
                then=Effect.DENY,
                message="Resources in hybrid transitiefase moeten hybrid algoritmes gebruiken",
            )
            .build()
        )


# ============================================================================
# PQC-KEY: Key Management
# ============================================================================


class RequirePQCKeyVaultPolicy(PQCPolicy):
    """
    PQC-KEY-001: Vereist PQC-enabled Key Vault voor gevoelige sleutels.
    """

    name = "pqc-require-keyvault"
    display_name = "PQC - Vereist PQC-Enabled Key Vault"
    description = "Cryptografische sleutels moeten in een PQC-enabled Key Vault worden opgeslagen"
    pqc_category = "PQC-KEY"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.KeyVault/vaults"),
                    field("properties.enablePqcSupport").not_equals(True),
                ),
                then=Effect.AUDIT,
                message="Key Vaults moeten PQC ondersteuning hebben ingeschakeld",
            )
            .build()
        )


class RequirePQCKeyRotationPolicy(PQCPolicy):
    """
    PQC-KEY-002: Vereist frequente key rotation voor quantum readiness.

    Sleutels moeten regelmatig geroteerd worden om crypto-agility te bewerkstelligen.
    """

    name = "pqc-require-key-rotation"
    display_name = "PQC - Vereist Key Rotation"
    description = "Cryptografische sleutels moeten regelmatig geroteerd worden"
    pqc_category = "PQC-KEY"
    nist_reference = "N/A"

    @classmethod
    def build(
        cls,
        max_key_age_days: int = 90,
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .parameter(
                "maxKeyAgeDays",
                type="Integer",
                display_name="Maximum Sleutelleeftijd (dagen)",
                description="Maximale leeftijd van een cryptografische sleutel",
                default=max_key_age_days,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.KeyVault/keys"),
                    field("properties.rotationPolicy.lifetimeActions").exists(False),
                ),
                then=Effect.AUDIT,
                message=f"Keys moeten een rotation policy hebben (max {max_key_age_days} dagen)",
            )
            .build()
        )


class RequireMinimumSecurityLevelPolicy(PQCPolicy):
    """
    PQC-KEY-003: Vereist minimum NIST security level.

    Voor gevoelige data moet minimaal NIST Level 3 (128-bit quantum security) gebruikt worden.
    """

    name = "pqc-minimum-security-level"
    display_name = "PQC - Minimum Security Level"
    description = "Vereist minimaal NIST security level 3 voor gevoelige data"
    pqc_category = "PQC-KEY"
    nist_reference = "NIST PQC Security Levels"

    @classmethod
    def build(
        cls,
        minimum_level: int = 3,
        **kwargs: Any,
    ) -> PolicyDefinition:
        # Algorithms by security level
        level_3_plus = [
            "ML-KEM-768", "ML-KEM-1024",
            "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s",
            "X25519-ML-KEM-768", "P256-ML-KEM-768", "P384-ML-KEM-1024",
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "nist_reference": cls.nist_reference,
                "compliance_standard": "PQC",
            })
            .parameter(
                "minimumSecurityLevel",
                type="Integer",
                display_name="Minimum Security Level",
                description="Minimum NIST PQC security level (1-5)",
                default=minimum_level,
                allowed_values=[1, 2, 3, 4, 5],
            )
            .with_rule(
                if_=all_of(
                    any_of(
                        field("tags.dataClassification").equals("vertrouwelijk"),
                        field("tags.dataClassification").equals("geheim"),
                    ),
                    field("properties.cryptoConfig.algorithm").not_in(*level_3_plus),
                ),
                then=Effect.DENY,
                message=f"Gevoelige data vereist minimaal NIST security level {minimum_level}",
            )
            .build()
        )


# ============================================================================
# PQC-TLS: Transport Security
# ============================================================================


class RequirePQCTLSPolicy(PQCPolicy):
    """
    PQC-TLS-001: Vereist PQC-enabled TLS configuratie.
    """

    name = "pqc-require-tls"
    display_name = "PQC - Vereist Quantum-Safe TLS"
    description = "TLS configuratie moet quantum-safe key exchange ondersteunen"
    pqc_category = "PQC-TLS"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        pqc_cipher_suites = [
            "TLS_AES_256_GCM_SHA384_ML_KEM_768",
            "TLS_AES_128_GCM_SHA256_ML_KEM_768",
            "TLS_CHACHA20_POLY1305_SHA256_ML_KEM_768",
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .parameter(
                "pqcCipherSuites",
                type="Array",
                display_name="PQC Cipher Suites",
                description="Toegestane TLS cipher suites met PQC",
                default=pqc_cipher_suites,
            )
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("ITL.Network/applicationGateways"),
                        field("type").equals("ITL.Web/sites"),
                        field("type").equals("ITL.ApiManagement/service"),
                    ),
                    field("properties.sslPolicy.pqcEnabled").not_equals(True),
                ),
                then=Effect.AUDIT,
                message="TLS configuratie moet PQC cipher suites ondersteunen",
            )
            .build()
        )


class RequireTLS13WithPQCPolicy(PQCPolicy):
    """
    PQC-TLS-002: Vereist TLS 1.3 met PQC key exchange.

    TLS 1.3 is vereist voor hybrid PQC key exchange via KeyShare.
    """

    name = "pqc-require-tls13"
    display_name = "PQC - Vereist TLS 1.3"
    description = "TLS 1.3 is vereist voor PQC key exchange ondersteuning"
    pqc_category = "PQC-TLS"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").equals("ITL.Network/applicationGateways"),
                        field("type").equals("ITL.Web/sites"),
                        field("type").equals("ITL.Storage/storageAccounts"),
                    ),
                    field("properties.minimumTlsVersion").not_equals("1.3"),
                ),
                then=Effect.DENY,
                message="TLS 1.3 is vereist voor quantum-safe key exchange",
            )
            .build()
        )


# ============================================================================
# PQC-CERT: Certificates
# ============================================================================


class RequirePQCCertificatesPolicy(PQCPolicy):
    """
    PQC-CERT-001: Vereist quantum-safe certificaten.
    """

    name = "pqc-require-certificates"
    display_name = "PQC - Vereist Quantum-Safe Certificaten"
    description = "Certificaten moeten quantum-safe signature algoritmes gebruiken"
    pqc_category = "PQC-CERT"
    nist_reference = "FIPS 204, FIPS 205"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        pqc_cert_algorithms = NIST_PQC_SIGNATURES + HYBRID_SIGNATURES

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "nist_reference": cls.nist_reference,
                "compliance_standard": "PQC",
            })
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.KeyVault/certificates"),
                    field("properties.issuerParameters.signatureAlgorithm").not_in(*pqc_cert_algorithms),
                ),
                then=Effect.AUDIT,
                message="Certificaten moeten quantum-safe signature algoritmes gebruiken",
            )
            .build()
        )


class RequireShortCertValidityPolicy(PQCPolicy):
    """
    PQC-CERT-002: Vereist korte certificaat geldigheid.

    Tijdens de transitie naar PQC moeten certificaten een kortere
    geldigheid hebben om crypto-agility te faciliteren.
    """

    name = "pqc-short-cert-validity"
    display_name = "PQC - Korte Certificaat Geldigheid"
    description = "Certificaten moeten korte geldigheidsperiode hebben voor crypto-agility"
    pqc_category = "PQC-CERT"
    nist_reference = "N/A"

    @classmethod
    def build(
        cls,
        max_validity_months: int = 13,
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .parameter(
                "maxValidityMonths",
                type="Integer",
                display_name="Maximum Geldigheid (maanden)",
                description="Maximale geldigheidsperiode voor certificaten",
                default=max_validity_months,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.KeyVault/certificates"),
                    field("properties.validityInMonths").greater_than(max_validity_months),
                ),
                then=Effect.DENY,
                message=f"Certificaten mogen maximaal {max_validity_months} maanden geldig zijn",
            )
            .build()
        )


# ============================================================================
# PQC-AUDIT: Migration & Audit
# ============================================================================


class RequirePQCReadinessTagPolicy(PQCPolicy):
    """
    PQC-AUDIT-001: Vereist PQC readiness tag op resources.

    Resources moeten aangeven in welke fase van PQC transitie ze zitten.
    """

    name = "pqc-require-readiness-tag"
    display_name = "PQC - Vereist Readiness Tag"
    description = "Resources moeten een pqcReadiness tag hebben (planning/hybrid/native/compliant)"
    pqc_category = "PQC-AUDIT"
    nist_reference = "N/A"

    @classmethod
    def build(
        cls,
        allowed_phases: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_phases = allowed_phases or [
            "planning",     # Inventarisatie fase
            "hybrid",       # Hybrid mode (klassiek + PQC)
            "native",       # Pure PQC (geen legacy fallback)
            "compliant",    # Volledig PQC compliant
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .parameter(
                "allowedPhases",
                type="Array",
                display_name="Toegestane PQC Fases",
                description="Geldige waarden voor pqcReadiness tag",
                default=allowed_phases,
            )
            .with_rule(
                if_=any_of(
                    field("tags.pqcReadiness").exists(False),
                    field("tags.pqcReadiness").not_in(*allowed_phases),
                ),
                then=Effect.AUDIT,
                message="Resources moeten een geldige 'pqcReadiness' tag hebben",
            )
            .build()
        )


class AuditClassicalCryptoPolicy(PQCPolicy):
    """
    PQC-AUDIT-002: Audit resources die nog klassieke cryptografie gebruiken.
    """

    name = "pqc-audit-classical"
    display_name = "PQC - Audit Klassieke Cryptografie"
    description = "Audit resources die nog quantum-kwetsbare algoritmes gebruiken"
    pqc_category = "PQC-AUDIT"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .with_rule(
                if_=any_of(
                    field("properties.cryptoConfig.algorithm").in_(*DEPRECATED_ALGORITHMS),
                    field("properties.keyProperties.algorithm").in_(*DEPRECATED_ALGORITHMS),
                    field("properties.signatureAlgorithm").in_(*DEPRECATED_ALGORITHMS),
                ),
                then=Effect.AUDIT,
                message="Resource gebruikt klassieke cryptografie en moet gemigreerd worden naar PQC",
            )
            .build()
        )


class RequireCryptoInventoryTagPolicy(PQCPolicy):
    """
    PQC-AUDIT-003: Vereist crypto inventarisatie tags.

    Voor de PQC transitie moeten resources getagd zijn met hun cryptografische
    eigenschappen voor inventarisatie doeleinden.
    """

    name = "pqc-require-crypto-inventory"
    display_name = "PQC - Vereist Crypto Inventarisatie"
    description = "Resources moeten crypto inventarisatie tags hebben voor transitie planning"
    pqc_category = "PQC-AUDIT"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .with_rule(
                if_=all_of(
                    any_of(
                        field("type").like("ITL.KeyVault/*"),
                        field("type").like("ITL.Storage/*"),
                        field("type").like("ITL.Sql/*"),
                        field("type").like("ITL.Network/*"),
                    ),
                    any_of(
                        field("tags.cryptoUsesEncryption").exists(False),
                        field("tags.cryptoUsesSignatures").exists(False),
                        field("tags.cryptoUsesKeyExchange").exists(False),
                    ),
                ),
                then=Effect.AUDIT,
                message="Resources moeten crypto inventarisatie tags hebben (cryptoUsesEncryption, cryptoUsesSignatures, cryptoUsesKeyExchange)",
            )
            .build()
        )


class RequirePQCMigrationPlanPolicy(PQCPolicy):
    """
    PQC-AUDIT-004: Vereist migratie plan voor resources met klassieke crypto.
    """

    name = "pqc-require-migration-plan"
    display_name = "PQC - Vereist Migratie Plan"
    description = "Resources met klassieke crypto moeten een migratie plan hebben"
    pqc_category = "PQC-AUDIT"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
            })
            .with_rule(
                if_=all_of(
                    field("tags.pqcReadiness").equals("planning"),
                    field("tags.pqcMigrationDate").exists(False),
                ),
                then=Effect.AUDIT,
                message="Resources in planning fase moeten een 'pqcMigrationDate' tag hebben",
            )
            .build()
        )


class DenyNewClassicalCryptoPolicy(PQCPolicy):
    """
    PQC-AUDIT-005: Blokkeer nieuwe resources met klassieke cryptografie.

    Na de cutoff datum mogen geen nieuwe resources met quantum-kwetsbare
    cryptografie worden aangemaakt.
    """

    name = "pqc-deny-new-classical"
    display_name = "PQC - Blokkeer Nieuwe Klassieke Crypto"
    description = "Nieuwe resources mogen geen quantum-kwetsbare cryptografie gebruiken"
    pqc_category = "PQC-AUDIT"
    nist_reference = "N/A"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.pqc_category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .metadata({
                "pqc_category": cls.pqc_category,
                "compliance_standard": "PQC",
                "enforcement_date": "2027-01-01",
            })
            .with_rule(
                if_=all_of(
                    field("tags.pqcReadiness").exists(False),
                    any_of(
                        field("properties.cryptoConfig.algorithm").in_(*DEPRECATED_ALGORITHMS),
                        field("properties.keyProperties.algorithm").in_(*DEPRECATED_ALGORITHMS),
                    ),
                ),
                then=Effect.DENY,
                message="Nieuwe resources moeten quantum-safe cryptografie gebruiken",
            )
            .build()
        )


# ============================================================================
# Registry
# ============================================================================

_PQC_POLICIES: Dict[str, Type[PQCPolicy]] = {
    # PQC-ALG: Algorithms
    "pqc-require-kem": RequirePQCKeyExchangePolicy,
    "pqc-require-signature": RequirePQCSignaturePolicy,
    "pqc-deny-deprecated": DenyDeprecatedAlgorithmsPolicy,
    "pqc-require-hybrid": RequireHybridModePolicy,
    # PQC-KEY: Key Management
    "pqc-require-keyvault": RequirePQCKeyVaultPolicy,
    "pqc-require-key-rotation": RequirePQCKeyRotationPolicy,
    "pqc-minimum-security-level": RequireMinimumSecurityLevelPolicy,
    # PQC-TLS: Transport Security
    "pqc-require-tls": RequirePQCTLSPolicy,
    "pqc-require-tls13": RequireTLS13WithPQCPolicy,
    # PQC-CERT: Certificates
    "pqc-require-certificates": RequirePQCCertificatesPolicy,
    "pqc-short-cert-validity": RequireShortCertValidityPolicy,
    # PQC-AUDIT: Migration & Audit
    "pqc-require-readiness-tag": RequirePQCReadinessTagPolicy,
    "pqc-audit-classical": AuditClassicalCryptoPolicy,
    "pqc-require-crypto-inventory": RequireCryptoInventoryTagPolicy,
    "pqc-require-migration-plan": RequirePQCMigrationPlanPolicy,
    "pqc-deny-new-classical": DenyNewClassicalCryptoPolicy,
}


def list_pqc_policies() -> List[Tuple[str, str, str]]:
    """
    List all available PQC policies.

    Returns:
        List of (name, description, pqc_category) tuples
    """
    return [
        (cls.name, cls.description, cls.pqc_category)
        for cls in _PQC_POLICIES.values()
    ]


def get_pqc_policy(name: str, **kwargs: Any) -> PolicyDefinition:
    """
    Get a PQC policy by name.

    Args:
        name: Policy name (e.g., "pqc-require-kem")
        **kwargs: Policy-specific parameters

    Returns:
        PolicyDefinition: The built policy

    Raises:
        KeyError: If policy name is not found
    """
    if name not in _PQC_POLICIES:
        available = ", ".join(_PQC_POLICIES.keys())
        raise KeyError(f"Unknown PQC policy: {name}. Available: {available}")

    return _PQC_POLICIES[name].build(**kwargs)


def get_all_pqc_policies(**default_kwargs: Any) -> List[PolicyDefinition]:
    """
    Get all PQC policies.

    Args:
        **default_kwargs: Default parameters passed to all policies

    Returns:
        List of all PQC PolicyDefinitions
    """
    return [cls.build(**default_kwargs) for cls in _PQC_POLICIES.values()]


def get_pqc_policies_by_category(category: str, **kwargs: Any) -> List[PolicyDefinition]:
    """
    Get PQC policies filtered by category.

    Args:
        category: PQC category (e.g., "PQC-ALG", "PQC-TLS")
        **kwargs: Policy-specific parameters

    Returns:
        List of PolicyDefinitions in the specified category
    """
    return [
        cls.build(**kwargs)
        for cls in _PQC_POLICIES.values()
        if cls.pqc_category == category
    ]


# ============================================================================
# PQC Initiative (Policy Set)
# ============================================================================


def get_pqc_initiative(**kwargs: Any) -> PolicySetDefinition:
    """
    Get the complete PQC compliance initiative.

    This creates a PolicySet containing all PQC policies, organized
    by category for easy compliance reporting.

    Returns:
        PolicySetDefinition: Complete PQC initiative
    """
    builder = (
        PolicySetBuilder("pqc-quantum-safe-initiative")
        .display_name("Post-Quantum Cryptography Readiness")
        .description(
            "Complete set van policies voor de transitie naar quantum-veilige "
            "cryptografie. Bevat controls voor algoritmes, key management, "
            "TLS configuratie, certificaten en migratie audit."
        )
        .metadata({
            "compliance_standard": "PQC",
            "version": "1.0",
            "author": "ITL Platform Team",
            "nist_reference": "NIST FIPS 203, 204, 205",
            "reference": "https://csrc.nist.gov/projects/post-quantum-cryptography",
        })
    )

    # Add policy definition groups
    for category, category_name in PQC_CATEGORIES.items():
        builder.add_group(name=category_name, display_name=category_name)

    # Add all PQC policies grouped by category
    for category, category_name in PQC_CATEGORIES.items():
        policies = get_pqc_policies_by_category(category, **kwargs)
        for policy in policies:
            builder.add_policy(
                policy_definition_id=f"/providers/ITL.Authorization/policyDefinitions/{policy.name}",
                groups=[category_name],
            )

    return builder.build()


def get_pqc_transition_initiative(**kwargs: Any) -> PolicySetDefinition:
    """
    Get a minimal PQC initiative for the transition period.

    This creates a PolicySet with audit-only policies suitable for
    the initial discovery and planning phase.

    Returns:
        PolicySetDefinition: Transition-focused PQC initiative
    """
    transition_policies = [
        "pqc-require-readiness-tag",
        "pqc-audit-classical",
        "pqc-require-crypto-inventory",
        "pqc-require-migration-plan",
        "pqc-require-key-rotation",
    ]

    builder = (
        PolicySetBuilder("pqc-transition-initiative")
        .display_name("PQC Transition Assessment")
        .description(
            "Audit policies voor de inventarisatie en planning fase van de "
            "PQC transitie. Geen blokkerende policies, alleen audit en tagging."
        )
        .metadata({
            "compliance_standard": "PQC",
            "version": "1.0",
            "phase": "transition",
        })
    )

    for policy_name in transition_policies:
        policy = get_pqc_policy(policy_name, **kwargs)
        builder.add_policy(
            policy_definition_id=f"/providers/ITL.Authorization/policyDefinitions/{policy.name}",
        )

    return builder.build()
