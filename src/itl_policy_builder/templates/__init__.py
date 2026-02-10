"""
Built-in policy templates for common governance scenarios.

Includes:
- General cloud governance policies
- BIO (Baseline Informatiebeveiliging Overheid) compliance policies
- PQC (Post-Quantum Cryptography) readiness policies
"""

from itl_policy_builder.templates.general import (
    get_builtin_policy,
    list_builtin_policies,
    get_all_builtin_policies,
    AllowedLocationsPolicy,
    RequireTagPolicy,
    AuditMissingTagPolicy,
    AllowedResourceTypesPolicy,
    DenyPublicIPPolicy,
    RequireNetworkSecurityGroupPolicy,
)

from itl_policy_builder.templates.bio import (
    get_bio_policy,
    list_bio_policies,
    get_all_bio_policies,
    get_bio_policies_by_category,
    get_bio_initiative,
    BIO_CATEGORIES,
    # BIO Policy Classes
    RequireDataClassificationPolicy,
    RequireOwnerTagPolicy,
    DenyAnonymousAccessPolicy,
    RequireEncryptionAtRestPolicy,
    RequireEncryptionInTransitPolicy,
    RequireDiagnosticLogsPolicy,
    DenyPublicEndpointsPolicy,
    RequireNSGPolicy as BIORequireNSGPolicy,
    DenyRDPFromInternetPolicy,
    AllowedLocationsNLPolicy,
)

from itl_policy_builder.templates.pqc import (
    get_pqc_policy,
    list_pqc_policies,
    get_all_pqc_policies,
    get_pqc_policies_by_category,
    get_pqc_initiative,
    get_pqc_transition_initiative,
    PQC_CATEGORIES,
    NIST_PQC_KEMs,
    NIST_PQC_SIGNATURES,
    HYBRID_KEMs,
    HYBRID_SIGNATURES,
    DEPRECATED_ALGORITHMS,
    # PQC Policy Classes
    RequirePQCKeyExchangePolicy,
    RequirePQCSignaturePolicy,
    DenyDeprecatedAlgorithmsPolicy,
    RequireHybridModePolicy,
    RequirePQCKeyVaultPolicy,
    RequirePQCTLSPolicy,
    RequirePQCCertificatesPolicy,
    RequirePQCReadinessTagPolicy,
    AuditClassicalCryptoPolicy,
)

__all__ = [
    # General
    "get_builtin_policy",
    "list_builtin_policies",
    "get_all_builtin_policies",
    "AllowedLocationsPolicy",
    "RequireTagPolicy",
    "AuditMissingTagPolicy",
    "AllowedResourceTypesPolicy",
    "DenyPublicIPPolicy",
    "RequireNetworkSecurityGroupPolicy",
    # BIO
    "get_bio_policy",
    "list_bio_policies",
    "get_all_bio_policies",
    "get_bio_policies_by_category",
    "get_bio_initiative",
    "BIO_CATEGORIES",
    # BIO Policy Classes
    "RequireDataClassificationPolicy",
    "RequireOwnerTagPolicy",
    "DenyAnonymousAccessPolicy",
    "RequireEncryptionAtRestPolicy",
    "RequireEncryptionInTransitPolicy",
    "RequireDiagnosticLogsPolicy",
    "DenyPublicEndpointsPolicy",
    "BIORequireNSGPolicy",
    "DenyRDPFromInternetPolicy",
    "AllowedLocationsNLPolicy",
    # PQC
    "get_pqc_policy",
    "list_pqc_policies",
    "get_all_pqc_policies",
    "get_pqc_policies_by_category",
    "get_pqc_initiative",
    "get_pqc_transition_initiative",
    "PQC_CATEGORIES",
    "NIST_PQC_KEMs",
    "NIST_PQC_SIGNATURES",
    "HYBRID_KEMs",
    "HYBRID_SIGNATURES",
    "DEPRECATED_ALGORITHMS",
    # PQC Policy Classes
    "RequirePQCKeyExchangePolicy",
    "RequirePQCSignaturePolicy",
    "DenyDeprecatedAlgorithmsPolicy",
    "RequireHybridModePolicy",
    "RequirePQCKeyVaultPolicy",
    "RequirePQCTLSPolicy",
    "RequirePQCCertificatesPolicy",
    "RequirePQCReadinessTagPolicy",
    "AuditClassicalCryptoPolicy",
]
