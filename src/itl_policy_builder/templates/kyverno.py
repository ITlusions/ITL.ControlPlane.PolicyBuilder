"""
Built-in Kyverno policy templates for ITL ControlPlane.

Includes security, compliance, and PQC-specific policies for
Kubernetes clusters running Talos Linux.

Architecture
------------
This module follows the same pattern as the other template modules (bio, cis_azure, pqc):

  KyvernoPolicyTemplate (base class)
      â†“  subclasses per policy
  PodSecurityBaselinePolicy, DisallowPrivilegedPolicy, â€¦
      â†“  collected in a registry
  _KYVERNO_POLICIES: Dict[str, Type[KyvernoPolicyTemplate]]
      â†“  helper functions
  get_kyverno_policy(), list_kyverno_policies(), get_kyverno_policies_by_category()
      â†“  profiles (Kyverno equivalent of initiatives)
  KyvernoProfileBuilder â†’ KyvernoProfileDefinition
  get_security_profile(), get_talos_profile(), get_strict_profile(), â€¦
"""

from typing import Any, Dict, List, Type

from itl_policy_builder.export.kyverno import (
    KyvernoPolicyBuilder,
    KyvernoPodSecurityBuilder,
    KyvernoImageSecurityBuilder,
    KyvernoNetworkPolicyBuilder,
    KyvernoPQCBuilder,
    KyvernoProfileBuilder,
    KyvernoProfileDefinition,
    KyvernoMatch,
    ValidationAction,
    MatchKind,
)



# ============================================================================
# BASE CLASS
# ============================================================================

class KyvernoPolicyTemplate:
    """
    Base class for Kyverno policy templates.

    Mirrors the BIOPolicy / BuiltInPolicy base class pattern.
    Each subclass represents one ClusterPolicy and must define:

      name         â€” Kubernetes resource name (slug)
      display_name â€” Human-readable title
      description  â€” What this policy enforces
      category     â€” Grouping key (matches KYVERNO_CATEGORIES)
      version      â€” Semver string

    And implement:

      build(**kwargs) -> Dict[str, Any]
          Returns a complete Kyverno ClusterPolicy manifest dict.
    """

    name: str = ""
    display_name: str = ""
    description: str = ""
    category: str = ""
    version: str = "1.0.0"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        """Build and return the ClusterPolicy manifest dict."""
        raise NotImplementedError


# ============================================================================
# POD SECURITY POLICIES
# ============================================================================

class PodSecurityBaselinePolicy(KyvernoPolicyTemplate):
    """Pod Security Standards baseline â€” prevents privilege escalation."""

    name = "pod-security-baseline"
    display_name = "Pod Security Baseline"
    description = (
        "Enforce Kubernetes Pod Security Standards (baseline). "
        "Prevents unprivileged container escalation."
    )
    category = "security"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        return (
            KyvernoPodSecurityBuilder(cls.name)
            .with_display_name(cls.display_name)
            .with_description(cls.description)
            .require_security_context()
            .require_non_root()
            .build()
        )


class PodSecurityRestrictedPolicy(KyvernoPolicyTemplate):
    """Pod Security Standards restricted â€” strictest stance, read-only FS."""

    name = "pod-security-restricted"
    display_name = "Pod Security Restricted"
    description = (
        "Enforce Kubernetes Pod Security Standards (restricted). "
        "Follows Kubernetes security best practices."
    )
    category = "security"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        return (
            KyvernoPodSecurityBuilder(cls.name)
            .with_display_name(cls.display_name)
            .with_description(cls.description)
            .require_security_context()
            .require_non_root()
            .require_read_only_fs()
            .build()
        )


class RequireResourceLimitsPolicy(KyvernoPolicyTemplate):
    """Require CPU and memory resource limits on all containers."""

    name = "require-resource-limits"
    display_name = "Require Resource Limits"
    description = (
        "Ensure all containers specify resource requests and limits "
        "to prevent resource exhaustion."
    )
    category = "resources"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.ENFORCE)
        policy.add_validation_rule(
            rule_name="check-resource-limits",
            message="CPU and memory resources must be specified",
            pattern={
                "spec": {
                    "containers": [
                        {
                            "resources": {
                                "requests": {"cpu": "?", "memory": "?"},
                                "limits": {"cpu": "?", "memory": "?"},
                            }
                        }
                    ]
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return policy.build()


# ============================================================================
# IMAGE SECURITY POLICIES
# ============================================================================

class RequireApprovedRegistryPolicy(KyvernoPolicyTemplate):
    """Restrict container images to approved registries only."""

    name = "require-image-registry"
    display_name = "Require Approved Image Registries"
    description = (
        "Restrict container images to approved registries only. "
        "Prevents use of public/untrusted registries."
    )
    category = "image"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoImageSecurityBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.ENFORCE)
        policy.require_image_pull_policy()
        return policy.build()


class DisallowLatestTagPolicy(KyvernoPolicyTemplate):
    """Prevent deployment of images with the 'latest' tag."""

    name = "disallow-latest-tag"
    display_name = "Disallow Latest Image Tag"
    description = (
        "Prevent deployment of images with 'latest' tag. "
        "Requires explicit version for reproducibility."
    )
    category = "image"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.ENFORCE)
        policy.add_validation_rule(
            rule_name="check-image-tag",
            message="Image tag 'latest' is not allowed, use explicit version",
            pattern={"spec": {"containers": [{"image": "!*:latest"}]}},
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return policy.build()


# ============================================================================
# NETWORK POLICIES
# ============================================================================

class RequireNetworkPoliciesPolicy(KyvernoPolicyTemplate):
    """Enforce network isolation via Kubernetes NetworkPolicies."""

    name = "require-network-policies"
    display_name = "Require Network Policies"
    description = (
        "Enforce network isolation via Kubernetes NetworkPolicies. "
        "Default deny all, explicit allow required."
    )
    category = "network"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoNetworkPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.require_network_policy_label()
        return policy.build()


class DisallowPrivilegedPolicy(KyvernoPolicyTemplate):
    """Prevent deployment of privileged containers."""

    name = "disallow-privileged"
    display_name = "Disallow Privileged Containers"
    description = (
        "Prevent deployment of privileged containers. "
        "Major security vulnerability."
    )
    category = "security"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.ENFORCE)
        policy.add_validation_rule(
            rule_name="check-privileged",
            message="Privileged containers are not allowed",
            pattern={
                "spec": {
                    "containers": [
                        {"securityContext": {"privileged": False}}
                    ]
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return policy.build()


# ============================================================================
# STORAGE & VOLUME POLICIES
# ============================================================================

class RequirePVCPolicy(KyvernoPolicyTemplate):
    """Require persistent volumes for stateful applications."""

    name = "require-pvc"
    display_name = "Require PersistentVolumeClaims"
    description = (
        "Stateful Deployments must use PersistentVolumeClaims. "
        "Prevents data loss on pod termination."
    )
    category = "resources"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.AUDIT)
        policy.add_validation_rule(
            rule_name="check-pvc",
            message="StatefulSet should use PersistentVolumeClaims",
            pattern={"spec": {"volumeClaimTemplates": "?"}},
            match=KyvernoMatch(kind=MatchKind.STATEFULSET),
            action=ValidationAction.AUDIT,
        )
        return policy.build()


# ============================================================================
# PQC (POST-QUANTUM CRYPTOGRAPHY) POLICIES
# ============================================================================

class PQCCryptographyReadinessPolicy(KyvernoPolicyTemplate):
    """Label workloads as PQC-ready for the transition to quantum-safe cryptography."""

    name = "pqc-cryptography-readiness"
    display_name = "Post-Quantum Cryptography Readiness"
    description = (
        "Enforce PQC-compatible configurations. Label workloads "
        "as PQC-ready for the transition to quantum-safe cryptography."
    )
    category = "pqc"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        return (
            KyvernoPQCBuilder(cls.name)
            .with_display_name(cls.display_name)
            .with_description(cls.description)
            .require_pqc_label()
            .build()
        )


class PQCCertificateDurationPolicy(KyvernoPolicyTemplate):
    """Enforce shorter certificate durations (90 days) for PQC transition."""

    name = "pqc-certificate-duration"
    display_name = "PQC Certificate Duration Policy"
    description = (
        "Enforce shorter certificate lifetimes (90 days) for "
        "safer PQC migration. Reduces exposure window."
    )
    category = "pqc"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        return (
            KyvernoPQCBuilder(cls.name)
            .with_display_name(cls.display_name)
            .with_description(cls.description)
            .require_crypto_certduration()
            .build()
        )


# ============================================================================
# TALOS-SPECIFIC POLICIES
# ============================================================================

class TalosSecurityHardeningPolicy(KyvernoPolicyTemplate):
    """Enforce Talos-specific hardening â€” immutable OS + read-only FS."""

    name = "talos-security-hardening"
    display_name = "Talos Cluster Security Hardening"
    description = (
        "Enforce Talos-specific security hardening. "
        "Immutable OS + container restrictions."
    )
    category = "talos"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.ENFORCE)
        policy.add_validation_rule(
            rule_name="enforce-readonly-rootfs",
            message="Talos clusters require read-only root filesystem",
            pattern={
                "spec": {
                    "containers": [
                        {"securityContext": {"readOnlyRootFilesystem": True}}
                    ]
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return policy.build()


class RequireTalosLabelPolicy(KyvernoPolicyTemplate):
    """Require 'talos-cluster: true' label on all pods."""

    name = "require-talos-label"
    display_name = "Require Talos Cluster Label"
    description = (
        "Label all pods with 'talos-cluster: true' for identification "
        "and management of workloads on Talos infrastructure."
    )
    category = "talos"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.AUDIT)
        policy.add_validation_rule(
            rule_name="check-talos-label",
            message="Pod should have 'talos-cluster: true' label",
            pattern={"metadata": {"labels": {"talos-cluster": "true"}}},
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.AUDIT,
        )
        return policy.build()


# ============================================================================
# GOVERNANCE & COMPLIANCE POLICIES
# ============================================================================

class RequireStandardLabelsPolicy(KyvernoPolicyTemplate):
    """Require app, team, and environment labels on all resources."""

    name = "require-standard-labels"
    display_name = "Require Standard Resource Labels"
    description = (
        "All resources must have standard labels: "
        "app, team, environment, cost-center"
    )
    category = "governance"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.ENFORCE)
        policy.add_validation_rule(
            rule_name="check-labels",
            message="Standard labels (app, team, environment) are required",
            pattern={
                "metadata": {
                    "labels": {"app": "?", "team": "?", "environment": "?"}
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return policy.build()


class RequirePodDisruptionBudgetPolicy(KyvernoPolicyTemplate):
    """Require PodDisruptionBudget for high-availability applications."""

    name = "require-pdb"
    display_name = "Require PodDisruptionBudget"
    description = (
        "High-availability applications must define PodDisruptionBudget "
        "to survive node disruptions."
    )
    category = "governance"

    @classmethod
    def build(cls, **kwargs: Any) -> Dict[str, Any]:
        policy = KyvernoPolicyBuilder(cls.name)
        policy.with_display_name(cls.display_name)
        policy.with_description(cls.description)
        policy.with_validation_action(ValidationAction.AUDIT)
        policy.add_validation_rule(
            rule_name="check-pdb",
            message="Application should have a PodDisruptionBudget defined",
            pattern={"metadata": {"labels": {"high-availability": "true"}}},
            match=KyvernoMatch(kind=MatchKind.DEPLOYMENT),
            action=ValidationAction.AUDIT,
        )
        return policy.build()


# ============================================================================
# POLICY REGISTRY
# ============================================================================

_KYVERNO_POLICIES: Dict[str, Type[KyvernoPolicyTemplate]] = {
    # Pod Security
    "pod-security-baseline":      PodSecurityBaselinePolicy,
    "pod-security-restricted":    PodSecurityRestrictedPolicy,
    "require-resource-limits":    RequireResourceLimitsPolicy,
    # Image Security
    "require-image-registry":     RequireApprovedRegistryPolicy,
    "disallow-latest-tag":        DisallowLatestTagPolicy,
    # Network & Access
    "require-network-policies":   RequireNetworkPoliciesPolicy,
    "disallow-privileged":        DisallowPrivilegedPolicy,
    # Storage
    "require-pvc":                RequirePVCPolicy,
    # PQC
    "pqc-cryptography-readiness": PQCCryptographyReadinessPolicy,
    "pqc-certificate-duration":   PQCCertificateDurationPolicy,
    # Talos-specific
    "talos-security-hardening":   TalosSecurityHardeningPolicy,
    "require-talos-label":        RequireTalosLabelPolicy,
    # Governance
    "require-standard-labels":    RequireStandardLabelsPolicy,
    "require-pdb":                RequirePodDisruptionBudgetPolicy,
}

KYVERNO_CATEGORIES: Dict[str, List[str]] = {
    "security":   ["pod-security-baseline", "pod-security-restricted", "disallow-privileged"],
    "image":      ["require-image-registry", "disallow-latest-tag"],
    "network":    ["require-network-policies"],
    "resources":  ["require-resource-limits", "require-pvc"],
    "pqc":        ["pqc-cryptography-readiness", "pqc-certificate-duration"],
    "talos":      ["talos-security-hardening", "require-talos-label"],
    "governance": ["require-standard-labels", "require-pdb"],
}


# ============================================================================
# HELPER FUNCTIONS  (same public API as bio / cis_azure / pqc)
# ============================================================================

def get_kyverno_policy(policy_name: str, **kwargs: Any) -> Dict[str, Any]:
    """Get a built ClusterPolicy manifest by name.

    Args:
        policy_name: Key in ``_KYVERNO_POLICIES``.
        **kwargs: Passed to the policy class ``build()`` method.

    Raises:
        ValueError: If the policy name is not recognised.
    """
    if policy_name not in _KYVERNO_POLICIES:
        raise ValueError(
            f"Unknown Kyverno policy: {policy_name!r}. "
            f"Available: {list(_KYVERNO_POLICIES.keys())}"
        )
    return _KYVERNO_POLICIES[policy_name].build(**kwargs)


def list_kyverno_policies() -> List[str]:
    """Return the list of all registered policy names."""
    return list(_KYVERNO_POLICIES.keys())


def get_all_kyverno_policies(**kwargs: Any) -> List[Dict[str, Any]]:
    """Build and return all registered policies."""
    return [cls.build(**kwargs) for cls in _KYVERNO_POLICIES.values()]


def get_kyverno_policies_by_category(category: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """Build and return all policies in a given category.

    Args:
        category: One of the keys in ``KYVERNO_CATEGORIES``.
        **kwargs: Passed to each policy class ``build()`` method.
    """
    if category not in KYVERNO_CATEGORIES:
        return []
    return [
        _KYVERNO_POLICIES[name].build(**kwargs)
        for name in KYVERNO_CATEGORIES[category]
        if name in _KYVERNO_POLICIES
    ]


# ============================================================================
# PROFILES  (Kyverno equivalent of Initiatives / Policy Sets)
# ============================================================================
# A profile is a named, curated bundle of policies representing a complete
# deployment stance.  Use KyvernoProfileBuilder (analogous to PolicySetBuilder)
# to compose profiles, and KyvernoProfileDefinition as the result type
# (analogous to PolicySetDefinition).
#
# Each get_*_profile() function is the Kyverno equivalent of get_bio_initiative().

KYVERNO_PROFILE_CATEGORIES: Dict[str, str] = {
    "security":   "Core Security Policies",
    "network":    "Network Isolation",
    "registry":   "Image Registry Controls",
    "talos":      "Talos-Specific Hardening",
    "pqc":        "Post-Quantum Cryptography",
    "governance": "Governance & Compliance",
}


def get_security_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """Core security profile â€” the recommended baseline for any cluster."""
    return (
        KyvernoProfileBuilder("itl-security-profile")
        .display_name("ITL Security Profile")
        .description(
            "Core security policies for ITL ControlPlane clusters. "
            "Covers pod security, privilege escalation, image hygiene, "
            "and resource limits."
        )
        .category("Security")
        .metadata(version="1.0.0", author="ITL Platform Team")
        .add_group("pod-security",   "Pod Security Policies")
        .add_group("image-security", "Image Security Policies")
        .add_policy(PodSecurityBaselinePolicy,   group="pod-security",   **kwargs)
        .add_policy(DisallowPrivilegedPolicy,    group="pod-security",   **kwargs)
        .add_policy(DisallowLatestTagPolicy,     group="image-security", **kwargs)
        .add_policy(RequireResourceLimitsPolicy, group="pod-security",   **kwargs)
        .build()
    )


def get_network_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """Network isolation profile â€” requires NetworkPolicy per namespace."""
    return (
        KyvernoProfileBuilder("itl-network-profile")
        .display_name("ITL Network Isolation Profile")
        .description(
            "Network isolation policies for ITL ControlPlane clusters. "
            "Enforces NetworkPolicy-based micro-segmentation."
        )
        .category("Network")
        .metadata(version="1.0.0", author="ITL Platform Team")
        .add_group("network-isolation", "Network Isolation Policies")
        .add_policy(RequireNetworkPoliciesPolicy, group="network-isolation", **kwargs)
        .build()
    )


def get_registry_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """Registry controls profile â€” approved registries only."""
    return (
        KyvernoProfileBuilder("itl-registry-profile")
        .display_name("ITL Registry Controls Profile")
        .description(
            "Image registry restriction policies. "
            "Prevents use of public or untrusted container registries."
        )
        .category("Registry")
        .metadata(version="1.0.0", author="ITL Platform Team")
        .add_group("registry-controls", "Registry Control Policies")
        .add_policy(RequireApprovedRegistryPolicy, group="registry-controls", **kwargs)
        .build()
    )


def get_strict_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """Strict profile â€” restricted pod security + network + registry enforcement."""
    return (
        KyvernoProfileBuilder("itl-strict-profile")
        .display_name("ITL Strict Security Profile")
        .description(
            "Strict security stance for ITL ControlPlane clusters. "
            "Restricted pod security (read-only FS), network isolation, "
            "registry controls, and resource limits."
        )
        .category("Security")
        .metadata(version="1.0.0", author="ITL Platform Team")
        .add_group("pod-security",      "Pod Security Policies")
        .add_group("image-security",    "Image Security Policies")
        .add_group("network-isolation", "Network Isolation Policies")
        .add_group("registry-controls", "Registry Control Policies")
        .add_policy(PodSecurityRestrictedPolicy,   group="pod-security",      **kwargs)
        .add_policy(DisallowPrivilegedPolicy,      group="pod-security",      **kwargs)
        .add_policy(DisallowLatestTagPolicy,       group="image-security",    **kwargs)
        .add_policy(RequireResourceLimitsPolicy,   group="pod-security",      **kwargs)
        .add_policy(RequireNetworkPoliciesPolicy,  group="network-isolation", **kwargs)
        .add_policy(RequireApprovedRegistryPolicy, group="registry-controls", **kwargs)
        .build()
    )


def get_talos_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """Talos-optimised profile â€” core security + Talos-specific hardening."""
    return (
        KyvernoProfileBuilder("itl-talos-profile")
        .display_name("ITL Talos Security Profile")
        .description(
            "Talos-optimised security policies for ITL ControlPlane clusters. "
            "Combines core security with Talos-specific hardening (immutable OS, "
            "read-only root FS, cluster identification labels)."
        )
        .category("Talos")
        .metadata(
            version="1.0.0",
            author="ITL Platform Team",
            reference="https://github.com/ITlusions/ITL.Talos.HardenedOS",
        )
        .add_group("pod-security",   "Pod Security Policies")
        .add_group("image-security", "Image Security Policies")
        .add_group("talos",          "Talos-Specific Policies")
        .add_policy(PodSecurityBaselinePolicy,    group="pod-security",   **kwargs)
        .add_policy(DisallowPrivilegedPolicy,     group="pod-security",   **kwargs)
        .add_policy(DisallowLatestTagPolicy,      group="image-security", **kwargs)
        .add_policy(RequireResourceLimitsPolicy,  group="pod-security",   **kwargs)
        .add_policy(TalosSecurityHardeningPolicy, group="talos",          **kwargs)
        .add_policy(RequireTalosLabelPolicy,      group="talos",          **kwargs)
        .build()
    )


def get_pqc_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """PQC transition profile â€” Post-Quantum Cryptography readiness."""
    return (
        KyvernoProfileBuilder("itl-pqc-profile")
        .display_name("ITL Post-Quantum Cryptography Profile")
        .description(
            "Post-Quantum Cryptography readiness policies. "
            "Prepares clusters for the transition to quantum-safe cryptography."
        )
        .category("PQC")
        .metadata(version="1.0.0", author="ITL Platform Team")
        .add_group("pqc", "Post-Quantum Cryptography Policies")
        .add_policy(PQCCryptographyReadinessPolicy, group="pqc", **kwargs)
        .add_policy(PQCCertificateDurationPolicy,   group="pqc", **kwargs)
        .add_policy(RequireTalosLabelPolicy,        group="pqc", **kwargs)
        .build()
    )


def get_all_profile(**kwargs: Any) -> KyvernoProfileDefinition:
    """All available policies combined (deduped, insertion-ordered)."""
    seen: set = set()
    builder = (
        KyvernoProfileBuilder("itl-all-profile")
        .display_name("ITL All Policies Profile")
        .description("All available Kyverno policies combined.")
        .category("All")
        .metadata(version="1.0.0", author="ITL Platform Team")
    )
    for profile_fn in (
        get_security_profile,
        get_network_profile,
        get_registry_profile,
        get_strict_profile,
        get_talos_profile,
        get_pqc_profile,
    ):
        for entry in profile_fn(**kwargs).policies:
            pol_name = entry.get("metadata", {}).get("name", "")
            if pol_name not in seen:
                seen.add(pol_name)
                if pol_name in _KYVERNO_POLICIES:
                    builder.add_policy(_KYVERNO_POLICIES[pol_name], **kwargs)
    return builder.build()


# Profile registry â€” maps profile name to its builder function
_KYVERNO_PROFILE_BUILDERS: Dict[str, Any] = {
    "security": get_security_profile,
    "network":  get_network_profile,
    "registry": get_registry_profile,
    "strict":   get_strict_profile,
    "talos":    get_talos_profile,
    "pqc":      get_pqc_profile,
    "all":      get_all_profile,
}


def get_profile(profile_name: str, **kwargs: Any) -> KyvernoProfileDefinition:
    """Build and return a named profile (KyvernoProfileDefinition).

    Args:
        profile_name: One of the keys in ``_KYVERNO_PROFILE_BUILDERS``.
        **kwargs: Passed to the profile builder function.

    Raises:
        ValueError: If the profile name is not recognised.
    """
    if profile_name not in _KYVERNO_PROFILE_BUILDERS:
        raise ValueError(
            f"Unknown profile: {profile_name!r}. "
            f"Available: {list(_KYVERNO_PROFILE_BUILDERS.keys())}"
        )
    return _KYVERNO_PROFILE_BUILDERS[profile_name](**kwargs)


def list_profiles() -> List[str]:
    """Return the list of available profile names."""
    return list(_KYVERNO_PROFILE_BUILDERS.keys())


# ============================================================================
# CONVENIENCE: flat policy list from a profile  (backward-compatible shim)
# ============================================================================

def get_profile_policies(profile_name: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """Return the flat list of ClusterPolicy dicts for a named profile.

    Convenience wrapper around ``get_profile()`` that returns only the
    manifest list â€” preserving the previous API.
    """
    return get_profile(profile_name, **kwargs).policies


def get_talos_security_bundle(**kwargs: Any) -> List[Dict[str, Any]]:
    """All security policies recommended for Talos clusters."""
    return get_talos_profile(**kwargs).policies


def get_pqc_transition_bundle(**kwargs: Any) -> List[Dict[str, Any]]:
    """All policies needed for PQC transition."""
    return get_pqc_profile(**kwargs).policies


# ============================================================================
# BACKWARD-COMPAT: standalone function shims
# ============================================================================
# Thin wrappers so existing code calling get_pod_security_baseline() etc.
# keeps working without changes.

def get_pod_security_baseline(**kwargs: Any) -> Dict[str, Any]:
    return PodSecurityBaselinePolicy.build(**kwargs)

def get_pod_security_restricted(**kwargs: Any) -> Dict[str, Any]:
    return PodSecurityRestrictedPolicy.build(**kwargs)

def get_require_resource_limits(**kwargs: Any) -> Dict[str, Any]:
    return RequireResourceLimitsPolicy.build(**kwargs)

def get_require_image_registry(**kwargs: Any) -> Dict[str, Any]:
    return RequireApprovedRegistryPolicy.build(**kwargs)

def get_require_image_tag(**kwargs: Any) -> Dict[str, Any]:
    return DisallowLatestTagPolicy.build(**kwargs)

def get_require_network_policies(**kwargs: Any) -> Dict[str, Any]:
    return RequireNetworkPoliciesPolicy.build(**kwargs)

def get_disallow_privileged_containers(**kwargs: Any) -> Dict[str, Any]:
    return DisallowPrivilegedPolicy.build(**kwargs)

def get_require_persistent_volume_claim(**kwargs: Any) -> Dict[str, Any]:
    return RequirePVCPolicy.build(**kwargs)

def get_pqc_cryptography_readiness(**kwargs: Any) -> Dict[str, Any]:
    return PQCCryptographyReadinessPolicy.build(**kwargs)

def get_pqc_certificate_duration(**kwargs: Any) -> Dict[str, Any]:
    return PQCCertificateDurationPolicy.build(**kwargs)

def get_talos_cluster_security(**kwargs: Any) -> Dict[str, Any]:
    return TalosSecurityHardeningPolicy.build(**kwargs)

def get_require_talos_label(**kwargs: Any) -> Dict[str, Any]:
    return RequireTalosLabelPolicy.build(**kwargs)

def get_require_resource_labels(**kwargs: Any) -> Dict[str, Any]:
    return RequireStandardLabelsPolicy.build(**kwargs)

def get_require_pod_disruption_budget(**kwargs: Any) -> Dict[str, Any]:
    return RequirePodDisruptionBudgetPolicy.build(**kwargs)


# Legacy alias â€” KYVERNO_POLICY_TEMPLATES was the old function-based registry
KYVERNO_POLICY_TEMPLATES: Dict[str, Any] = {
    name: cls.build for name, cls in _KYVERNO_POLICIES.items()
}


if __name__ == "__main__":
    import yaml

    print("=" * 80)
    print("Talos Security Profile")
    print("=" * 80)
    profile = get_talos_profile()
    print(f"Profile  : {profile.display_name}")
    print(f"Policies : {len(profile)}")
    print()
    for policy in profile.to_manifests():
        print(yaml.dump(policy, default_flow_style=False, sort_keys=False))
        print("---")

