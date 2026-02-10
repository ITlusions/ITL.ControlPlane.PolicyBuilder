"""
Built-in Kyverno policy templates for ITL ControlPlane.

Includes security, compliance, and PQC-specific policies for
Kubernetes clusters running Talos Linux.
"""

import json
from typing import Dict, Any, List

from itl_policy_builder.kyverno import (
    KyvernoPolicyBuilder,
    KyvernoPodSecurityBuilder,
    KyvernoImageSecurityBuilder,
    KyvernoNetworkPolicyBuilder,
    KyvernoPQCBuilder,
    KyvernoMatch,
    ValidationAction,
    MatchKind,
)


# ============================================================================
# POD SECURITY POLICIES
# ============================================================================

def get_pod_security_baseline() -> Dict[str, Any]:
    """Pod Security Standards baseline policy."""
    return (
        KyvernoPodSecurityBuilder("pod-security-baseline")
        .with_display_name("Pod Security Baseline")
        .with_description(
            "Enforce Kubernetes Pod Security Standards (baseline). "
            "Prevents unprivileged container escalation."
        )
        .require_security_context()
        .require_non_root()
        .build()
    )


def get_pod_security_restricted() -> Dict[str, Any]:
    """Pod Security Standards restricted policy (strictest)."""
    return (
        KyvernoPodSecurityBuilder("pod-security-restricted")
        .with_display_name("Pod Security Restricted")
        .with_description(
            "Enforce Kubernetes Pod Security Standards (restricted). "
            "Follows Kubernetes security best practices."
        )
        .require_security_context()
        .require_non_root()
        .require_read_only_fs()
        .build()
    )


def get_require_resource_limits() -> Dict[str, Any]:
    """Require CPU and memory resource limits."""
    policy = KyvernoPolicyBuilder("require-resource-limits")
    policy.with_display_name("Require Resource Limits")
    policy.with_description(
        "Ensure all containers specify resource requests and limits "
        "to prevent resource exhaustion."
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    policy.add_validation_rule(
        rule_name="check-resource-limits",
        message="CPU and memory resources must be specified",
        pattern={
            "spec": {
                "containers": [
                    {
                        "resources": {
                            "requests": {
                                "cpu": "?",
                                "memory": "?"
                            },
                            "limits": {
                                "cpu": "?",
                                "memory": "?"
                            }
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

def get_require_image_registry() -> Dict[str, Any]:
    """Require container images from approved registries."""
    policy = KyvernoImageSecurityBuilder("require-approved-registry")
    policy.with_display_name("Require Approved Image Registries")
    policy.with_description(
        "Restrict container images to approved registries only. "
        "Prevents use of public/untrusted registries."
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    policy.require_image_pull_policy()
    return policy.build()


def get_require_image_tag() -> Dict[str, Any]:
    """Require explicit image tags (no latest)."""
    policy = KyvernoPolicyBuilder("disallow-latest-tag")
    policy.with_display_name("Disallow Latest Image Tag")
    policy.with_description(
        "Prevent deployment of images with 'latest' tag. "
        "Requires explicit version for reproducibility."
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    policy.add_validation_rule(
        rule_name="check-image-tag",
        message="Image tag 'latest' is not allowed, use explicit version",
        pattern={
            "spec": {
                "containers": [
                    {
                        "image": "!*:latest"
                    }
                ]
            }
        },
        match=KyvernoMatch(kind=MatchKind.POD),
        action=ValidationAction.ENFORCE,
    )
    return policy.build()


# ============================================================================
# NETWORK POLICIES
# ============================================================================

def get_require_network_policies() -> Dict[str, Any]:
    """Require NetworkPolicy for pod isolation."""
    policy = KyvernoNetworkPolicyBuilder("require-network-policies")
    policy.with_display_name("Require Network Policies")
    policy.with_description(
        "Enforce network isolation via Kubernetes NetworkPolicies. "
        "Default deny all, explicit allow required."
    )
    policy.require_network_policy_label()
    return policy.build()


def get_disallow_privileged_containers() -> Dict[str, Any]:
    """Disallow privileged containers."""
    policy = KyvernoPolicyBuilder("disallow-privileged")
    policy.with_display_name("Disallow Privileged Containers")
    policy.with_description(
        "Prevent deployment of privileged containers. "
        "Major security vulnerability."
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    policy.add_validation_rule(
        rule_name="check-privileged",
        message="Privileged containers are not allowed",
        pattern={
            "spec": {
                "containers": [
                    {
                        "securityContext": {
                            "privileged": False
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
# STORAGE & VOLUME POLICIES
# ============================================================================

def get_require_persistent_volume_claim() -> Dict[str, Any]:
    """Require persistent volumes for stateful applications."""
    policy = KyvernoPolicyBuilder("require-pvc")
    policy.with_display_name("Require PersistentVolumeClaims")
    policy.with_description(
        "Stateful Deployments must use PersistentVolumeClaims. "
        "Prevents data loss on pod termination."
    )
    policy.with_validation_action(ValidationAction.AUDIT)
    policy.add_validation_rule(
        rule_name="check-pvc",
        message="StatefulSet should use PersistentVolumeClaims",
        pattern={
            "spec": {
                "volumeClaimTemplates": "?"
            }
        },
        match=KyvernoMatch(kind=MatchKind.STATEFULSET),
        action=ValidationAction.AUDIT,
    )
    return policy.build()


# ============================================================================
# PQC (POST-QUANTUM CRYPTOGRAPHY) POLICIES
# ============================================================================

def get_pqc_cryptography_readiness() -> Dict[str, Any]:
    """Post-Quantum Cryptography readiness policy."""
    return (
        KyvernoPQCBuilder("pqc-crypto-readiness")
        .with_display_name("Post-Quantum Cryptography Readiness")
        .with_description(
            "Enforce PQC-compatible configurations. Label workloads "
            "as PQC-ready for the transition to quantum-safe cryptography."
        )
        .require_pqc_label()
        .build()
    )


def get_pqc_certificate_duration() -> Dict[str, Any]:
    """Enforce shorter certificate durations for PQC transition."""
    return (
        KyvernoPQCBuilder("pqc-cert-duration")
        .with_display_name("PQC Certificate Duration Policy")
        .with_description(
            "Enforce shorter certificate lifetimes (90 days) for "
            "safer PQC migration. Reduces exposure window."
        )
        .require_crypto_certduration()
        .build()
    )


# ============================================================================
# TALOS-SPECIFIC POLICIES
# ============================================================================

def get_talos_cluster_security() -> Dict[str, Any]:
    """Talos cluster security hardening policy."""
    policy = KyvernoPolicyBuilder("talos-security-hardening")
    policy.with_display_name("Talos Cluster Security Hardening")
    policy.with_description(
        "Enforce Talos-specific security hardening. "
        "Immutable OS + container restrictions."
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    
    # Talos runs read-only root filesystem
    policy.add_validation_rule(
        rule_name="enforce-readonly-rootfs",
        message="Talos clusters require read-only root filesystem",
        pattern={
            "spec": {
                "containers": [
                    {
                        "securityContext": {
                            "readOnlyRootFilesystem": True
                        }
                    }
                ]
            }
        },
        match=KyvernoMatch(kind=MatchKind.POD),
        action=ValidationAction.ENFORCE,
    )
    
    return policy.build()


def get_require_talos_label() -> Dict[str, Any]:
    """Require Talos cluster identification label."""
    policy = KyvernoPolicyBuilder("require-talos-label")
    policy.with_display_name("Require Talos Cluster Label")
    policy.with_description(
        "Label all pods with 'talos-cluster: true' for identification "
        "and management of workloads on Talos infrastructure."
    )
    policy.with_validation_action(ValidationAction.AUDIT)
    
    policy.add_validation_rule(
        rule_name="check-talos-label",
        message="Pod should have 'talos-cluster: true' label",
        pattern={
            "metadata": {
                "labels": {
                    "talos-cluster": "true"
                }
            }
        },
        match=KyvernoMatch(kind=MatchKind.POD),
        action=ValidationAction.AUDIT,
    )
    
    return policy.build()


# ============================================================================
# GOVERNANCE & COMPLIANCE POLICIES
# ============================================================================

def get_require_resource_labels() -> Dict[str, Any]:
    """Require standard resource labels."""
    policy = KyvernoPolicyBuilder("require-standard-labels")
    policy.with_display_name("Require Standard Resource Labels")
    policy.with_description(
        "All resources must have standard labels: "
        "app, team, environment, cost-center"
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    
    policy.add_validation_rule(
        rule_name="check-labels",
        message="Standard labels (app, team, environment) are required",
        pattern={
            "metadata": {
                "labels": {
                    "app": "?",
                    "team": "?",
                    "environment": "?"
                }
            }
        },
        match=KyvernoMatch(kind=MatchKind.POD),
        action=ValidationAction.ENFORCE,
    )
    
    return policy.build()


def get_require_pod_disruption_budget() -> Dict[str, Any]:
    """Require PodDisruptionBudget for high-availability applications."""
    policy = KyvernoPolicyBuilder("require-pdb")
    policy.with_display_name("Require PodDisruptionBudget")
    policy.with_description(
        "High-availability applications must define PodDisruptionBudget "
        "to survive node disruptions."
    )
    policy.with_validation_action(ValidationAction.AUDIT)
    
    policy.add_validation_rule(
        rule_name="check-pdb",
        message="Application should have a PodDisruptionBudget defined",
        pattern={
            "metadata": {
                "labels": {
                    "high-availability": "true"
                }
            }
        },
        match=KyvernoMatch(kind=MatchKind.DEPLOYMENT),
        action=ValidationAction.AUDIT,
    )
    
    return policy.build()


# ============================================================================
# TEMPLATE REGISTRY
# ============================================================================

KYVERNO_POLICY_TEMPLATES = {
    # Pod Security
    "pod-security-baseline": get_pod_security_baseline,
    "pod-security-restricted": get_pod_security_restricted,
    "require-resource-limits": get_require_resource_limits,
    
    # Image Security
    "require-image-registry": get_require_image_registry,
    "disallow-latest-tag": get_require_image_tag,
    
    # Network & Access
    "require-network-policies": get_require_network_policies,
    "disallow-privileged": get_disallow_privileged_containers,
    
    # Storage
    "require-pvc": get_require_persistent_volume_claim,
    
    # PQC
    "pqc-cryptography-readiness": get_pqc_cryptography_readiness,
    "pqc-certificate-duration": get_pqc_certificate_duration,
    
    # Talos-specific
    "talos-security-hardening": get_talos_cluster_security,
    "require-talos-label": get_require_talos_label,
    
    # Governance
    "require-standard-labels": get_require_resource_labels,
    "require-pdb": get_require_pod_disruption_budget,
}

KYVERNO_CATEGORIES = {
    "security": [
        "pod-security-baseline",
        "pod-security-restricted",
        "disallow-privileged",
    ],
    "image": [
        "require-image-registry",
        "disallow-latest-tag",
    ],
    "network": [
        "require-network-policies",
    ],
    "resources": [
        "require-resource-limits",
        "require-pvc",
    ],
    "pqc": [
        "pqc-cryptography-readiness",
        "pqc-certificate-duration",
    ],
    "talos": [
        "talos-security-hardening",
        "require-talos-label",
    ],
    "governance": [
        "require-standard-labels",
        "require-pdb",
    ],
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_kyverno_policy(policy_name: str) -> Dict[str, Any]:
    """Get a Kyverno policy by name."""
    if policy_name not in KYVERNO_POLICY_TEMPLATES:
        raise ValueError(f"Unknown Kyverno policy: {policy_name}")
    return KYVERNO_POLICY_TEMPLATES[policy_name]()


def list_kyverno_policies() -> List[str]:
    """List all available Kyverno policies."""
    return list(KYVERNO_POLICY_TEMPLATES.keys())


def get_kyverno_policies_by_category(category: str) -> List[Dict[str, Any]]:
    """Get all policies in a category."""
    if category not in KYVERNO_CATEGORIES:
        return []
    policy_names = KYVERNO_CATEGORIES[category]
    return [get_kyverno_policy(name) for name in policy_names]


def get_talos_security_bundle() -> List[Dict[str, Any]]:
    """Get all security policies recommended for Talos clusters."""
    return [
        get_pod_security_baseline(),
        get_talos_cluster_security(),
        get_disallow_privileged_containers(),
        get_require_image_tag(),
        get_require_network_policies(),
        get_require_resource_limits(),
        get_require_talos_label(),
    ]


def get_pqc_transition_bundle() -> List[Dict[str, Any]]:
    """Get all policies needed for PQC transition."""
    return [
        get_pqc_cryptography_readiness(),
        get_pqc_certificate_duration(),
        get_require_talos_label(),  # Talos is good for PQC
    ]


if __name__ == "__main__":
    # Example: Export all policies as YAML
    import yaml
    
    print("=" * 80)
    print("Talos Security Bundle")
    print("=" * 80)
    for policy in get_talos_security_bundle():
        print(yaml.dump(policy, default_flow_style=False, sort_keys=False))
        print("---")
