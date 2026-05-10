"""
Kyverno Policy Builder — Kubernetes-native policy engine for ITL ControlPlane.

Kyverno is a policy engine that runs as a Kubernetes admission controller,
enabling validation, mutation, and image verification policies.

Policies can be:
- validate: Enforce policy rules (reject or warn)
- mutate: Transform resources
- generate: Create resources automatically
- verifyimages: Verify container image signatures
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field as dataclass_field, asdict
import json


class KyvernoRuleType(str, Enum):
    """Kyverno policy rule types."""
    VALIDATE = "validate"
    MUTATE = "mutate"
    GENERATE = "generate"
    VERIFY_IMAGES = "verifyImages"


class ValidationAction(str, Enum):
    """Validation actions: audit (warn) or enforce (deny)."""
    AUDIT = "audit"
    ENFORCE = "enforce"


class MatchKind(str, Enum):
    """Kubernetes resource kind matching."""
    POD = "Pod"
    DEPLOYMENT = "Deployment"
    STATEFULSET = "StatefulSet"
    DAEMONSET = "DaemonSet"
    JOB = "Job"
    CRONJOB = "CronJob"
    SERVICE = "Service"
    INGRESS = "Ingress"
    NETWORKPOLICY = "NetworkPolicy"
    ALL = "*"


@dataclass
class KyvernoMatch:
    """Match resources by kind, name, namespace, labels, annotations."""
    kind: Union[MatchKind, str] = MatchKind.POD
    name: Optional[str] = None
    namespace: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None
    selector: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {"kind": self.kind.value if isinstance(self.kind, MatchKind) else self.kind}
        if self.name:
            result["name"] = self.name
        if self.namespace:
            result["namespace"] = self.namespace
        if self.labels:
            result["selector"] = {"matchLabels": self.labels}
        if self.annotations:
            result["annotations"] = self.annotations
        if self.selector:
            if "selector" in result:
                result["selector"].update(self.selector)
            else:
                result["selector"] = self.selector
        return result


@dataclass
class KyvernoValidationRule:
    """Kyverno validation rule."""
    message: str
    pattern: Optional[Dict[str, Any]] = None
    pattern_not: Optional[Dict[str, Any]] = None
    anyPattern: Optional[List[Dict[str, Any]]] = None
    allPattern: Optional[List[Dict[str, Any]]] = None
    deny: Optional[Dict[str, Any]] = None
    validation_action: ValidationAction = ValidationAction.AUDIT

    def to_dict(self) -> Dict[str, Any]:
        result = {"message": self.message}
        if self.pattern:
            result["pattern"] = self.pattern
        if self.pattern_not:
            result["pattern"] = {"patternNotEqual": self.pattern_not}
        if self.anyPattern:
            result["anyPattern"] = self.anyPattern
        if self.allPattern:
            result["allPattern"] = self.allPattern
        if self.deny:
            result["deny"] = self.deny
        result["validationAction"] = self.validation_action.value
        return result


@dataclass
class KyvernoMutationRule:
    """Kyverno mutation (patch) rule."""
    message: str
    patchStrategicMergePatch: Optional[Dict[str, Any]] = None
    patchJsonPatch: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {"message": self.message}
        if self.patchStrategicMergePatch:
            result["patchStrategicMergePatch"] = self.patchStrategicMergePatch
        if self.patchJsonPatch:
            result["patchJsonPatch"] = self.patchJsonPatch
        return result


@dataclass
class KyvernoRule:
    """Kyverno policy rule container."""
    name: str
    rule_type: KyvernoRuleType
    match: KyvernoMatch
    exclude: Optional[KyvernoMatch] = None
    validate_rule: Optional[KyvernoValidationRule] = None
    mutate_rule: Optional[KyvernoMutationRule] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "name": self.name,
            "match": self.match.to_dict(),
        }
        if self.exclude:
            result["exclude"] = self.exclude.to_dict()

        if self.rule_type == KyvernoRuleType.VALIDATE and self.validate_rule:
            result.update(self.validate_rule.to_dict())
        elif self.rule_type == KyvernoRuleType.MUTATE and self.mutate_rule:
            result.update(self.mutate_rule.to_dict())

        return result


class KyvernoPolicyBuilder:
    """Fluent builder for Kyverno ClusterPolicies."""

    def __init__(self, name: str):
        self.name = name
        self.display_name = name
        self.description = ""
        self.policy_type = "ClusterPolicy"  # ClusterPolicy or Policy (namespaced)
        self.validation_failure_action = ValidationAction.AUDIT
        self.background = True  # Apply to existing resources
        self.fail_policy_on_error = False
        self.rules: List[KyvernoRule] = []

    def with_display_name(self, name: str) -> "KyvernoPolicyBuilder":
        """Set display name."""
        self.display_name = name
        return self

    def with_description(self, desc: str) -> "KyvernoPolicyBuilder":
        """Set description."""
        self.description = desc
        return self

    def with_namespaced_policy(self) -> "KyvernoPolicyBuilder":
        """Use namespaced Policy instead of ClusterPolicy."""
        self.policy_type = "Policy"
        return self

    def with_validation_action(self, action: ValidationAction) -> "KyvernoPolicyBuilder":
        """Set validation failure action (audit or enforce)."""
        self.validation_failure_action = action
        return self

    def with_background(self, enabled: bool) -> "KyvernoPolicyBuilder":
        """Enable/disable application to existing resources."""
        self.background = enabled
        return self

    def add_validation_rule(
        self,
        rule_name: str,
        message: str,
        pattern: Optional[Dict[str, Any]] = None,
        match: Optional[KyvernoMatch] = None,
        action: ValidationAction = ValidationAction.AUDIT,
    ) -> "KyvernoPolicyBuilder":
        """Add a validation rule."""
        if match is None:
            match = KyvernoMatch(kind=MatchKind.POD)

        validate_rule = KyvernoValidationRule(
            message=message,
            pattern=pattern,
            validation_action=action,
        )
        rule = KyvernoRule(
            name=rule_name,
            rule_type=KyvernoRuleType.VALIDATE,
            match=match,
            validate_rule=validate_rule,
        )
        self.rules.append(rule)
        return self

    def add_mutation_rule(
        self,
        rule_name: str,
        message: str,
        patch: Dict[str, Any],
        match: Optional[KyvernoMatch] = None,
    ) -> "KyvernoPolicyBuilder":
        """Add a mutation (patch) rule."""
        if match is None:
            match = KyvernoMatch(kind=MatchKind.POD)

        mutate_rule = KyvernoMutationRule(
            message=message,
            patchStrategicMergePatch=patch,
        )
        rule = KyvernoRule(
            name=rule_name,
            rule_type=KyvernoRuleType.MUTATE,
            match=match,
            mutate_rule=mutate_rule,
        )
        self.rules.append(rule)
        return self

    def build(self) -> Dict[str, Any]:
        """Build the Kyverno policy manifest."""
        policy = {
            "apiVersion": "kyverno.io/v1",
            "kind": self.policy_type,
            "metadata": {
                "name": self.name,
            },
            "spec": {
                "validationFailureAction": self.validation_failure_action.value,
                "background": self.background,
                "failurePolicy": "fail" if self.fail_policy_on_error else "ignore",
                "rules": [rule.to_dict() for rule in self.rules],
            },
        }

        if self.display_name:
            policy["metadata"]["labels"] = {
                "app.kubernetes.io/name": self.display_name.lower().replace(" ", "-")
            }

        if self.description:
            policy["metadata"]["annotations"] = {
                "description": self.description
            }

        return policy

    def to_yaml(self) -> str:
        """Export as YAML."""
        try:
            import yaml
            return yaml.dump(self.build(), default_flow_style=False, sort_keys=False)
        except ImportError:
            raise ImportError("PyYAML is required for YAML export. Install with: pip install itl-policy-builder[yaml]")

    def to_json(self) -> str:
        """Export as JSON."""
        return json.dumps(self.build(), indent=2)

    def __str__(self) -> str:
        return self.to_json()


# Convenience builders for common classes
class KyvernoPodSecurityBuilder(KyvernoPolicyBuilder):
    """Builder for Pod Security policies."""

    def __init__(self, name: str = "require-pod-security"):
        super().__init__(name)
        self.with_display_name("Pod Security Baseline")
        self.with_description("Enforce Kubernetes Pod Security Standards (baseline)")

    def require_security_context(self) -> "KyvernoPodSecurityBuilder":
        """Require securityContext."""
        self.add_validation_rule(
            rule_name="check-security-context",
            message="Security context is required",
            pattern={
                "spec": {
                    "securityContext": "?"
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return self

    def require_non_root(self) -> "KyvernoPodSecurityBuilder":
        """Require runAsNonRoot."""
        self.add_validation_rule(
            rule_name="check-non-root",
            message="Running as root is not allowed",
            pattern={
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": True
                    }
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return self

    def require_read_only_fs(self) -> "KyvernoPodSecurityBuilder":
        """Require read-only root filesystem."""
        self.add_validation_rule(
            rule_name="check-readonly-fs",
            message="Read-only root filesystem is required",
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
        return self


class KyvernoImageSecurityBuilder(KyvernoPolicyBuilder):
    """Builder for container image policies."""

    def __init__(self, name: str = "require-image-registry"):
        super().__init__(name)
        self.with_display_name("Container Image Security")
        self.with_description("Enforce container image policies")

    def require_registry(self, registries: List[str]) -> "KyvernoImageSecurityBuilder":
        """Require images from specific registries."""
        # Build pattern that requires image to start with one of the registries
        pattern = {
            "spec": {
                "containers": [
                    {
                        "image": f"{registries[0]}/*"  # Simplified
                    }
                ]
            }
        }

        self.add_validation_rule(
            rule_name="check-registry",
            message=f"Images must come from trusted registries: {', '.join(registries)}",
            pattern=pattern,
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return self

    def require_image_pull_policy(self) -> "KyvernoImageSecurityBuilder":
        """Require imagePullPolicy: Always."""
        self.add_validation_rule(
            rule_name="check-image-pull-policy",
            message="imagePullPolicy must be Always",
            pattern={
                "spec": {
                    "containers": [
                        {
                            "imagePullPolicy": "Always"
                        }
                    ]
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        return self


class KyvernoNetworkPolicyBuilder(KyvernoPolicyBuilder):
    """Builder for network policies."""

    def __init__(self, name: str = "require-network-policy-label"):
        super().__init__(name)
        self.with_display_name("Network Policy Enforcement")
        self.with_description("Enforce network isolation policies")

    def require_network_policy_label(self) -> "KyvernoNetworkPolicyBuilder":
        """Require pods to have network policy label."""
        self.add_validation_rule(
            rule_name="check-network-policy",
            message="Pod must have 'network-policy: enabled' label",
            pattern={
                "metadata": {
                    "labels": {
                        "network-policy": "enabled"
                    }
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.AUDIT,
        )
        return self


class KyvernoPQCBuilder(KyvernoPolicyBuilder):
    """Builder for Post-Quantum Cryptography policies."""

    def __init__(self, name: str = "pqc-crypto-readiness"):
        super().__init__(name)
        self.with_display_name("Post-Quantum Cryptography Readiness")
        self.with_description("Enforce PQC-compatible configurations for Talos clusters")

    def require_pqc_label(self) -> "KyvernoPQCBuilder":
        """Require PQC readiness label."""
        self.add_validation_rule(
            rule_name="check-pqc-label",
            message="Pod must have 'pqc-compatible: true' label for PQC transition",
            pattern={
                "metadata": {
                    "labels": {
                        "pqc-compatible": "true"
                    }
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.AUDIT,
        )
        return self

    def require_crypto_certduration(self) -> "KyvernoPQCBuilder":
        """Require shorter certificate durations for PQC compatibility."""
        self.add_mutation_rule(
            rule_name="mutate-cert-duration",
            message="Setting certificate duration to 90 days for PQC transition",
            patch={
                "metadata": {
                    "annotations": {
                        "cert-duration": "2160h"  # 90 days
                    }
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
        )
        return self


# ============================================================================
# Kyverno Profile (Initiative equivalent)
# ============================================================================

@dataclass
class KyvernoProfileDefinition:
    """
    The result of building a Kyverno profile — the Kyverno equivalent of
    a PolicySetDefinition (initiative).

    A profile is a named, curated set of ClusterPolicy manifests that
    represent a complete deployment stance (e.g. 'security', 'talos', 'strict').

    Attributes:
        name: Profile identifier (e.g. 'itl-security-profile')
        display_name: Human-readable title
        description: What this profile enforces
        metadata: Arbitrary key-value metadata (version, author, reference, …)
        groups: Policy groups within the profile (like initiative groups)
        policies: List of built ClusterPolicy dicts, ready for serialisation
    """

    name: str
    display_name: str
    description: str
    metadata: Dict[str, Any]
    groups: List[Dict[str, str]]
    policies: List[Dict[str, Any]]

    def to_manifests(self) -> List[Dict[str, Any]]:
        """Return the list of ClusterPolicy manifests."""
        return self.policies

    def to_yaml(self) -> str:
        """Serialise all policies as a multi-document YAML string."""
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required for YAML export. "
                "Install with: pip install itl-policy-builder[yaml]"
            )
        docs = []
        for policy in self.policies:
            docs.append(yaml.dump(policy, default_flow_style=False, allow_unicode=True).rstrip())
        return "---\n" + "\n---\n".join(docs)

    def to_json(self) -> str:
        """Serialise all policies as a JSON array."""
        return json.dumps(self.policies, indent=2)

    def __len__(self) -> int:
        return len(self.policies)

    def __repr__(self) -> str:
        return (
            f"KyvernoProfileDefinition(name={self.name!r}, "
            f"policies={len(self.policies)})"
        )


class KyvernoProfileBuilder:
    """
    Fluent builder for Kyverno profiles — the Kyverno equivalent of PolicySetBuilder.

    A profile groups multiple Kyverno ClusterPolicies into a named, deployable
    bundle.  Policies are added by class (not by name) so they can receive
    per-profile kwargs at build time.

    Example::

        from itl_policy_builder.export.kyverno import KyvernoProfileBuilder

        profile = (
            KyvernoProfileBuilder("itl-talos-profile")
            .display_name("ITL Talos Security Profile")
            .description("Talos-optimised security policies")
            .category("Talos")
            .metadata(version="1.0.0", author="ITL Platform Team")
            .add_group("pod-security", "Pod Security Policies")
            .add_group("talos", "Talos-Specific Policies")
            .add_policy(PodSecurityBaselinePolicy, group="pod-security")
            .add_policy(TalosSecurityHardeningPolicy, group="talos")
            .build()
        )
    """

    def __init__(self, name: str):
        self._name = name
        self._display_name: str = name
        self._description: str = ""
        self._metadata: Dict[str, Any] = {}
        self._groups: List[Dict[str, str]] = []
        self._entries: List[Dict[str, Any]] = []  # {cls, group, kwargs}

    def display_name(self, name: str) -> "KyvernoProfileBuilder":
        """Set the human-readable display name."""
        self._display_name = name
        return self

    def description(self, desc: str) -> "KyvernoProfileBuilder":
        """Set the profile description."""
        self._description = desc
        return self

    def category(self, cat: str) -> "KyvernoProfileBuilder":
        """Set the profile category (stored in metadata)."""
        self._metadata["category"] = cat
        return self

    def version(self, ver: str) -> "KyvernoProfileBuilder":
        """Set the profile version (stored in metadata)."""
        self._metadata["version"] = ver
        return self

    def metadata(
        self,
        data: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> "KyvernoProfileBuilder":
        """Add arbitrary metadata key-value pairs."""
        if data:
            self._metadata.update(data)
        self._metadata.update(kwargs)
        return self

    def add_group(
        self,
        name: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> "KyvernoProfileBuilder":
        """
        Add a logical group for organising policies within the profile.

        Args:
            name: Group identifier (e.g. 'pod-security')
            display_name: Human-readable group name
            description: Group description
        """
        group: Dict[str, str] = {"name": name}
        if display_name:
            group["displayName"] = display_name
        if description:
            group["description"] = description
        self._groups.append(group)
        return self

    def add_policy(
        self,
        policy_class: Any,  # KyvernoPolicyTemplate subclass
        group: Optional[str] = None,
        **kwargs: Any,
    ) -> "KyvernoProfileBuilder":
        """
        Add a policy class to the profile.

        Args:
            policy_class: A KyvernoPolicyTemplate subclass (not an instance)
            group: Optional group name this policy belongs to
            **kwargs: Build-time parameters passed to policy_class.build()
        """
        self._entries.append({"cls": policy_class, "group": group, "kwargs": kwargs})
        return self

    def build(self) -> KyvernoProfileDefinition:
        """Build and return the KyvernoProfileDefinition."""
        policies = [entry["cls"].build(**entry["kwargs"]) for entry in self._entries]
        return KyvernoProfileDefinition(
            name=self._name,
            display_name=self._display_name,
            description=self._description,
            metadata=self._metadata,
            groups=list(self._groups),
            policies=policies,
        )


if __name__ == "__main__":
    # Example: Pod security policy
    policy = (
        KyvernoPodSecurityBuilder()
        .require_security_context()
        .require_non_root()
        .build()
    )
    print(json.dumps(policy, indent=2))
