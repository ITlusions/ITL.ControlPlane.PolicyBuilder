"""
Fluent builder for policy definitions.

The PolicyBuilder provides a fluent API for constructing policy definitions
with validation and serialization support.

Example::

    from itl_policy_builder import PolicyBuilder, Effect, field, all_of

    policy = (
        PolicyBuilder("require-tags")
        .display_name("Require Required Tags")
        .description("Ensures resources have required tags")
        .mode("Indexed")
        .parameter("requiredTags", type="Array", default=["environment", "owner"])
        .with_rule(
            if_=all_of(
                field("type").not_equals("ITL.Core/resourceGroups"),
                field("tags.environment").exists(False),
            ),
            then=Effect.DENY,
            message="Resource must have an 'environment' tag",
        )
        .build()
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from itl_policy_builder.conditions import Condition
from itl_policy_builder.enums import Effect, PolicyMode, PolicyType
from itl_policy_builder.models import (
    PolicyDefinition,
    PolicyDefinitionProperties,
    PolicyParameter,
    PolicyRule as PolicyRuleModel,
)


@dataclass
class PolicyRuleEffect:
    """
    Represents the 'then' portion of a policy rule.

    Contains the effect and any additional effect-specific details.
    """

    effect: Effect
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"effect": self.effect.value}
        if self.message:
            result["message"] = self.message
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class PolicyRule:
    """
    A complete policy rule with condition and effect.
    """

    condition: Condition
    effect: PolicyRuleEffect

    def to_dict(self) -> Dict[str, Any]:
        return {
            "if": self.condition.to_dict(),
            "then": self.effect.to_dict(),
        }


class PolicyBuilder:
    """
    Fluent builder for creating policy definitions.

    Usage::

        policy = (
            PolicyBuilder("allowed-locations")
            .display_name("Allowed Locations")
            .description("Restrict resources to specific locations")
            .mode("All")
            .parameter("allowedLocations", type="Array", default=["westeurope", "northeurope"])
            .with_rule(
                if_=field("location").not_in("[parameters('allowedLocations')]"),
                then=Effect.DENY,
            )
            .build()
        )
    """

    def __init__(self, name: str, scope: Optional[str] = None):
        """
        Initialize a new policy builder.

        Args:
            name: Unique policy name (used in resource ID)
            scope: Optional scope prefix (subscription, management group)
        """
        self._name = name
        self._scope = scope
        self._display_name: Optional[str] = None
        self._description: Optional[str] = None
        self._policy_type: PolicyType = PolicyType.CUSTOM
        self._mode: PolicyMode = PolicyMode.INDEXED
        self._metadata: Dict[str, Any] = {}
        self._parameters: Dict[str, PolicyParameter] = {}
        self._rule: Optional[PolicyRule] = None
        self._tags: Dict[str, str] = {}

    def display_name(self, name: str) -> PolicyBuilder:
        """Set the human-readable display name."""
        self._display_name = name
        return self

    def description(self, desc: str) -> PolicyBuilder:
        """Set the policy description."""
        self._description = desc
        return self

    def policy_type(self, ptype: Union[PolicyType, str]) -> PolicyBuilder:
        """Set the policy type (BuiltIn, Custom, Static)."""
        if isinstance(ptype, str):
            ptype = PolicyType(ptype)
        self._policy_type = ptype
        return self

    def mode(self, mode: Union[PolicyMode, str]) -> PolicyBuilder:
        """
        Set the evaluation mode.

        - "All": Evaluate all resource types
        - "Indexed": Only evaluate resources with tags and location
        """
        if isinstance(mode, str):
            mode = PolicyMode.from_string(mode)
        self._mode = mode
        return self

    def metadata(self, data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> PolicyBuilder:
        """
        Add metadata to the policy.
        
        Args:
            data: Dictionary of metadata to add
            **kwargs: Additional metadata as keyword arguments
        """
        if data:
            self._metadata.update(data)
        self._metadata.update(kwargs)
        return self

    def category(self, category: str) -> PolicyBuilder:
        """Set the policy category (shorthand for metadata)."""
        self._metadata["category"] = category
        return self

    def version(self, version: str) -> PolicyBuilder:
        """Set the policy version (shorthand for metadata)."""
        self._metadata["version"] = version
        return self

    def parameter(
        self,
        name: str,
        type: str = "String",
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        default: Optional[Any] = None,
        allowed_values: Optional[List[Any]] = None,
    ) -> PolicyBuilder:
        """
        Add a parameter to the policy.

        Parameters allow the policy to be reusable with different values.

        Args:
            name: Parameter name
            type: Type (String, Array, Object, Boolean, Integer, Float, DateTime)
            display_name: Human-readable name
            description: Parameter description
            default: Default value if not specified
            allowed_values: List of allowed values

        Example::

            .parameter("allowedLocations", type="Array", default=["westeurope"])
            .parameter("effect", type="String", default="Deny", allowed_values=["Deny", "Audit"])
        """
        self._parameters[name] = PolicyParameter(
            type=type,
            display_name=display_name or name,
            description=description,
            default_value=default,
            allowed_values=allowed_values,
        )
        return self

    def with_rule(
        self,
        if_: Condition,
        then: Union[Effect, Dict[str, Any]],
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> PolicyBuilder:
        """
        Set the policy rule.

        Args:
            if_: Condition that triggers the policy
            then: Effect to apply (Effect enum or dict for complex effects)
            message: Non-compliance message
            details: Additional effect details (for Modify, DeployIfNotExists, etc.)

        Example::

            .with_rule(
                if_=field("location").not_equals("westeurope"),
                then=Effect.DENY,
                message="Resources must be in West Europe",
            )

            # Complex effect with details
            .with_rule(
                if_=field("tags.CostCenter").exists(False),
                then=Effect.MODIFY,
                details={
                    "operations": [
                        {"operation": "addOrReplace", "field": "tags.CostCenter", "value": "Unknown"}
                    ]
                },
            )
        """
        if isinstance(then, Effect):
            effect = PolicyRuleEffect(effect=then, message=message, details=details)
        else:
            # Dict format for complex effects
            effect = PolicyRuleEffect(
                effect=Effect(then.get("effect", "Audit")),
                message=message or then.get("message"),
                details=details or then.get("details"),
            )

        self._rule = PolicyRule(condition=if_, effect=effect)
        return self

    def tag(self, key: str, value: str) -> PolicyBuilder:
        """Add a tag to the policy resource."""
        self._tags[key] = value
        return self

    def tags(self, **kwargs: str) -> PolicyBuilder:
        """Add multiple tags to the policy resource."""
        self._tags.update(kwargs)
        return self

    def _generate_id(self) -> str:
        """Generate the ARM resource ID for this policy."""
        if self._scope:
            return f"{self._scope}/providers/ITL.Authorization/policyDefinitions/{self._name}"
        return f"/providers/ITL.Authorization/policyDefinitions/{self._name}"

    def build(self) -> PolicyDefinition:
        """
        Build and return the PolicyDefinition.

        Returns:
            PolicyDefinition: The complete policy definition.

        Raises:
            ValueError: If required fields are missing.
        """
        if self._rule is None:
            raise ValueError("Policy must have a rule. Use with_rule() to define one.")

        rule_dict = self._rule.to_dict()

        properties = PolicyDefinitionProperties(
            display_name=self._display_name or self._name,
            description=self._description,
            policy_type=self._policy_type,
            mode=self._mode,
            metadata=self._metadata if self._metadata else None,
            parameters=self._parameters if self._parameters else None,
            policy_rule=PolicyRuleModel(
                if_condition=rule_dict["if"],
                then_effect=rule_dict["then"],
            ),
        )

        return PolicyDefinition(
            id=self._generate_id(),
            name=self._name,
            type="ITL.Authorization/policyDefinitions",
            properties=properties,
        )

    def build_json(self) -> str:
        """Build and return ARM-compatible JSON."""
        return self.build().to_arm_json()

    def build_dict(self) -> Dict[str, Any]:
        """Build and return ARM-compatible dictionary."""
        return self.build().to_arm_dict()


# ============================================================================
# Convenience Factory Functions
# ============================================================================


def deny_if(condition: Condition, message: Optional[str] = None) -> PolicyBuilder:
    """
    Quick factory for a deny policy.

    Example::

        policy = deny_if(
            field("location").not_equals("westeurope"),
            message="Only West Europe is allowed",
        ).display_name("Deny Non-WestEurope").build()
    """
    builder = PolicyBuilder(f"deny-{uuid4().hex[:8]}")
    builder.with_rule(if_=condition, then=Effect.DENY, message=message)
    return builder


def audit_if(condition: Condition, message: Optional[str] = None) -> PolicyBuilder:
    """
    Quick factory for an audit policy.

    Example::

        policy = audit_if(
            field("tags.CostCenter").exists(False),
            message="Consider adding a CostCenter tag",
        ).display_name("Audit Missing CostCenter").build()
    """
    builder = PolicyBuilder(f"audit-{uuid4().hex[:8]}")
    builder.with_rule(if_=condition, then=Effect.AUDIT, message=message)
    return builder


def require_tag(tag_name: str, allowed_values: Optional[List[str]] = None) -> PolicyBuilder:
    """
    Factory for a policy that requires a specific tag.

    Args:
        tag_name: Name of the required tag
        allowed_values: Optional list of allowed tag values

    Example::

        policy = require_tag("environment", ["dev", "test", "prod"]).build()
    """
    from itl_policy_builder.conditions import field, all_of, any_of

    builder = PolicyBuilder(f"require-tag-{tag_name}")
    builder.display_name(f"Require '{tag_name}' Tag")
    builder.description(f"Ensures resources have the '{tag_name}' tag")
    builder.category("Tags")

    if allowed_values:
        # Tag must exist AND have one of the allowed values
        condition = any_of(
            field(f"tags.{tag_name}").exists(False),
            field(f"tags.{tag_name}").not_in(*allowed_values),
        )
        builder.with_rule(
            if_=condition,
            then=Effect.DENY,
            message=f"Tag '{tag_name}' is required and must be one of: {', '.join(allowed_values)}",
        )
    else:
        # Just require the tag exists
        condition = field(f"tags.{tag_name}").exists(False)
        builder.with_rule(
            if_=condition,
            then=Effect.DENY,
            message=f"Tag '{tag_name}' is required",
        )

    return builder


def allowed_locations(*locations: str) -> PolicyBuilder:
    """
    Factory for a policy that restricts allowed locations.

    Example::

        policy = allowed_locations("westeurope", "northeurope").build()
    """
    from itl_policy_builder.conditions import field, all_of

    builder = PolicyBuilder("allowed-locations")
    builder.display_name("Allowed Locations")
    builder.description(f"Restricts resources to: {', '.join(locations)}")
    builder.category("General")
    builder.mode("All")

    # Skip resource groups (they can be in any location)
    condition = all_of(
        field("type").not_equals("ITL.Core/resourceGroups"),
        field("location").not_in(*locations),
    )

    builder.with_rule(
        if_=condition,
        then=Effect.DENY,
        message=f"Resource location must be one of: {', '.join(locations)}",
    )

    return builder
