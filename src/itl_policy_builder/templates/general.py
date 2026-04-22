"""
General built-in policy templates.

This module provides common policy templates that are applicable
across various resource types and scenarios.
"""

from typing import Any, Dict, List, Optional, Tuple, Type

from itl_policy_builder.builders.policy import PolicyBuilder
from itl_policy_builder.conditions import all_of, field
from itl_policy_builder.enums import Effect, PolicyType
from itl_policy_builder.models import PolicyDefinition


# ============================================================================
# Base Class for Built-in Policies
# ============================================================================


class BuiltInPolicy:
    """
    Base class for built-in policy templates.

    Subclasses must define:
        - name: Unique policy identifier
        - display_name: Human-readable name
        - description: What the policy does
        - category: Policy category for grouping
        - build(): Class method returning PolicyDefinition
    """

    name: str = ""
    display_name: str = ""
    description: str = ""
    category: str = "General"
    version: str = "1.0.0"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        """Build the policy with optional parameters."""
        raise NotImplementedError


# ============================================================================
# Location Policies
# ============================================================================


class AllowedLocationsPolicy(BuiltInPolicy):
    """
    Restricts resources to a specified set of locations.

    Parameters:
        allowed_locations: List of allowed location identifiers
    """

    name = "allowed-locations"
    display_name = "Allowed Locations"
    description = "Restricts resources to the specified set of locations."
    category = "General"

    @classmethod
    def build(
        cls,
        allowed_locations: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_locations = allowed_locations or ["westeurope", "northeurope"]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .parameter(
                "allowedLocations",
                type="Array",
                display_name="Allowed Locations",
                description="List of locations where resources can be created",
                default=allowed_locations,
            )
            .with_rule(
                if_=field("location").not_in(*allowed_locations),
                then=Effect.DENY,
                message="Resources are not allowed in this location",
            )
            .build()
        )


# ============================================================================
# Tag Policies
# ============================================================================


class RequireTagPolicy(BuiltInPolicy):
    """
    Requires a specific tag on resources.

    Parameters:
        tag_name: Name of the required tag
    """

    name = "require-tag"
    display_name = "Require Tag"
    description = "Requires a specific tag on resources."
    category = "Tags"

    @classmethod
    def build(
        cls,
        tag_name: str = "environment",
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(f"require-tag-{tag_name}")
            .display_name(f"Require '{tag_name}' Tag")
            .description(f"Resources must have a '{tag_name}' tag")
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .with_rule(
                if_=field(f"tags.{tag_name}").exists(False),
                then=Effect.DENY,
                message=f"Resources must have a '{tag_name}' tag",
            )
            .build()
        )


class InheritTagFromResourceGroupPolicy(BuiltInPolicy):
    """
    Inherits a tag value from the parent resource group.

    Parameters:
        tag_name: Name of the tag to inherit
    """

    name = "inherit-tag-from-rg"
    display_name = "Inherit Tag from Resource Group"
    description = "Adds or replaces a tag with its value from the parent resource group."
    category = "Tags"

    @classmethod
    def build(
        cls,
        tag_name: str = "environment",
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(f"inherit-tag-{tag_name}-from-rg")
            .display_name(f"Inherit '{tag_name}' from Resource Group")
            .description(f"Adds the '{tag_name}' tag from the resource group if missing")
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .with_rule(
                if_=all_of(
                    field(f"tags.{tag_name}").exists(False),
                ),
                then=Effect.MODIFY,
                details={
                    "roleDefinitionIds": [
                        "/providers/ITL.Authorization/roleDefinitions/contributor"
                    ],
                    "operations": [
                        {
                            "operation": "addOrReplace",
                            "field": f"tags.{tag_name}",
                            "value": "[resourceGroup().tags['{}']".format(tag_name),
                        }
                    ],
                },
            )
            .build()
        )


class AuditMissingTagPolicy(BuiltInPolicy):
    """
    Audits resources missing a specific tag (non-blocking).

    Parameters:
        tag_name: Name of the tag to audit
    """

    name = "audit-missing-tag"
    display_name = "Audit Missing Tag"
    description = "Audits resources that are missing a specific tag."
    category = "Tags"

    @classmethod
    def build(
        cls,
        tag_name: str = "cost-center",
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(f"audit-missing-tag-{tag_name}")
            .display_name(f"Audit Missing '{tag_name}' Tag")
            .description(f"Audits resources that don't have a '{tag_name}' tag")
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .with_rule(
                if_=field(f"tags.{tag_name}").exists(False),
                then=Effect.AUDIT,
                message=f"Consider adding a '{tag_name}' tag for better resource management",
            )
            .build()
        )


# ============================================================================
# Resource Type Policies
# ============================================================================


class AllowedResourceTypesPolicy(BuiltInPolicy):
    """
    Restricts which resource types can be created.

    Parameters:
        allowed_types: List of allowed resource type patterns
    """

    name = "allowed-resource-types"
    display_name = "Allowed Resource Types"
    description = "Restricts which resource types can be created."
    category = "General"

    @classmethod
    def build(
        cls,
        allowed_types: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> PolicyDefinition:
        allowed_types = allowed_types or [
            "ITL.Core/*",
            "ITL.Compute/virtualMachines",
        ]

        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("All")
            .parameter(
                "allowedTypes",
                type="Array",
                display_name="Allowed Resource Types",
                description="List of allowed resource types (supports wildcards)",
                default=allowed_types,
            )
            .with_rule(
                if_=field("type").not_in(*allowed_types),
                then=Effect.DENY,
                message="This resource type is not allowed",
            )
            .build()
        )


# ============================================================================
# Network Policies
# ============================================================================


class DenyPublicIPPolicy(BuiltInPolicy):
    """
    Denies creation of public IP resources.
    """

    name = "deny-public-ip"
    display_name = "Deny Public IP"
    description = "Prevents creation of public IP addresses."
    category = "Network"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("All")
            .with_rule(
                if_=field("type").equals("ITL.Network/publicIPAddresses"),
                then=Effect.DENY,
                message="Public IP addresses are not allowed in this environment",
            )
            .build()
        )


class RequireNetworkSecurityGroupPolicy(BuiltInPolicy):
    """
    Requires network interfaces to have a network security group.
    """

    name = "require-nsg"
    display_name = "Require Network Security Group"
    description = "Network interfaces must have a network security group attached."
    category = "Network"

    @classmethod
    def build(cls, **kwargs: Any) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(cls.description)
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("Indexed")
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.Network/networkInterfaces"),
                    field("properties.networkSecurityGroup.id").exists(False),
                ),
                then=Effect.DENY,
                message="Network interfaces must have a network security group",
            )
            .build()
        )


# ============================================================================
# Cost Policies
# ============================================================================


class MaxResourceGroupCountPolicy(BuiltInPolicy):
    """
    Limits the number of resource groups per subscription.
    """

    name = "max-resource-groups"
    display_name = "Maximum Resource Groups"
    description = "Limits the number of resource groups in a subscription."
    category = "Cost"

    @classmethod
    def build(
        cls,
        max_count: int = 100,
        **kwargs: Any,
    ) -> PolicyDefinition:
        return (
            PolicyBuilder(cls.name)
            .display_name(cls.display_name)
            .description(f"Limits resource groups to {max_count} per subscription")
            .category(cls.category)
            .version(cls.version)
            .policy_type(PolicyType.BUILTIN)
            .mode("All")
            .parameter(
                "maxCount",
                type="Integer",
                display_name="Maximum Count",
                description="Maximum number of resource groups allowed",
                default=max_count,
            )
            .with_rule(
                if_=all_of(
                    field("type").equals("ITL.Core/resourceGroups"),
                ),
                then=Effect.AUDIT,
                message=f"Consider whether you need another resource group (max: {max_count})",
            )
            .build()
        )


# ============================================================================
# Registry
# ============================================================================

_BUILTIN_POLICIES: Dict[str, Type[BuiltInPolicy]] = {
    "allowed-locations": AllowedLocationsPolicy,
    "require-tag": RequireTagPolicy,
    "inherit-tag-from-rg": InheritTagFromResourceGroupPolicy,
    "audit-missing-tag": AuditMissingTagPolicy,
    "allowed-resource-types": AllowedResourceTypesPolicy,
    "deny-public-ip": DenyPublicIPPolicy,
    "require-nsg": RequireNetworkSecurityGroupPolicy,
    "max-resource-groups": MaxResourceGroupCountPolicy,
}


def list_builtin_policies() -> List[Tuple[str, str]]:
    """
    List all available built-in policies.

    Returns:
        List of (name, description) tuples
    """
    return [(cls.name, cls.description) for cls in _BUILTIN_POLICIES.values()]


def get_builtin_policy(name: str, **kwargs: Any) -> PolicyDefinition:
    """
    Get a built-in policy by name.

    Args:
        name: Policy name (e.g., "allowed-locations")
        **kwargs: Policy-specific parameters

    Returns:
        PolicyDefinition: The built policy

    Raises:
        KeyError: If policy name is not found
    """
    if name not in _BUILTIN_POLICIES:
        available = ", ".join(_BUILTIN_POLICIES.keys())
        raise KeyError(f"Unknown built-in policy: {name}. Available: {available}")

    return _BUILTIN_POLICIES[name].build(**kwargs)


def get_all_builtin_policies(**default_kwargs: Any) -> List[PolicyDefinition]:
    """
    Get all built-in policies.

    Args:
        **default_kwargs: Default parameters passed to all policies

    Returns:
        List of all built-in PolicyDefinitions
    """
    return [cls.build(**default_kwargs) for cls in _BUILTIN_POLICIES.values()]
