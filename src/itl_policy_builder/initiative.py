"""
Builder for policy sets (initiatives).

Policy sets group multiple policies together for easier management
and assignment.

Example::

    from itl_policy_builder import PolicySetBuilder

    initiative = (
        PolicySetBuilder("security-baseline")
        .display_name("Security Baseline")
        .description("Core security policies for all environments")
        .category("Security")
        .add_policy("/providers/ITL.Authorization/policyDefinitions/require-https")
        .add_policy(
            "/providers/ITL.Authorization/policyDefinitions/allowed-locations",
            parameters={"allowedLocations": ["westeurope", "northeurope"]},
        )
        .add_group("Network", "Network security policies")
        .add_policy(
            "/providers/ITL.Authorization/policyDefinitions/require-nsg",
            groups=["Network"],
        )
        .build()
    )
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from itl_policy_builder.enums import PolicyType
from itl_policy_builder.models import (
    PolicySetDefinition,
    PolicySetDefinitionReference,
    PolicyParameter,
)


class PolicySetBuilder:
    """
    Fluent builder for creating policy sets (initiatives).

    Policy sets allow grouping multiple policies for easier assignment
    and management.
    """

    def __init__(self, name: str, scope: Optional[str] = None):
        """
        Initialize a new policy set builder.

        Args:
            name: Unique policy set name
            scope: Optional scope prefix (subscription, management group)
        """
        self._name = name
        self._scope = scope
        self._display_name: Optional[str] = None
        self._description: Optional[str] = None
        self._policy_type: PolicyType = PolicyType.CUSTOM
        self._metadata: Dict[str, Any] = {}
        self._parameters: Dict[str, PolicyParameter] = {}
        self._policy_definitions: List[PolicySetDefinitionReference] = []
        self._policy_definition_groups: List[Dict[str, Any]] = []

    def display_name(self, name: str) -> PolicySetBuilder:
        """Set the human-readable display name."""
        self._display_name = name
        return self

    def description(self, desc: str) -> PolicySetBuilder:
        """Set the policy set description."""
        self._description = desc
        return self

    def policy_type(self, ptype: Union[PolicyType, str]) -> PolicySetBuilder:
        """Set the policy type (BuiltIn, Custom)."""
        if isinstance(ptype, str):
            ptype = PolicyType(ptype)
        self._policy_type = ptype
        return self

    def metadata(self, data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> PolicySetBuilder:
        """
        Add metadata to the policy set.
        
        Args:
            data: Dictionary of metadata to add
            **kwargs: Additional metadata as keyword arguments
        """
        if data:
            self._metadata.update(data)
        self._metadata.update(kwargs)
        return self

    def category(self, category: str) -> PolicySetBuilder:
        """Set the policy set category."""
        self._metadata["category"] = category
        return self

    def version(self, version: str) -> PolicySetBuilder:
        """Set the policy set version."""
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
    ) -> PolicySetBuilder:
        """
        Add a parameter to the policy set.

        These parameters can be passed to individual policies within the set.
        """
        self._parameters[name] = PolicyParameter(
            type=type,
            display_name=display_name or name,
            description=description,
            default_value=default,
            allowed_values=allowed_values,
        )
        return self

    def add_group(
        self,
        name: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[str] = None,
    ) -> PolicySetBuilder:
        """
        Add a policy group for organizing policies within the set.

        Args:
            name: Group identifier
            display_name: Human-readable name
            description: Group description
            category: Group category
        """
        group: Dict[str, Any] = {"name": name}
        if display_name:
            group["displayName"] = display_name
        if description:
            group["description"] = description
        if category:
            group["category"] = category
        self._policy_definition_groups.append(group)
        return self

    def add_policy(
        self,
        policy_definition_id: str,
        reference_id: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        groups: Optional[List[str]] = None,
    ) -> PolicySetBuilder:
        """
        Add a policy to the set.

        Args:
            policy_definition_id: Full ARM resource ID of the policy definition
            reference_id: Optional reference ID within the set (auto-generated if not provided)
            parameters: Parameter values for this policy
            groups: Group names this policy belongs to
        """
        ref = PolicySetDefinitionReference(
            policy_definition_id=policy_definition_id,
            policy_definition_reference_id=reference_id or f"ref-{uuid4().hex[:8]}",
            parameters=(
                {k: {"value": v} for k, v in parameters.items()} if parameters else None
            ),
            group_names=groups,
        )
        self._policy_definitions.append(ref)
        return self

    def add_policies(self, *policy_definition_ids: str) -> PolicySetBuilder:
        """Add multiple policies without custom parameters."""
        for pid in policy_definition_ids:
            self.add_policy(pid)
        return self

    def _generate_id(self) -> str:
        """Generate the ARM resource ID for this policy set."""
        if self._scope:
            return f"{self._scope}/providers/ITL.Authorization/policySetDefinitions/{self._name}"
        return f"/providers/ITL.Authorization/policySetDefinitions/{self._name}"

    def build(self) -> PolicySetDefinition:
        """
        Build and return the PolicySetDefinition.

        Returns:
            PolicySetDefinition: The complete policy set definition.

        Raises:
            ValueError: If no policies are added.
        """
        if not self._policy_definitions:
            raise ValueError("Policy set must contain at least one policy. Use add_policy().")

        properties: Dict[str, Any] = {
            "displayName": self._display_name or self._name,
            "policyType": self._policy_type.value,
            "policyDefinitions": [
                p.model_dump(by_alias=True, exclude_none=True)
                for p in self._policy_definitions
            ],
        }

        if self._description:
            properties["description"] = self._description

        if self._metadata:
            properties["metadata"] = self._metadata

        if self._parameters:
            properties["parameters"] = {
                k: v.model_dump(by_alias=True, exclude_none=True)
                for k, v in self._parameters.items()
            }

        if self._policy_definition_groups:
            properties["policyDefinitionGroups"] = self._policy_definition_groups

        return PolicySetDefinition(
            id=self._generate_id(),
            name=self._name,
            type="ITL.Authorization/policySetDefinitions",
            properties=properties,
        )

    def build_json(self) -> str:
        """Build and return ARM-compatible JSON."""
        return self.build().to_arm_json()

    def build_dict(self) -> Dict[str, Any]:
        """Build and return ARM-compatible dictionary."""
        return self.build().model_dump(by_alias=True)


# ============================================================================
# Built-in Initiative Templates
# ============================================================================


def security_baseline(
    allowed_locations: Optional[List[str]] = None,
    required_tags: Optional[List[str]] = None,
) -> PolicySetBuilder:
    """
    Factory for a security baseline initiative.

    Includes common security policies for production environments.
    """
    builder = PolicySetBuilder("security-baseline")
    builder.display_name("Security Baseline")
    builder.description("Core security policies for ITL environments")
    builder.category("Security")
    builder.version("1.0.0")

    # Add groups
    builder.add_group("General", "General security policies")
    builder.add_group("Tags", "Tagging requirements")
    builder.add_group("Network", "Network security")

    # Add policies (these would be built-in policy IDs)
    if allowed_locations:
        builder.add_policy(
            "/providers/ITL.Authorization/policyDefinitions/allowed-locations",
            parameters={"allowedLocations": allowed_locations},
            groups=["General"],
        )

    if required_tags:
        for tag in required_tags:
            builder.add_policy(
                f"/providers/ITL.Authorization/policyDefinitions/require-tag-{tag}",
                groups=["Tags"],
            )

    return builder


def cost_management() -> PolicySetBuilder:
    """
    Factory for a cost management initiative.

    Includes policies for cost tracking and optimization.
    """
    builder = PolicySetBuilder("cost-management")
    builder.display_name("Cost Management")
    builder.description("Policies for cost tracking and optimization")
    builder.category("Cost")
    builder.version("1.0.0")

    builder.add_group("Tagging", "Cost allocation tags")
    builder.add_group("Sizing", "Resource sizing controls")

    return builder
