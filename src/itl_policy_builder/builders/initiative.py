"""
Fluent builder for policy sets (initiatives).
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
    """Fluent builder for creating policy sets (initiatives)."""

    def __init__(self, name: str, scope: Optional[str] = None):
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
        self._display_name = name
        return self

    def description(self, desc: str) -> PolicySetBuilder:
        self._description = desc
        return self

    def policy_type(self, ptype: Union[PolicyType, str]) -> PolicySetBuilder:
        if isinstance(ptype, str):
            ptype = PolicyType(ptype)
        self._policy_type = ptype
        return self

    def metadata(self, data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> PolicySetBuilder:
        if data:
            self._metadata.update(data)
        self._metadata.update(kwargs)
        return self

    def category(self, category: str) -> PolicySetBuilder:
        self._metadata["category"] = category
        return self

    def version(self, version: str) -> PolicySetBuilder:
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
        version: Optional[str] = None,
    ) -> PolicySetBuilder:
        ref = PolicySetDefinitionReference(
            policy_definition_id=policy_definition_id,
            policy_definition_reference_id=reference_id or f"ref-{uuid4().hex[:8]}",
            parameters=(
                {k: {"value": v} for k, v in parameters.items()} if parameters else None
            ),
            group_names=groups,
            policy_definition_version=version,
        )
        self._policy_definitions.append(ref)
        return self

    def add_policies(self, *policy_definition_ids: str) -> PolicySetBuilder:
        for pid in policy_definition_ids:
            self.add_policy(pid)
        return self

    def _generate_id(self) -> str:
        if self._scope:
            return f"{self._scope}/providers/ITL.Authorization/policySetDefinitions/{self._name}"
        return f"/providers/ITL.Authorization/policySetDefinitions/{self._name}"

    def build(self) -> PolicySetDefinition:
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
        return self.build().to_arm_json()

    def build_dict(self) -> Dict[str, Any]:
        return self.build().model_dump(by_alias=True)

    def to_azure_dict(self) -> Dict[str, Any]:
        return self.build_dict()

    def to_azure_json(self) -> str:
        return self.build_json()


def security_baseline(
    allowed_locations: Optional[List[str]] = None,
    required_tags: Optional[List[str]] = None,
) -> PolicySetBuilder:
    """Factory for a security baseline initiative."""
    builder = PolicySetBuilder("security-baseline")
    builder.display_name("Security Baseline")
    builder.description("Core security policies for ITL environments")
    builder.category("Security")
    builder.version("1.0.0")

    builder.add_group("General", "General security policies")
    builder.add_group("Tags", "Tagging requirements")
    builder.add_group("Network", "Network security")

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
    """Factory for a cost management initiative."""
    builder = PolicySetBuilder("cost-management")
    builder.display_name("Cost Management")
    builder.description("Policies for cost tracking and optimization")
    builder.category("Cost")
    builder.version("1.0.0")

    builder.add_group("Tagging", "Cost allocation tags")
    builder.add_group("Sizing", "Resource sizing controls")

    return builder
