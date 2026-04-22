"""
Policy definition Pydantic models.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict

from itl_policy_builder.enums import (
    PolicyMode,
    PolicyType,
)


class PolicyParameter(BaseModel):
    """
    A parameter definition for a policy.
    """

    model_config = ConfigDict(populate_by_name=True)

    type: str = Field(
        ...,
        description="Parameter type: String, Array, Object, Boolean, Integer, Float, DateTime",
    )
    display_name: Optional[str] = Field(
        default=None,
        alias="displayName",
        description="Human-readable parameter name",
    )
    description: Optional[str] = Field(
        default=None,
        description="Parameter description",
    )
    default_value: Optional[Any] = Field(
        default=None,
        alias="defaultValue",
        description="Default value if not provided at assignment",
    )
    allowed_values: Optional[List[Any]] = Field(
        default=None,
        alias="allowedValues",
        description="List of allowed values (validation)",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional metadata for the parameter",
    )


class PolicyRule(BaseModel):
    """
    The rule portion of a policy definition.
    """

    model_config = ConfigDict(populate_by_name=True)

    if_condition: Dict[str, Any] = Field(
        ...,
        alias="if",
        description="Condition that triggers the policy",
    )
    then_effect: Dict[str, Any] = Field(
        ...,
        alias="then",
        description="Effect to apply when condition is met",
    )


class PolicyDefinitionProperties(BaseModel):
    """
    Properties of a policy definition.
    """

    model_config = ConfigDict(populate_by_name=True)

    display_name: Optional[str] = Field(
        default=None,
        alias="displayName",
        description="Human-readable name",
    )
    description: Optional[str] = Field(
        default=None,
        description="Policy description",
    )
    policy_type: PolicyType = Field(
        default=PolicyType.CUSTOM,
        alias="policyType",
        description="Type of policy (BuiltIn, Custom, Static)",
    )
    mode: PolicyMode = Field(
        default=PolicyMode.INDEXED,
        description="Evaluation mode (All, Indexed)",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional metadata",
    )
    parameters: Optional[Dict[str, PolicyParameter]] = Field(
        default=None,
        description="Policy parameters",
    )
    policy_rule: PolicyRule = Field(
        ...,
        alias="policyRule",
        description="The policy rule (if/then)",
    )


class PolicyDefinition(BaseModel):
    """
    A complete policy definition resource.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        ...,
        description="Full ARM resource ID",
    )
    name: str = Field(
        ...,
        description="Policy name (unique identifier)",
    )
    type: str = Field(
        default="ITL.Authorization/policyDefinitions",
        description="Resource type",
    )
    properties: PolicyDefinitionProperties = Field(
        ...,
        description="Policy properties",
    )

    def to_arm_json(self, indent: int = 2) -> str:
        """Serialize to ARM-compatible JSON."""
        return self.model_dump_json(by_alias=True, indent=indent)

    def to_arm_dict(self) -> Dict[str, Any]:
        """Convert to ARM-compatible dictionary."""
        return self.model_dump(by_alias=True)

    @classmethod
    def from_arm_json(cls, json_str: str) -> "PolicyDefinition":
        """Deserialize from ARM JSON."""
        return cls.model_validate_json(json_str)
