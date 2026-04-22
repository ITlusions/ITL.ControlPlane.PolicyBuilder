"""
Policy set (initiative) Pydantic models.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


class PolicySetDefinitionReference(BaseModel):
    """
    Reference to a policy within a policy set (initiative).
    """

    model_config = ConfigDict(populate_by_name=True)

    policy_definition_id: str = Field(
        ...,
        alias="policyDefinitionId",
        description="ID of the policy definition",
    )
    policy_definition_reference_id: Optional[str] = Field(
        default=None,
        alias="policyDefinitionReferenceId",
        description="Reference ID within the set",
    )
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parameter values for this policy",
    )
    group_names: Optional[List[str]] = Field(
        default=None,
        alias="groupNames",
        description="Groups this policy belongs to",
    )
    policy_definition_version: Optional[str] = Field(
        default=None,
        alias="policyDefinitionVersion",
        description="Pinned version of the referenced policy definition",
    )


class PolicySetDefinition(BaseModel):
    """
    A policy set definition (initiative) that groups multiple policies.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        ...,
        description="Full ARM resource ID",
    )
    name: str = Field(
        ...,
        description="Policy set name",
    )
    type: str = Field(
        default="ITL.Authorization/policySetDefinitions",
        description="Resource type",
    )
    properties: Dict[str, Any] = Field(
        default_factory=dict,
        description="Policy set properties",
    )

    def to_arm_json(self, indent: int = 2) -> str:
        """Serialize to ARM-compatible JSON."""
        return self.model_dump_json(by_alias=True, indent=indent)

    def to_arm_dict(self) -> Dict[str, Any]:
        """Convert to ARM-compatible dictionary."""
        return self.model_dump(by_alias=True)

    @classmethod
    def from_arm_json(cls, json_str: str) -> "PolicySetDefinition":
        """Deserialize from ARM JSON."""
        return cls.model_validate_json(json_str)
