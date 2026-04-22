"""
Policy assignment Pydantic models.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


class PolicyAssignmentProperties(BaseModel):
    """
    Properties of a policy assignment.
    """

    model_config = ConfigDict(populate_by_name=True)

    display_name: Optional[str] = Field(
        default=None,
        alias="displayName",
        description="Human-readable name",
    )
    description: Optional[str] = Field(
        default=None,
        description="Assignment description",
    )
    policy_definition_id: str = Field(
        ...,
        alias="policyDefinitionId",
        description="ID of the policy definition to assign",
    )
    scope: str = Field(
        ...,
        description="Scope where policy applies (subscription, RG, etc.)",
    )
    not_scopes: Optional[List[str]] = Field(
        default=None,
        alias="notScopes",
        description="Scopes excluded from this assignment",
    )
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parameter values for this assignment",
    )
    enforcement_mode: str = Field(
        default="Default",
        alias="enforcementMode",
        description="Default = enforce, DoNotEnforce = audit only",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional metadata",
    )
    non_compliance_messages: Optional[List[Dict[str, str]]] = Field(
        default=None,
        alias="nonComplianceMessages",
        description="Custom messages for non-compliance",
    )
    overrides: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Override policy effect for selected resources",
    )
    resource_selectors: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        alias="resourceSelectors",
        description="Limit assignment to a subset of resources by location or type",
    )


class PolicyAssignment(BaseModel):
    """
    A policy assignment resource.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        ...,
        description="Full ARM resource ID",
    )
    name: str = Field(
        ...,
        description="Assignment name",
    )
    type: str = Field(
        default="ITL.Authorization/policyAssignments",
        description="Resource type",
    )
    location: Optional[str] = Field(
        default=None,
        description="Location (required for managed identity)",
    )
    identity: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Managed identity for remediation",
    )
    properties: PolicyAssignmentProperties = Field(
        ...,
        description="Assignment properties",
    )

    def to_arm_json(self, indent: int = 2) -> str:
        """Serialize to ARM-compatible JSON."""
        return self.model_dump_json(by_alias=True, indent=indent, exclude_none=True)
