"""
Pydantic models for policy definitions, assignments, and compliance.

These models are ARM-compatible and can be serialized to JSON for
storage and API transmission.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict

from itl_policy_builder.enums import (
    Effect,
    PolicyMode,
    PolicyType,
    ComplianceState,
    ExemptionCategory,
    RemediationState,
)


class PolicyParameter(BaseModel):
    """
    A parameter definition for a policy.

    Parameters allow policies to be reusable with different values
    provided at assignment time.
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

    Contains the condition (if) and effect (then) of the policy.
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

    Example ARM-style resource::

        {
            "id": "/providers/ITL.Authorization/policyDefinitions/require-tag-environment",
            "name": "require-tag-environment",
            "type": "ITL.Authorization/policyDefinitions",
            "properties": {
                "displayName": "Require Environment Tag",
                "policyType": "Custom",
                "mode": "Indexed",
                "policyRule": {
                    "if": {"field": "tags.environment", "exists": false},
                    "then": {"effect": "Deny"}
                }
            }
        }
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
    def from_arm_json(cls, json_str: str) -> PolicyDefinition:
        """Deserialize from ARM JSON."""
        return cls.model_validate_json(json_str)


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


class PolicyAssignment(BaseModel):
    """
    A policy assignment resource.

    Assigns a policy definition to a specific scope.
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


class PolicySetDefinition(BaseModel):
    """
    A policy set definition (initiative) that groups multiple policies.

    Initiatives allow applying multiple policies as a single unit.
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


class PolicyExemption(BaseModel):
    """
    A policy exemption that excludes resources from policy evaluation.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        ...,
        description="Full ARM resource ID",
    )
    name: str = Field(
        ...,
        description="Exemption name",
    )
    type: str = Field(
        default="ITL.Authorization/policyExemptions",
        description="Resource type",
    )
    properties: Dict[str, Any] = Field(
        default_factory=dict,
        description="Exemption properties",
    )


class ComplianceResult(BaseModel):
    """
    Compliance evaluation result for a single resource.
    """

    model_config = ConfigDict(populate_by_name=True)

    resource_id: str = Field(
        ...,
        alias="resourceId",
        description="ID of the evaluated resource",
    )
    policy_assignment_id: str = Field(
        ...,
        alias="policyAssignmentId",
        description="ID of the policy assignment",
    )
    policy_definition_id: str = Field(
        ...,
        alias="policyDefinitionId",
        description="ID of the policy definition",
    )
    compliance_state: ComplianceState = Field(
        ...,
        alias="complianceState",
        description="Compliance state of the resource",
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When compliance was evaluated",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason for non-compliance",
    )
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional compliance details",
    )


class RemediationTask(BaseModel):
    """
    A remediation task for fixing non-compliant resources.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        default_factory=lambda: f"remediation-{uuid4().hex[:8]}",
        description="Remediation task ID",
    )
    name: str = Field(
        ...,
        description="Task name",
    )
    policy_assignment_id: str = Field(
        ...,
        alias="policyAssignmentId",
        description="Policy assignment to remediate",
    )
    policy_definition_id: Optional[str] = Field(
        default=None,
        alias="policyDefinitionId",
        description="Specific policy definition (for initiatives)",
    )
    resource_discovery_mode: str = Field(
        default="ExistingNonCompliant",
        alias="resourceDiscoveryMode",
        description="Which resources to remediate",
    )
    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Filters to limit remediation scope",
    )
    state: RemediationState = Field(
        default=RemediationState.PENDING,
        description="Current state of the task",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        alias="createdAt",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        alias="completedAt",
    )
    deployment_status: Optional[Dict[str, Any]] = Field(
        default=None,
        alias="deploymentStatus",
        description="Status of remediation deployments",
    )
