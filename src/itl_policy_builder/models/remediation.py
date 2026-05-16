"""
Remediation and compliance Pydantic models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict

from itl_policy_builder.enums import ComplianceState, RemediationState


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
        default_factory=lambda: datetime.now(timezone.utc),
        description="When compliance was evaluated",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason for non-compliance",
    )
    last_evaluation_time: Optional[datetime] = Field(
        default=None,
        alias="lastEvaluationTime",
        description="Timestamp of the most recent evaluation",
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
        default_factory=lambda: datetime.now(timezone.utc),
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
