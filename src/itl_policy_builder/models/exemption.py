"""
Policy exemption Pydantic models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict

from itl_policy_builder.enums import ExemptionCategory


class PolicyExemptionProperties(BaseModel):
    """
    Typed properties for a policy exemption.
    """

    model_config = ConfigDict(populate_by_name=True)

    policy_assignment_id: str = Field(
        ...,
        alias="policyAssignmentId",
        description="ID of the policy assignment this exemption applies to",
    )
    exemption_category: ExemptionCategory = Field(
        ...,
        alias="exemptionCategory",
        description="Waiver or Mitigated",
    )
    display_name: Optional[str] = Field(
        default=None,
        alias="displayName",
        description="Human-readable display name",
    )
    description: Optional[str] = Field(
        default=None,
        description="Exemption description",
    )
    expires_on: Optional[datetime] = Field(
        default=None,
        alias="expiresOn",
        description="Expiry date/time (ISO 8601); exemption auto-expires after this",
    )
    policy_definition_reference_ids: Optional[List[str]] = Field(
        default=None,
        alias="policyDefinitionReferenceIds",
        description="Limit exemption to specific definitions within an initiative",
    )
    assignment_scope_validation: Optional[str] = Field(
        default=None,
        alias="assignmentScopeValidation",
        description="'Default' or 'DoNotValidate'",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional metadata",
    )


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
    properties: PolicyExemptionProperties = Field(
        ...,
        description="Exemption properties",
    )
