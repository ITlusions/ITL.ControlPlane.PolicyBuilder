"""
Fluent builder for policy exemptions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from itl_policy_builder.enums import ExemptionCategory
from itl_policy_builder.models import PolicyExemption, PolicyExemptionProperties


class PolicyExemptionBuilder:
    """Fluent builder for PolicyExemption."""

    def __init__(self, name: str, scope: Optional[str] = None):
        self._name = name
        self._scope = scope
        self._policy_assignment_id: Optional[str] = None
        self._exemption_category: ExemptionCategory = ExemptionCategory.WAIVER
        self._display_name: Optional[str] = None
        self._description: Optional[str] = None
        self._expires_on: Optional[datetime] = None
        self._policy_definition_reference_ids: List[str] = []
        self._assignment_scope_validation: Optional[str] = None
        self._metadata: Dict[str, Any] = {}

    def scope(self, scope: str) -> PolicyExemptionBuilder:
        self._scope = scope
        return self

    def policy_assignment_id(self, assignment_id: str) -> PolicyExemptionBuilder:
        self._policy_assignment_id = assignment_id
        return self

    def category(self, category: Union[ExemptionCategory, str]) -> PolicyExemptionBuilder:
        if isinstance(category, str):
            category = ExemptionCategory(category)
        self._exemption_category = category
        return self

    def waiver(self) -> PolicyExemptionBuilder:
        self._exemption_category = ExemptionCategory.WAIVER
        return self

    def mitigated(self) -> PolicyExemptionBuilder:
        self._exemption_category = ExemptionCategory.MITIGATED
        return self

    def display_name(self, name: str) -> PolicyExemptionBuilder:
        self._display_name = name
        return self

    def description(self, desc: str) -> PolicyExemptionBuilder:
        self._description = desc
        return self

    def expires_on(self, dt: Union[datetime, str]) -> PolicyExemptionBuilder:
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt)
        self._expires_on = dt
        return self

    def for_policy_references(self, *reference_ids: str) -> PolicyExemptionBuilder:
        self._policy_definition_reference_ids.extend(reference_ids)
        return self

    def validate_scope(self, mode: str = "Default") -> PolicyExemptionBuilder:
        self._assignment_scope_validation = mode
        return self

    def metadata(self, **kwargs: Any) -> PolicyExemptionBuilder:
        self._metadata.update(kwargs)
        return self

    def _generate_id(self) -> str:
        if self._scope:
            return (
                f"{self._scope}/providers/ITL.Authorization"
                f"/policyExemptions/{self._name}"
            )
        return f"/providers/ITL.Authorization/policyExemptions/{self._name}"

    def build(self) -> PolicyExemption:
        if not self._policy_assignment_id:
            raise ValueError(
                "Policy assignment ID is required. Use .policy_assignment_id()."
            )

        return PolicyExemption(
            id=self._generate_id(),
            name=self._name,
            properties=PolicyExemptionProperties(
                policy_assignment_id=self._policy_assignment_id,
                exemption_category=self._exemption_category,
                display_name=self._display_name,
                description=self._description,
                expires_on=self._expires_on,
                policy_definition_reference_ids=(
                    self._policy_definition_reference_ids
                    if self._policy_definition_reference_ids
                    else None
                ),
                assignment_scope_validation=self._assignment_scope_validation,
                metadata=self._metadata if self._metadata else None,
            ),
        )

    def build_json(self) -> str:
        return self.build().model_dump_json(by_alias=True, indent=2, exclude_none=True)

    def build_dict(self) -> Dict[str, Any]:
        return self.build().model_dump(by_alias=True, exclude_none=True)
