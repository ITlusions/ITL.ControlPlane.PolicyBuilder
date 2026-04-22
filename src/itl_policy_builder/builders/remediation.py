"""
Fluent builder for policy remediation tasks.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from itl_policy_builder.models import RemediationTask


class RemediationBuilder:
    """Fluent builder for RemediationTask."""

    def __init__(self, name: str):
        self._name = name
        self._policy_assignment_id: Optional[str] = None
        self._policy_definition_id: Optional[str] = None
        self._resource_discovery_mode: str = "ExistingNonCompliant"
        self._filters: Optional[Dict[str, Any]] = None

    def policy_assignment_id(self, assignment_id: str) -> RemediationBuilder:
        self._policy_assignment_id = assignment_id
        return self

    def policy_definition_id(self, definition_id: str) -> RemediationBuilder:
        self._policy_definition_id = definition_id
        return self

    def all_non_compliant(self) -> RemediationBuilder:
        self._resource_discovery_mode = "ExistingNonCompliant"
        return self

    def re_evaluate_compliance(self) -> RemediationBuilder:
        self._resource_discovery_mode = "ReEvaluateCompliance"
        return self

    def filters(
        self,
        resource_type: Optional[str] = None,
        locations: Optional[List[str]] = None,
        **extra: Any,
    ) -> RemediationBuilder:
        if self._filters is None:
            self._filters = {}
        if resource_type is not None:
            self._filters["resourceType"] = resource_type
        if locations is not None:
            self._filters["locations"] = locations
        self._filters.update(extra)
        return self

    def build(self) -> RemediationTask:
        if not self._policy_assignment_id:
            raise ValueError(
                "Policy assignment ID is required. Use .policy_assignment_id()."
            )

        return RemediationTask(
            name=self._name,
            policy_assignment_id=self._policy_assignment_id,
            policy_definition_id=self._policy_definition_id,
            resource_discovery_mode=self._resource_discovery_mode,
            filters=self._filters,
        )

    def build_dict(self) -> Dict[str, Any]:
        return self.build().model_dump(by_alias=True, exclude_none=True)

    def build_json(self) -> str:
        return self.build().model_dump_json(by_alias=True, indent=2, exclude_none=True)
