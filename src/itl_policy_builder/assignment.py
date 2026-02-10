"""
Builder for policy assignments.

Policy assignments apply policy definitions to specific scopes
(subscriptions, resource groups, management groups).

Example::

    from itl_policy_builder import PolicyAssignmentBuilder

    assignment = (
        PolicyAssignmentBuilder("enforce-tags-prod")
        .policy_definition_id("/providers/ITL.Authorization/policyDefinitions/require-tags")
        .scope("/subscriptions/sub-prod-001")
        .display_name("Enforce Tags in Production")
        .parameter("requiredTags", ["environment", "owner", "cost-center"])
        .exclude_scope("/subscriptions/sub-prod-001/resourceGroups/legacy-rg")
        .build()
    )
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from itl_policy_builder.models import (
    PolicyAssignment,
    PolicyAssignmentProperties,
)


class PolicyAssignmentBuilder:
    """
    Fluent builder for creating policy assignments.

    Policy assignments bind policy definitions to scopes where they
    should be enforced.
    """

    def __init__(self, name: str):
        """
        Initialize a new assignment builder.

        Args:
            name: Unique assignment name
        """
        self._name = name
        self._policy_definition_id: Optional[str] = None
        self._scope: Optional[str] = None
        self._display_name: Optional[str] = None
        self._description: Optional[str] = None
        self._not_scopes: List[str] = []
        self._parameters: Dict[str, Any] = {}
        self._enforcement_mode: str = "Default"
        self._location: Optional[str] = None
        self._identity: Optional[Dict[str, Any]] = None
        self._metadata: Dict[str, Any] = {}
        self._non_compliance_messages: List[Dict[str, str]] = []

    def policy_definition_id(self, definition_id: str) -> PolicyAssignmentBuilder:
        """
        Set the policy definition to assign.

        Args:
            definition_id: Full ARM resource ID of the policy definition

        Example::

            .policy_definition_id("/providers/ITL.Authorization/policyDefinitions/allowed-locations")
        """
        self._policy_definition_id = definition_id
        return self

    def policy_set_definition_id(self, set_id: str) -> PolicyAssignmentBuilder:
        """
        Set a policy set (initiative) to assign.

        Args:
            set_id: Full ARM resource ID of the policy set definition
        """
        self._policy_definition_id = set_id
        return self

    def scope(self, scope: str) -> PolicyAssignmentBuilder:
        """
        Set the scope where the policy applies.

        Args:
            scope: ARM resource ID of the scope (subscription, RG, or management group)

        Examples::

            .scope("/subscriptions/sub-001")
            .scope("/subscriptions/sub-001/resourceGroups/app-rg")
            .scope("/providers/ITL.Management/managementGroups/prod-mg")
        """
        self._scope = scope
        return self

    def display_name(self, name: str) -> PolicyAssignmentBuilder:
        """Set the human-readable display name."""
        self._display_name = name
        return self

    def description(self, desc: str) -> PolicyAssignmentBuilder:
        """Set the assignment description."""
        self._description = desc
        return self

    def exclude_scope(self, scope: str) -> PolicyAssignmentBuilder:
        """
        Exclude a scope from this assignment.

        Child scopes of excluded scopes are also excluded.

        Args:
            scope: ARM resource ID of the scope to exclude
        """
        self._not_scopes.append(scope)
        return self

    def exclude_scopes(self, *scopes: str) -> PolicyAssignmentBuilder:
        """Exclude multiple scopes from this assignment."""
        self._not_scopes.extend(scopes)
        return self

    def parameter(self, name: str, value: Any) -> PolicyAssignmentBuilder:
        """
        Set a parameter value for this assignment.

        Args:
            name: Parameter name (must match policy definition parameter)
            value: Parameter value
        """
        self._parameters[name] = {"value": value}
        return self

    def parameters(self, **kwargs: Any) -> PolicyAssignmentBuilder:
        """Set multiple parameter values."""
        for name, value in kwargs.items():
            self.parameter(name, value)
        return self

    def enforcement_mode(self, mode: str) -> PolicyAssignmentBuilder:
        """
        Set the enforcement mode.

        Args:
            mode: "Default" (enforce) or "DoNotEnforce" (audit only)
        """
        if mode not in ("Default", "DoNotEnforce"):
            raise ValueError(f"Invalid enforcement mode: {mode}")
        self._enforcement_mode = mode
        return self

    def audit_only(self) -> PolicyAssignmentBuilder:
        """Set enforcement mode to audit only (DoNotEnforce)."""
        self._enforcement_mode = "DoNotEnforce"
        return self

    def enforce(self) -> PolicyAssignmentBuilder:
        """Set enforcement mode to Default (enforce)."""
        self._enforcement_mode = "Default"
        return self

    def location(self, location: str) -> PolicyAssignmentBuilder:
        """
        Set the location for managed identity.

        Required when using DeployIfNotExists or Modify effects.
        """
        self._location = location
        return self

    def with_managed_identity(
        self,
        identity_type: str = "SystemAssigned",
        user_assigned_id: Optional[str] = None,
    ) -> PolicyAssignmentBuilder:
        """
        Configure managed identity for remediation.

        Required for policies with DeployIfNotExists or Modify effects.

        Args:
            identity_type: "SystemAssigned" or "UserAssigned"
            user_assigned_id: Resource ID of user-assigned identity (if UserAssigned)
        """
        if identity_type == "SystemAssigned":
            self._identity = {"type": "SystemAssigned"}
        elif identity_type == "UserAssigned":
            if not user_assigned_id:
                raise ValueError("user_assigned_id required for UserAssigned identity")
            self._identity = {
                "type": "UserAssigned",
                "userAssignedIdentities": {user_assigned_id: {}},
            }
        else:
            raise ValueError(f"Invalid identity type: {identity_type}")
        return self

    def metadata(self, **kwargs: Any) -> PolicyAssignmentBuilder:
        """Add metadata to the assignment."""
        self._metadata.update(kwargs)
        return self

    def non_compliance_message(
        self,
        message: str,
        policy_definition_reference_id: Optional[str] = None,
    ) -> PolicyAssignmentBuilder:
        """
        Add a custom non-compliance message.

        Args:
            message: Message to display for non-compliant resources
            policy_definition_reference_id: For initiatives, the specific policy reference
        """
        msg: Dict[str, str] = {"message": message}
        if policy_definition_reference_id:
            msg["policyDefinitionReferenceId"] = policy_definition_reference_id
        self._non_compliance_messages.append(msg)
        return self

    def _generate_id(self) -> str:
        """Generate the ARM resource ID for this assignment."""
        if self._scope:
            return f"{self._scope}/providers/ITL.Authorization/policyAssignments/{self._name}"
        return f"/providers/ITL.Authorization/policyAssignments/{self._name}"

    def build(self) -> PolicyAssignment:
        """
        Build and return the PolicyAssignment.

        Returns:
            PolicyAssignment: The complete policy assignment.

        Raises:
            ValueError: If required fields are missing.
        """
        if not self._policy_definition_id:
            raise ValueError("Policy definition ID is required. Use policy_definition_id().")
        if not self._scope:
            raise ValueError("Scope is required. Use scope().")

        properties = PolicyAssignmentProperties(
            display_name=self._display_name or self._name,
            description=self._description,
            policy_definition_id=self._policy_definition_id,
            scope=self._scope,
            not_scopes=self._not_scopes if self._not_scopes else None,
            parameters=self._parameters if self._parameters else None,
            enforcement_mode=self._enforcement_mode,
            metadata=self._metadata if self._metadata else None,
            non_compliance_messages=(
                self._non_compliance_messages if self._non_compliance_messages else None
            ),
        )

        return PolicyAssignment(
            id=self._generate_id(),
            name=self._name,
            type="ITL.Authorization/policyAssignments",
            location=self._location,
            identity=self._identity,
            properties=properties,
        )

    def build_json(self) -> str:
        """Build and return ARM-compatible JSON."""
        return self.build().to_arm_json()

    def build_dict(self) -> Dict[str, Any]:
        """Build and return ARM-compatible dictionary."""
        return self.build().model_dump(by_alias=True, exclude_none=True)
