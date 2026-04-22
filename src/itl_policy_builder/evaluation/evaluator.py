"""
Policy evaluation engine.

The PolicyEvaluator evaluates resources against policy definitions
and assignments to determine compliance and effects.

Example::

    from itl_policy_builder import PolicyEvaluator, PolicyBuilder, field, Effect

    # Create evaluator
    evaluator = PolicyEvaluator()

    # Register a policy
    policy = (
        PolicyBuilder("require-westeurope")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY,
        )
        .build()
    )
    evaluator.register_policy(policy)

    # Evaluate a resource
    resource = {
        "id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/ITL.Compute/virtualMachines/vm-1",
        "name": "vm-1",
        "type": "ITL.Compute/virtualMachines",
        "location": "eastus",
        "properties": {},
    }

    result = evaluator.evaluate(resource)
    # Result: EvaluationResult(effect=Effect.DENY, policy_id="...", message="...")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from itl_policy_builder.conditions import Condition, _get_nested_value
from itl_policy_builder.enums import ComplianceState, Effect, PolicyMode
from itl_policy_builder.models import (
    ComplianceResult,
    PolicyAssignment,
    PolicyDefinition,
    PolicyExemption,
)


@dataclass
class EvaluationResult:
    """
    Result of evaluating a single policy against a resource.
    """

    effect: Effect
    policy_definition_id: str
    policy_assignment_id: Optional[str] = None
    compliant: bool = True
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    modifications: Optional[List[Dict[str, Any]]] = None
    unknown: bool = False

    @property
    def should_deny(self) -> bool:
        """Returns True if this evaluation should block the operation."""
        return self.effect == Effect.DENY and not self.compliant

    @property
    def should_audit(self) -> bool:
        """Returns True if this evaluation should create an audit log."""
        return self.effect.is_audit_only and not self.compliant


@dataclass
class AggregateEvaluationResult:
    """
    Aggregated result of evaluating all policies against a resource.
    """

    resource_id: str
    results: List[EvaluationResult] = dataclass_field(default_factory=list)
    denied: bool = False
    deny_reasons: List[str] = dataclass_field(default_factory=list)
    audit_findings: List[str] = dataclass_field(default_factory=list)
    modifications: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    unknown_findings: List[str] = dataclass_field(default_factory=list)

    @property
    def overall_compliance(self) -> ComplianceState:
        """Calculate overall compliance state."""
        if self.denied:
            return ComplianceState.NON_COMPLIANT
        if self.audit_findings:
            return ComplianceState.NON_COMPLIANT
        if self.unknown_findings:
            return ComplianceState.UNKNOWN
        return ComplianceState.COMPLIANT

    def to_compliance_results(self) -> List[ComplianceResult]:
        """Convert to compliance result records."""
        from datetime import datetime

        results = []
        for result in self.results:
            if not result.compliant:
                results.append(
                    ComplianceResult(
                        resource_id=self.resource_id,
                        policy_assignment_id=result.policy_assignment_id or "",
                        policy_definition_id=result.policy_definition_id,
                        compliance_state=(
                            ComplianceState.NON_COMPLIANT
                            if result.effect.is_blocking
                            else ComplianceState.NON_COMPLIANT
                        ),
                        reason=result.message,
                        details=result.details,
                    )
                )
        return results


class PolicyEvaluator:
    """
    Policy evaluation engine.

    Evaluates resources against registered policies to determine
    compliance and effects. Can be used standalone or integrated
    into API Gateway middleware.
    """

    def __init__(self):
        self._policies: Dict[str, PolicyDefinition] = {}
        self._assignments: Dict[str, PolicyAssignment] = {}
        self._exemptions: Dict[str, PolicyExemption] = {}
        self._scope_cache: Dict[str, List[str]] = {}
        self._existence_checker: Optional[Callable[[Dict[str, Any], Dict[str, Any]], bool]] = None

    def set_existence_checker(
        self,
        fn: Callable[[Dict[str, Any], Dict[str, Any]], bool],
    ) -> None:
        """
        Register a callable for ``AuditIfNotExists`` / ``DeployIfNotExists`` checks.

        The callable receives ``(resource, details)`` where *resource* is the
        resource being evaluated and *details* is the ``then.details`` dict from
        the policy rule (containing ``type``, ``existenceCondition``, etc.).

        It must return ``True`` if the *related resource exists* (→ compliant)
        or ``False`` if it does not (→ non-compliant).

        Without a checker, existence-dependent effects are marked ``unknown``
        rather than non-compliant, because the evaluator cannot determine
        whether the related resource is present.

        Example::

            def my_checker(resource, details):
                # Look up whether the related resource exists in the real inventory
                return related_resource_exists(resource, details.get("type"))

            evaluator.set_existence_checker(my_checker)
        """
        self._existence_checker = fn

    def register_policy(self, policy: PolicyDefinition) -> None:
        """
        Register a policy definition.

        Args:
            policy: The policy definition to register
        """
        self._policies[policy.id] = policy

    def register_policies(self, *policies: PolicyDefinition) -> None:
        """Register multiple policy definitions."""
        for policy in policies:
            self.register_policy(policy)

    def unregister_policy(self, policy_id: str) -> None:
        """Remove a policy definition."""
        self._policies.pop(policy_id, None)

    def register_assignment(self, assignment: PolicyAssignment) -> None:
        """
        Register a policy assignment.

        Args:
            assignment: The policy assignment to register
        """
        self._assignments[assignment.id] = assignment
        # Invalidate scope cache
        self._scope_cache.clear()

    def register_exemption(self, exemption: PolicyExemption) -> None:
        """
        Register a policy exemption.

        Resources matching exemptions are skipped during evaluation.
        """
        self._exemptions[exemption.id] = exemption

    def _is_resource_in_scope(self, resource_id: str, scope: str) -> bool:
        """Check if a resource is within a scope."""
        # Resource is in scope if resource_id starts with scope
        return resource_id.lower().startswith(scope.lower())

    def _is_resource_excluded(
        self, resource_id: str, not_scopes: Optional[List[str]]
    ) -> bool:
        """Check if a resource is in an excluded scope."""
        if not not_scopes:
            return False
        resource_id_lower = resource_id.lower()
        return any(
            resource_id_lower.startswith(ns.lower()) for ns in not_scopes
        )

    def _is_resource_exempt(
        self, resource_id: str, assignment_id: str
    ) -> bool:
        """Check if a resource is exempt from a policy assignment."""
        for exemption in self._exemptions.values():
            props = exemption.properties
            # Check if exemption applies to this assignment
            if props.get("policyAssignmentId") != assignment_id:
                continue
            # Check if resource matches exemption scope
            exemption_scope = props.get("scope", "")
            if self._is_resource_in_scope(resource_id, exemption_scope):
                return True
        return False

    def _should_evaluate_resource_type(
        self, resource_type: str, mode: PolicyMode
    ) -> bool:
        """
        Determine if a resource type should be evaluated based on mode.

        - ALL: Evaluate all resource types
        - INDEXED: Only evaluate types that support tags and location
        """
        if mode == PolicyMode.ALL:
            return True

        # For INDEXED mode, skip certain resource types
        # that don't support tags/location
        skip_types = {
            "itl.core/resourcegroups",
            "itl.core/deployments",
            "itl.core/locations",
        }
        return resource_type.lower() not in skip_types

    def _evaluate_condition(
        self, condition_dict: Dict[str, Any], resource: Dict[str, Any]
    ) -> bool:
        """
        Evaluate a condition dictionary against a resource.

        Reconstructs condition from serialized form and evaluates.
        """
        # Handle logical operators
        if "allOf" in condition_dict:
            return all(
                self._evaluate_condition(c, resource)
                for c in condition_dict["allOf"]
            )
        if "anyOf" in condition_dict:
            return any(
                self._evaluate_condition(c, resource)
                for c in condition_dict["anyOf"]
            )
        if "not" in condition_dict:
            return not self._evaluate_condition(condition_dict["not"], resource)

        # Handle field conditions
        if "field" in condition_dict:
            field_path = condition_dict["field"]
            actual = _get_nested_value(resource, field_path)

            # Check each possible operator
            for op in [
                "equals", "notEquals", "in", "notIn",
                "contains", "notContains", "exists",
                "greater", "greaterOrEquals", "less", "lessOrEquals",
                "like", "notLike", "match", "notMatch",
            ]:
                if op in condition_dict:
                    expected = condition_dict[op]
                    return self._evaluate_operator(op, actual, expected)

        # Handle count conditions
        if "count" in condition_dict:
            count_def = condition_dict["count"]
            array = _get_nested_value(resource, count_def["field"])
            if not isinstance(array, list):
                count = 0
            elif "where" in count_def:
                count = sum(
                    1 for item in array
                    if self._evaluate_condition(count_def["where"], item)
                )
            else:
                count = len(array)

            for op in ["equals", "notEquals", "greater", "greaterOrEquals", "less", "lessOrEquals"]:
                if op in condition_dict:
                    return self._evaluate_operator(op, count, condition_dict[op])

        return False

    def _evaluate_operator(
        self, operator: str, actual: Any, expected: Any
    ) -> bool:
        """Evaluate a single operator."""
        match operator:
            case "equals":
                return actual == expected
            case "notEquals":
                return actual != expected
            case "in":
                return actual in expected if expected else False
            case "notIn":
                return actual not in expected if expected else True
            case "contains":
                if isinstance(actual, str):
                    return expected in actual
                if isinstance(actual, list):
                    return expected in actual
                return False
            case "notContains":
                return not self._evaluate_operator("contains", actual, expected)
            case "exists":
                return (actual is not None) == expected
            case "greater":
                return actual is not None and actual > expected
            case "greaterOrEquals":
                return actual is not None and actual >= expected
            case "less":
                return actual is not None and actual < expected
            case "lessOrEquals":
                return actual is not None and actual <= expected
            case "like":
                if actual is None:
                    return False
                pattern = expected.replace("%", ".*").replace("_", ".")
                return bool(re.fullmatch(pattern, str(actual), re.IGNORECASE))
            case "notLike":
                return not self._evaluate_operator("like", actual, expected)
            case "match":
                if actual is None:
                    return False
                return bool(re.search(expected, str(actual), re.IGNORECASE))
            case "notMatch":
                return not self._evaluate_operator("match", actual, expected)
            case _:
                return False

    def _evaluate_policy(
        self,
        policy: PolicyDefinition,
        resource: Dict[str, Any],
        assignment: Optional[PolicyAssignment] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> EvaluationResult:
        """
        Evaluate a single policy against a resource.

        Returns an EvaluationResult with the effect and compliance status.
        """
        props = policy.properties
        rule = props.policy_rule

        # Check if resource type should be evaluated
        resource_type = resource.get("type", "")
        if not self._should_evaluate_resource_type(resource_type, props.mode):
            return EvaluationResult(
                effect=Effect.DISABLED,
                policy_definition_id=policy.id,
                policy_assignment_id=assignment.id if assignment else None,
                compliant=True,
            )

        # Evaluate the condition
        # If condition is TRUE, the resource violates the policy
        if_condition = rule.if_condition
        condition_met = self._evaluate_condition(if_condition, resource)

        if condition_met:
            # Resource violates policy - apply effect
            then_effect = rule.then_effect
            effect = Effect(then_effect.get("effect", "Audit"))
            message = then_effect.get("message")
            details = then_effect.get("details")

            # AuditIfNotExists / DeployIfNotExists require an existence check
            # against a *related* resource rather than the resource itself.
            if effect in (Effect.AUDIT_IF_NOT_EXISTS, Effect.DEPLOY_IF_NOT_EXISTS):
                if self._existence_checker is not None:
                    exists = self._existence_checker(resource, details or {})
                    if exists:
                        # Related resource exists → this resource is compliant
                        return EvaluationResult(
                            effect=effect,
                            policy_definition_id=policy.id,
                            policy_assignment_id=assignment.id if assignment else None,
                            compliant=True,
                        )
                    # Related resource absent → non-compliant
                    return EvaluationResult(
                        effect=effect,
                        policy_definition_id=policy.id,
                        policy_assignment_id=assignment.id if assignment else None,
                        compliant=False,
                        message=message or f"Required related resource not found for {policy.id}",
                        details=details,
                    )
                else:
                    # No checker registered — compliance cannot be determined locally
                    return EvaluationResult(
                        effect=effect,
                        policy_definition_id=policy.id,
                        policy_assignment_id=assignment.id if assignment else None,
                        compliant=False,
                        unknown=True,
                        message=(
                            message
                            or f"Existence check required for {effect.value} policy "
                            f"{policy.id} — register an existence_checker to resolve"
                        ),
                        details=details,
                    )

            return EvaluationResult(
                effect=effect,
                policy_definition_id=policy.id,
                policy_assignment_id=assignment.id if assignment else None,
                compliant=False,
                message=message,
                details=details,
            )
        else:
            # Resource is compliant
            return EvaluationResult(
                effect=Effect.DISABLED,
                policy_definition_id=policy.id,
                policy_assignment_id=assignment.id if assignment else None,
                compliant=True,
            )

    def evaluate(
        self,
        resource: Dict[str, Any],
        scope: Optional[str] = None,
    ) -> AggregateEvaluationResult:
        """
        Evaluate all applicable policies against a resource.

        Args:
            resource: The resource to evaluate
            scope: Optional scope to limit evaluation (defaults to resource scope)

        Returns:
            AggregateEvaluationResult with all evaluation results
        """
        resource_id = resource.get("id", "")
        if not scope:
            # Extract scope from resource_id
            scope = resource_id

        aggregate = AggregateEvaluationResult(resource_id=resource_id)

        # First, evaluate through assignments (scope-aware)
        for assignment in self._assignments.values():
            assignment_scope = assignment.properties.scope

            # Check if resource is in scope
            if not self._is_resource_in_scope(resource_id, assignment_scope):
                continue

            # Check if resource is excluded
            if self._is_resource_excluded(
                resource_id, assignment.properties.not_scopes
            ):
                continue

            # Check if resource is exempt
            if self._is_resource_exempt(resource_id, assignment.id):
                continue

            # Check enforcement mode
            if assignment.properties.enforcement_mode == "DoNotEnforce":
                # Audit only - don't deny
                pass

            # Get the policy definition
            policy_id = assignment.properties.policy_definition_id
            policy = self._policies.get(policy_id)
            if not policy:
                continue

            # Get parameter values
            params = assignment.properties.parameters

            # Evaluate
            result = self._evaluate_policy(policy, resource, assignment, params)
            aggregate.results.append(result)

            if result.should_deny:
                # Only deny if enforcement mode is Default
                if assignment.properties.enforcement_mode == "Default":
                    aggregate.denied = True
                    aggregate.deny_reasons.append(
                        result.message or f"Denied by {policy_id}"
                    )
                else:
                    # Audit only
                    aggregate.audit_findings.append(
                        result.message or f"Would be denied by {policy_id}"
                    )

            if result.should_audit:
                aggregate.audit_findings.append(
                    result.message or f"Audit finding from {policy_id}"
                )

            if result.unknown:
                aggregate.unknown_findings.append(
                    result.message
                    or f"Existence check needed for {policy_id}"
                )

            if result.modifications:
                aggregate.modifications.extend(result.modifications)

        # Also evaluate unassigned policies (global evaluation)
        assigned_policy_ids = {
            a.properties.policy_definition_id for a in self._assignments.values()
        }
        for policy in self._policies.values():
            if policy.id in assigned_policy_ids:
                continue  # Already evaluated through assignment

            result = self._evaluate_policy(policy, resource)
            aggregate.results.append(result)

            # Unassigned policies only audit, never deny
            if result.unknown:
                aggregate.unknown_findings.append(
                    result.message or f"Existence check needed for unassigned {policy.id}"
                )
            elif not result.compliant:
                aggregate.audit_findings.append(
                    result.message or f"Audit finding from unassigned {policy.id}"
                )

        return aggregate

    def evaluate_for_deny(
        self,
        resource: Dict[str, Any],
    ) -> Tuple[bool, List[str]]:
        """
        Quick evaluation to check if a resource should be denied.

        Used by API Gateway middleware for fast pre-request checks.

        Returns:
            Tuple of (should_deny, list_of_reasons)
        """
        result = self.evaluate(resource)
        return result.denied, result.deny_reasons

    def get_applicable_policies(
        self, scope: str
    ) -> List[Tuple[PolicyAssignment, PolicyDefinition]]:
        """
        Get all policies applicable to a scope.

        Returns list of (assignment, policy) tuples.
        """
        applicable = []
        for assignment in self._assignments.values():
            assignment_scope = assignment.properties.scope
            # Assignment is applicable if scope is equal or a parent
            if scope.lower().startswith(assignment_scope.lower()):
                policy_id = assignment.properties.policy_definition_id
                policy = self._policies.get(policy_id)
                if policy:
                    applicable.append((assignment, policy))
        return applicable

    def clear(self) -> None:
        """Clear all registered policies, assignments, and exemptions."""
        self._policies.clear()
        self._assignments.clear()
        self._exemptions.clear()
        self._scope_cache.clear()


# ============================================================================
# Singleton Evaluator
# ============================================================================

_default_evaluator: Optional[PolicyEvaluator] = None


def get_evaluator() -> PolicyEvaluator:
    """Get the default policy evaluator singleton."""
    global _default_evaluator
    if _default_evaluator is None:
        _default_evaluator = PolicyEvaluator()
    return _default_evaluator


def evaluate_resource(resource: Dict[str, Any]) -> AggregateEvaluationResult:
    """Evaluate a resource using the default evaluator."""
    return get_evaluator().evaluate(resource)
