"""
Policy testing helpers for unit testing policy definitions.

Provides assertion-style helpers that make it easy to test policy behaviour
against sample resources without needing a real ITL or Azure environment.

The helpers integrate with standard ``pytest`` (or ``unittest``) workflows:
``PolicyAssertionError`` extends ``AssertionError``, so failed assertions
show up as ordinary test failures.

Example::

    import pytest
    from itl_policy_builder import PolicyBuilder, Effect, field
    from itl_policy_builder.testing import PolicyTestHelper

    @pytest.fixture
    def policy():
        return (
            PolicyBuilder("deny-non-westeurope")
            .with_rule(
                if_=field("location").not_equals("westeurope"),
                then=Effect.DENY,
            )
            .build()
        )

    def test_deny_wrong_location(policy):
        t = PolicyTestHelper(policy)
        t.assert_deny({"id": "r1", "location": "eastus"})

    def test_allow_correct_location(policy):
        t = PolicyTestHelper(policy)
        t.assert_compliant({"id": "r2", "location": "westeurope"})
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from itl_policy_builder.enums import Effect
from itl_policy_builder.evaluation.evaluator import AggregateEvaluationResult, PolicyEvaluator
from itl_policy_builder.models import PolicyDefinition


class PolicyAssertionError(AssertionError):
    """
    Raised when a policy assertion fails.

    Attributes:
        resource: The resource dict that was evaluated.
        expected: Human-readable description of the expected outcome.
        actual: Human-readable description of the actual outcome.
    """

    def __init__(
        self,
        message: str,
        resource: Dict[str, Any],
        expected: str,
        actual: str,
    ):
        self.resource = resource
        self.expected = expected
        self.actual = actual
        resource_label = resource.get("id") or resource.get("name") or repr(resource)
        super().__init__(
            f"{message}\n"
            f"  Resource : {resource_label}\n"
            f"  Expected : {expected}\n"
            f"  Actual   : {actual}"
        )


class PolicyTestHelper:
    """
    Assertion helper for unit-testing a single :class:`PolicyDefinition`.

    Wraps a :class:`~itl_policy_builder.evaluator.PolicyEvaluator` configured
    with the provided policy and exposes ``assert_*`` methods that raise
    :class:`PolicyAssertionError` on failure.

    Example::

        helper = PolicyTestHelper(my_policy)

        # Must deny
        helper.assert_deny({"id": "bad-vm", "location": "eastus"})

        # Must be compliant
        helper.assert_compliant({"id": "good-vm", "location": "westeurope"})

        # Must trigger an audit (not block)
        helper.assert_audit({"id": "audit-vm", "type": "legacy/resource"})
    """

    def __init__(self, policy: PolicyDefinition):
        """
        Initialise the helper with a policy definition.

        Args:
            policy: The :class:`PolicyDefinition` to test.
        """
        self._policy = policy
        self._evaluator = PolicyEvaluator()
        self._evaluator.register_policy(policy)

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _evaluate(self, resource: Dict[str, Any]) -> AggregateEvaluationResult:
        return self._evaluator.evaluate(resource)

    # ------------------------------------------------------------------ #
    # Assertions                                                           #
    # ------------------------------------------------------------------ #

    def _would_deny(self, result: AggregateEvaluationResult) -> bool:
        """True if the result is (or would be) a deny — including unassigned policies."""
        if result.denied:
            return True
        return any(
            r.effect == Effect.DENY and not r.compliant
            for r in result.results
        )

    def assert_deny(
        self,
        resource: Dict[str, Any],
        message: Optional[str] = None,
    ) -> None:
        """
        Assert that *resource* would be **denied**.

        Args:
            resource: Resource dict to evaluate.
            message: Optional prefix for the failure message.

        Raises:
            PolicyAssertionError: If the resource is not denied.
        """
        result = self._evaluate(resource)
        if not self._would_deny(result):
            effects = [r.effect.value for r in result.results if not r.compliant]
            raise PolicyAssertionError(
                message or "Expected resource to be DENIED",
                resource,
                expected="Deny",
                actual=", ".join(effects) if effects else "Compliant",
            )

    def assert_compliant(
        self,
        resource: Dict[str, Any],
        message: Optional[str] = None,
    ) -> None:
        """
        Assert that *resource* is **compliant** (no deny, no audit findings).

        Args:
            resource: Resource dict to evaluate.
            message: Optional prefix for the failure message.

        Raises:
            PolicyAssertionError: If the resource is denied or has audit findings.
        """
        result = self._evaluate(resource)
        if result.denied or result.audit_findings:
            issues = result.deny_reasons + result.audit_findings
            raise PolicyAssertionError(
                message or "Expected resource to be COMPLIANT",
                resource,
                expected="Compliant",
                actual="; ".join(issues),
            )

    def assert_audit(
        self,
        resource: Dict[str, Any],
        message: Optional[str] = None,
    ) -> None:
        """
        Assert that *resource* produces an **audit finding** but is **not denied**.

        Args:
            resource: Resource dict to evaluate.
            message: Optional prefix for the failure message.

        Raises:
            PolicyAssertionError: If the resource is denied, or if there are no
                audit findings.
        """
        result = self._evaluate(resource)
        if result.denied:
            raise PolicyAssertionError(
                message or "Expected AUDIT but resource was DENIED",
                resource,
                expected="Audit",
                actual=f"Denied: {'; '.join(result.deny_reasons)}",
            )
        if not result.audit_findings:
            raise PolicyAssertionError(
                message or "Expected AUDIT finding but resource was COMPLIANT",
                resource,
                expected="Audit finding",
                actual="Compliant",
            )

    def assert_effect(
        self,
        resource: Dict[str, Any],
        effect: Effect,
        message: Optional[str] = None,
    ) -> None:
        """
        Assert that *resource* triggers the given *effect*.

        Args:
            resource: Resource dict to evaluate.
            effect: The :class:`~itl_policy_builder.enums.Effect` expected.
            message: Optional prefix for the failure message.

        Raises:
            PolicyAssertionError: If the expected effect is not produced.
        """
        result = self._evaluate(resource)
        actual_effects = [r.effect for r in result.results]
        if effect not in actual_effects:
            raise PolicyAssertionError(
                message or f"Expected effect {effect.value!r}",
                resource,
                expected=effect.value,
                actual=", ".join(e.value for e in actual_effects) or "Compliant",
            )

    def assert_modifications(
        self,
        resource: Dict[str, Any],
        expected_count: Optional[int] = None,
        message: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Assert that *resource* would be **modified** by an Append/Modify policy.

        Args:
            resource: Resource dict to evaluate.
            expected_count: If provided, assert exactly this many modification
                operations are returned.
            message: Optional prefix for the failure message.

        Returns:
            The list of modification operation dicts.

        Raises:
            PolicyAssertionError: If no modifications are produced, or if
                *expected_count* does not match.
        """
        result = self._evaluate(resource)
        if not result.modifications:
            raise PolicyAssertionError(
                message or "Expected MODIFICATIONS but none were produced",
                resource,
                expected="At least one modification",
                actual="None",
            )
        if expected_count is not None and len(result.modifications) != expected_count:
            raise PolicyAssertionError(
                message or f"Expected {expected_count} modification(s)",
                resource,
                expected=f"{expected_count} modification(s)",
                actual=f"{len(result.modifications)} modification(s)",
            )
        return result.modifications

    def assert_not_deny(
        self,
        resource: Dict[str, Any],
        message: Optional[str] = None,
    ) -> None:
        """
        Assert that *resource* is **not denied** (may still have audit findings).

        Args:
            resource: Resource dict to evaluate.
            message: Optional prefix for the failure message.

        Raises:
            PolicyAssertionError: If the resource is denied.
        """
        result = self._evaluate(resource)
        if self._would_deny(result):
            raise PolicyAssertionError(
                message or "Expected resource NOT to be denied",
                resource,
                expected="Not denied",
                actual=f"Denied: {'; '.join(result.deny_reasons)}",
            )

    # ------------------------------------------------------------------ #
    # Batch helpers                                                        #
    # ------------------------------------------------------------------ #

    def assert_all_deny(
        self, resources: List[Dict[str, Any]], message: Optional[str] = None
    ) -> None:
        """Assert that every resource in *resources* is denied."""
        for resource in resources:
            self.assert_deny(resource, message=message)

    def assert_all_compliant(
        self, resources: List[Dict[str, Any]], message: Optional[str] = None
    ) -> None:
        """Assert that every resource in *resources* is compliant."""
        for resource in resources:
            self.assert_compliant(resource, message=message)
