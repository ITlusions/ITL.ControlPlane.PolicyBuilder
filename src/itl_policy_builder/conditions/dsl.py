"""
Policy condition DSL for expressing policy rules.

This module provides a fluent API for building policy conditions
that evaluate resources against rules.

Example usage::

    from itl_policy_builder.conditions import field, all_of, any_of, not_

    # Simple condition: location must be westeurope
    cond = field("location").equals("westeurope")

    # Nested condition: must be in allowed regions AND have required tags
    cond = all_of(
        field("location").in_("westeurope", "northeurope"),
        field("tags.environment").exists(),
        field("tags.cost-center").matches(r"^CC-\d{4}$"),
    )

    # Complex condition with negation
    cond = all_of(
        not_(field("type").equals("ITL.Compute/virtualMachines")),
        any_of(
            field("properties.sku").equals("Standard"),
            field("properties.sku").equals("Premium"),
        ),
    )
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field as dataclass_field
from typing import Any, List, Optional, Sequence, Union


class Condition(ABC):
    """
    Base class for all policy conditions.

    Conditions can be serialized to ARM-compatible JSON format
    for storage and evaluation.
    """

    @abstractmethod
    def to_dict(self) -> dict:
        """Convert condition to ARM-compatible dictionary."""
        ...

    @abstractmethod
    def evaluate(self, resource: dict) -> bool:
        """
        Evaluate the condition against a resource.

        Args:
            resource: The resource dictionary to evaluate.

        Returns:
            True if the condition matches, False otherwise.
        """
        ...

    def to_json(self) -> str:
        """Serialize condition to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def __and__(self, other: Condition) -> AllOfCondition:
        """Combine conditions with AND."""
        return all_of(self, other)

    def __or__(self, other: Condition) -> AnyOfCondition:
        """Combine conditions with OR."""
        return any_of(self, other)

    def __invert__(self) -> NotCondition:
        """Negate condition with ~."""
        return not_(self)


@dataclass
class FieldCondition(Condition):
    """
    Condition that evaluates a specific field of a resource.

    Supports various comparison operators like equals, contains,
    exists, matches (regex), greater/less than, etc.
    """

    field_path: str
    operator: str
    value: Any = None
    case_sensitive: bool = True

    def to_dict(self) -> dict:
        result = {
            "field": self.field_path,
            self.operator: self.value,
        }
        if not self.case_sensitive and self.operator in ("equals", "contains", "like"):
            result["caseSensitive"] = False
        return result

    def evaluate(self, resource: dict) -> bool:
        """Evaluate field condition against resource."""
        actual = _get_nested_value(resource, self.field_path)

        match self.operator:
            case "equals":
                return _compare_values(actual, self.value, self.case_sensitive)
            case "notEquals":
                return not _compare_values(actual, self.value, self.case_sensitive)
            case "in":
                return actual in self.value if self.value else False
            case "notIn":
                return actual not in self.value if self.value else True
            case "contains":
                if isinstance(actual, str) and isinstance(self.value, str):
                    if self.case_sensitive:
                        return self.value in actual
                    return self.value.lower() in actual.lower()
                if isinstance(actual, list):
                    return self.value in actual
                return False
            case "notContains":
                return not FieldCondition(
                    self.field_path, "contains", self.value, self.case_sensitive
                ).evaluate(resource)
            case "exists":
                return (actual is not None) == self.value
            case "greater":
                return actual is not None and actual > self.value
            case "greaterOrEquals":
                return actual is not None and actual >= self.value
            case "less":
                return actual is not None and actual < self.value
            case "lessOrEquals":
                return actual is not None and actual <= self.value
            case "like":
                # SQL-style LIKE with % wildcards
                if actual is None or self.value is None:
                    return False
                pattern = self.value.replace("%", ".*").replace("_", ".")
                flags = 0 if self.case_sensitive else re.IGNORECASE
                return bool(re.fullmatch(pattern, str(actual), flags))
            case "notLike":
                return not FieldCondition(
                    self.field_path, "like", self.value, self.case_sensitive
                ).evaluate(resource)
            case "match":
                # Regex match
                if actual is None:
                    return False
                flags = 0 if self.case_sensitive else re.IGNORECASE
                return bool(re.search(self.value, str(actual), flags))
            case "notMatch":
                return not FieldCondition(
                    self.field_path, "match", self.value, self.case_sensitive
                ).evaluate(resource)
            case "matchInsensitively":
                if actual is None:
                    return False
                return bool(re.search(self.value, str(actual), re.IGNORECASE))
            case "notMatchInsensitively":
                if actual is None:
                    return True
                return not bool(re.search(self.value, str(actual), re.IGNORECASE))
            case "containsInsensitively":
                if actual is None:
                    return False
                if isinstance(actual, str) and isinstance(self.value, str):
                    return self.value.lower() in actual.lower()
                if isinstance(actual, list):
                    return any(
                        str(self.value).lower() == str(e).lower() for e in actual
                    )
                return False
            case "notContainsInsensitively":
                return not FieldCondition(
                    self.field_path, "containsInsensitively", self.value
                ).evaluate(resource)
            case "hasValue":
                # True when field exists AND is non-null / non-empty string
                if self.value:
                    return actual is not None and actual != ""
                return actual is None or actual == ""
            case _:
                raise ValueError(f"Unknown operator: {self.operator}")


class FieldBuilder:
    """
    Fluent builder for field conditions.

    Usage::

        field("location").equals("westeurope")
        field("tags.environment").exists()
        field("properties.sku").in_("Standard", "Premium")
    """

    def __init__(self, field_path: str, case_sensitive: bool = True):
        self.field_path = field_path
        self.case_sensitive = case_sensitive

    def ignore_case(self) -> FieldBuilder:
        """Make subsequent comparisons case-insensitive."""
        return FieldBuilder(self.field_path, case_sensitive=False)

    def equals(self, value: Any) -> FieldCondition:
        """Field must equal the value."""
        return FieldCondition(self.field_path, "equals", value, self.case_sensitive)

    def not_equals(self, value: Any) -> FieldCondition:
        """Field must not equal the value."""
        return FieldCondition(self.field_path, "notEquals", value, self.case_sensitive)

    def in_(self, *values: Any) -> FieldCondition:
        """Field must be one of the values."""
        return FieldCondition(self.field_path, "in", list(values), self.case_sensitive)

    def not_in(self, *values: Any) -> FieldCondition:
        """Field must not be one of the values."""
        return FieldCondition(self.field_path, "notIn", list(values), self.case_sensitive)

    def contains(self, value: str) -> FieldCondition:
        """Field must contain the substring (for strings) or element (for arrays)."""
        return FieldCondition(self.field_path, "contains", value, self.case_sensitive)

    def not_contains(self, value: str) -> FieldCondition:
        """Field must not contain the substring/element."""
        return FieldCondition(self.field_path, "notContains", value, self.case_sensitive)

    def exists(self, exists: bool = True) -> FieldCondition:
        """Field must exist (or not exist if exists=False)."""
        return FieldCondition(self.field_path, "exists", exists)

    def greater_than(self, value: Union[int, float]) -> FieldCondition:
        """Field must be greater than the value."""
        return FieldCondition(self.field_path, "greater", value)

    def greater_or_equals(self, value: Union[int, float]) -> FieldCondition:
        """Field must be greater than or equal to the value."""
        return FieldCondition(self.field_path, "greaterOrEquals", value)

    def less_than(self, value: Union[int, float]) -> FieldCondition:
        """Field must be less than the value."""
        return FieldCondition(self.field_path, "less", value)

    def less_or_equals(self, value: Union[int, float]) -> FieldCondition:
        """Field must be less than or equal to the value."""
        return FieldCondition(self.field_path, "lessOrEquals", value)

    def like(self, pattern: str) -> FieldCondition:
        """Field must match SQL-style LIKE pattern (% = any chars, _ = single char)."""
        return FieldCondition(self.field_path, "like", pattern, self.case_sensitive)

    def not_like(self, pattern: str) -> FieldCondition:
        """Field must not match SQL-style LIKE pattern."""
        return FieldCondition(self.field_path, "notLike", pattern, self.case_sensitive)

    def matches(self, regex: str) -> FieldCondition:
        """Field must match the regex pattern."""
        return FieldCondition(self.field_path, "match", regex, self.case_sensitive)

    def not_matches(self, regex: str) -> FieldCondition:
        """Field must not match the regex pattern."""
        return FieldCondition(self.field_path, "notMatch", regex, self.case_sensitive)

    def match_insensitively(self, regex: str) -> FieldCondition:
        """Field must match regex, case-insensitively (ARM native operator)."""
        return FieldCondition(self.field_path, "matchInsensitively", regex)

    def not_match_insensitively(self, regex: str) -> FieldCondition:
        """Field must not match regex, case-insensitively (ARM native operator)."""
        return FieldCondition(self.field_path, "notMatchInsensitively", regex)

    def contains_insensitively(self, value: str) -> FieldCondition:
        """Field must contain the value, case-insensitively (ARM native operator)."""
        return FieldCondition(self.field_path, "containsInsensitively", value)

    def not_contains_insensitively(self, value: str) -> FieldCondition:
        """Field must not contain the value, case-insensitively (ARM native operator)."""
        return FieldCondition(self.field_path, "notContainsInsensitively", value)

    def has_value(self, exists: bool = True) -> FieldCondition:
        """Field must be non-null and non-empty (or null/empty if exists=False)."""
        return FieldCondition(self.field_path, "hasValue", exists)


def field(path: str) -> FieldBuilder:
    """
    Start building a field condition.

    Args:
        path: Dot-separated path to the field (e.g., ``"properties.sku.name"``)

    Returns:
        FieldBuilder for chaining condition operators.

    Example::

        field("location").equals("westeurope")
        field("tags.environment").exists()
        field("properties.vmSize").in_("Standard_D2_v3", "Standard_D4_v3")
    """
    return FieldBuilder(path)


def array_field(
    array_path: str,
    element_field: Optional[str] = None,
) -> FieldBuilder:
    """
    Build a field path for an element within an array using the ``[*]`` alias.

    In ARM policy, ``[*]`` notation accesses elements within an array property.
    This helper constructs the correct dot-path so you can use all
    :class:`FieldBuilder` operators on array element properties.

    Args:
        array_path: Path to the array property, optionally including ``[*]``
                    (e.g. ``"properties.networkInterfaces[*]"`` or
                    ``"properties.networkInterfaces"``).
        element_field: Optional sub-field within each array element.  When
                       provided it is appended to *array_path* with a ``"."``
                       separator.

    Returns:
        :class:`FieldBuilder` targeting the composed path.

    Example::

        # Check if any network interface references the restricted subnet
        array_field("properties.networkInterfaces[*]", "properties.subnet.id")
            .contains("restricted-subnet")

        # Used inside count() to filter array elements
        count("properties.securityRules[*]").where(
            array_field("properties.access").equals("Allow")
        ).greater_than(0)
    """
    path = f"{array_path}.{element_field}" if element_field else array_path
    return FieldBuilder(path)


@dataclass
class AllOfCondition(Condition):
    """
    Logical AND of multiple conditions.

    All conditions must evaluate to True for this condition to be True.
    """

    conditions: List[Condition] = dataclass_field(default_factory=list)

    def to_dict(self) -> dict:
        return {"allOf": [c.to_dict() for c in self.conditions]}

    def evaluate(self, resource: dict) -> bool:
        return all(c.evaluate(resource) for c in self.conditions)


@dataclass
class AnyOfCondition(Condition):
    """
    Logical OR of multiple conditions.

    At least one condition must evaluate to True for this condition to be True.
    """

    conditions: List[Condition] = dataclass_field(default_factory=list)

    def to_dict(self) -> dict:
        return {"anyOf": [c.to_dict() for c in self.conditions]}

    def evaluate(self, resource: dict) -> bool:
        return any(c.evaluate(resource) for c in self.conditions)


@dataclass
class NotCondition(Condition):
    """
    Logical NOT of a condition.

    Inverts the result of the inner condition.
    """

    condition: Condition

    def to_dict(self) -> dict:
        return {"not": self.condition.to_dict()}

    def evaluate(self, resource: dict) -> bool:
        return not self.condition.evaluate(resource)


def all_of(*conditions: Condition) -> AllOfCondition:
    """
    Create an AND condition that requires all conditions to be true.

    Example::

        all_of(
            field("location").equals("westeurope"),
            field("tags.environment").exists(),
        )
    """
    return AllOfCondition(conditions=list(conditions))


def any_of(*conditions: Condition) -> AnyOfCondition:
    """
    Create an OR condition that requires at least one condition to be true.

    Example::

        any_of(
            field("location").equals("westeurope"),
            field("location").equals("northeurope"),
        )
    """
    return AnyOfCondition(conditions=list(conditions))


def not_(condition: Condition) -> NotCondition:
    """
    Create a NOT condition that inverts the inner condition.

    Example::

        not_(field("type").equals("ITL.Compute/virtualMachines"))
    """
    return NotCondition(condition=condition)


@dataclass
class CountCondition(Condition):
    """
    Count condition for array fields.

    Counts elements in an array that match a condition and compares
    the count to a threshold.
    """

    field_path: str
    where: Optional[Condition] = None
    operator: str = "greater"
    count_value: int = 0

    def to_dict(self) -> dict:
        result: dict = {
            "count": {
                "field": self.field_path,
            },
            self.operator: self.count_value,
        }
        if self.where:
            result["count"]["where"] = self.where.to_dict()
        return result

    def evaluate(self, resource: dict) -> bool:
        array = _get_nested_value(resource, self.field_path)
        if not isinstance(array, list):
            return False

        if self.where:
            matching = sum(1 for item in array if self.where.evaluate(item))
        else:
            matching = len(array)

        match self.operator:
            case "equals":
                return matching == self.count_value
            case "notEquals":
                return matching != self.count_value
            case "greater":
                return matching > self.count_value
            case "greaterOrEquals":
                return matching >= self.count_value
            case "less":
                return matching < self.count_value
            case "lessOrEquals":
                return matching <= self.count_value
            case _:
                raise ValueError(f"Unknown count operator: {self.operator}")


class CountBuilder:
    """Builder for count conditions on array fields."""

    def __init__(self, field_path: str):
        self.field_path = field_path
        self._where: Optional[Condition] = None

    def where(self, condition: Condition) -> CountBuilder:
        """Filter which elements to count."""
        self._where = condition
        return self

    def equals(self, value: int) -> CountCondition:
        """Count must equal the value."""
        return CountCondition(self.field_path, self._where, "equals", value)

    def not_equals(self, value: int) -> CountCondition:
        """Count must not equal the value."""
        return CountCondition(self.field_path, self._where, "notEquals", value)

    def greater_than(self, value: int) -> CountCondition:
        """Count must be greater than the value."""
        return CountCondition(self.field_path, self._where, "greater", value)

    def greater_or_equals(self, value: int) -> CountCondition:
        """Count must be greater than or equal to the value."""
        return CountCondition(self.field_path, self._where, "greaterOrEquals", value)

    def less_than(self, value: int) -> CountCondition:
        """Count must be less than the value."""
        return CountCondition(self.field_path, self._where, "less", value)

    def less_or_equals(self, value: int) -> CountCondition:
        """Count must be less than or equal to the value."""
        return CountCondition(self.field_path, self._where, "lessOrEquals", value)


def count(field_path: str) -> CountBuilder:
    """
    Start building a count condition for array fields.

    Example::

        # Require at least 2 tags
        count("tags").greater_or_equals(2)

        # Require at least one network interface in a specific subnet
        count("properties.networkInterfaces").where(
            field("properties.subnet").contains("prod-subnet")
        ).greater_or_equals(1)
    """
    return CountBuilder(field_path)


@dataclass
class ValueCondition(Condition):
    """
    Condition that evaluates a parameter or runtime value.

    Used for parameterized policies where values are provided at assignment time.
    """

    parameter_name: str
    operator: str
    value: Any

    def to_dict(self) -> dict:
        return {
            "value": f"[parameters('{self.parameter_name}')]",
            self.operator: self.value,
        }

    def evaluate(self, resource: dict, parameters: Optional[dict] = None) -> bool:
        # Value conditions are evaluated with parameters at runtime
        if parameters is None:
            return True  # Skip if no parameters provided
        actual = parameters.get(self.parameter_name)
        return _compare_values(actual, self.value, True)


class ValueBuilder:
    """Builder for value/parameter conditions."""

    def __init__(self, parameter_name: str):
        self.parameter_name = parameter_name

    def equals(self, value: Any) -> ValueCondition:
        return ValueCondition(self.parameter_name, "equals", value)

    def not_equals(self, value: Any) -> ValueCondition:
        return ValueCondition(self.parameter_name, "notEquals", value)


def value(parameter_name: str) -> ValueBuilder:
    """
    Reference a policy parameter value.

    Example::

        value("allowedLocations").contains(field("location"))
    """
    return ValueBuilder(parameter_name)


def current(alias: str = "") -> FieldBuilder:
    """
    Reference the current resource being evaluated.

    Used in count conditions to reference properties of array elements.

    Example::

        count("properties.ipConfigurations").where(
            current("publicIpAddress").exists()
        ).equals(0)
    """
    return FieldBuilder(f"current.{alias}" if alias else "current")


# ============================================================================
# RequestContext
# ============================================================================


@dataclass
class RequestContextCondition(Condition):
    """
    Condition that evaluates a value from the ARM request context.

    Maps to ``{"value": "[requestContext().property]", operator: val}`` in ARM JSON.
    Used to inspect metadata about the incoming ARM request, most commonly
    ``apiVersion``.
    """

    property_name: str
    operator: str
    value: Any

    def to_dict(self) -> dict:
        return {
            "value": f"[requestContext().{self.property_name}]",
            self.operator: self.value,
        }

    def evaluate(self, resource: dict) -> bool:  # pragma: no cover
        # requestContext is only available at ARM evaluation time.
        return True


class _RequestContextPropertyBuilder:
    """Builds conditions against a single requestContext property."""

    def __init__(self, property_name: str):
        self._property_name = property_name

    def equals(self, value: Any) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "equals", value)

    def not_equals(self, value: Any) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "notEquals", value)

    def greater_or_equals(self, value: str) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "greaterOrEquals", value)

    def greater_than(self, value: str) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "greater", value)

    def less_or_equals(self, value: str) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "lessOrEquals", value)

    def less_than(self, value: str) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "less", value)

    def in_(self, *values: str) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "in", list(values))

    def not_in(self, *values: str) -> RequestContextCondition:
        return RequestContextCondition(self._property_name, "notIn", list(values))


class _RequestContextProxy:
    """Entry point for request_context() conditions."""

    @property
    def api_version(self) -> _RequestContextPropertyBuilder:
        """The API version used in the ARM request."""
        return _RequestContextPropertyBuilder("apiVersion")


def request_context() -> _RequestContextProxy:
    """
    Reference ARM request context values.

    Currently only ``apiVersion`` is supported by Azure Policy.

    Example::

        request_context().api_version.greater_or_equals("2019-09-01")
    """
    return _RequestContextProxy()


# ============================================================================
# Helper Functions
# ============================================================================


def _get_nested_value(obj: dict, path: str) -> Any:
    """
    Get a nested value from a dictionary using dot notation.

    Supports:
    - Simple paths: "location"
    - Nested paths: "properties.sku.name"
    - Array indexing: "properties.ipConfigurations[0].name"
    - Wildcards: "properties.ipConfigurations[*].name" (returns list of all)
    """
    if not path:
        return obj

    parts = path.replace("[", ".[").split(".")
    current = obj

    for part in parts:
        if current is None:
            return None

        if part.startswith("[") and part.endswith("]"):
            # Array index
            index_str = part[1:-1]
            if not isinstance(current, list):
                return None
            if index_str == "*":
                # Wildcard - return all elements
                return current
            try:
                index = int(index_str)
                current = current[index] if 0 <= index < len(current) else None
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None

    return current


def _compare_values(actual: Any, expected: Any, case_sensitive: bool) -> bool:
    """Compare two values, optionally case-insensitive for strings."""
    if actual is None and expected is None:
        return True
    if actual is None or expected is None:
        return False
    if isinstance(actual, str) and isinstance(expected, str) and not case_sensitive:
        return actual.lower() == expected.lower()
    return actual == expected
