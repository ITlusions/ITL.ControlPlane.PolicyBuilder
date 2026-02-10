"""
Policy enums for effects, modes, and states.

These enums mirror Azure Policy semantics for compatibility
while extending with ITL-specific functionality.
"""

from enum import Enum


class Effect(str, Enum):
    """
    Policy effects determine what happens when a policy condition is met.

    Azure Policy compatible effects:
    - DENY: Block the operation
    - AUDIT: Log but don't block
    - APPEND: Add fields to the request
    - MODIFY: Modify existing fields
    - DEPLOY_IF_NOT_EXISTS: Deploy a resource if it doesn't exist
    - AUDIT_IF_NOT_EXISTS: Audit if related resource doesn't exist
    - DISABLED: Policy is disabled

    ITL-specific effects:
    - REMEDIATE: Automatically fix non-compliant resources
    - ALERT: Send alert to monitoring system
    - QUARANTINE: Isolate the resource
    """

    # Azure Policy compatible
    DENY = "Deny"
    AUDIT = "Audit"
    APPEND = "Append"
    MODIFY = "Modify"
    DEPLOY_IF_NOT_EXISTS = "DeployIfNotExists"
    AUDIT_IF_NOT_EXISTS = "AuditIfNotExists"
    DISABLED = "Disabled"

    # ITL extensions
    REMEDIATE = "Remediate"
    ALERT = "Alert"
    QUARANTINE = "Quarantine"

    @property
    def is_blocking(self) -> bool:
        """Returns True if this effect blocks the operation."""
        return self in (Effect.DENY,)

    @property
    def is_modifying(self) -> bool:
        """Returns True if this effect modifies the request/resource."""
        return self in (Effect.APPEND, Effect.MODIFY, Effect.REMEDIATE)

    @property
    def is_audit_only(self) -> bool:
        """Returns True if this effect only audits without blocking."""
        return self in (Effect.AUDIT, Effect.AUDIT_IF_NOT_EXISTS, Effect.ALERT)


class PolicyMode(str, Enum):
    """
    Policy evaluation mode.

    - ALL: Evaluate all resource types
    - INDEXED: Only evaluate resources that support tags and location
    - PROVIDER_SPECIFIC: Provider-specific evaluation (e.g., ITL.Compute only)
    """

    ALL = "All"
    INDEXED = "Indexed"
    PROVIDER_SPECIFIC = "Provider-Specific"

    @classmethod
    def from_string(cls, value: str) -> "PolicyMode":
        """Convert string to PolicyMode, case-insensitive."""
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        for mode in cls:
            if mode.value.lower().replace("-", "_").replace(" ", "_") == normalized:
                return mode
        raise ValueError(f"Unknown policy mode: {value}")


class PolicyType(str, Enum):
    """
    Policy definition type.

    - BUILTIN: Provided by ITL platform (read-only)
    - CUSTOM: Created by customers
    - STATIC: System policies that cannot be modified or deleted
    """

    BUILTIN = "BuiltIn"
    CUSTOM = "Custom"
    STATIC = "Static"


class ComplianceState(str, Enum):
    """
    Resource compliance state.

    - COMPLIANT: Resource meets policy requirements
    - NON_COMPLIANT: Resource violates policy
    - EXEMPT: Resource is exempted from policy
    - UNKNOWN: Compliance hasn't been evaluated yet
    - CONFLICT: Multiple policies conflict on this resource
    """

    COMPLIANT = "Compliant"
    NON_COMPLIANT = "NonCompliant"
    EXEMPT = "Exempt"
    UNKNOWN = "Unknown"
    CONFLICT = "Conflict"


class AssignmentScope(str, Enum):
    """
    Scope levels for policy assignments.
    
    Determines where the policy applies and inheritance behavior.
    """

    TENANT = "tenant"
    MANAGEMENT_GROUP = "managementGroup"
    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resourceGroup"

    @classmethod
    def from_resource_id(cls, resource_id: str) -> "AssignmentScope":
        """Determine scope from a resource ID."""
        resource_id_lower = resource_id.lower()
        if "/resourcegroups/" in resource_id_lower:
            return cls.RESOURCE_GROUP
        elif "/subscriptions/" in resource_id_lower:
            return cls.SUBSCRIPTION
        elif "/managementgroups/" in resource_id_lower:
            return cls.MANAGEMENT_GROUP
        else:
            return cls.TENANT


class ExemptionCategory(str, Enum):
    """
    Category for policy exemptions.

    - WAIVER: Compliance is waived (manual approval)
    - MITIGATED: Non-compliance is mitigated by other means
    """

    WAIVER = "Waiver"
    MITIGATED = "Mitigated"


class RemediationState(str, Enum):
    """
    State of a remediation task.
    """

    PENDING = "Pending"
    IN_PROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"
