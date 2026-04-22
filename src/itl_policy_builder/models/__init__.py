"""
Policy models — public re-export surface for ``itl_policy_builder.models``.

Each class lives in a focused sub-module; import from here for convenience or
go directly to the sub-module for finer-grained control:

    # Convenience (this file)
    from itl_policy_builder.models import PolicyDefinition, PolicyAssignment

    # Canonical sub-module paths
    from itl_policy_builder.models.policy     import PolicyDefinition, PolicyDefinitionProperties, PolicyParameter, PolicyRule
    from itl_policy_builder.models.assignment import PolicyAssignment, PolicyAssignmentProperties
    from itl_policy_builder.models.initiative import PolicySetDefinition, PolicySetDefinitionReference
    from itl_policy_builder.models.exemption  import PolicyExemption, PolicyExemptionProperties
    from itl_policy_builder.models.remediation import ComplianceResult, RemediationTask
"""

# -- policy.py ----------------------------------------------------------------
from itl_policy_builder.models.policy import (
    PolicyParameter,
    PolicyRule,
    PolicyDefinitionProperties,
    PolicyDefinition,
)

# -- assignment.py ------------------------------------------------------------
from itl_policy_builder.models.assignment import (
    PolicyAssignmentProperties,
    PolicyAssignment,
)

# -- initiative.py ------------------------------------------------------------
from itl_policy_builder.models.initiative import (
    PolicySetDefinitionReference,
    PolicySetDefinition,
)

# -- exemption.py -------------------------------------------------------------
from itl_policy_builder.models.exemption import (
    PolicyExemptionProperties,
    PolicyExemption,
)

# -- remediation.py -----------------------------------------------------------
from itl_policy_builder.models.remediation import (
    ComplianceResult,
    RemediationTask,
)

__all__ = [
    # Policy definition
    "PolicyParameter",
    "PolicyRule",
    "PolicyDefinitionProperties",
    "PolicyDefinition",
    # Assignment
    "PolicyAssignmentProperties",
    "PolicyAssignment",
    # Initiative / policy set
    "PolicySetDefinitionReference",
    "PolicySetDefinition",
    # Exemption
    "PolicyExemptionProperties",
    "PolicyExemption",
    # Compliance & remediation
    "ComplianceResult",
    "RemediationTask",
]
