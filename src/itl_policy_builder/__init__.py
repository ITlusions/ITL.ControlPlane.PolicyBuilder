"""
ITL Policy Builder - Fluent DSL for defining governance policies.

This package provides a programmatic way to define, serialize, and manage
ITL ControlPlane policies using a fluent builder pattern.

Example usage::

    from itl_policy_builder import PolicyBuilder, Effect, field

    # Define a policy that requires location to be westeurope
    policy = (
        PolicyBuilder("require-westeurope-location")
        .display_name("Require West Europe Location")
        .description("Ensures all resources are deployed in West Europe")
        .mode("All")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY
        )
        .build()
    )

    # Serialize to ARM-compatible JSON
    policy_json = policy.to_arm_json()

    # Create an assignment
    assignment = (
        PolicyAssignmentBuilder("enforce-location-prod")
        .policy_definition_id(policy.id)
        .scope("/subscriptions/sub-prod-001")
        .build()
    )
"""

from itl_policy_builder.enums import (
    Effect,
    PolicyMode,
    PolicyType,
    ComplianceState,
    AssignmentScope,
)
from itl_policy_builder.conditions import (
    Condition,
    field,
    all_of,
    any_of,
    not_,
    count,
    value,
    current,
)
from itl_policy_builder.builder import (
    PolicyBuilder,
    PolicyRule,
)
from itl_policy_builder.models import (
    PolicyDefinition,
    PolicyDefinitionProperties,
    PolicyParameter,
    PolicyAssignment,
    PolicyAssignmentProperties,
    PolicySetDefinition,
    PolicyExemption,
    ComplianceResult,
)
from itl_policy_builder.assignment import PolicyAssignmentBuilder
from itl_policy_builder.initiative import PolicySetBuilder
from itl_policy_builder.evaluator import PolicyEvaluator
from itl_policy_builder.templates import (
    # General templates
    get_builtin_policy,
    list_builtin_policies,
    get_all_builtin_policies,
    # BIO templates
    get_bio_policy,
    list_bio_policies,
    get_all_bio_policies,
    get_bio_policies_by_category,
    get_bio_initiative,
    BIO_CATEGORIES,
    # PQC templates
    get_pqc_policy,
    list_pqc_policies,
    get_all_pqc_policies,
    get_pqc_policies_by_category,
    get_pqc_initiative,
    get_pqc_transition_initiative,
    PQC_CATEGORIES,
    NIST_PQC_KEMs,
    NIST_PQC_SIGNATURES,
)
from itl_policy_builder.kyverno import (
    # Kyverno policy builders
    KyvernoPolicyBuilder,
    KyvernoPodSecurityBuilder,
    KyvernoImageSecurityBuilder,
    KyvernoNetworkPolicyBuilder,
    KyvernoPQCBuilder,
    # Kyverno models
    KyvernoRule,
    KyvernoMatch,
    KyvernoValidationRule,
    KyvernoMutationRule,
    KyvernoRuleType,
    ValidationAction,
    MatchKind,
)

__version__ = "1.0.0"

__all__ = [
    # Enums
    "Effect",
    "PolicyMode",
    "PolicyType",
    "ComplianceState",
    "AssignmentScope",
    # Conditions
    "Condition",
    "field",
    "all_of",
    "any_of",
    "not_",
    "count",
    "value",
    "current",
    # Builders
    "PolicyBuilder",
    "PolicyRule",
    "PolicyAssignmentBuilder",
    "PolicySetBuilder",
    # Models
    "PolicyDefinition",
    "PolicyDefinitionProperties",
    "PolicyParameter",
    "PolicyAssignment",
    "PolicyAssignmentProperties",
    "PolicySetDefinition",
    "PolicyExemption",
    "ComplianceResult",
    # Evaluation
    "PolicyEvaluator",
    # General Templates
    "get_builtin_policy",
    "list_builtin_policies",
    "get_all_builtin_policies",
    # BIO Templates
    "get_bio_policy",
    "list_bio_policies",
    "get_all_bio_policies",
    "get_bio_policies_by_category",
    "get_bio_initiative",
    "BIO_CATEGORIES",
    # PQC Templates
    "get_pqc_policy",
    "list_pqc_policies",
    "get_all_pqc_policies",
    "get_pqc_policies_by_category",
    "get_pqc_initiative",
    "get_pqc_transition_initiative",
    "PQC_CATEGORIES",
    "NIST_PQC_KEMs",
    "NIST_PQC_SIGNATURES",
    # Kyverno Builders
    "KyvernoPolicyBuilder",
    "KyvernoPodSecurityBuilder",
    "KyvernoImageSecurityBuilder",
    "KyvernoNetworkPolicyBuilder",
    "KyvernoPQCBuilder",
    # Kyverno Models
    "KyvernoRule",
    "KyvernoMatch",
    "KyvernoValidationRule",
    "KyvernoMutationRule",
    "KyvernoRuleType",
    "ValidationAction",
    "MatchKind",
]
