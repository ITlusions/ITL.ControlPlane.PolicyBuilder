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
    ExemptionCategory,
    RemediationState,
    ParameterType,
)
from itl_policy_builder.conditions import (
    Condition,
    field,
    array_field,
    all_of,
    any_of,
    not_,
    count,
    value,
    current,
    request_context,
    RequestContextCondition,
)
from itl_policy_builder.builders.policy import (
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
    PolicyExemptionProperties,
    ComplianceResult,
)
from itl_policy_builder.builders.assignment import PolicyAssignmentBuilder
from itl_policy_builder.builders.initiative import PolicySetBuilder
from itl_policy_builder.evaluation.evaluator import PolicyEvaluator
from itl_policy_builder.builders.exemption import PolicyExemptionBuilder
from itl_policy_builder.builders.remediation import RemediationBuilder
from itl_policy_builder.testing.helpers import PolicyTestHelper, PolicyAssertionError
from itl_policy_builder.export.arm import ArmDeploymentTemplate
from itl_policy_builder.export.bicep import BicepCompiler, BicepCompilationError
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
from itl_policy_builder.export.kyverno import (
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
    "ExemptionCategory",
    "RemediationState",
    "ParameterType",
    # Conditions
    "Condition",
    "field",
    "array_field",
    "all_of",
    "any_of",
    "not_",
    "count",
    "value",
    "current",
    "request_context",
    "RequestContextCondition",
    # Builders
    "PolicyBuilder",
    "PolicyRule",
    "PolicyAssignmentBuilder",
    "PolicySetBuilder",
    "PolicyExemptionBuilder",
    "RemediationBuilder",
    # Models
    "PolicyDefinition",
    "PolicyDefinitionProperties",
    "PolicyParameter",
    "PolicyAssignment",
    "PolicyAssignmentProperties",
    "PolicySetDefinition",
    "PolicyExemption",
    "PolicyExemptionProperties",
    "ComplianceResult",
    # Evaluation
    "PolicyEvaluator",
    # Testing
    "PolicyTestHelper",
    "PolicyAssertionError",
    # ARM Deploy Template
    "ArmDeploymentTemplate",
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

