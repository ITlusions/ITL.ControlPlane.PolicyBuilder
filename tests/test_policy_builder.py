"""Tests for the Policy Builder SDK."""

import pytest

from itl_policy_builder import (
    PolicyBuilder,
    PolicyAssignmentBuilder,
    PolicySetBuilder,
    PolicyEvaluator,
    Effect,
    PolicyMode,
    ComplianceState,
    field,
    all_of,
    any_of,
    not_,
    count,
)
from itl_policy_builder.templates import get_builtin_policy, list_builtin_policies


class TestConditions:
    """Test condition DSL."""

    def test_field_equals(self):
        cond = field("location").equals("westeurope")
        assert cond.evaluate({"location": "westeurope"}) is True
        assert cond.evaluate({"location": "eastus"}) is False

    def test_field_not_equals(self):
        cond = field("location").not_equals("westeurope")
        assert cond.evaluate({"location": "westeurope"}) is False
        assert cond.evaluate({"location": "eastus"}) is True

    def test_field_in(self):
        cond = field("location").in_("westeurope", "northeurope")
        assert cond.evaluate({"location": "westeurope"}) is True
        assert cond.evaluate({"location": "northeurope"}) is True
        assert cond.evaluate({"location": "eastus"}) is False

    def test_field_not_in(self):
        cond = field("location").not_in("eastus", "westus")
        assert cond.evaluate({"location": "westeurope"}) is True
        assert cond.evaluate({"location": "eastus"}) is False

    def test_field_contains(self):
        cond = field("name").contains("prod")
        assert cond.evaluate({"name": "app-prod-001"}) is True
        assert cond.evaluate({"name": "app-dev-001"}) is False

    def test_field_exists(self):
        cond = field("tags.environment").exists()
        assert cond.evaluate({"tags": {"environment": "prod"}}) is True
        assert cond.evaluate({"tags": {}}) is False
        assert cond.evaluate({}) is False

    def test_field_exists_false(self):
        cond = field("tags.environment").exists(False)
        assert cond.evaluate({"tags": {}}) is True
        assert cond.evaluate({"tags": {"environment": "prod"}}) is False

    def test_field_greater_than(self):
        cond = field("properties.size").greater_than(10)
        assert cond.evaluate({"properties": {"size": 15}}) is True
        assert cond.evaluate({"properties": {"size": 10}}) is False
        assert cond.evaluate({"properties": {"size": 5}}) is False

    def test_field_matches_regex(self):
        cond = field("name").matches(r"^app-\d{3}$")
        assert cond.evaluate({"name": "app-001"}) is True
        assert cond.evaluate({"name": "app-1"}) is False
        assert cond.evaluate({"name": "other-001"}) is False

    def test_field_like_pattern(self):
        cond = field("name").like("app-%")
        assert cond.evaluate({"name": "app-001"}) is True
        assert cond.evaluate({"name": "app-prod-web"}) is True
        assert cond.evaluate({"name": "other-001"}) is False

    def test_nested_field(self):
        cond = field("properties.sku.name").equals("Standard")
        resource = {"properties": {"sku": {"name": "Standard"}}}
        assert cond.evaluate(resource) is True

    def test_all_of(self):
        cond = all_of(
            field("location").equals("westeurope"),
            field("tags.environment").exists(),
        )
        assert cond.evaluate({"location": "westeurope", "tags": {"environment": "prod"}}) is True
        assert cond.evaluate({"location": "westeurope", "tags": {}}) is False
        assert cond.evaluate({"location": "eastus", "tags": {"environment": "prod"}}) is False

    def test_any_of(self):
        cond = any_of(
            field("location").equals("westeurope"),
            field("location").equals("northeurope"),
        )
        assert cond.evaluate({"location": "westeurope"}) is True
        assert cond.evaluate({"location": "northeurope"}) is True
        assert cond.evaluate({"location": "eastus"}) is False

    def test_not(self):
        cond = not_(field("type").equals("ITL.Core/resourceGroups"))
        assert cond.evaluate({"type": "ITL.Compute/virtualMachines"}) is True
        assert cond.evaluate({"type": "ITL.Core/resourceGroups"}) is False

    def test_operator_overloads(self):
        # AND with &
        cond = field("a").equals(1) & field("b").equals(2)
        assert cond.evaluate({"a": 1, "b": 2}) is True
        assert cond.evaluate({"a": 1, "b": 3}) is False

        # OR with |
        cond = field("a").equals(1) | field("a").equals(2)
        assert cond.evaluate({"a": 1}) is True
        assert cond.evaluate({"a": 2}) is True
        assert cond.evaluate({"a": 3}) is False

        # NOT with ~
        cond = ~field("a").equals(1)
        assert cond.evaluate({"a": 2}) is True
        assert cond.evaluate({"a": 1}) is False

    def test_count_condition(self):
        cond = count("items").greater_than(2)
        assert cond.evaluate({"items": [1, 2, 3]}) is True
        assert cond.evaluate({"items": [1, 2]}) is False
        assert cond.evaluate({"items": []}) is False

    def test_count_with_where(self):
        cond = count("items").where(field("active").equals(True)).greater_than(0)
        assert cond.evaluate({"items": [{"active": True}, {"active": False}]}) is True
        assert cond.evaluate({"items": [{"active": False}, {"active": False}]}) is False


class TestPolicyBuilder:
    """Test PolicyBuilder class."""

    def test_basic_policy(self):
        policy = (
            PolicyBuilder("test-policy")
            .display_name("Test Policy")
            .description("A test policy")
            .with_rule(
                if_=field("location").not_equals("westeurope"),
                then=Effect.DENY,
            )
            .build()
        )

        assert policy.name == "test-policy"
        assert policy.properties.display_name == "Test Policy"
        assert policy.properties.description == "A test policy"
        assert "if" in policy.properties.policy_rule.model_dump(by_alias=True)

    def test_policy_with_parameters(self):
        policy = (
            PolicyBuilder("param-policy")
            .parameter(
                "allowedLocations",
                type="Array",
                default=["westeurope"],
            )
            .with_rule(
                if_=field("location").not_in("westeurope"),
                then=Effect.DENY,
            )
            .build()
        )

        assert "allowedLocations" in policy.properties.parameters
        assert policy.properties.parameters["allowedLocations"].type == "Array"

    def test_policy_with_metadata(self):
        policy = (
            PolicyBuilder("meta-policy")
            .category("Security")
            .version("1.0.0")
            .metadata(author="test", team="platform")
            .with_rule(
                if_=field("type").equals("test"),
                then=Effect.AUDIT,
            )
            .build()
        )

        assert policy.properties.metadata["category"] == "Security"
        assert policy.properties.metadata["version"] == "1.0.0"
        assert policy.properties.metadata["author"] == "test"

    def test_policy_json_serialization(self):
        policy = (
            PolicyBuilder("json-policy")
            .with_rule(
                if_=field("location").equals("eastus"),
                then=Effect.DENY,
            )
            .build()
        )

        json_str = policy.to_arm_json()
        assert '"name": "json-policy"' in json_str
        assert '"effect": "Deny"' in json_str

    def test_policy_without_rule_raises(self):
        with pytest.raises(ValueError, match="must have a rule"):
            PolicyBuilder("no-rule-policy").build()


class TestPolicyAssignmentBuilder:
    """Test PolicyAssignmentBuilder class."""

    def test_basic_assignment(self):
        assignment = (
            PolicyAssignmentBuilder("test-assignment")
            .policy_definition_id("/providers/ITL.Authorization/policyDefinitions/test")
            .scope("/subscriptions/sub-001")
            .build()
        )

        assert assignment.name == "test-assignment"
        assert assignment.properties.policy_definition_id == "/providers/ITL.Authorization/policyDefinitions/test"
        assert assignment.properties.scope == "/subscriptions/sub-001"

    def test_assignment_with_exclusions(self):
        assignment = (
            PolicyAssignmentBuilder("excl-assignment")
            .policy_definition_id("/providers/ITL.Authorization/policyDefinitions/test")
            .scope("/subscriptions/sub-001")
            .exclude_scope("/subscriptions/sub-001/resourceGroups/legacy")
            .exclude_scope("/subscriptions/sub-001/resourceGroups/temp")
            .build()
        )

        assert len(assignment.properties.not_scopes) == 2

    def test_assignment_audit_only(self):
        assignment = (
            PolicyAssignmentBuilder("audit-assignment")
            .policy_definition_id("/providers/ITL.Authorization/policyDefinitions/test")
            .scope("/subscriptions/sub-001")
            .audit_only()
            .build()
        )

        assert assignment.properties.enforcement_mode == "DoNotEnforce"

    def test_assignment_without_scope_raises(self):
        with pytest.raises(ValueError, match="Scope is required"):
            (
                PolicyAssignmentBuilder("no-scope")
                .policy_definition_id("/providers/ITL.Authorization/policyDefinitions/test")
                .build()
            )


class TestPolicySetBuilder:
    """Test PolicySetBuilder (initiatives)."""

    def test_basic_initiative(self):
        initiative = (
            PolicySetBuilder("test-initiative")
            .display_name("Test Initiative")
            .add_policy("/providers/ITL.Authorization/policyDefinitions/policy1")
            .add_policy("/providers/ITL.Authorization/policyDefinitions/policy2")
            .build()
        )

        assert initiative.name == "test-initiative"
        assert len(initiative.properties["policyDefinitions"]) == 2

    def test_initiative_with_groups(self):
        initiative = (
            PolicySetBuilder("grouped-initiative")
            .add_group("Security", "Security policies")
            .add_group("Tags", "Tag policies")
            .add_policy(
                "/providers/ITL.Authorization/policyDefinitions/nsg",
                groups=["Security"],
            )
            .add_policy(
                "/providers/ITL.Authorization/policyDefinitions/tags",
                groups=["Tags"],
            )
            .build()
        )

        assert len(initiative.properties["policyDefinitionGroups"]) == 2

    def test_initiative_without_policies_raises(self):
        with pytest.raises(ValueError, match="at least one policy"):
            PolicySetBuilder("empty-initiative").build()


class TestPolicyEvaluator:
    """Test PolicyEvaluator."""

    def test_evaluate_deny(self):
        evaluator = PolicyEvaluator()

        policy = (
            PolicyBuilder("deny-eastus")
            .with_rule(
                if_=field("location").equals("eastus"),
                then=Effect.DENY,
                message="eastus not allowed",
            )
            .build()
        )
        evaluator.register_policy(policy)

        assignment = (
            PolicyAssignmentBuilder("enforce")
            .policy_definition_id(policy.id)
            .scope("/subscriptions/sub-001")
            .build()
        )
        evaluator.register_assignment(assignment)

        resource = {
            "id": "/subscriptions/sub-001/resourceGroups/rg/providers/ITL.Compute/vms/vm1",
            "location": "eastus",
            "type": "ITL.Compute/virtualMachines",
        }

        result = evaluator.evaluate(resource)
        assert result.denied is True
        assert "eastus not allowed" in result.deny_reasons[0]

    def test_evaluate_compliant(self):
        evaluator = PolicyEvaluator()

        policy = (
            PolicyBuilder("require-westeurope")
            .with_rule(
                if_=field("location").not_equals("westeurope"),
                then=Effect.DENY,
            )
            .build()
        )
        evaluator.register_policy(policy)

        assignment = (
            PolicyAssignmentBuilder("enforce")
            .policy_definition_id(policy.id)
            .scope("/subscriptions/sub-001")
            .build()
        )
        evaluator.register_assignment(assignment)

        resource = {
            "id": "/subscriptions/sub-001/resourceGroups/rg/providers/ITL.Compute/vms/vm1",
            "location": "westeurope",
            "type": "ITL.Compute/virtualMachines",
        }

        result = evaluator.evaluate(resource)
        assert result.denied is False
        assert result.overall_compliance == ComplianceState.COMPLIANT

    def test_scope_filtering(self):
        evaluator = PolicyEvaluator()

        policy = (
            PolicyBuilder("deny-all")
            .with_rule(if_=field("location").exists(), then=Effect.DENY)
            .build()
        )
        evaluator.register_policy(policy)

        assignment = (
            PolicyAssignmentBuilder("enforce-prod")
            .policy_definition_id(policy.id)
            .scope("/subscriptions/sub-prod")
            .build()
        )
        evaluator.register_assignment(assignment)

        # Resource in prod - should be denied
        prod_resource = {
            "id": "/subscriptions/sub-prod/resourceGroups/rg/providers/ITL.Compute/vms/vm1",
            "location": "westeurope",
            "type": "ITL.Compute/virtualMachines",
        }
        assert evaluator.evaluate(prod_resource).denied is True

        # Resource in dev - should NOT be denied (different subscription)
        dev_resource = {
            "id": "/subscriptions/sub-dev/resourceGroups/rg/providers/ITL.Compute/vms/vm1",
            "location": "westeurope",
            "type": "ITL.Compute/virtualMachines",
        }
        assert evaluator.evaluate(dev_resource).denied is False

    def test_excluded_scope(self):
        evaluator = PolicyEvaluator()

        policy = (
            PolicyBuilder("deny-all")
            .with_rule(if_=field("location").exists(), then=Effect.DENY)
            .build()
        )
        evaluator.register_policy(policy)

        assignment = (
            PolicyAssignmentBuilder("enforce")
            .policy_definition_id(policy.id)
            .scope("/subscriptions/sub-001")
            .exclude_scope("/subscriptions/sub-001/resourceGroups/legacy")
            .build()
        )
        evaluator.register_assignment(assignment)

        # Normal resource - denied
        normal = {
            "id": "/subscriptions/sub-001/resourceGroups/app/providers/ITL.Compute/vms/vm1",
            "location": "westeurope",
            "type": "ITL.Compute/virtualMachines",
        }
        assert evaluator.evaluate(normal).denied is True

        # Legacy resource - NOT denied (excluded)
        legacy = {
            "id": "/subscriptions/sub-001/resourceGroups/legacy/providers/ITL.Compute/vms/vm1",
            "location": "westeurope",
            "type": "ITL.Compute/virtualMachines",
        }
        assert evaluator.evaluate(legacy).denied is False

    def test_audit_only_enforcement(self):
        evaluator = PolicyEvaluator()

        policy = (
            PolicyBuilder("deny-policy")
            .with_rule(
                if_=field("location").equals("eastus"),
                then=Effect.DENY,
            )
            .build()
        )
        evaluator.register_policy(policy)

        assignment = (
            PolicyAssignmentBuilder("audit-only")
            .policy_definition_id(policy.id)
            .scope("/subscriptions/sub-001")
            .audit_only()  # DoNotEnforce mode
            .build()
        )
        evaluator.register_assignment(assignment)

        resource = {
            "id": "/subscriptions/sub-001/resourceGroups/rg/providers/ITL.Compute/vms/vm1",
            "location": "eastus",
            "type": "ITL.Compute/virtualMachines",
        }

        result = evaluator.evaluate(resource)
        # Should NOT be denied (audit only)
        assert result.denied is False
        # But should have audit findings
        assert len(result.audit_findings) > 0


class TestBuiltinPolicies:
    """Test built-in policy templates."""

    def test_list_builtin_policies(self):
        policies = list_builtin_policies()
        assert len(policies) > 0
        assert any(name == "allowed-locations" for name, _ in policies)

    def test_allowed_locations_policy(self):
        policy = get_builtin_policy("allowed-locations", locations=["westeurope"])
        assert policy.name == "allowed-locations"
        assert "allowedLocations" in policy.properties.parameters

    def test_require_tag_policy(self):
        policy = get_builtin_policy("require-tag", tag_name="environment")
        assert "require-tag-environment" in policy.name

    def test_require_tag_with_allowed_values(self):
        policy = get_builtin_policy(
            "require-tag",
            tag_name="environment",
            allowed_values=["dev", "test", "prod"],
        )
        assert policy.properties.description is not None

    def test_unknown_builtin_raises(self):
        with pytest.raises(KeyError, match="Unknown built-in policy"):
            get_builtin_policy("nonexistent-policy")
