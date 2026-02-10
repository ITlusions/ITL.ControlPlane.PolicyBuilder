"""Unit tests for Kyverno policy builder."""

import json
import pytest

from itl_policy_builder.kyverno import (
    KyvernoPolicyBuilder,
    KyvernoPodSecurityBuilder,
    KyvernoImageSecurityBuilder,
    KyvernoMatch,
    ValidationAction,
    MatchKind,
)


class TestKyvernoPolicyBuilder:
    """Test KyvernoPolicyBuilder."""

    def test_basic_policy_creation(self):
        """Test creating a basic Kyverno policy."""
        policy = KyvernoPolicyBuilder("test-policy").build()
        
        assert policy["apiVersion"] == "kyverno.io/v1"
        assert policy["kind"] == "ClusterPolicy"
        assert policy["metadata"]["name"] == "test-policy"
        assert policy["spec"]["validationFailureAction"] == "audit"
        assert policy["spec"]["background"] is True

    def test_policy_with_description(self):
        """Test policy with display name and description."""
        policy = (
            KyvernoPolicyBuilder("test-policy")
            .with_display_name("Test Policy")
            .with_description("A test policy description")
            .build()
        )
        
        assert policy["metadata"]["labels"]["app.kubernetes.io/name"] == "test-policy"
        assert policy["metadata"]["annotations"]["description"] == "A test policy description"

    def test_pod_security_builder(self):
        """Test PodSecurityBuilder."""
        policy = (
            KyvernoPodSecurityBuilder()
            .require_security_context()
            .require_non_root()
            .build()
        )
        
        assert policy["kind"] == "ClusterPolicy"
        assert len(policy["spec"]["rules"]) == 2
        assert policy["spec"]["validationFailureAction"] == "audit"

    def test_image_security_builder(self):
        """Test ImageSecurityBuilder."""
        policy = (
            KyvernoImageSecurityBuilder()
            .require_image_pull_policy()
            .build()
        )
        
        assert len(policy["spec"]["rules"]) >= 1

    def test_validation_action(self):
        """Test validation action setting."""
        policy = (
            KyvernoPolicyBuilder("enforce-policy")
            .with_validation_action(ValidationAction.ENFORCE)
            .build()
        )
        
        assert policy["spec"]["validationFailureAction"] == "enforce"

    def test_namespaced_policy(self):
        """Test namespaced policy (Policy vs ClusterPolicy)."""
        policy = (
            KyvernoPolicyBuilder("test-policy")
            .with_namespaced_policy()
            .build()
        )
        
        assert policy["kind"] == "Policy"

    def test_policy_to_json(self):
        """Test JSON serialization."""
        policy_obj = KyvernoPolicyBuilder("test-policy")
        json_str = policy_obj.to_json()
        
        parsed = json.loads(json_str)
        assert parsed["apiVersion"] == "kyverno.io/v1"
        assert parsed["metadata"]["name"] == "test-policy"

    def test_policy_to_yaml(self):
        """Test YAML serialization."""
        policy_obj = KyvernoPolicyBuilder("test-policy")
        yaml_str = policy_obj.to_yaml()
        
        assert "apiVersion: kyverno.io/v1" in yaml_str
        assert "kind: ClusterPolicy" in yaml_str
        assert "name: test-policy" in yaml_str

    def test_validation_rule(self):
        """Test adding validation rule."""
        policy = (
            KyvernoPolicyBuilder("test-policy")
            .add_validation_rule(
                rule_name="test-rule",
                message="Test message",
                pattern={"spec": {"image": "?"}},
                action=ValidationAction.ENFORCE,
            )
            .build()
        )
        
        assert len(policy["spec"]["rules"]) == 1
        rule = policy["spec"]["rules"][0]
        assert rule["name"] == "test-rule"
        assert rule["message"] == "Test message"
        assert rule["validationAction"] == "enforce"

    def test_mutation_rule(self):
        """Test adding mutation rule."""
        policy = (
            KyvernoPolicyBuilder("test-policy")
            .add_mutation_rule(
                rule_name="mutate-rule",
                message="Adding label",
                patch={"metadata": {"labels": {"added": "true"}}},
            )
            .build()
        )
        
        assert len(policy["spec"]["rules"]) == 1
        rule = policy["spec"]["rules"][0]
        assert rule["name"] == "mutate-rule"
        assert "patchStrategicMergePatch" in rule or "patchJsonPatch" in rule

    def test_match_kind_enum(self):
        """Test MatchKind enumeration."""
        match = KyvernoMatch(kind=MatchKind.POD)
        match_dict = match.to_dict()
        
        assert match_dict["kind"] == "Pod"

    def test_background_disabled(self):
        """Test disabling background policy application."""
        policy = (
            KyvernoPolicyBuilder("test-policy")
            .with_background(False)
            .build()
        )
        
        assert policy["spec"]["background"] is False

    def test_pod_security_baseline_preset(self):
        """Test predefined pod security baseline."""
        policy = (
            KyvernoPodSecurityBuilder("pss-baseline")
            .require_security_context()
            .build()
        )
        
        assert "pss-baseline" in policy["metadata"]["name"]
        assert len(policy["spec"]["rules"]) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
