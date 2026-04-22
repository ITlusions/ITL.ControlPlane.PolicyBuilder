"""
Fluent builder for policy definitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from itl_policy_builder.conditions import Condition
from itl_policy_builder.enums import Effect, PolicyMode, PolicyType
from itl_policy_builder.models import (
    PolicyDefinition,
    PolicyDefinitionProperties,
    PolicyParameter,
    PolicyRule as PolicyRuleModel,
)


@dataclass
class PolicyRuleEffect:
    """Represents the 'then' portion of a policy rule."""

    effect: Effect
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"effect": self.effect.value}
        if self.message:
            result["message"] = self.message
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class PolicyRule:
    """A complete policy rule with condition and effect."""

    condition: Condition
    effect: PolicyRuleEffect

    def to_dict(self) -> Dict[str, Any]:
        return {
            "if": self.condition.to_dict(),
            "then": self.effect.to_dict(),
        }


class PolicyBuilder:
    """
    Fluent builder for creating policy definitions.
    """

    def __init__(self, name: str, scope: Optional[str] = None):
        self._name = name
        self._scope = scope
        self._display_name: Optional[str] = None
        self._description: Optional[str] = None
        self._policy_type: PolicyType = PolicyType.CUSTOM
        self._mode: PolicyMode = PolicyMode.INDEXED
        self._metadata: Dict[str, Any] = {}
        self._parameters: Dict[str, PolicyParameter] = {}
        self._rule: Optional[PolicyRule] = None
        self._tags: Dict[str, str] = {}

    def display_name(self, name: str) -> PolicyBuilder:
        """Set the human-readable display name."""
        self._display_name = name
        return self

    def description(self, desc: str) -> PolicyBuilder:
        """Set the policy description."""
        self._description = desc
        return self

    def policy_type(self, ptype: Union[PolicyType, str]) -> PolicyBuilder:
        """Set the policy type (BuiltIn, Custom, Static)."""
        if isinstance(ptype, str):
            ptype = PolicyType(ptype)
        self._policy_type = ptype
        return self

    def mode(self, mode: Union[PolicyMode, str]) -> PolicyBuilder:
        """Set the evaluation mode."""
        if isinstance(mode, str):
            mode = PolicyMode.from_string(mode)
        self._mode = mode
        return self

    def metadata(self, data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> PolicyBuilder:
        """Add metadata to the policy."""
        if data:
            self._metadata.update(data)
        self._metadata.update(kwargs)
        return self

    def category(self, category: str) -> PolicyBuilder:
        """Set the policy category (shorthand for metadata)."""
        self._metadata["category"] = category
        return self

    def version(self, version: str) -> PolicyBuilder:
        """Set the policy version (shorthand for metadata)."""
        self._metadata["version"] = version
        return self

    def parameter(
        self,
        name: str,
        type: str = "String",
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        default: Optional[Any] = None,
        allowed_values: Optional[List[Any]] = None,
    ) -> PolicyBuilder:
        """Add a parameter to the policy."""
        self._parameters[name] = PolicyParameter(
            type=type,
            display_name=display_name or name,
            description=description,
            default_value=default,
            allowed_values=allowed_values,
        )
        return self

    def with_rule(
        self,
        if_: Condition,
        then: Union[Effect, Dict[str, Any]],
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> PolicyBuilder:
        """Set the policy rule."""
        if isinstance(then, Effect):
            effect = PolicyRuleEffect(effect=then, message=message, details=details)
        else:
            effect = PolicyRuleEffect(
                effect=Effect(then.get("effect", "Audit")),
                message=message or then.get("message"),
                details=details or then.get("details"),
            )

        self._rule = PolicyRule(condition=if_, effect=effect)
        return self

    def with_dine_rule(
        self,
        if_: Condition,
        deployment_template: Union[str, Path, Dict[str, Any]],
        role_definition_ids: List[str],
        exists_condition: Union[Condition, Dict[str, Any]],
        deployment_parameters: Optional[Dict[str, Any]] = None,
        deployment_mode: str = "incremental",
        message: Optional[str] = None,
        existence_scope: Optional[str] = None,
        deployment_scope: Optional[str] = None,
        evaluation_delay: Optional[str] = None,
        template_link: Optional[str] = None,
    ) -> PolicyBuilder:
        """Set a DeployIfNotExists rule with a Bicep or ARM JSON deployment template."""
        if isinstance(exists_condition, Condition):
            existence_dict: Dict[str, Any] = {
                "existenceCondition": exists_condition.to_dict()
            }
        else:
            existence_dict = dict(exists_condition)

        deployment_block: Dict[str, Any]
        if template_link:
            deployment_block = {
                "properties": {
                    "mode": deployment_mode,
                    "templateLink": {"uri": template_link},
                    "parameters": {},
                }
            }
        elif isinstance(deployment_template, dict):
            arm_template = deployment_template
            deployment_block = {
                "properties": {
                    "mode": deployment_mode,
                    "template": arm_template,
                    "parameters": {},
                }
            }
        else:
            path = (
                Path(deployment_template)
                if isinstance(deployment_template, str)
                else deployment_template
            )
            if path.suffix == ".bicep" and path.exists():
                from itl_policy_builder.export.bicep import BicepCompiler
                arm_template = BicepCompiler.from_file(path)
            elif isinstance(deployment_template, str) and not path.exists():
                from itl_policy_builder.export.bicep import BicepCompiler
                arm_template = BicepCompiler.from_string(deployment_template)
            else:
                import json as _json
                arm_template = _json.loads(path.read_text(encoding="utf-8"))
            deployment_block = {
                "properties": {
                    "mode": deployment_mode,
                    "template": arm_template,
                    "parameters": {},
                }
            }

        for k, v in (deployment_parameters or {}).items():
            deployment_block["properties"]["parameters"][k] = (
                v if isinstance(v, dict) and "value" in v else {"value": v}
            )

        details: Dict[str, Any] = {
            **existence_dict,
            "roleDefinitionIds": role_definition_ids,
            "deployment": deployment_block,
        }
        if existence_scope:
            details["existenceScope"] = existence_scope
        if deployment_scope:
            details["deploymentScope"] = deployment_scope
        if evaluation_delay:
            details["evaluationDelay"] = evaluation_delay

        return self.with_rule(
            if_=if_,
            then=Effect.DEPLOY_IF_NOT_EXISTS,
            message=message,
            details=details,
        )

    def with_aine_rule(
        self,
        if_: Condition,
        resource_type: str,
        exists_condition: Union[Condition, Dict[str, Any]],
        role_definition_ids: Optional[List[str]] = None,
        resource_name: Optional[str] = None,
        existence_scope: Optional[str] = None,
        evaluation_delay: Optional[str] = None,
        message: Optional[str] = None,
    ) -> PolicyBuilder:
        """Set an AuditIfNotExists rule."""
        if isinstance(exists_condition, Condition):
            existence_fragment: Dict[str, Any] = {
                "existenceCondition": exists_condition.to_dict()
            }
        else:
            existence_fragment = dict(exists_condition)

        details: Dict[str, Any] = {"type": resource_type, **existence_fragment}
        if resource_name:
            details["name"] = resource_name
        if role_definition_ids:
            details["roleDefinitionIds"] = role_definition_ids
        if existence_scope:
            details["existenceScope"] = existence_scope
        if evaluation_delay:
            details["evaluationDelay"] = evaluation_delay

        return self.with_rule(
            if_=if_,
            then=Effect.AUDIT_IF_NOT_EXISTS,
            message=message,
            details=details,
        )

    def with_append_rule(
        self,
        if_: Condition,
        operations: List[Dict[str, Any]],
        message: Optional[str] = None,
    ) -> PolicyBuilder:
        """Set an Append rule."""
        return self.with_rule(
            if_=if_,
            then=Effect.APPEND,
            message=message,
            details={"details": operations},
        )

    def with_modify_rule(
        self,
        if_: Condition,
        operations: List[Dict[str, Any]],
        role_definition_ids: List[str],
        message: Optional[str] = None,
    ) -> PolicyBuilder:
        """Set a Modify rule."""
        return self.with_rule(
            if_=if_,
            then=Effect.MODIFY,
            message=message,
            details={
                "roleDefinitionIds": role_definition_ids,
                "operations": operations,
            },
        )

    def tag(self, key: str, value: str) -> PolicyBuilder:
        """Add a tag to the policy resource."""
        self._tags[key] = value
        return self

    def tags(self, **kwargs: str) -> PolicyBuilder:
        """Add multiple tags to the policy resource."""
        self._tags.update(kwargs)
        return self

    def _generate_id(self) -> str:
        if self._scope:
            return f"{self._scope}/providers/ITL.Authorization/policyDefinitions/{self._name}"
        return f"/providers/ITL.Authorization/policyDefinitions/{self._name}"

    def build(self) -> PolicyDefinition:
        """Build and return the PolicyDefinition."""
        if self._rule is None:
            raise ValueError("Policy must have a rule. Use with_rule() to define one.")

        rule_dict = self._rule.to_dict()

        properties = PolicyDefinitionProperties(
            display_name=self._display_name or self._name,
            description=self._description,
            policy_type=self._policy_type,
            mode=self._mode,
            metadata=self._metadata if self._metadata else None,
            parameters=self._parameters if self._parameters else None,
            policy_rule=PolicyRuleModel(
                if_condition=rule_dict["if"],
                then_effect=rule_dict["then"],
            ),
        )

        return PolicyDefinition(
            id=self._generate_id(),
            name=self._name,
            type="ITL.Authorization/policyDefinitions",
            properties=properties,
        )

    def build_json(self) -> str:
        """Build and return ARM-compatible JSON."""
        return self.build().to_arm_json()

    def build_dict(self) -> Dict[str, Any]:
        """Build and return ARM-compatible dictionary."""
        return self.build().to_arm_dict()


# ============================================================================
# Convenience Factory Functions
# ============================================================================


def deny_if(condition: Condition, message: Optional[str] = None) -> PolicyBuilder:
    """Quick factory for a deny policy."""
    builder = PolicyBuilder(f"deny-{uuid4().hex[:8]}")
    builder.with_rule(if_=condition, then=Effect.DENY, message=message)
    return builder


def audit_if(condition: Condition, message: Optional[str] = None) -> PolicyBuilder:
    """Quick factory for an audit policy."""
    builder = PolicyBuilder(f"audit-{uuid4().hex[:8]}")
    builder.with_rule(if_=condition, then=Effect.AUDIT, message=message)
    return builder


def require_tag(tag_name: str, allowed_values: Optional[List[str]] = None) -> PolicyBuilder:
    """Factory for a policy that requires a specific tag."""
    from itl_policy_builder.conditions import field, all_of, any_of

    builder = PolicyBuilder(f"require-tag-{tag_name}")
    builder.display_name(f"Require '{tag_name}' Tag")
    builder.description(f"Ensures resources have the '{tag_name}' tag")
    builder.category("Tags")

    if allowed_values:
        condition = any_of(
            field(f"tags.{tag_name}").exists(False),
            field(f"tags.{tag_name}").not_in(*allowed_values),
        )
        builder.with_rule(
            if_=condition,
            then=Effect.DENY,
            message=f"Tag '{tag_name}' is required and must be one of: {', '.join(allowed_values)}",
        )
    else:
        condition = field(f"tags.{tag_name}").exists(False)
        builder.with_rule(
            if_=condition,
            then=Effect.DENY,
            message=f"Tag '{tag_name}' is required",
        )

    return builder


def allowed_locations(*locations: str) -> PolicyBuilder:
    """Factory for a policy that restricts allowed locations."""
    from itl_policy_builder.conditions import field, all_of

    builder = PolicyBuilder("allowed-locations")
    builder.display_name("Allowed Locations")
    builder.description(f"Restricts resources to: {', '.join(locations)}")
    builder.category("General")
    builder.mode("All")

    condition = all_of(
        field("type").not_equals("ITL.Core/resourceGroups"),
        field("location").not_in(*locations),
    )
    builder.with_rule(
        if_=condition,
        then=Effect.DENY,
        message=f"Resource location must be one of: {', '.join(locations)}",
    )

    return builder
