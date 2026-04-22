"""
ARM deployment template builder for policy resources.

Wraps one or more policy definitions, assignments, exemptions, and initiatives
in a full ARM deployment template (``$schema``, ``contentVersion``,
``parameters``, ``resources``) suitable for ``az deployment`` or the ITL API.

Example::

    from itl_policy_builder import PolicyBuilder, PolicyAssignmentBuilder, Effect, field
    from itl_policy_builder.deploy_template import ArmDeploymentTemplate

    policy = (
        PolicyBuilder("require-westeurope")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY,
        )
        .build()
    )

    assignment = (
        PolicyAssignmentBuilder("enforce-westeurope-prod")
        .policy_definition_id(policy.id)
        .scope("/subscriptions/sub-001")
        .build()
    )

    template = (
        ArmDeploymentTemplate("location-governance")
        .add_policy(policy)
        .add_assignment(assignment)
        .build()
    )

    print(template.to_json())
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from itl_policy_builder.models import (
    PolicyAssignment,
    PolicyDefinition,
    PolicyExemption,
    PolicySetDefinition,
)

_ARM_SCHEMA = (
    "https://schema.management.azure.com/schemas/"
    "2019-04-01/deploymentTemplate.json#"
)
_CONTENT_VERSION = "1.0.0.0"


class ArmDeploymentTemplate:
    """
    Builder for ARM deployment templates containing policy resources.

    Produces a JSON document with ``$schema``, ``contentVersion``,
    optional ``parameters``, and a ``resources`` array ready to be
    submitted to the ITL API Gateway or ``az deployment`` commands.

    Example::

        template = (
            ArmDeploymentTemplate("policy-baseline")
            .add_policy(require_https_policy)
            .add_initiative(security_initiative)
            .add_assignment(require_https_assignment)
            .build()
        )

        # Write to file
        with open("policy-baseline.json", "w") as f:
            f.write(template.to_json())
    """

    def __init__(self, description: Optional[str] = None):
        """
        Initialise a new ARM deployment template builder.

        Args:
            description: Optional description stored in the template's
                ``metadata.description`` field.
        """
        self._description = description
        self._resources: List[Dict[str, Any]] = []
        self._parameters: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Resource helpers                                                     #
    # ------------------------------------------------------------------ #

    def add_policy(self, policy: PolicyDefinition) -> ArmDeploymentTemplate:
        """
        Add a policy definition to the template.

        Args:
            policy: A :class:`~itl_policy_builder.models.PolicyDefinition` instance.
        """
        self._resources.append(policy.to_arm_dict())
        return self

    def add_assignment(self, assignment: PolicyAssignment) -> ArmDeploymentTemplate:
        """
        Add a policy assignment to the template.

        Args:
            assignment: A :class:`~itl_policy_builder.models.PolicyAssignment` instance.
        """
        self._resources.append(assignment.model_dump(by_alias=True, exclude_none=True))
        return self

    def add_initiative(
        self, initiative: PolicySetDefinition
    ) -> ArmDeploymentTemplate:
        """
        Add a policy set (initiative) to the template.

        Args:
            initiative: A :class:`~itl_policy_builder.models.PolicySetDefinition` instance.
        """
        self._resources.append(initiative.to_arm_dict())
        return self

    def add_exemption(self, exemption: PolicyExemption) -> ArmDeploymentTemplate:
        """
        Add a policy exemption to the template.

        Args:
            exemption: A :class:`~itl_policy_builder.models.PolicyExemption` instance.
        """
        self._resources.append(exemption.model_dump(by_alias=True, exclude_none=True))
        return self

    def add_resource(self, resource: Dict[str, Any]) -> ArmDeploymentTemplate:
        """
        Add a raw ARM resource dict to the template.

        Useful for including resource types that do not have a dedicated
        helper method (e.g. role assignments, custom RBAC definitions).
        """
        self._resources.append(resource)
        return self

    # ------------------------------------------------------------------ #
    # Parameters                                                           #
    # ------------------------------------------------------------------ #

    def parameter(
        self,
        name: str,
        type: str = "string",
        default_value: Any = None,
        allowed_values: Optional[List[Any]] = None,
        description: Optional[str] = None,
    ) -> ArmDeploymentTemplate:
        """
        Declare a template parameter.

        Parameters can be referenced inside resource definitions as the ARM
        expression ``[parameters('paramName')]``.

        Args:
            name: Parameter name.
            type: ARM parameter type (``"string"``, ``"array"``, ``"object"``,
                  ``"bool"``, ``"int"``, ``"securestring"``).
            default_value: Optional default value.
            allowed_values: Optional list of allowed values.
            description: Optional description shown in the portal.

        Example::

            .parameter("environment", type="string", allowed_values=["prod", "dev"])
        """
        param: Dict[str, Any] = {"type": type}
        if default_value is not None:
            param["defaultValue"] = default_value
        if allowed_values:
            param["allowedValues"] = allowed_values
        if description:
            param["metadata"] = {"description": description}
        self._parameters[name] = param
        return self

    # ------------------------------------------------------------------ #
    # Build                                                                #
    # ------------------------------------------------------------------ #

    def build(self) -> _ArmTemplate:
        """
        Build and return the :class:`_ArmTemplate`.

        Returns:
            A built template object with :meth:`~_ArmTemplate.to_json` and
            :meth:`~_ArmTemplate.to_dict` methods.
        """
        return _ArmTemplate(
            schema=_ARM_SCHEMA,
            content_version=_CONTENT_VERSION,
            description=self._description,
            parameters=dict(self._parameters),
            resources=list(self._resources),
        )


class _ArmTemplate:
    """
    A fully built ARM deployment template.

    Returned by :meth:`ArmDeploymentTemplate.build`. Use :meth:`to_json`
    or :meth:`to_dict` to serialise.
    """

    def __init__(
        self,
        schema: str,
        content_version: str,
        description: Optional[str],
        parameters: Dict[str, Any],
        resources: List[Dict[str, Any]],
    ):
        self._schema = schema
        self._content_version = content_version
        self._description = description
        self._parameters = parameters
        self._resources = resources

    def to_dict(self) -> Dict[str, Any]:
        """Convert to an ARM-compatible dictionary."""
        doc: Dict[str, Any] = {
            "$schema": self._schema,
            "contentVersion": self._content_version,
        }
        if self._description:
            doc["metadata"] = {"description": self._description}
        if self._parameters:
            doc["parameters"] = self._parameters
        doc["resources"] = self._resources
        return doc

    def to_json(self, indent: int = 2) -> str:
        """
        Serialise to ARM-compatible JSON.

        Args:
            indent: JSON indentation level (default ``2``).
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @property
    def resource_count(self) -> int:
        """Number of resources in the template."""
        return len(self._resources)

    def __repr__(self) -> str:
        return (
            f"<ArmTemplate resources={self.resource_count}"
            f" parameters={len(self._parameters)}>"
        )
