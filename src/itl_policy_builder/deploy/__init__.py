"""
Policy Deployment Module — Programmatic deployment of policies to targets.

This module provides the core deployment functionality (no CLI dependencies).
It can be used standalone for SDK users or extended by the CLI tool.

Components:
- PolicyDeployer: Main deployment orchestrator
- DeployTarget: Target enumeration (kubernetes, itl_api, azure, kyverno_webhook)
- DeployConfig: Configuration for deployment
- DeployResult: Result tracking
- KubernetesTarget: Deploy Kyverno policies to Kubernetes clusters
- ITLAPITarget: Deploy policies to ITL Control Plane API Gateway
- AzureTarget: Deploy Azure ARM policies to Azure subscriptions (NEW)

Supported Targets:
- Kubernetes: Via Kyverno ClusterPolicies
- ITL Control Plane: Via REST API
- Azure: Via Azure Resource Manager API (with azure-mgmt-authorization, azure-identity)
"""

from itl_policy_builder.deploy.deployer import (
    PolicyDeployer,
    DeployTarget,
    DeployConfig,
    DeployResult,
)

__all__ = [
    "PolicyDeployer",
    "DeployTarget",
    "DeployConfig",
    "DeployResult",
]
