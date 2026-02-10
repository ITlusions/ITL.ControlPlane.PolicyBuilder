"""
Core policy deployment engine — framework for deploying policies to various targets.

Supports:
- Kubernetes clusters (via kubectl/client)
- ITL ControlPlane API Gateway
- Multiple simultaneous targets
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import json
from abc import ABC, abstractmethod


class DeployTarget(str, Enum):
    """Deployment target types."""
    KUBERNETES = "kubernetes"
    ITL_API = "itl_api"
    AZURE = "azure"
    KYVERNO_WEBHOOK = "kyverno_webhook"


class DeployAction(str, Enum):
    """Deployment action types."""
    AUDIT = "audit"
    ENFORCE = "enforce"
    DRY_RUN = "dry-run"


@dataclass
class DeployConfig:
    """Configuration for policy deployment."""
    target: DeployTarget
    
    # Kubernetes config
    kubeconfig_path: Optional[str] = None
    namespace: str = "kyverno"
    context: Optional[str] = None
    
    # ITL API config
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None
    api_timeout: int = 30
    
    # Azure config
    azure_subscription_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    azure_assignment_scope: Optional[str] = None  # e.g., /subscriptions/{sub_id}
    azure_credential: Optional[str] = None  # 'default', 'cli', 'env' for auth method
    
    # Deployment config
    action: DeployAction = DeployAction.AUDIT
    verify_ca: bool = True
    dry_run: bool = False
    
    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class DeployResult:
    """Result of a deployment operation."""
    success: bool
    target: DeployTarget
    deployed_count: int = 0
    failed_count: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def summary(self) -> str:
        """Human-readable summary."""
        if self.success:
            return f"✅ {self.deployed_count} policies deployed to {self.target.value}"
        else:
            return f"❌ Failed to deploy to {self.target.value}: {', '.join(self.errors)}"


class DeploymentTarget(ABC):
    """Abstract base class for deployment targets."""
    
    def __init__(self, config: DeployConfig):
        self.config = config
    
    @abstractmethod
    async def deploy(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Deploy policies to target."""
        pass
    
    @abstractmethod
    async def validate(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Validate policies without deploying."""
        pass
    
    @abstractmethod
    async def get_status(self, policy_id: str) -> Dict[str, Any]:
        """Get deployment status of a policy."""
        pass


class KubernetesTarget(DeploymentTarget):
    """Deploy policies to Kubernetes clusters via Kyverno."""
    
    def __init__(self, config: DeployConfig):
        super().__init__(config)
        self._client = None
    
    async def deploy(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Deploy Kyverno policies to Kubernetes."""
        result = DeployResult(
            success=True,
            target=DeployTarget.KUBERNETES,
        )
        
        if self.config.dry_run:
            result.details["dry_run"] = True
            result.details["policies"] = [p["metadata"]["name"] for p in policies]
            return result
        
        try:
            from kubernetes import client, config
            from kubernetes.client.rest import ApiException
        except ImportError:
            result.success = False
            result.errors.append(
                "kubernetes package not installed. Install with: pip install kubernetes"
            )
            return result
        
        try:
            # Load kubeconfig
            if self.config.kubeconfig_path:
                config.load_kube_config(
                    config_file=self.config.kubeconfig_path,
                    context=self.config.context,
                )
            else:
                config.load_incluster_config()
            
            # Create API client
            api = client.CustomObjectsApi()
            
            # Deploy each policy
            for policy in policies:
                try:
                    api.create_namespaced_custom_object(
                        group="kyverno.io",
                        version="v1",
                        namespace=self.config.namespace,
                        plural="clusterpolicies" if policy["kind"] == "ClusterPolicy" else "policies",
                        body=policy,
                    )
                    result.deployed_count += 1
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        # Update instead
                        api.patch_namespaced_custom_object(
                            group="kyverno.io",
                            version="v1",
                            namespace=self.config.namespace,
                            plural="clusterpolicies" if policy["kind"] == "ClusterPolicy" else "policies",
                            name=policy["metadata"]["name"],
                            body=policy,
                        )
                        result.deployed_count += 1
                    else:
                        result.failed_count += 1
                        result.errors.append(
                            f"Failed to deploy {policy['metadata']['name']}: {e.reason}"
                        )
        
        except Exception as e:
            result.success = False
            result.errors.append(f"Kubernetes deployment failed: {str(e)}")
            return result
        
        result.success = result.failed_count == 0
        return result
    
    async def validate(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Validate Kyverno policies."""
        result = DeployResult(
            success=True,
            target=DeployTarget.KUBERNETES,
        )
        
        for policy in policies:
            # Basic validation
            if "metadata" not in policy or "name" not in policy["metadata"]:
                result.errors.append(f"Policy missing metadata.name: {policy}")
            elif "spec" not in policy:
                result.errors.append(f"Policy missing spec: {policy['metadata']['name']}")
            else:
                result.deployed_count += 1
        
        result.success = len(result.errors) == 0
        return result
    
    async def get_status(self, policy_id: str) -> Dict[str, Any]:
        """Get deployment status."""
        return {
            "policy_id": policy_id,
            "status": "unknown",  # Would query K8s API
            "deployed_to": [],
        }


class ITLAPITarget(DeploymentTarget):
    """Deploy policies to ITL ControlPlane API Gateway."""
    
    async def deploy(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Deploy policies to ITL API."""
        result = DeployResult(
            success=True,
            target=DeployTarget.ITL_API,
        )
        
        if self.config.dry_run:
            result.details["dry_run"] = True
            result.details["endpoint"] = self.config.api_endpoint
            result.deployed_count = len(policies)
            return result
        
        try:
            import httpx
        except ImportError:
            result.success = False
            result.errors.append(
                "httpx package not installed. Install with: pip install httpx"
            )
            return result
        
        try:
            async with httpx.AsyncClient(
                verify=self.config.verify_ca,
                timeout=self.config.api_timeout,
            ) as client:
                for policy in policies:
                    try:
                        response = await client.post(
                            f"{self.config.api_endpoint}/policies",
                            json=policy,
                            headers={
                                "Authorization": f"Bearer {self.config.api_key}",
                                "Content-Type": "application/json",
                            },
                        )
                        
                        if 200 <= response.status_code < 300:
                            result.deployed_count += 1
                        else:
                            result.failed_count += 1
                            result.errors.append(
                                f"API returned {response.status_code} for {policy['metadata']['name']}"
                            )
                    except Exception as e:
                        result.failed_count += 1
                        result.errors.append(f"Failed to deploy {policy['metadata']['name']}: {str(e)}")
        
        except Exception as e:
            result.success = False
            result.errors.append(f"ITL API deployment failed: {str(e)}")
            return result
        
        result.success = result.failed_count == 0
        return result
    
    async def validate(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Validate policies via ITL API."""
        result = DeployResult(
            success=True,
            target=DeployTarget.ITL_API,
        )
        
        try:
            import httpx
        except ImportError:
            result.success = False
            result.errors.append("httpx not installed")
            return result
        
        try:
            async with httpx.AsyncClient(verify=self.config.verify_ca) as client:
                response = await client.post(
                    f"{self.config.api_endpoint}/policies/validate",
                    json={"policies": policies},
                    headers={"Authorization": f"Bearer {self.config.api_key}"},
                )
                
                if response.status_code == 200:
                    data = response.json()
                    result.success = data.get("valid", True)
                    result.errors = data.get("errors", [])
                else:
                    result.success = False
                    result.errors.append(f"Validation API returned {response.status_code}")
        
        except Exception as e:
            result.success = False
            result.errors.append(f"Validation failed: {str(e)}")
        
        return result
    
    async def get_status(self, policy_id: str) -> Dict[str, Any]:
        """Get policy status from ITL API."""
        try:
            import httpx
        except ImportError:
            return {"error": "httpx not installed"}
        
        try:
            async with httpx.AsyncClient(verify=self.config.verify_ca) as client:
                response = await client.get(
                    f"{self.config.api_endpoint}/policies/{policy_id}/status",
                    headers={"Authorization": f"Bearer {self.config.api_key}"},
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    return {"error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


class AzureTarget(DeploymentTarget):
    """Deploy policies to Azure subscriptions using Azure SDK."""
    
    async def deploy(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Deploy policies to Azure subscriptions."""
        result = DeployResult(
            success=True,
            target=DeployTarget.AZURE,
        )
        
        # Validate required config
        if not self.config.azure_subscription_id:
            result.success = False
            result.errors.append("azure_subscription_id is required for Azure deployment")
            return result
        
        if not self.config.azure_assignment_scope:
            result.success = False
            result.errors.append("azure_assignment_scope is required for Azure deployment")
            return result
        
        if self.config.dry_run:
            result.details["dry_run"] = True
            result.details["subscription_id"] = self.config.azure_subscription_id
            result.details["scope"] = self.config.azure_assignment_scope
            result.deployed_count = len(policies)
            return result
        
        try:
            from azure.identity import DefaultAzureCredential, AzureCliCredential, EnvironmentCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError:
            result.success = False
            result.errors.append(
                "Azure SDK not installed. Install with: pip install azure-mgmt-authorization azure-identity"
            )
            return result
        
        try:
            # Get credentials based on auth method
            credential = None
            if self.config.azure_credential == "cli":
                try:
                    credential = AzureCliCredential()
                except Exception:
                    credential = DefaultAzureCredential()
            elif self.config.azure_credential == "env":
                try:
                    credential = EnvironmentCredential()
                except Exception:
                    credential = DefaultAzureCredential()
            else:  # default
                credential = DefaultAzureCredential()
            
            # Create client
            client = AuthorizationManagementClient(
                credential=credential,
                subscription_id=self.config.azure_subscription_id,
            )
            
            # Deploy each policy
            for policy in policies:
                try:
                    # Extract policy definition
                    policy_name = policy.get("name", policy.get("metadata", {}).get("name"))
                    
                    if not policy_name:
                        result.failed_count += 1
                        result.errors.append("Policy missing name field")
                        continue
                    
                    # Create policy definition
                    policy_def = {
                        "properties": {
                            "displayName": policy.get("properties", {}).get("displayName", policy_name),
                            "policyType": "Custom",
                            "mode": policy.get("properties", {}).get("mode", "All"),
                            "description": policy.get("properties", {}).get("description", ""),
                            "policyRule": policy.get("properties", {}).get("policyRule", {}),
                            "parameters": policy.get("properties", {}).get("parameters", {}),
                            "metadata": {
                                "category": policy.get("properties", {}).get("metadata", {}).get("category", "General"),
                            }
                        }
    }
                    
                    # Create policy definition in Azure
                    create_result = client.policy_definitions.create_or_update(
                        policy_definition_name=policy_name,
                        parameters=policy_def,
                    )
                    
                    # Create assignment
                    assignment_name = f"{policy_name}-assign-{self.config.action}"
                    assignment = {
                        "properties": {
                            "policyDefinitionId": create_result.id,
                            "scope": self.config.azure_assignment_scope,
                            "enforcementMode": "DoNotEnforce" if self.config.action == DeployAction.AUDIT else "Default",
                            "parameters": {},
                            "metadata": {
                                "managedBy": "itl-policy-builder",
                                "createdTime": __import__("datetime").datetime.utcnow().isoformat(),
                            }
                        }
                    }
                    
                    assign_result = client.policy_assignments.create(
                        scope=self.config.azure_assignment_scope,
                        policy_assignment_name=assignment_name,
                        parameters=assignment,
                    )
                    
                    result.deployed_count += 1
                    result.details[policy_name] = {
                        "definition_id": create_result.id,
                        "assignment_id": assign_result.id,
                    }
                
                except Exception as e:
                    result.failed_count += 1
                    result.errors.append(f"Failed to deploy {policy_name}: {str(e)}")
        
        except Exception as e:
            result.success = False
            result.errors.append(f"Azure deployment failed: {str(e)}")
            return result
        
        result.success = result.failed_count == 0
        return result
    
    async def validate(self, policies: List[Dict[str, Any]]) -> DeployResult:
        """Validate Azure ARM policies."""
        result = DeployResult(
            success=True,
            target=DeployTarget.AZURE,
        )
        
        for policy in policies:
            policy_name = policy.get("name", policy.get("metadata", {}).get("name"))
            
            # Validate structure
            if not policy_name:
                result.errors.append("Policy missing name field")
                continue
            
            props = policy.get("properties", {})
            if not props.get("policyRule"):
                result.errors.append(f"Policy {policy_name} missing policyRule")
                continue
            
            result.deployed_count += 1
        
        result.success = len(result.errors) == 0
        return result
    
    async def get_status(self, policy_id: str) -> Dict[str, Any]:
        """Get Azure policy status."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError:
            return {"error": "Azure SDK not installed"}
        
        try:
            credential = DefaultAzureCredential()
            client = AuthorizationManagementClient(
                credential=credential,
                subscription_id=self.config.azure_subscription_id,
            )
            
            # Try to get the policy definition
            result = client.policy_definitions.get(policy_definition_name=policy_id)
            
            return {
                "id": result.id,
                "name": result.name,
                "type": result.type,
                "properties": result.properties,
            }
        except Exception as e:
            return {"error": str(e)}


class PolicyDeployer:
    """Main policy deployment orchestrator."""
    
    def __init__(self, configs: List[DeployConfig] = None, config: DeployConfig = None):
        """Initialize deployer with one or more target configs."""
        if config:
            self.configs = [config]
        elif configs:
            self.configs = configs
        else:
            raise ValueError("Must provide at least one DeployConfig")
        
        self.targets = self._create_targets()
    
    def _create_targets(self) -> List[DeploymentTarget]:
        """Create deployment target instances."""
        targets = []
        for config in self.configs:
            if config.target == DeployTarget.KUBERNETES:
                targets.append(KubernetesTarget(config))
            elif config.target == DeployTarget.ITL_API:
                targets.append(ITLAPITarget(config))
            elif config.target == DeployTarget.AZURE:
                targets.append(AzureTarget(config))
            else:
                raise ValueError(f"Unknown deployment target: {config.target}")
        return targets
    
    async def deploy(self, policies: List[Dict[str, Any]]) -> List[DeployResult]:
        """Deploy policies to all configured targets."""
        results = []
        for target in self.targets:
            result = await target.deploy(policies)
            results.append(result)
        return results
    
    async def validate(self, policies: List[Dict[str, Any]]) -> List[DeployResult]:
        """Validate policies on all targets."""
        results = []
        for target in self.targets:
            result = await target.validate(policies)
            results.append(result)
        return results
    
    async def get_status_all(self, policy_id: str) -> Dict[str, Any]:
        """Get status of a policy on all targets."""
        status = {}
        for target in self.targets:
            target_status = await target.get_status(policy_id)
            status[target.config.target.value] = target_status
        return status


if __name__ == "__main__":
    # Example usage
    config = DeployConfig(
        target=DeployTarget.KUBERNETES,
        kubeconfig_path="~/.kube/config",
    )
    
    deployer = PolicyDeployer(config=config)
    print(f"Initialized deployer for target: {config.target.value}")
