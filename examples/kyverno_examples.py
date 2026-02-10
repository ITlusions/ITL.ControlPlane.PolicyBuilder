"""
Examples: Policy generation for multiple frameworks.

This example demonstrates how to build and export policies in multiple formats:
- Kyverno: Kubernetes-native admission controller policies
- Azure ARM: Azure Resource Manager policy definitions
Both support equivalent governance and compliance use cases.
"""

import json
import yaml

from itl_policy_builder import (
    KyvernoPolicyBuilder,
    KyvernoPodSecurityBuilder,
    KyvernoImageSecurityBuilder,
    KyvernoNetworkPolicyBuilder,
    KyvernoPQCBuilder,
    KyvernoMatch,
    MatchKind,
    ValidationAction,
    PolicyBuilder,
    field,
    Effect,
)
from itl_policy_builder.templates.kyverno import (
    get_talos_security_bundle,
    get_pqc_transition_bundle,
    list_kyverno_policies,
    get_kyverno_policies_by_category,
)
from itl_policy_builder.templates import (
    get_builtin_policy,
    list_builtin_policies,
)


def example_1_pod_security():
    """Example 1: Pod security baseline policy."""
    print("\n" + "=" * 80)
    print("Example 1: Pod Security Baseline Policy")
    print("=" * 80)
    
    policy = (
        KyvernoPodSecurityBuilder("pod-security-baseline")
        .require_security_context()
        .require_non_root()
        .build()
    )
    
    print("\nPolicy (JSON):")
    print(json.dumps(policy, indent=2))
    
    print("\nPolicy (YAML):")
    print(yaml.dump(policy, default_flow_style=False, sort_keys=False))


def example_2_image_security():
    """Example 2: Image security policies."""
    print("\n" + "=" * 80)
    print("Example 2: Image Security Policy (No Latest Tag)")
    print("=" * 80)
    
    policy = (
        KyvernoImageSecurityBuilder("disallow-latest-tag")
        .require_image_pull_policy()
        .build()
    )
    
    print("\nPolicy (YAML):")
    print(yaml.dump(policy, default_flow_style=False, sort_keys=False))


def example_3_custom_policy():
    """Example 3: Custom validation policy."""
    print("\n" + "=" * 80)
    print("Example 3: Custom Policy - Require Resource Limits")
    print("=" * 80)
    
    policy = KyvernoPolicyBuilder("require-resource-limits")
    policy.with_display_name("Resource Limits Required")
    policy.with_description(
        "All containers must specify CPU and memory resource limits."
    )
    policy.with_validation_action(ValidationAction.ENFORCE)
    
    policy.add_validation_rule(
        rule_name="check-resources",
        message="CPU and memory requests/limits are required",
        pattern={
            "spec": {
                "containers": [
                    {
                        "resources": {
                            "requests": {
                                "cpu": "?",
                                "memory": "?"
                            },
                            "limits": {
                                "cpu": "?",
                                "memory": "?"
                            }
                        }
                    }
                ]
            }
        },
        match=KyvernoMatch(kind=MatchKind.POD),
        action=ValidationAction.ENFORCE,
    )
    
    policy_dict = policy.build()
    
    print("\nPolicy (YAML):")
    print(yaml.dump(policy_dict, default_flow_style=False, sort_keys=False))


def example_4_pqc_readiness():
    """Example 4: PQC readiness policies."""
    print("\n" + "=" * 80)
    print("Example 4: Post-Quantum Cryptography Readiness")
    print("=" * 80)
    
    policy = (
        KyvernoPQCBuilder("pqc-crypto-readiness")
        .require_pqc_label()
        .build()
    )
    
    print("\nPolicy (YAML):")
    print(yaml.dump(policy, default_flow_style=False, sort_keys=False))


def example_5_talos_bundle():
    """Example 5: Complete Talos security bundle."""
    print("\n" + "=" * 80)
    print("Example 5: Talos Security Bundle (All-in-One)")
    print("=" * 80)
    
    policies = get_talos_security_bundle()
    
    print(f"\nBundle contains {len(policies)} policies:")
    for i, policy in enumerate(policies, 1):
        print(f"  {i}. {policy['metadata']['name']} - {policy['spec']['rules'][0]['name']}")
    
    # Export as YAML manifests
    yaml_output = "\n---\n".join(
        yaml.dump(policy, default_flow_style=False, sort_keys=False)
        for policy in policies
    )
    
    print("\n\nBundle (YAML - first 500 chars):")
    print(yaml_output[:500] + "...")


def example_6_list_policies():
    """Example 6: List all available Kyverno policies."""
    print("\n" + "=" * 80)
    print("Example 6: Available Kyverno Policies")
    print("=" * 80)
    
    policies = list_kyverno_policies()
    print(f"\nTotal policies: {len(policies)}")
    
    for category in ["security", "image", "pqc", "talos"]:
        policies_in_cat = get_kyverno_policies_by_category(category)
        print(f"\n{category.upper()} ({len(policies_in_cat)} policies):")
        for policy in policies_in_cat:
            name = policy['metadata']['name']
            print(f"  - {name}")


def example_7_mutation():
    """Example 7: Mutation rule (modify resources)."""
    print("\n" + "=" * 80)
    print("Example 7: Mutation Policy - Auto-label Pods")
    print("=" * 80)
    
    policy = KyvernoPolicyBuilder("auto-label-pods")
    policy.with_display_name("Auto-label Pods")
    policy.with_description(
        "Automatically add environment and team labels to all pods."
    )
    
    policy.add_mutation_rule(
        rule_name="add-labels",
        message="Adding required labels",
        patch={
            "metadata": {
                "labels": {
                    "environment": "production",
                    "managed-by": "kyverno",
                    "talos-cluster": "true"
                }
            }
        },
        match=KyvernoMatch(kind=MatchKind.POD),
    )
    
    policy_dict = policy.build()
    
    print("\nPolicy (YAML):")
    print(yaml.dump(policy_dict, default_flow_style=False, sort_keys=False))


def example_8_deployment_manifest():
    """Example 8: Generate kubectl-ready manifest file."""
    print("\n" + "=" * 80)
    print("Example 8: Generate kubectl Manifest")
    print("=" * 80)
    
    # Get the Talos security bundle
    policies = get_talos_security_bundle()
    
    # Create multi-document YAML (kubectl manifests)
    manifest = "\n---\n".join(
        yaml.dump(policy, default_flow_style=False, sort_keys=False)
        for policy in policies
    )
    
    print("\n# ============================================================================")
    print("# Talos Security Policies Manifest")
    print("# Generated by ITL Policy Builder - Kyverno")
    print("# ")
    print("# Deploy with: kubectl apply -f talos-policies.yaml")
    print("# ============================================================================")
    print("\n" + manifest[:1000] + "\n\n# ... (more policies) ...")
    
    # Show how to save it
    print("\n\nTo save this manifest:")
    print("```python")
    print("with open('talos-policies.yaml', 'w') as f:")
    print("    for policy in get_talos_security_bundle():")
    print("        yaml.dump(policy, f)")
    print("        f.write('---\\n')")
    print("```")
    
    print("\nThen apply with:")
    print("  kubectl apply -f talos-policies.yaml")
    print("  kubectl get ClusterPolicy")


# ==============================================================
# AZURE ARM EXAMPLES
# ==============================================================

def example_9_azure_require_location():
    """Example 9: Azure ARM policy - Require West Europe location."""
    print("\n" + "=" * 80)
    print("Example 9: Azure ARM - Require Location Policy")
    print("=" * 80)
    
    policy = (
        PolicyBuilder("require-westeurope")
        .display_name("Require West Europe Location")
        .description("Ensures all resources are deployed in West Europe")
        .category("General")
        .mode("All")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY,
            message="Resources must be deployed in West Europe",
        )
        .build()
    )
    
    print("\nPolicy (JSON):")
    print(json.dumps(policy.to_arm_json(), indent=2))
    
    print("\nPolicy (YAML representation):")
    arm_json = policy.to_arm_json()
    print(yaml.dump(arm_json, default_flow_style=False, sort_keys=False))


def example_10_azure_require_tag():
    """Example 10: Azure ARM policy - Require environment tag."""
    print("\n" + "=" * 80)
    print("Example 10: Azure ARM - Require Tag Policy")
    print("=" * 80)
    
    # Use built-in template
    policy = get_builtin_policy(
        "require-tag",
        tag_name="environment",
        allowed_values=["dev", "test", "prod"],
    )
    
    print("\nPolicy (JSON):")
    print(json.dumps(policy.to_arm_json(), indent=2))


def example_11_azure_comparing_styles():
    """Example 11: Compare same policy in Kyverno vs Azure ARM."""
    print("\n" + "=" * 80)
    print("Example 11: Same Policy - Different Frameworks")
    print("=" * 80)
    
    print("\nScenario: Enforce pod resource limits")
    print("-" * 80)
    
    # Kyverno version
    kyverno_policy = (
        KyvernoPolicyBuilder("require-resource-limits")
        .with_display_name("Resource Limits Required")
        .with_description("All containers must specify CPU & memory requests/limits")
        .add_validation_rule(
            rule_name="check-limits",
            message="CPU and memory limits are required",
            pattern={
                "spec": {
                    "containers": [
                        {
                            "resources": {
                                "requests": {"cpu": "?", "memory": "?"},
                                "limits": {"cpu": "?", "memory": "?"}
                            }
                        }
                    ]
                }
            },
            match=KyvernoMatch(kind=MatchKind.POD),
            action=ValidationAction.ENFORCE,
        )
        .build()
    )
    
    print("\nKyverno (Kubernetes-native):")
    print("- Effect: Enforce (blocks violations)")
    print("- Target: Pod resources")
    print("- Pattern match on resource.spec.containers[*].resources")
    print("\nKyverno YAML (excerpt):")
    print(yaml.dump(kyverno_policy, default_flow_style=False, sort_keys=False)[:400] + "...")
    
    # Azure ARM version (conceptual equivalent)
    azure_policy = (
        PolicyBuilder("require-compute-resources")
        .display_name("Require Compute Resources on Pods")
        .description("Enforces CPU and memory resource specifications")
        .category("Security")
        .mode("All")
        .with_rule(
            if_=field("type").equals("Pod"),
            then=Effect.DENY,
            message="Pods must specify CPU and memory limits",
        )
        .build()
    )
    
    print("\n\nAzure ARM (Control Plane policy):")
    print("- Effect: Deny (blocks violations)")
    print("- Target: Pod resources by type")
    print("- Policy rules evaluated in ARM provider")
    print("\nAzure ARM JSON (excerpt):")
    arm_json = azure_policy.to_arm_json()
    print(json.dumps(arm_json["properties"]["policyRule"], indent=2)[:400] + "...")
    
    print("\n\nKey Differences:")
    print("- Kyverno: Real-time admission control in Kubernetes API server")
    print("- Azure ARM: Policy evaluated by Azure Resource Manager for compliance")
    print("- Both: Achieve similar governance goals on different platforms")


def example_12_azure_pqc_policies():
    """Example 12: Azure ARM PQC readiness policies."""
    print("\n" + "=" * 80)
    print("Example 12: Azure ARM - PQC Readiness Policies")
    print("=" * 80)
    
    # Create a PQC-focused policy
    policy = (
        PolicyBuilder("require-pqc-readiness-tag")
        .display_name("Require PQC Readiness Status")
        .description("All resources must be tagged with PQC readiness status")
        .category("Security")
        .parameter(
            "allowedValues",
            type="Array",
            default=["planning", "hybrid", "native", "compliant"],
        )
        .with_rule(
            if_=field("tags['pqc-readiness']").not_in("[parameters('allowedValues')]"),
            then=Effect.AUDIT,
            message="Resource must have valid PQC readiness tag",
        )
        .build()
    )
    
    print("\nAzure ARM Policy (JSON):")
    print(json.dumps(policy.to_arm_json(), indent=2))


def example_13_azure_initiative():
    """Example 13: Azure policy initiative (set of policies)."""
    print("\n" + "=" * 80)
    print("Example 13: Azure ARM - Policy Initiative")
    print("=" * 80)
    
    # Create individual policies
    policy_1 = (
        PolicyBuilder("require-westeurope")
        .display_name("Require West Europe")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY,
        )
        .build()
    )
    
    policy_2 = (
        PolicyBuilder("require-encryption")
        .display_name("Require Encryption at Rest")
        .with_rule(
            if_=field("properties.encryption.enabled").equals(False),
            then=Effect.DENY,
        )
        .build()
    )
    
    print("\nInitiative: Security Baseline")
    print("- Policy 1: Require West Europe Location")
    print("- Policy 2: Require Encryption at Rest")
    
    print("\nPolicy 1 (JSON):")
    print(json.dumps(policy_1.to_arm_json(), indent=2)[:300] + "...")
    
    print("\n...")
    print("\nPolicy 2 (JSON):")
    print(json.dumps(policy_2.to_arm_json(), indent=2)[:300] + "...")
    
    print("\n\nTo deploy as initiative, use itl-policy CLI:")
    print("  itl-policy generate --template security-baseline --style azure")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("ITL Policy Builder - Multi-Format Examples")
    print("=" * 80)
    
    # Kyverno examples
    print("\n\n" + "#" * 80)
    print("# KYVERNO EXAMPLES (Kubernetes)")
    print("#" * 80)
    example_1_pod_security()
    example_2_image_security()
    example_3_custom_policy()
    example_4_pqc_readiness()
    example_6_list_policies()
    example_7_mutation()
    example_8_deployment_manifest()
    
    # Azure ARM examples
    print("\n\n" + "#" * 80)
    print("# AZURE ARM EXAMPLES (Control Plane)")
    print("#" * 80)
    example_9_azure_require_location()
    example_10_azure_require_tag()
    example_11_azure_comparing_styles()
    example_12_azure_pqc_policies()
    example_13_azure_initiative()
    
    print("\n" + "=" * 80)
    print("Examples completed! (Kyverno + Azure ARM)")
    print("=" * 80)
