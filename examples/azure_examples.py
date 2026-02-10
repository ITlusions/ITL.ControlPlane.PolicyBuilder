"""
Examples: Azure ARM policies using ITL Policy Builder.

This example demonstrates how to build and export Azure Resource Manager (ARM)
policies for governance, compliance, and resource control at the subscription level.

Azure ARM policies are evaluated by the Control Plane API Gateway and can enforce:
- Location restrictions
- Tagging requirements
- Encryption mandates
- SKU restrictions
- Post-Quantum Cryptography (PQC) readiness
"""

import json
import yaml

from itl_policy_builder import (
    PolicyBuilder,
    PolicyAssignmentBuilder,
    PolicySetBuilder,
    field,
    all_of,
    any_of,
    not_,
    count,
    Effect,
)
from itl_policy_builder.templates import (
    get_builtin_policy,
    get_bio_policy,
    get_bio_initiative,
    get_pqc_policy,
    list_builtin_policies,
    list_bio_policies,
    list_pqc_policies,
)


def example_1_simple_location_policy():
    """Example 1: Simple policy - Require resources in West Europe."""
    print("\n" + "=" * 80)
    print("Example 1: Simple Policy - Require Location")
    print("=" * 80)
    
    policy = (
        PolicyBuilder("enforce-westeurope")
        .display_name("Enforce West Europe Location")
        .description("Ensures all resources must be created in West Europe region")
        .category("General")
        .mode("All")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY,
            message="All resources must be deployed in West Europe (westeurope)",
        )
        .build()
    )
    
    arm_json = policy.to_arm_json()
    
    print("\nPolicy Definition (JSON):")
    print(json.dumps(arm_json, indent=2))
    
    print("\n\nPolicRule (the actual rule):")
    print(json.dumps(arm_json["properties"]["policyRule"], indent=2))
    
    print("\n\nTo use this policy:")
    print("1. Save to file: azure-location-policy.json")
    print("2. Deploy via API: POST /policies/definitions")
    print("3. Create assignment on subscription scope")


def example_2_tagging_policy():
    """Example 2: Require specific tags on all resources."""
    print("\n" + "=" * 80)
    print("Example 2: Tagging Policy - Require Environment Tag")
    print("=" * 80)
    
    policy = (
        PolicyBuilder("require-environment-tag")
        .display_name("Require Environment Tag")
        .description("All resources must have an 'environment' tag with allowed values")
        .category("Tags")
        .mode("All")
        .parameter(
            "allowedEnvironments",
            type="Array",
            display_name="Allowed Environment Values",
            default=["dev", "test", "staging", "prod"],
        )
        .with_rule(
            if_=all_of(
                field("type").not_equals("ITL.Core/resourceGroups"),
                not_(field("tags.environment").exists()),
            ),
            then=Effect.DENY,
            message="Resource must have 'environment' tag with value: dev, test, staging, or prod",
        )
        .build()
    )
    
    arm_json = policy.to_arm_json()
    
    print("\nPolicy Definition (JSON):")
    print(json.dumps(arm_json, indent=2))
    
    print("\n\nParameterization:")
    print("- Admins can specify allowed values when assigning policy")
    print("- Default: dev, test, staging, prod")
    print("- Example assignment could restrict to only 'prod'")


def example_3_complex_conditions():
    """Example 3: Complex policy with AND/OR/NOT conditions."""
    print("\n" + "=" * 80)
    print("Example 3: Complex Policy - Deny Storage Without Encryption")
    print("=" * 80)
    
    # Deny storage accounts that don't have encryption enabled
    policy = (
        PolicyBuilder("require-storage-encryption")
        .display_name("Require Storage Encryption")
        .description("Storage accounts must have encryption enabled at rest")
        .category("Security")
        .mode("All")
        .with_rule(
            if_=all_of(
                field("type").equals("ITL.Storage/storageAccounts"),
                field("properties.encryption.enabled").equals(False),
            ),
            then=Effect.DENY,
            message="Storage accounts must have encryption enabled",
        )
        .build()
    )
    
    arm_json = policy.to_arm_json()
    
    print("\nPolicy Rule:")
    print(json.dumps(arm_json["properties"]["policyRule"], indent=2))
    
    print("\n\nLogic:")
    print("if (type == 'StorageAccount') AND (encryption.enabled == false)")
    print("  then DENY with message")
    print("\nEffect: Blocks storage accounts without encryption")


def example_4_using_builtin_template():
    """Example 4: Use built-in policy template."""
    print("\n" + "=" * 80)
    print("Example 4: Using Built-in Template - Allowed Locations")
    print("=" * 80)
    
    print("\nAvailable built-in policies:")
    policies = list_builtin_policies()
    for i, (name, description) in enumerate(policies[:5], 1):
        print(f"  {i}. {name}: {description}")
    print(f"  ... and {len(policies) - 5} more")
    
    # Use the allowed-locations template
    policy = get_builtin_policy(
        "allowed-locations",
        locations=["westeurope", "northeurope"],
    )
    
    arm_json = policy.to_arm_json()
    
    print("\n\nSelectedPolicy: allowed-locations")
    print("Parameters:")
    print("- locations: ['westeurope', 'northeurope']")
    
    print("\nPolicy Definition (JSON):")
    print(json.dumps(arm_json, indent=2)[:500] + "...")


def example_5_bio_compliance():
    """Example 5: BIO (Dutch government baseline) compliance policy."""
    print("\n" + "=" * 80)
    print("Example 5: BIO Compliance - Data Classification")
    print("=" * 80)
    
    print("\nAvailable BIO policies (17 total for Dutch government):")
    bio_policies = list_bio_policies()
    for i, (name, description, control) in enumerate(bio_policies[:5], 1):
        print(f"  [{control}] {name}: {description}")
    print(f"  ... and {len(bio_policies) - 5} more")
    
    # Get a specific BIO policy
    policy = get_bio_policy("bio-require-data-classification")
    
    arm_json = policy.to_arm_json()
    
    print("\n\nSelected Policy: bio-require-data-classification")
    print("Control: BIO-8 (Classificatie van informatie)")
    print("Purpose: Enforces data classification tagging per Dutch government standards")
    
    print("\nPolicy Definition:")
    print(json.dumps(arm_json, indent=2)[:400] + "...")
    
    print("\n\nBIO Categories:")
    print("- BIO-8: Classificatie van informatie (Information classification)")
    print("- BIO-9: Toegangsbeheer (Access control)")
    print("- BIO-10: Cryptografie (Cryptography)")
    print("- BIO-12: Beveiliging bedrijfsvoering (Operations security)")
    print("- BIO-13: Communicatiebeveiliging (Communications security)")
    
    print("\nTo get full BIO initiative (all 17 policies):")
    print("  from itl_policy_builder import get_bio_initiative")
    print("  initiative = get_bio_initiative()")


def example_6_pqc_readiness():
    """Example 6: Post-Quantum Cryptography readiness policies."""
    print("\n" + "=" * 80)
    print("Example 6: PQC Readiness - Quantum-Safe Cryptography")
    print("=" * 80)
    
    print("\nAvailable PQC policies (16 total):")
    pqc_policies = list_pqc_policies()
    for i, (name, description, category) in enumerate(pqc_policies[:5], 1):
        print(f"  [{category}] {name}: {description}")
    print(f"  ... and {len(pqc_policies) - 5} more")
    
    # Get a PQC policy
    policy = get_pqc_policy("pqc-require-kem", allow_hybrid=True)
    
    arm_json = policy.to_arm_json()
    
    print("\n\nSelected Policy: pqc-require-kem")
    print("Category: PQC-ALG (Quantum-Safe Algorithms)")
    print("Purpose: Requires ML-KEM (CRYSTALS-Kyber) for key exchange")
    print("Hybrid Mode: Allows classical + PQC algorithms during transition")
    
    print("\nPolicy Definition:")
    print(json.dumps(arm_json, indent=2)[:400] + "...")
    
    print("\n\nPQC Categories:")
    print("- PQC-ALG: Quantum-safe algorithm requirements")
    print("- PQC-KEY: Key management for quantum-safe crypto")
    print("- PQC-TLS: Transport security with PQC cipher suites")
    print("- PQC-CERT: Certificate management for PQC")
    print("- PQC-AUDIT: Migration planning and audit policies")


def example_7_policy_with_parameters():
    """Example 7: Policy with parameters for flexible assignments."""
    print("\n" + "=" * 80)
    print("Example 7: Parameterized Policy - Allows Customization")
    print("=" * 80)
    
    policy = (
        PolicyBuilder("allowed-resource-locations")
        .display_name("Allowed Resource Locations")
        .description("Resources can only be created in specified locations")
        .category("General")
        .mode("All")
        .parameter(
            "allowedLocations",
            type="Array",
            display_name="Allowed Locations",
            description="Array of locations where resources are allowed",
            default=["westeurope", "northeurope"],
        )
        .parameter(
            "effect",
            type="String",
            display_name="Policy Effect",
            description="Enable or disable the policy",
            allowed_values=["Audit", "Deny", "AuditIfNotExists"],
            default="Deny",
        )
        .with_rule(
            if_=field("location").not_in("[parameters('allowedLocations')]"),
            then=Effect.DENY,
            message="Resource location must be in allowed list",
        )
        .build()
    )
    
    arm_json = policy.to_arm_json()
    
    print("\nParameters:")
    for param_name, param_config in arm_json["properties"]["parameters"].items():
        print(f"\n  {param_name}:")
        print(f"    Type: {param_config.get('type')}")
        print(f"    Default: {param_config.get('defaultValue')}")
        if param_config.get('allowedValues'):
            print(f"    Allowed: {param_config.get('allowedValues')}")
    
    print("\n\nWhen assigning this policy, admins can override:")
    print("  allowedLocations: ['westeurope']  # Different from default")
    print("  effect: 'Audit'  # Start with audit mode, switch to Deny later")


def example_8_policy_assignment():
    """Example 8: Create policy assignment (scope enforcement)."""
    print("\n" + "=" * 80)
    print("Example 8: Policy Assignment - Enforce on Subscription")
    print("=" * 80)
    
    # First, create the policy
    policy = (
        PolicyBuilder("require-westeurope")
        .display_name("Require West Europe")
        .with_rule(
            if_=field("location").not_equals("westeurope"),
            then=Effect.DENY,
        )
        .build()
    )
    
    # Then, assign it to a scope
    assignment = (
        PolicyAssignmentBuilder("enforce-location-prod")
        .policy_definition_id(policy.id)
        .scope("/subscriptions/sub-prod-001")
        .display_name("Enforce Location in Production")
        .description("All resources in production must be in West Europe")
        .parameter("effect", "Deny")
        .exclude_scope("/subscriptions/sub-prod-001/resourceGroups/legacy-rg")
        .non_compliance_message("Resource location must be westeurope")
        .build()
    )
    
    print("\nPolicy Definition ID:")
    print(f"  {policy.id}")
    
    print("\nAssignment:")
    print(f"  ID: {assignment['id']}")
    print(f"  Name: {assignment['name']}")
    print(f"  Scope: {assignment['properties']['scope']}")
    print(f"  Policy: {assignment['properties']['policyDefinitionId']}")
    print(f"  Effect: {assignment['properties']['parameters']['effect']['value']}")
    print(f"  Excluded Scope: {assignment['properties'].get('notScopes')}")
    
    print("\n\nAssignment JSON:")
    print(json.dumps(assignment, indent=2))


def example_9_policy_initiative():
    """Example 9: Policy initiative (grouped policies)."""
    print("\n" + "=" * 80)
    print("Example 9: Policy Initiative - Grouped Policies")
    print("=" * 80)
    
    # Create individual policies
    policy_1 = (
        PolicyBuilder("require-location")
        .display_name("Require Location")
        .with_rule(if_=field("location").exists(), then=Effect.AUDIT)
        .build()
    )
    
    policy_2 = (
        PolicyBuilder("require-tags")
        .display_name("Require Tags")
        .with_rule(if_=field("tags").exists(), then=Effect.AUDIT)
        .build()
    )
    
    # Group into initiative
    initiative = (
        PolicySetBuilder("security-baseline")
        .display_name("Security and Governance Baseline")
        .description("Foundational security policies for all resources")
        .category("Security")
        .add_group("Location Control", "Ensure resources in approved regions")
        .add_group("Tagging", "Enforce consistent tagging standards")
        .add_policy(
            policy_1.id,
            display_name="Location Policy",
            groups=["Location Control"],
        )
        .add_policy(
            policy_2.id,
            display_name="Tagging Policy",
            groups=["Tagging"],
        )
        .build()
    )
    
    print("\nInitiative Definition:")
    print(f"  Name: {initiative['name']}")
    print(f"  Display Name: {initiative['properties']['displayName']}")
    print(f"  Category: {initiative['properties']['metadata']['category']}")
    
    print("\nPolicy Groups:")
    for group in initiative["properties"]["policyGroupDefinitions"]:
        print(f"  - {group['name']}: {group.get('description')}")
    
    print("\nPolicies in Initiative:")
    for policy in initiative["properties"]["policyDefinitions"]:
        print(f"  - {policy['policyDefinitionId']}")
        print(f"    Groups: {policy.get('groupNames')}")
    
    print("\n\nInitiative JSON:")
    print(json.dumps(initiative, indent=2)[:600] + "...")


def example_10_export_to_formats():
    """Example 10: Export policies to different formats."""
    print("\n" + "=" * 80)
    print("Example 10: Export Formats - JSON vs YAML")
    print("=" * 80)
    
    policy = (
        PolicyBuilder("audit-encryption")
        .display_name("Audit Encryption Settings")
        .with_rule(
            if_=all_of(
                field("type").equals("ITL.Storage/storageAccounts"),
                field("properties.encryption.enabled").equals(False),
            ),
            then=Effect.AUDIT,
            message="Storage account encryption is not enabled",
        )
        .build()
    )
    
    arm_json = policy.to_arm_json()
    
    print("\n1. JSON Format (API-ready):")
    print(json.dumps(arm_json, indent=2)[:400] + "...")
    
    print("\n\n2. YAML Format (documentation/readability):")
    yaml_str = yaml.dump(arm_json, default_flow_style=False, sort_keys=False)
    print(yaml_str[:400] + "...")
    
    print("\n\nUse Cases:")
    print("- JSON: API deployments, programmatic processing")
    print("- YAML: Documentation, team reviews, version control")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("ITL Policy Builder - Azure ARM Examples")
    print("=" * 80)
    
    example_1_simple_location_policy()
    example_2_tagging_policy()
    example_3_complex_conditions()
    example_4_using_builtin_template()
    example_5_bio_compliance()
    example_6_pqc_readiness()
    example_7_policy_with_parameters()
    example_8_policy_assignment()
    example_9_policy_initiative()
    example_10_export_to_formats()
    
    print("\n" + "=" * 80)
    print("Azure ARM Examples completed!")
    print("=" * 80)
    print("\nNext steps:")
    print("1. Run examples: python azure_examples.py")
    print("2. Use CLI: itl-policy generate --template talos-security --style azure")
    print("3. Deploy via API: itl-policy deploy --file policies.json --target itl-api")
