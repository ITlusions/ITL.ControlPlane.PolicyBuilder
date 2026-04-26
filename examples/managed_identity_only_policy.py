"""
Azure Policy: Enforce Managed Identity and Workload Identity Only

This policy ensures that only passwordless authentication methods are used:
- ✅ System-assigned managed identities
- ✅ User-assigned managed identities  
- ✅ Workload identities (federated credentials)
- ❌ Service principals with password credentials
- ❌ Service principals with certificate credentials

Security rationale:
- Eliminates secret sprawl and credential theft risks
- Enforces automatic credential rotation (managed identities)
- Aligns with Zero Trust principles
- Supports modern OIDC federation for CI/CD pipelines
"""

import json
from pathlib import Path

from itl_policy_builder import (
    PolicyBuilder,
    PolicySetBuilder,
    PolicyAssignmentBuilder,
    field,
    all_of,
    any_of,
    not_,
    count,
    Effect,
)

# Optional: YAML export support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def create_deny_password_credentials_policy():
    """
    Policy 1: Deny creation of service principals with password credentials.
    
    Targets Microsoft Graph API service principal creation with passwordCredentials.
    """
    policy = (
        PolicyBuilder("deny-sp-password-credentials")
        .display_name("Deny Service Principals with Password Credentials")
        .description(
            "Prevents creation of service principals with password-based secrets. "
            "Use managed identities or federated credentials instead."
        )
        .category("Identity")
        .mode("All")
        .with_rule(
            if_=all_of(
                field("type").equals("Microsoft.AAD/servicePrincipals"),
                field("properties.passwordCredentials").exists(),
                count("properties.passwordCredentials").greater_than(0),
            ),
            then=Effect.DENY,
            message=(
                "Service principals with password credentials are not allowed. "
                "Use managed identities (system-assigned or user-assigned) or "
                "workload identities with federated credentials (OIDC)."
            ),
        )
        .build()
    )
    
    return policy


def create_deny_certificate_credentials_policy():
    """
    Policy 2: Deny creation of service principals with certificate credentials.
    
    While certificates are better than passwords, managed identities are preferred.
    """
    policy = (
        PolicyBuilder("deny-sp-certificate-credentials")
        .display_name("Deny Service Principals with Certificate Credentials")
        .description(
            "Prevents creation of service principals with certificate-based authentication. "
            "Use managed identities or federated credentials for passwordless auth."
        )
        .category("Identity")
        .mode("All")
        .with_rule(
            if_=all_of(
                field("type").equals("Microsoft.AAD/servicePrincipals"),
                field("properties.certificateCredentials").exists(),
                count("properties.certificateCredentials").greater_than(0),
                # Allow if it ALSO has federated credentials (hybrid scenario)
                not_(
                    all_of(
                        field("properties.federatedIdentityCredentials").exists(),
                        count("properties.federatedIdentityCredentials").greater_than(0),
                    )
                ),
            ),
            then=Effect.DENY,
            message=(
                "Service principals with certificate credentials are not allowed unless "
                "combined with federated credentials. Use managed identities (system-assigned "
                "or user-assigned) or workload identities with federated credentials (OIDC)."
            ),
        )
        .build()
    )
    
    return policy


def create_audit_existing_credentials_policy():
    """
    Policy 3: Audit existing service principals with legacy credentials.
    
    Marks existing resources for remediation without blocking deployments.
    """
    policy = (
        PolicyBuilder("audit-legacy-sp-credentials")
        .display_name("Audit Service Principals with Legacy Credentials")
        .description(
            "Identifies existing service principals using passwords or certificates "
            "for migration planning to managed identities or workload identities."
        )
        .category("Identity")
        .mode("All")
        .with_rule(
            if_=all_of(
                field("type").equals("Microsoft.AAD/servicePrincipals"),
                any_of(
                    all_of(
                        field("properties.passwordCredentials").exists(),
                        count("properties.passwordCredentials").greater_than(0),
                    ),
                    all_of(
                        field("properties.certificateCredentials").exists(),
                        count("properties.certificateCredentials").greater_than(0),
                    ),
                ),
                # Exclude if it has federated credentials (migration in progress)
                not_(
                    all_of(
                        field("properties.federatedIdentityCredentials").exists(),
                        count("properties.federatedIdentityCredentials").greater_than(0),
                    )
                ),
            ),
            then=Effect.AUDIT,
            message=(
                "This service principal uses legacy password or certificate credentials. "
                "Migrate to managed identity or workload identity with federated credentials."
            ),
        )
        .build()
    )
    
    return policy


def create_require_managed_identity_policy():
    """
    Policy 4: Require managed identity for Azure resources that support it.
    
    Enforces managed identity assignment on VMs, App Services, Functions, etc.
    Effect: AUDIT (marks non-compliant resources without blocking)
    """
    policy = (
        PolicyBuilder("require-managed-identity-resources")
        .display_name("Require Managed Identity on Supported Resources")
        .description(
            "Ensures that Azure resources supporting managed identities have one assigned. "
            "Applies to VMs, App Service, Function Apps, Container Apps, AKS, Logic Apps. "
            "Audits non-compliant resources for remediation planning."
        )
        .category("Identity")
        .mode("Indexed")
        .with_rule(
            if_=all_of(
                field("type").in_(
                    "Microsoft.Compute/virtualMachines",
                    "Microsoft.Web/sites",
                    "Microsoft.ContainerInstance/containerGroups",
                    "Microsoft.ContainerService/managedClusters",
                    "Microsoft.Logic/workflows",
                    "Microsoft.Automation/automationAccounts",
                ),
                not_(field("identity.type").in_(
                    "SystemAssigned",
                    "UserAssigned",
                    "SystemAssigned, UserAssigned",
                )),
            ),
            then=Effect.AUDIT,
            message=(
                "This resource type supports managed identity but none is assigned. "
                "Enable system-assigned or user-assigned managed identity."
            ),
        )
        .build()
    )
    
    return policy


def create_workload_identity_allowed_policy():
    """
    Policy 5: Explicitly allow workload identities (documentation policy).
    
    This is an 'allow' policy that documents the approved authentication methods.
    """
    policy = (
        PolicyBuilder("allow-workload-identity")
        .display_name("Allow Workload Identities with Federated Credentials")
        .description(
            "Permits service principals with ONLY federated identity credentials "
            "(no passwords or certificates). Used for GitHub Actions, Azure DevOps, "
            "and other OIDC-based CI/CD pipelines."
        )
        .category("Identity")
        .mode("All")
        .with_rule(
            if_=all_of(
                field("type").equals("Microsoft.AAD/servicePrincipals"),
                field("properties.federatedIdentityCredentials").exists(),
                count("properties.federatedIdentityCredentials").greater_than(0),
                # No legacy credentials allowed
                not_(field("properties.passwordCredentials").exists()),
                not_(field("properties.certificateCredentials").exists()),
            ),
            then=Effect.AUDIT,  # Just mark as compliant
            message=(
                "✅ This service principal uses workload identity with federated credentials. "
                "This is a recommended passwordless authentication method."
            ),
        )
        .build()
    )
    
    return policy


def create_managed_identity_initiative():
    """
    Initiative (Policy Set): Managed Identity Enforcement
    
    Groups all managed identity policies into a single assignment.
    """
    # Build all policies
    policies = [
        create_deny_password_credentials_policy(),
        create_deny_certificate_credentials_policy(),
        create_audit_existing_credentials_policy(),
        create_require_managed_identity_policy(),
        create_workload_identity_allowed_policy(),
    ]
    
    # Extract policy IDs for initiative
    policy_ids = [p.id for p in policies]
    
    # Create initiative
    initiative = (
        PolicySetBuilder("managed-identity-enforcement")
        .display_name("Managed Identity and Workload Identity Enforcement")
        .description(
            "Comprehensive policy set enforcing passwordless authentication across Azure. "
            "Requires managed identities or workload identities with federated credentials. "
            "Blocks service principals with password or certificate credentials."
        )
        .category("Identity")
        .add_policies(*policy_ids)
        .build()
    )
    
    return initiative, policies


def create_subscription_assignment():
    """
    Assignment: Deploy the initiative to a subscription.
    
    Targets the entire subscription. All policies use non-blocking effects
    (Deny for service principals, Audit for resources) to balance security
    with operational continuity.
    """
    assignment = (
        PolicyAssignmentBuilder("managed-identity-enforcement")
        .display_name("Managed Identity Enforcement (Subscription)")
        .description(
            "Enforces managed identity and workload identity usage across all resources. "
            "Blocks creation of service principals with password/certificate credentials. "
            "Audits resources without managed identities for remediation planning."
        )
        .scope("/subscriptions/{subscription-id}")
        .policy_definition_id(
            "/subscriptions/{subscription-id}/providers/ITL.Authorization/"
            "policySetDefinitions/managed-identity-enforcement"
        )
        .location("westeurope")
        .build()
    )
    
    return assignment


def main():
    """Generate and export all policies, initiative, and assignment."""
    
    print("=" * 80)
    print("Azure Policy: Managed Identity & Workload Identity Enforcement")
    print("=" * 80)
    
    # Create initiative with all policies
    initiative, policies = create_managed_identity_initiative()
    
    print(f"\n✅ Created {len(policies)} policies")
    print("✅ Created policy initiative")
    
    # Export directory
    output_dir = Path(__file__).parent.parent / "output" / "managed_identity_policies"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Export individual policies
    print(f"\n📁 Exporting to: {output_dir}")
    for policy in policies:
        policy_file = output_dir / f"{policy.name}.json"
        with open(policy_file, "w", encoding="utf-8") as f:
            json.dump(policy.to_arm_dict(), f, indent=2, ensure_ascii=False)
        print(f"   - {policy_file.name}")
    
    # Export initiative
    initiative_file = output_dir / "managed_identity_initiative.json"
    with open(initiative_file, "w", encoding="utf-8") as f:
        json.dump(initiative.to_arm_dict(), f, indent=2, ensure_ascii=False)
    print(f"   - {initiative_file.name}")
    
    # Export assignment example
    assignment = create_subscription_assignment()
    assignment_file = output_dir / "subscription_assignment.json"
    with open(assignment_file, "w", encoding="utf-8") as f:
        f.write(assignment.to_arm_json())
    print(f"   - {assignment_file.name}")
    
    # Export YaRM (YAML ARM) versions! 🎉
    if YAML_AVAILABLE:
        print("\n📄 Exporting YaRM (YAML ARM) versions:")
        yaml_dir = output_dir / "yaml"
        yaml_dir.mkdir(exist_ok=True)
        
        # Export individual policies as YAML
        for policy in policies:
            policy_file = yaml_dir / f"{policy.name}.yaml"
            # Convert to JSON first then to dict to ensure clean serialization
            policy_dict = json.loads(json.dumps(policy.to_arm_dict(), default=str))
            with open(policy_file, "w", encoding="utf-8") as f:
                yaml.dump(policy_dict, f, default_flow_style=False, sort_keys=False)
            print(f"   - yaml/{policy_file.name}")
        
        # Export initiative as YAML
        initiative_file = yaml_dir / "managed_identity_initiative.yaml"
        initiative_dict = json.loads(json.dumps(initiative.to_arm_dict(), default=str))
        with open(initiative_file, "w", encoding="utf-8") as f:
            yaml.dump(initiative_dict, f, default_flow_style=False, sort_keys=False)
        print(f"   - yaml/{initiative_file.name}")
        
        # Export assignment as YAML
        # Note: PolicyAssignment only has to_arm_json(), so we parse and dump as YAML
        assignment_file = yaml_dir / "subscription_assignment.yaml"
        assignment_dict = json.loads(assignment.to_arm_json())
        with open(assignment_file, "w", encoding="utf-8") as f:
            yaml.dump(assignment_dict, f, default_flow_style=False, sort_keys=False)
        print(f"   - yaml/{assignment_file.name}")
    else:
        print("\n💡 Tip: Install PyYAML for YaRM (YAML ARM) export: pip install pyyaml")
    
    # Print summary
    print("\n" + "=" * 80)
    print("Policy Summary")
    print("=" * 80)
    
    for idx, policy in enumerate(policies, 1):
        print(f"\n{idx}. {policy.properties.display_name}")
        print(f"   Name: {policy.name}")
        print(f"   Effect: {policy.properties.policy_rule.then_effect['effect']}")
        print(f"   Description: {policy.properties.description}")
    
    print("\n" + "=" * 80)
    print("Deployment Instructions")
    print("=" * 80)
    print("""
1. Review policies in output/managed_identity_policies/

2. Deploy initiative to subscription:
   POST /subscriptions/{subscription-id}/providers/ITL.Authorization/policySetDefinitions/managed-identity-enforcement
   Body: managed_identity_initiative.json

3. Assign to subscription (AUDIT mode first):
   POST /subscriptions/{subscription-id}/providers/ITL.Authorization/policyAssignments/managed-identity-enforcement
   Body: subscription_assignment.json

4. Review audit results:
   GET /subscriptions/{subscription-id}/providers/ITL.Authorization/policyStates/latest/summarize

5. Remediate non-compliant resources:
   - Migrate service principals to managed identities
   - Configure workload identities for CI/CD pipelines
   - Remove password/certificate credentials

6. Switch to ENFORCE mode:
   PATCH /subscriptions/{subscription-id}/providers/ITL.Authorization/policyAssignments/managed-identity-enforcement
   Body: { "parameters": { "effect": "Deny" } }

7. Monitor compliance:
   GET /subscriptions/{subscription-id}/providers/ITL.Authorization/policyStates/latest
    """)
    
    print("\n" + "=" * 80)
    print("Migration Guide")
    print("=" * 80)
    print("""
Common scenarios for migrating to managed identities:

1. Azure VM accessing Azure SQL:
   - Enable system-assigned managed identity on VM
   - Grant SQL permissions: CREATE USER [vm-name] FROM EXTERNAL PROVIDER
   - Update connection string to use managed identity auth

2. Azure Function calling Key Vault:
   - Enable system-assigned managed identity
   - Grant Key Vault access policy: Get/List secrets
   - Use DefaultAzureCredential in code

3. GitHub Actions deploying to Azure:
   - Create user-assigned managed identity
   - Configure federated credential: GitHub repo + branch
   - Use azure/login@v1 with client-id, tenant-id, subscription-id

4. Azure DevOps Pipeline:
   - Create service connection with workload identity
   - Configure federated credential for DevOps org
   - Update pipeline to use service connection

5. App Service calling Azure Storage:
   - Enable system-assigned or user-assigned managed identity
   - Grant Storage Blob Data Contributor role
   - Use DefaultAzureCredential in SDK
    """)
    
    print("\n✅ Policy generation complete!")
    print(f"📁 Output directory: {output_dir}")


if __name__ == "__main__":
    main()
