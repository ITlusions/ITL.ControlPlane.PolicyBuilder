"""
Test script for the two new managed identity policies:
1. deny-keyvault-access-policies
2. require-aks-aad-integration
"""
import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from itl_policy_builder.templates.managed_identity import (
    DenyKeyVaultAccessPoliciesPolicy,
    RequireAKSAADIntegrationPolicy,
    get_managed_identity_policy,
    list_managed_identity_policies,
    get_all_managed_identity_policies,
)


def print_policy(policy_def):
    """Pretty print a policy definition."""
    policy_dict = policy_def.model_dump(mode="json", exclude_none=True)
    # Show only first 500 chars to keep output manageable
    full_json = json.dumps(policy_dict, indent=2)
    if len(full_json) > 500:
        print(full_json[:500] + "...\n  [truncated for brevity]")
    else:
        print(full_json)
    print("\n" + "=" * 80 + "\n")


def test_deny_keyvault_access_policies():
    """Test Key Vault access policies denial policy."""
    print("🔐 Testing: DenyKeyVaultAccessPoliciesPolicy")
    print("=" * 80)
    
    policy = DenyKeyVaultAccessPoliciesPolicy.build()
    
    # Validate basic structure
    assert policy.name == "deny-keyvault-access-policies"
    assert policy.properties.display_name == "Deny Key Vault Access Policies (RBAC Only)"
    assert "RBAC" in policy.properties.description
    
    # Validate JSON output (using Python field names)
    policy_json = json.loads(policy.model_dump_json(exclude_none=True))
    assert policy_json["properties"]["policy_rule"]["then_effect"]["effect"] == "Deny"
    assert "Microsoft.KeyVault/vaults" in str(policy_json)
    assert "enableRbacAuthorization" in str(policy_json)
    assert "accessPolicies" in str(policy_json)
    
    print(f"✅ Policy name: {policy.name}")
    print(f"✅ Display name: {policy.properties.display_name}")
    print(f"✅ Effect: {policy_json['properties']['policy_rule']['then_effect']['effect']}")
    print(f"✅ Category: {policy.properties.metadata.get('category', 'N/A')}")
    print(f"✅ Version: {policy.properties.metadata.get('version', 'N/A')}")
    print("\nPolicy JSON Preview (first 300 chars):")
    print(json.dumps(policy_json, indent=2)[:300] + "...")
    print("\n")
    
    return policy


def test_require_aks_aad_integration():
    """Test AKS AAD integration requirement policy."""
    print("☸️  Testing: RequireAKSAADIntegrationPolicy")
    print("=" * 80)
    
    policy = RequireAKSAADIntegrationPolicy.build()
    
    # Validate basic structure
    assert policy.name == "require-aks-aad-integration"
    assert policy.properties.display_name == "Require AKS Azure AD Integration"
    assert "managed Azure AD" in policy.properties.description
    
    # Validate JSON output (using Python field names)
    policy_json = json.loads(policy.model_dump_json(exclude_none=True))
    assert policy_json["properties"]["policy_rule"]["then_effect"]["effect"] == "Deny"
    assert "Microsoft.ContainerService/managedClusters" in str(policy_json)
    assert "aadProfile" in str(policy_json)
    assert "enableRBAC" in str(policy_json)
    
    print(f"✅ Policy name: {policy.name}")
    print(f"✅ Display name: {policy.properties.display_name}")
    print(f"✅ Effect: {policy_json['properties']['policy_rule']['then_effect']['effect']}")
    print(f"✅ Category: {policy.properties.metadata.get('category', 'N/A')}")
    print(f"✅ Version: {policy.properties.metadata.get('version', 'N/A')}")
    print("\nPolicy JSON Preview (first 300 chars):")
    print(json.dumps(policy_json, indent=2)[:300] + "...")
    print("\n")
    
    return policy


def test_helper_functions():
    """Test that helper functions include the new policies."""
    print("🛠️  Testing: Helper Functions")
    print("=" * 80)
    
    # Test list_managed_identity_policies
    all_names = list_managed_identity_policies()
    print(f"Available policies ({len(all_names)}):")
    for name in all_names:
        print(f"  - {name}")
    
    assert "deny-keyvault-access-policies" in all_names
    assert "require-aks-aad-integration" in all_names
    print("\n✅ New policies in list_managed_identity_policies()")
    
    # Test get_managed_identity_policy
    kv_policy = get_managed_identity_policy("deny-keyvault-access-policies")
    assert kv_policy.name == "deny-keyvault-access-policies"
    print("✅ deny-keyvault-access-policies retrievable via get_managed_identity_policy()")
    
    aks_policy = get_managed_identity_policy("require-aks-aad-integration")
    assert aks_policy.name == "require-aks-aad-integration"
    print("✅ require-aks-aad-integration retrievable via get_managed_identity_policy()")
    
    # Test get_all_managed_identity_policies
    all_policies = get_all_managed_identity_policies()
    print(f"\n✅ get_all_managed_identity_policies() returns {len(all_policies)} policies")
    
    policy_names = [p.name for p in all_policies]
    assert "deny-keyvault-access-policies" in policy_names
    assert "require-aks-aad-integration" in policy_names
    print("✅ Both new policies in get_all_managed_identity_policies()")
    
    print("\n" + "=" * 80 + "\n")


def test_json_serialization():
    """Test that policies serialize correctly to JSON."""
    print("📄 Testing: JSON Serialization")
    print("=" * 80)
    
    # Test Key Vault policy
    kv_policy = DenyKeyVaultAccessPoliciesPolicy.build()
    kv_json = kv_policy.model_dump_json(indent=2, exclude_none=True)
    kv_parsed = json.loads(kv_json)
    
    assert kv_parsed["properties"]["policy_rule"]["then_effect"]["effect"] == "Deny"
    assert kv_parsed["properties"]["display_name"] == "Deny Key Vault Access Policies (RBAC Only)"
    print("✅ Key Vault policy serializes correctly")
    print(f"   - Effect: {kv_parsed['properties']['policy_rule']['then_effect']['effect']}")
    
    # Test AKS policy
    aks_policy = RequireAKSAADIntegrationPolicy.build()
    aks_json = aks_policy.model_dump_json(indent=2, exclude_none=True)
    aks_parsed = json.loads(aks_json)
    
    assert aks_parsed["properties"]["policy_rule"]["then_effect"]["effect"] == "Deny"
    assert aks_parsed["properties"]["display_name"] == "Require AKS Azure AD Integration"
    print("✅ AKS policy serializes correctly")
    print(f"   - Effect: {aks_parsed['properties']['policy_rule']['then_effect']['effect']}")
    
    print("\n" + "=" * 80 + "\n")


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "MANAGED IDENTITY POLICY TEST SUITE" + " " * 24 + "║")
    print("║" + " " * 17 + "Testing 2 New Policies (Phase 1 Expansion)" + " " * 18 + "║")
    print("╚" + "═" * 78 + "╝")
    print("\n")
    
    try:
        # Test individual policies
        kv_policy = test_deny_keyvault_access_policies()
        aks_policy = test_require_aks_aad_integration()
        
        # Test helper functions
        test_helper_functions()
        
        # Test JSON serialization
        test_json_serialization()
        
        # Success summary
        print("\n")
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 30 + "✅ ALL TESTS PASSED" + " " * 29 + "║")
        print("╚" + "═" * 78 + "╝")
        print("\n")
        print("Summary:")
        print(f"  ✅ deny-keyvault-access-policies - WORKING")
        print(f"  ✅ require-aks-aad-integration - WORKING")
        print(f"  ✅ Helper functions updated - WORKING")
        print(f"  ✅ JSON serialization - WORKING")
        print(f"\n  Total policies available: {len(list_managed_identity_policies())}")
        print("\nNext steps:")
        print("  1. Run: pytest tests/test_managed_identity_schema.py -v")
        print("  2. Test with CLI: python src/itl_policy_builder/cli/main.py generate managed-identity --policy deny-keyvault-access-policies")
        print("  3. Deploy to Azure (optional)")
        print()
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
