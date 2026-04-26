"""Generate JSON files for the 2 new managed identity policies."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from itl_policy_builder.templates.managed_identity import (
    DenyKeyVaultAccessPoliciesPolicy,
    RequireAKSAADIntegrationPolicy
)

# Output directory
OUTPUT_DIR = Path(__file__).parent.parent / "output" / "managed_identity_policies"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def generate_policy_json(policy_class, output_filename):
    """Generate and save policy JSON."""
    policy = policy_class.build()
    policy_dict = policy.model_dump(mode="json", exclude_none=True, by_alias=True)
    
    output_path = OUTPUT_DIR / output_filename
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(policy_dict, f, indent=2)
    
    print(f"✅ Generated: {output_path}")
    return policy_dict

# Generate both new policies
print("Generating JSON files for new managed identity policies...")
print("=" * 80)

kv_policy = generate_policy_json(DenyKeyVaultAccessPoliciesPolicy, "deny-keyvault-access-policies.json")
aks_policy = generate_policy_json(RequireAKSAADIntegrationPolicy, "require-aks-aad-integration.json")

print("\n" + "=" * 80)
print("✅ Successfully generated 2 new policy JSON files")
print("\nFiles created:")
print(f"  - {OUTPUT_DIR / 'deny-keyvault-access-policies.json'}")
print(f"  - {OUTPUT_DIR / 'require-aks-aad-integration.json'}")
