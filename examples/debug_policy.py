"""Quick debug script to see actual policy JSON structure"""
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from itl_policy_builder.templates.managed_identity import DenyKeyVaultAccessPoliciesPolicy

policy = DenyKeyVaultAccessPoliciesPolicy.build()
policy_json = json.loads(policy.model_dump_json(exclude_none=True))

print("FULL JSON STRUCTURE:")
print(json.dumps(policy_json, indent=2))
print("\n\nKEYS AT ROOT:")
print(list(policy_json.keys()))
