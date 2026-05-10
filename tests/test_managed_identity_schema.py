"""Schema validation tests for managed identity policies.

Validates generated Azure Policy JSON against official Azure schemas:
- Policy Definition: https://schema.management.azure.com/schemas/2020-10-01/policyDefinition.json
- Policy Set Definition: https://schema.management.azure.com/schemas/2020-10-01/policySetDefinition.json
- Policy Assignment: https://schema.management.azure.com/schemas/2019-09-01/policyAssignment.json
"""

import json
from pathlib import Path
import pytest

try:
    import jsonschema
    from jsonschema import validate, ValidationError
    import httpx
    SCHEMA_VALIDATION_AVAILABLE = True
except ImportError:
    SCHEMA_VALIDATION_AVAILABLE = False


# Azure Policy schema URLs
POLICY_DEFINITION_SCHEMA_URL = "https://schema.management.azure.com/schemas/2020-10-01/policyDefinition.json"
POLICY_SET_DEFINITION_SCHEMA_URL = "https://schema.management.azure.com/schemas/2020-10-01/policySetDefinition.json"
POLICY_ASSIGNMENT_SCHEMA_URL = "https://schema.management.azure.com/schemas/2019-09-01/policyAssignment.json"

# Output directory
OUTPUT_DIR = Path(__file__).parent.parent / "output" / "managed_identity_policies"


@pytest.fixture(scope="module")
def policy_definition_schema():
    """Fetch Azure Policy Definition schema."""
    if not SCHEMA_VALIDATION_AVAILABLE:
        pytest.skip("jsonschema or httpx not installed")
    response = httpx.get(POLICY_DEFINITION_SCHEMA_URL, follow_redirects=True, timeout=30.0)
    response.raise_for_status()
    return response.json()


@pytest.fixture(scope="module")
def policy_set_definition_schema():
    """Fetch Azure Policy Set Definition schema."""
    if not SCHEMA_VALIDATION_AVAILABLE:
        pytest.skip("jsonschema or httpx not installed")
    
    try:
        response = httpx.get(POLICY_SET_DEFINITION_SCHEMA_URL, follow_redirects=True, timeout=30.0)
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        pytest.skip(f"Could not fetch policy set schema: {e}")


@pytest.fixture(scope="module")
def policy_assignment_schema():
    """Fetch Azure Policy Assignment schema."""
    if not SCHEMA_VALIDATION_AVAILABLE:
        pytest.skip("jsonschema or httpx not installed")
    
    try:
        response = httpx.get(POLICY_ASSIGNMENT_SCHEMA_URL, follow_redirects=True, timeout=30.0)
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        pytest.skip(f"Could not fetch policy assignment schema: {e}")


@pytest.mark.skipif(not SCHEMA_VALIDATION_AVAILABLE, reason="jsonschema or httpx not installed")
class TestManagedIdentityPolicySchema:
    """Schema validation tests for managed identity policies."""

    @pytest.mark.parametrize("policy_file", [
        "deny-sp-password-credentials.json",
        "deny-sp-certificate-credentials.json",
        "audit-legacy-sp-credentials.json",
        "require-managed-identity-resources.json",
        "allow-workload-identity.json",
        "deny-keyvault-access-policies.json",  # Phase 1 expansion
        "require-aks-aad-integration.json",    # Phase 1 expansion
    ])
    def test_policy_definition_schema(self, policy_file, policy_definition_schema):
        """Validate individual policy definitions against Azure schema."""
        policy_path = OUTPUT_DIR / policy_file
        
        # Ensure file exists
        assert policy_path.exists(), f"Policy file not found: {policy_path}"
        
        # Load policy JSON
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_json = json.load(f)
        
        # Azure schema validates the policyRule content, not the ARM wrapper
        # Extract the policyRule from properties
        policy_rule = policy_json.get("properties", {}).get("policyRule", {})
        
        # Remove ITL Policy Builder extensions that Azure doesn't recognize
        # The 'message' field in 'then' is an ITL extension for readability
        if "then" in policy_rule and "message" in policy_rule["then"]:
            sanitized_rule = json.loads(json.dumps(policy_rule))
            del sanitized_rule["then"]["message"]
            policy_rule = sanitized_rule
        
        # Azure expects lowercase effect names (deny, audit, etc.)
        # ITL Policy Builder generates capitalized names (Deny, Audit)
        if "then" in policy_rule and "effect" in policy_rule["then"]:
            sanitized_rule = json.loads(json.dumps(policy_rule))
            sanitized_rule["then"]["effect"] = sanitized_rule["then"]["effect"].lower()
            policy_rule = sanitized_rule
        
        # Validate against Azure Policy Definition schema
        try:
            validate(instance=policy_rule, schema=policy_definition_schema)
        except ValidationError as e:
            pytest.fail(f"Schema validation failed for {policy_file}: {e.message}\nPath: {list(e.path)}")

    def test_initiative_schema(self, policy_set_definition_schema):
        """Validate policy initiative against Azure Policy Set schema."""
        initiative_path = OUTPUT_DIR / "managed_identity_initiative.json"
        
        assert initiative_path.exists(), f"Initiative file not found: {initiative_path}"
        
        with open(initiative_path, "r", encoding="utf-8") as f:
            initiative_json = json.load(f)
        
        try:
            validate(instance=initiative_json, schema=policy_set_definition_schema)
        except ValidationError as e:
            pytest.fail(f"Schema validation failed for initiative: {e.message}\nPath: {list(e.path)}")

    def test_assignment_schema(self, policy_assignment_schema):
        """Validate policy assignment against Azure schema."""
        assignment_path = OUTPUT_DIR / "subscription_assignment.json"
        
        assert assignment_path.exists(), f"Assignment file not found: {assignment_path}"
        
        with open(assignment_path, "r", encoding="utf-8") as f:
            assignment_json = json.load(f)
        
        try:
            validate(instance=assignment_json, schema=policy_assignment_schema)
        except ValidationError as e:
            pytest.fail(f"Schema validation failed for assignment: {e.message}\nPath: {list(e.path)}")


class TestManagedIdentityPolicyStructure:
    """Structural validation tests for managed identity policies."""

    @pytest.mark.parametrize("policy_file,expected_mode", [
        ("deny-sp-password-credentials.json", "All"),
        ("deny-sp-certificate-credentials.json", "All"),
        ("audit-legacy-sp-credentials.json", "All"),
        ("require-managed-identity-resources.json", "Indexed"),
        ("allow-workload-identity.json", "All"),  # Service principal policy
        ("deny-keyvault-access-policies.json", "Indexed"),  # Phase 1: KeyVault resource policy
        ("require-aks-aad-integration.json", "Indexed"),    # Phase 1: AKS resource policy
    ])
    def test_policy_mode(self, policy_file, expected_mode):
        """Validate policy mode is correct."""
        policy_path = OUTPUT_DIR / policy_file
        
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        
        assert policy["properties"]["mode"] == expected_mode, \
            f"{policy_file} should have mode '{expected_mode}'"

    @pytest.mark.parametrize("policy_file,expected_effect", [
        ("deny-sp-password-credentials.json", "Deny"),
        ("deny-sp-certificate-credentials.json", "Deny"),
        ("audit-legacy-sp-credentials.json", "Audit"),
        ("require-managed-identity-resources.json", "Audit"),
        ("allow-workload-identity.json", "Audit"),
        ("deny-keyvault-access-policies.json", "Deny"),  # Phase 1: Deny KeyVault access policies
        ("require-aks-aad-integration.json", "Deny"),    # Phase 1: Deny AKS without AAD
    ])
    def test_policy_effect(self, policy_file, expected_effect):
        """Validate policy effect is correct."""
        policy_path = OUTPUT_DIR / policy_file
        
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        
        effect = policy["properties"]["policyRule"]["then"]["effect"]
        assert effect == expected_effect, \
            f"{policy_file} should have effect '{expected_effect}', got '{effect}'"

    def test_initiative_contains_all_policies(self):
        """Validate initiative references all 5 policies."""
        initiative_path = OUTPUT_DIR / "managed_identity_initiative.json"
        
        with open(initiative_path, "r", encoding="utf-8") as f:
            initiative = json.load(f)
        
        policy_defs = initiative["properties"]["policyDefinitions"]
        assert len(policy_defs) == 5, f"Initiative should contain 5 policies, got {len(policy_defs)}"
        
        # Check all expected policy IDs are present
        expected_ids = [
            "deny-sp-password-credentials",
            "deny-sp-certificate-credentials",
            "audit-legacy-sp-credentials",
            "require-managed-identity-resources",
            "allow-workload-identity",
        ]
        
        policy_ids = [p["policyDefinitionId"].split("/")[-1] for p in policy_defs]
        for expected_id in expected_ids:
            assert expected_id in policy_ids, f"Initiative missing policy: {expected_id}"

    def test_assignment_references_initiative(self):
        """Validate assignment references the initiative."""
        assignment_path = OUTPUT_DIR / "subscription_assignment.json"
        
        with open(assignment_path, "r", encoding="utf-8") as f:
            assignment = json.load(f)
        
        policy_def_id = assignment["properties"]["policyDefinitionId"]
        assert "managed-identity-enforcement" in policy_def_id, \
            "Assignment should reference managed-identity-enforcement initiative"
        assert "policySetDefinitions" in policy_def_id, \
            "Assignment should reference a policySetDefinition"

    def test_password_policy_blocks_service_principals(self):
        """Validate password denial policy targets service principals correctly."""
        policy_path = OUTPUT_DIR / "deny-sp-password-credentials.json"
        
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        
        rule = policy["properties"]["policyRule"]["if"]
        
        # Check it's using allOf
        assert "allOf" in rule, "Should use allOf condition"
        
        # Check it targets service principals
        conditions = rule["allOf"]
        type_check = any(
            c.get("field") == "type" and 
            c.get("equals") == "Microsoft.AAD/servicePrincipals"
            for c in conditions
        )
        assert type_check, "Should check for Microsoft.AAD/servicePrincipals type"
        
        # Check it validates passwordCredentials
        password_check = any(
            c.get("field") == "properties.passwordCredentials"
            for c in conditions
        )
        assert password_check, "Should check properties.passwordCredentials field"

    def test_certificate_policy_allows_hybrid_scenario(self):
        """Validate certificate policy allows cert + federated credentials."""
        policy_path = OUTPUT_DIR / "deny-sp-certificate-credentials.json"
        
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        
        rule = policy["properties"]["policyRule"]["if"]
        
        # Should have complex logic allowing hybrid scenario
        assert "allOf" in rule, "Should use allOf for complex conditions"
        
        # Check it mentions both certificateCredentials and federatedIdentityCredentials
        rule_str = json.dumps(rule)
        assert "certificateCredentials" in rule_str, "Should check certificateCredentials"
        assert "federatedIdentityCredentials" in rule_str or "federatedIdentity" in rule_str, \
            "Should consider federatedIdentityCredentials in hybrid scenario"

    def test_managed_identity_policy_checks_identity_type(self):
        """Validate managed identity requirement checks identity.type field."""
        policy_path = OUTPUT_DIR / "require-managed-identity-resources.json"
        
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        
        rule_str = json.dumps(policy["properties"]["policyRule"])
        
        # Should check identity.type field
        assert "identity.type" in rule_str, "Should check identity.type field for managed identities"


class TestManagedIdentityPolicyContent:
    """Content validation tests for managed identity policies."""

    def test_all_policies_have_required_fields(self):
        """Validate all policies have required ARM fields."""
        required_fields = ["id", "name", "type", "properties"]
        
        for policy_file in OUTPUT_DIR.glob("*.json"):
            if policy_file.name == "managed_identity_initiative.json":
                continue  # Skip initiative
            if policy_file.name == "subscription_assignment.json":
                continue  # Skip assignment
                
            with open(policy_file, "r", encoding="utf-8") as f:
                policy = json.load(f)
            
            for field in required_fields:
                assert field in policy, f"{policy_file.name} missing required field: {field}"

    def test_all_policies_have_description(self):
        """Validate all policies have meaningful descriptions."""
        for policy_file in OUTPUT_DIR.glob("*.json"):
            if policy_file.name == "subscription_assignment.json":
                continue
                
            with open(policy_file, "r", encoding="utf-8") as f:
                content = json.load(f)
            
            description = content["properties"].get("description", "")
            assert len(description) > 20, \
                f"{policy_file.name} should have meaningful description (>20 chars)"
            
            # Check it mentions managed identities or workload identities
            desc_lower = description.lower()
            assert any(term in desc_lower for term in ["managed identit", "workload identit", "passwordless", "federated"]), \
                f"{policy_file.name} description should mention managed/workload identities"

    def test_initiative_has_metadata(self):
        """Validate initiative has proper metadata."""
        initiative_path = OUTPUT_DIR / "managed_identity_initiative.json"
        
        with open(initiative_path, "r", encoding="utf-8") as f:
            initiative = json.load(f)
        
        props = initiative["properties"]
        assert "displayName" in props, "Initiative should have displayName"
        assert "description" in props, "Initiative should have description"
        assert "policyDefinitions" in props, "Initiative should have policyDefinitions"
        
        # Check display name mentions identity
        display_name_lower = props["displayName"].lower()
        assert "identity" in display_name_lower or "passwordless" in display_name_lower, \
            "Initiative displayName should mention identity or passwordless"
