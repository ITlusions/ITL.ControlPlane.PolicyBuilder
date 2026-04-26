"""
CLI entry point for ITL Policy Builder.

Provides commands for:
- Generating policies from templates
- Deploying policies to Kubernetes and ITL API Gateway
- Validating policies
- Checking compliance status
- Managing configurations
"""

try:
    import click
except ImportError:
    raise ImportError(
        "Click is required for CLI support. Install with: pip install itl-policy-builder[cli]"
    )

import json
import os
import sys
import asyncio
from pathlib import Path
from typing import Optional

from itl_policy_builder.templates.kyverno import (
    get_kyverno_policy,
    list_kyverno_policies,
    get_talos_security_bundle,
    get_pqc_transition_bundle,
    get_profile,
    list_profiles,
    KYVERNO_PROFILE_CATEGORIES,
)
from itl_policy_builder.templates.managed_identity import (
    get_all_managed_identity_policies,
    get_managed_identity_initiative,
    create_subscription_assignment,
)
from itl_policy_builder.deploy import (
    PolicyDeployer,
    DeployConfig,
    DeployTarget,
    DeployAction,
)


@click.group()
@click.version_option()
def cli():
    """ITL Policy Builder CLI — Manage governance policies for ITL ControlPlane."""
    pass


# ============================================================================
# GENERATE COMMAND
# ============================================================================

# All Kyverno profile names (kept in sync with _KYVERNO_PROFILE_BUILDERS)
_KYVERNO_PROFILE_NAMES = ["security", "network", "registry", "strict", "talos", "pqc", "all"]
_ALL_TEMPLATES = ["talos-security", "pqc-transition", "cis-azure", "managed-identity"] + _KYVERNO_PROFILE_NAMES


@cli.command()
@click.option(
    "--template",
    type=click.Choice(_ALL_TEMPLATES),
    default="talos-security",
    help=(
        "Policy template to use. "
        "Kyverno profiles: security, network, registry, strict, talos, pqc, all. "
        "Legacy bundles: talos-security, pqc-transition. "
        "Azure: cis-azure, managed-identity."
    ),
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file (default: stdout)",
)
@click.option(
    "--style",
    type=click.Choice(["kyverno", "azure", "custom"]),
    default="kyverno",
    help="Policy style/format (kyverno for Kubernetes, azure for ARM Resource Manager)",
)
@click.option(
    "--format",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Serialization format (YAML or JSON)",
)
def generate(template: str, output: Optional[str], style: str, format: str):
    """Generate policies from templates."""
    try:
        # Load template policies based on style
        if style == "kyverno":
            # Kubernetes-native Kyverno policies
            if template in _KYVERNO_PROFILE_NAMES:
                # New profile-based generation
                profile = get_profile(template)
                policies = profile.policies
            elif template == "talos-security":
                policies = get_talos_security_bundle()
            elif template == "pqc-transition":
                policies = get_pqc_transition_bundle()
            elif template == "cis-azure":
                click.echo(
                    "Error: 'cis-azure' is an Azure ARM template. "
                    "Use --style azure instead of --style kyverno.",
                    err=True,
                )
                sys.exit(1)
            elif template == "managed-identity":
                click.echo(
                    "Error: 'managed-identity' is an Azure ARM template. "
                    "Use --style azure instead of --style kyverno.",
                    err=True,
                )
                sys.exit(1)
            else:
                click.echo(f"Unknown template: {template}", err=True)
                sys.exit(1)
        
        elif style == "azure":
            # Azure ARM-style policies
            try:
                from itl_policy_builder.templates import (
                    get_builtin_policy,
                    get_pqc_initiative,
                    get_bio_initiative,
                    get_cis_initiative,
                )

                if template == "talos-security":
                    # Azure security baseline initiative
                    policies = [get_bio_initiative()]
                elif template == "pqc-transition":
                    # PQC transition initiative (ARM policies)
                    policies = [get_pqc_initiative()]
                elif template == "cis-azure":
                    # CIS Microsoft Azure Foundations Benchmark initiative
                    policies = [get_cis_initiative()]
                elif template == "managed-identity":
                    # Managed Identity and Workload Identity enforcement
                    all_policies = get_all_managed_identity_policies()
                    initiative = get_managed_identity_initiative()
                    # Return all policies plus the initiative
                    policies = all_policies + [initiative]
                else:
                    click.echo(f"Unknown template: {template}", err=True)
                    sys.exit(1)
            except ImportError:
                click.echo("Error: PolicyBuilder (ARM policies) required", err=True)
                sys.exit(1)
        
        else:
            click.echo(f"Unknown style: {style}. Use kyverno or azure", err=True)
            sys.exit(1)
        
        # Serialize based on style and format
        if style == "kyverno":
            if format == "yaml":
                try:
                    import yaml
                    output_str = "\n---\n".join(
                        yaml.dump(p, default_flow_style=False, sort_keys=False)
                        for p in policies
                    )
                except ImportError:
                    click.echo("Error: PyYAML required. Install with: pip install itl-policy-builder[cli]", err=True)
                    sys.exit(1)
            else:  # json
                output_str = json.dumps(policies, indent=2)
        
        elif style == "azure":
            if format == "yaml":
                try:
                    import yaml
                    # Use to_arm_dict() and JSON round-trip for clean YAML (no Python tags)
                    arm_policies = [
                        p.to_arm_dict() if hasattr(p, 'to_arm_dict') else p
                        for p in policies
                    ]
                    # JSON round-trip to convert all Python objects to native types
                    clean_policies = json.loads(json.dumps({"policies": arm_policies}, default=str))
                    output_str = yaml.dump(clean_policies, default_flow_style=False, sort_keys=False)
                except ImportError:
                    click.echo("Error: PyYAML required", err=True)
                    sys.exit(1)
            else:  # json
                # Use to_arm_dict() to avoid double-encoding strings inside json.dumps
                arm_policies = [
                    p.to_arm_dict() if hasattr(p, 'to_arm_dict') else p
                    for p in policies
                ]
                output_str = json.dumps({"policies": arm_policies}, indent=2)
        
        # Write output
        if output:
            Path(output).write_text(output_str)
            click.echo(f"✅ Generated {len(policies)} {style} policies to {output} (format: {format})")
        else:
            click.echo(output_str)
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


# ============================================================================
# LIST COMMAND
# ============================================================================

@cli.command()
@click.option(
    "--category",
    type=click.Choice(["security", "image", "network", "pqc", "talos", "governance"]),
    help="Filter by policy category",
)
@click.option(
    "--profiles",
    is_flag=True,
    default=False,
    help="List available Kyverno profiles instead of individual policies",
)
def list(category: Optional[str], profiles: bool):
    """List available Kyverno policies or profiles."""
    try:
        from itl_policy_builder.templates.kyverno import (
            KYVERNO_CATEGORIES,
            list_kyverno_policies,
        )

        if profiles:
            available = list_profiles()
            click.echo(f"\nAvailable profiles ({len(available)}):\n")
            for name in available:
                prof = get_profile(name)
                category_label = KYVERNO_PROFILE_CATEGORIES.get(name, "")
                click.echo(f"  {name:10s}  {prof.display_name}")
                click.echo(f"  {'':10s}  {prof.description}")
                if category_label:
                    click.echo(f"  {'':10s}  Category   : {category_label}")
                click.echo(f"  {'':10s}  Policies   : {len(prof)}")
                click.echo()
            click.echo("Generate with: itl-policy generate --template <profile-name>")
            return

        if category:
            if category not in KYVERNO_CATEGORIES:
                click.echo(f"Unknown category: {category}", err=True)
                sys.exit(1)
            policies = KYVERNO_CATEGORIES[category]
        else:
            policies = list_kyverno_policies()

        click.echo(f"\nAvailable policies ({len(policies)}):\n")
        for policy in policies:
            click.echo(f"  • {policy}")

        if not category:
            click.echo(f"\nCategories: {', '.join(KYVERNO_CATEGORIES.keys())}")
            click.echo("Use --category to filter by category")
            click.echo("Use --profiles to list available policy profiles")

    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


# ============================================================================
# DEPLOY COMMAND
# ============================================================================

@cli.command()
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True),
    required=True,
    help="Policy file (YAML or JSON)",
)
@click.option(
    "--target",
    type=click.Choice(["kubernetes", "itl-api", "azure", "both"]),
    default="kubernetes",
    help="Deployment target (kubernetes, itl-api, azure, or both)",
)
@click.option(
    "--kubeconfig",
    type=click.Path(exists=True),
    help="Kubeconfig path (for Kubernetes)",
)
@click.option(
    "--api-endpoint",
    help="ITL API endpoint (for itl-api)",
)
@click.option(
    "--api-key",
    help="ITL API key (for itl-api)",
)
@click.option(
    "--subscription-id",
    help="Azure subscription ID (for azure)",
)
@click.option(
    "--tenant-id",
    help="Azure tenant ID (for azure)",
)
@click.option(
    "--resource-group",
    help="Azure resource group (for azure)",
)
@click.option(
    "--assignment-scope",
    help="Azure assignment scope, e.g., /subscriptions/{sub-id}",
)
@click.option(
    "--azure-auth",
    type=click.Choice(["default", "cli", "env"]),
    default="default",
    help="Azure authentication method",
)
@click.option(
    "--action",
    type=click.Choice(["audit", "enforce"]),
    default="audit",
    help="Deployment action (audit or enforce)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Simulate deployment without making changes",
)
def deploy(
    file: str,
    target: str,
    kubeconfig: Optional[str],
    api_endpoint: Optional[str],
    api_key: Optional[str],
    subscription_id: Optional[str],
    tenant_id: Optional[str],
    resource_group: Optional[str],
    assignment_scope: Optional[str],
    azure_auth: str,
    action: str,
    dry_run: bool,
):
    """Deploy policies to Kubernetes, Azure, and/or ITL Control Plane."""
    try:
        # Load policies
        file_path = Path(file)
        content = file_path.read_text()
        
        try:
            import yaml
            policies = yaml.safe_load_all(content)
            policies = [p for p in policies if p is not None]
        except ImportError:
            click.echo("Error: PyYAML required. Install with: pip install itl-policy-builder[cli]", err=True)
            sys.exit(1)
        
        click.echo(f"📋 Loaded {len(policies)} policies from {file}")
        
        # Create deployment configs
        configs = []
        
        if target in ["kubernetes", "both"]:
            kubeconfig = kubeconfig or os.path.expanduser("~/.kube/config")
            configs.append(
                DeployConfig(
                    target=DeployTarget.KUBERNETES,
                    kubeconfig_path=kubeconfig if Path(kubeconfig).exists() else None,
                    action=DeployAction.AUDIT if action == "audit" else DeployAction.ENFORCE,
                    dry_run=dry_run,
                )
            )
        
        if target in ["itl-api", "both"]:
            if not api_endpoint:
                click.echo("❌ Error: --api-endpoint required for ITL API deployment", err=True)
                sys.exit(1)
            if not api_key:
                api_key = os.getenv("ITL_API_KEY")
                if not api_key:
                    click.echo("❌ Error: --api-key or ITL_API_KEY env var required", err=True)
                    sys.exit(1)
            
            configs.append(
                DeployConfig(
                    target=DeployTarget.ITL_API,
                    api_endpoint=api_endpoint,
                    api_key=api_key,
                    action=DeployAction.AUDIT if action == "audit" else DeployAction.ENFORCE,
                    dry_run=dry_run,
                )
            )
        
        if target in ["azure", "both"]:
            # Get Azure credentials from arguments or environment
            sub_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
            tenant = tenant_id or os.getenv("AZURE_TENANT_ID")
            scope = assignment_scope or os.getenv("AZURE_ASSIGNMENT_SCOPE")
            rg = resource_group or os.getenv("AZURE_RESOURCE_GROUP")
            
            if not sub_id:
                click.echo("❌ Error: --subscription-id or AZURE_SUBSCRIPTION_ID required", err=True)
                sys.exit(1)
            if not scope:
                click.echo("❌ Error: --assignment-scope or AZURE_ASSIGNMENT_SCOPE required", err=True)
                click.echo("   Example: /subscriptions/sub-12345", err=True)
                sys.exit(1)
            
            configs.append(
                DeployConfig(
                    target=DeployTarget.AZURE,
                    azure_subscription_id=sub_id,
                    azure_tenant_id=tenant,
                    azure_resource_group=rg,
                    azure_assignment_scope=scope,
                    azure_credential=azure_auth,
                    action=DeployAction.AUDIT if action == "audit" else DeployAction.ENFORCE,
                    dry_run=dry_run,
                )
            )
        
        # Deploy
        deployer = PolicyDeployer(configs=configs)
        
        click.echo(f"\n🚀 Deploying {len(policies)} policies...")
        if dry_run:
            click.echo("   (DRY RUN MODE)")
        
        results = asyncio.run(deployer.deploy(policies))
        
        # Report results
        click.echo()
        for result in results:
            if result.success:
                click.secho(f"✅ {result.summary}", fg="green")
            else:
                click.secho(f"❌ {result.summary}", fg="red")
                for error in result.errors:
                    click.echo(f"   - {error}")
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


# ============================================================================
# VALIDATE COMMAND
# ============================================================================

@cli.command()
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True),
    required=True,
    help="Policy file to validate",
)
@click.option(
    "--target",
    type=click.Choice(["kubernetes", "itl-api", "azure", "both"]),
    default="kubernetes",
    help="Validation target",
)
def validate(file: str, target: str):
    """Validate policies without deploying."""
    try:
        file_path = Path(file)
        content = file_path.read_text()
        
        try:
            import yaml
            policies = list(yaml.safe_load_all(content))
            policies = [p for p in policies if p is not None]
        except ImportError:
            click.echo("Error: PyYAML required", err=True)
            sys.exit(1)
        
        click.echo(f"🔍 Validating {len(policies)} policies from {file}...\n")
        
        configs = []
        if target in ["kubernetes", "both"]:
            configs.append(DeployConfig(target=DeployTarget.KUBERNETES))
        
        if target in ["itl-api", "both"]:
            api_endpoint = os.getenv("ITL_API_ENDPOINT")
            api_key = os.getenv("ITL_API_KEY")
            if api_endpoint and api_key:
                configs.append(
                    DeployConfig(
                        target=DeployTarget.ITL_API,
                        api_endpoint=api_endpoint,
                        api_key=api_key,
                    )
                )

        if target == "azure":
            subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
            if subscription_id:
                configs.append(
                    DeployConfig(
                        target=DeployTarget.AZURE,
                        azure_subscription_id=subscription_id,
                        azure_credential=os.getenv("AZURE_CREDENTIAL", "default"),
                    )
                )
        
        deployer = PolicyDeployer(configs=configs)
        results = asyncio.run(deployer.validate(policies))
        
        for result in results:
            if result.success:
                click.secho(f"✅ Valid for {result.target.value}", fg="green")
            else:
                click.secho(f"❌ Invalid for {result.target.value}", fg="red")
                for error in result.errors:
                    click.echo(f"   - {error}")
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


# ============================================================================
# INIT COMMAND (Create config file)
# ============================================================================

@cli.command()
@click.option(
    "--api-endpoint",
    help="ITL API endpoint",
)
@click.option(
    "--api-key",
    help="ITL API key",
)
def init(api_endpoint: Optional[str], api_key: Optional[str]):
    """Initialize ITL Policy CLI configuration."""
    config_dir = Path.home() / ".itl-policy"
    config_file = config_dir / "config.json"
    
    config_data = {
        "api_endpoint": api_endpoint or "",
        "api_key": api_key or "",
        "kubeconfig": str(Path.home() / ".kube" / "config"),
    }
    
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file.write_text(json.dumps(config_data, indent=2))
    
    click.echo(f"✅ Configuration saved to {config_file}")
    click.echo("\nYou can now use:")
    click.echo("  itl-policy deploy --file policies.yaml")
    click.echo("\nOr set environment variables:")
    click.echo("  export ITL_API_ENDPOINT=https://...")
    click.echo("  export ITL_API_KEY=sk-...")


# ============================================================================
# EXPLAIN COMMAND
# ============================================================================

@cli.command()
@click.option(
    "--template",
    type=click.Choice(["cis-azure", "talos-security", "pqc-transition"]),
    default=None,
    show_default=False,
    help="Template to explain (default: cis-azure when --about is not set)",
)
@click.option(
    "--about",
    type=click.Choice([
        "azure-governance",
        "management-group",
        "subscription",
        "resource-group",
        "policy-definition",
        "policy-initiative",
        "policy-assignment",
        "policy-effect",
    ]),
    default=None,
    help="Explain an Azure governance concept instead of a template",
)
@click.option(
    "--section",
    default=None,
    metavar="SECTION",
    help="Filter by section (cis-azure only, e.g. 'CIS-3', 'AKS', 'Governance')",
)
@click.option(
    "--severity",
    type=click.Choice(["High", "Medium", "Low"], case_sensitive=False),
    default=None,
    help="Filter by severity (cis-azure only)",
)
@click.option(
    "--as-json",
    is_flag=True,
    default=False,
    help="Output as machine-readable JSON instead of formatted text",
)
def explain(
    template: Optional[str],
    about: Optional[str],
    section: Optional[str],
    severity: Optional[str],
    as_json: bool,
):
    """Explain policy templates or Azure governance concepts in readable text.

    \b
    Template examples:
      itl-policy explain --template cis-azure
      itl-policy explain --template cis-azure --section AKS
      itl-policy explain --template cis-azure --severity High
      itl-policy explain --template talos-security

    \b
    Concept examples:
      itl-policy explain --about azure-governance
      itl-policy explain --about management-group
      itl-policy explain --about policy-assignment
      itl-policy explain --about policy-effect
    """
    try:
        if about:
            _explain_about(topic=about, as_json=as_json)
            return

        # Default to cis-azure when neither --about nor --template is given
        resolved_template = template or "cis-azure"
        if resolved_template == "cis-azure":
            _explain_cis_azure(section=section, severity=severity, as_json=as_json)
        elif resolved_template in ("talos-security", "pqc-transition"):
            _explain_kyverno(template=resolved_template, as_json=as_json)
        else:
            click.echo(f"Unknown template: {resolved_template}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


def _severity_color(sev: str) -> str:
    """Return a click color name for a severity string."""
    return {"High": "red", "Medium": "yellow", "Low": "green"}.get(sev, "white")


# ---------------------------------------------------------------------------
# EXPLAIN --about  (Azure governance concept reference)
# ---------------------------------------------------------------------------

_ABOUT_TOPICS: dict = {
    "azure-governance": {
        "title": "Azure Governance Hierarchy",
        "summary": (
            "Azure organises resources into a four-level management hierarchy. "
            "Policies, RBAC roles, and cost budgets assigned at a higher level "
            "automatically flow down (inherit) to all levels beneath it."
        ),
        "sections": [
            {
                "heading": "Level 1 — Root Management Group",
                "body": (
                    "Every Azure Active Directory tenant has exactly one Root "
                    "Management Group. Policies assigned here apply to every "
                    "subscription in the tenant. Only Global Admins (elevated) can "
                    "manage it. Use it sparingly — for universal baseline controls only."
                ),
            },
            {
                "heading": "Level 2 — Management Groups",
                "body": (
                    "Management Groups are containers that group subscriptions. "
                    "You can nest them up to 6 levels deep (below root). Typical "
                    "patterns: per-environment (Prod/Dev), per-department, or "
                    "per-landing-zone. See: itl-policy explain --about management-group"
                ),
            },
            {
                "heading": "Level 3 — Subscriptions",
                "body": (
                    "A subscription is a billing and access boundary. Resources "
                    "live in subscriptions. Large organisations use separate "
                    "subscriptions per workload or environment to isolate costs and "
                    "blast-radius. See: itl-policy explain --about subscription"
                ),
            },
            {
                "heading": "Level 4 — Resource Groups",
                "body": (
                    "Resource Groups are logical containers within a subscription. "
                    "They share a lifecycle — deploy, update, and delete all "
                    "resources together. RBAC and policies assigned to a resource "
                    "group apply to every resource inside it."
                ),
            },
            {
                "heading": "Policy Definitions & Assignments",
                "body": (
                    "Policies define rules (what is allowed or required). "
                    "Assignments attach a policy to a scope (MG, sub, RG). "
                    "Initiatives (policy sets) bundle multiple policies into one "
                    "assignment. See: itl-policy explain --about policy-assignment"
                ),
            },
        ],
    },
    "management-group": {
        "title": "Management Groups",
        "summary": (
            "Management Groups are containers above subscriptions that allow "
            "centralised governance across multiple subscriptions. Policies, "
            "RBAC, and Blueprints assigned to a Management Group are inherited "
            "by all subscriptions and resources below."
        ),
        "sections": [
            {
                "heading": "How it works",
                "body": (
                    "Each Management Group has a unique ID and display name. "
                    "You can nest up to 6 levels below the Root Management Group. "
                    "A subscription can belong to only one Management Group at a time, "
                    "but you can move it between groups."
                ),
            },
            {
                "heading": "Common patterns",
                "body": (
                    "  • Platform MG  — shared services (logging, networking, identity)\n"
                    "  • Landing Zones MG  — workload subscriptions per environment\n"
                    "    └─ Corp MG  — connected (hub-spoke) workloads\n"
                    "    └─ Online MG  — internet-facing workloads\n"
                    "  • Sandbox MG  — developer/test subscriptions with relaxed policy"
                ),
            },
            {
                "heading": "Inventory & policy scope",
                "body": (
                    "Use 'itl-policy inventory --target azure' to list all Management "
                    "Groups and their assigned policies. Assignments scoped to a MG "
                    "are visible in the output under 'management_groups'."
                ),
            },
            {
                "heading": "Azure portal path",
                "body": "Azure Portal > Management Groups (search in top bar)",
            },
        ],
    },
    "subscription": {
        "title": "Subscriptions",
        "summary": (
            "A subscription is both a billing unit and a security boundary in Azure. "
            "Every resource belongs to exactly one subscription. Subscriptions "
            "inherit policies from the Management Group above them."
        ),
        "sections": [
            {
                "heading": "Billing boundary",
                "body": (
                    "All costs for resources in a subscription are rolled up to a "
                    "single invoice. Cost budgets and alerts are configured at the "
                    "subscription level (or Resource Group level for finer control)."
                ),
            },
            {
                "heading": "Access boundary",
                "body": (
                    "RBAC roles assigned at the subscription level apply to all "
                    "Resource Groups and resources within. This makes subscriptions "
                    "a natural isolation boundary between teams or workloads."
                ),
            },
            {
                "heading": "Policy scope",
                "body": (
                    "Policies can be assigned directly to a subscription. They take "
                    "effect on all Resource Groups and resources in that subscription. "
                    "Policies inherited from a parent Management Group are additive."
                ),
            },
            {
                "heading": "Useful CLI",
                "body": (
                    "  itl-policy inventory --target azure --all-subscriptions\n"
                    "  itl-policy inventory --target azure --subscription-id <id>"
                ),
            },
        ],
    },
    "resource-group": {
        "title": "Resource Groups",
        "summary": (
            "A Resource Group is a logical container within a subscription. "
            "It groups related resources that share the same lifecycle — "
            "they are deployed, updated, and deleted together."
        ),
        "sections": [
            {
                "heading": "Lifecycle management",
                "body": (
                    "Deleting a Resource Group removes all resources inside it. "
                    "This makes it ideal for scoping environments: you can "
                    "tear down an entire test environment with a single delete."
                ),
            },
            {
                "heading": "Policy & RBAC scope",
                "body": (
                    "Policies and RBAC roles can be assigned directly to a Resource "
                    "Group. Assignments here are more specific than subscription-level "
                    "assignments and can override or supplement them (within limits)."
                ),
            },
            {
                "heading": "Tagging strategy",
                "body": (
                    "Resource Groups are the recommended unit for applying cost and "
                    "ownership tags (e.g. environment=prod, team=platform). "
                    "Tags on a Resource Group do not auto-inherit to resources — "
                    "use Azure Policy (Inherit a tag) to enforce this."
                ),
            },
        ],
    },
    "policy-definition": {
        "title": "Policy Definitions",
        "summary": (
            "A Policy Definition describes a single governance rule in Azure. "
            "It specifies what to evaluate, which resources are in scope, "
            "and what effect to apply when the rule is violated."
        ),
        "sections": [
            {
                "heading": "Built-in vs. Custom",
                "body": (
                    "Azure ships hundreds of Built-in policy definitions (maintained "
                    "by Microsoft). You can also create Custom definitions for rules "
                    "specific to your organisation. Custom policies are stored at the "
                    "Management Group or subscription scope."
                ),
            },
            {
                "heading": "Structure",
                "body": (
                    "  • displayName  — human-readable name\n"
                    "  • description  — what the policy checks and why\n"
                    "  • mode         — 'All' (all resources) or 'Indexed' (tagged resources)\n"
                    "  • parameters   — configurable values (e.g. allowed SKUs)\n"
                    "  • policyRule   — if/then logic: condition + effect"
                ),
            },
            {
                "heading": "ITL Policy Builder",
                "body": (
                    "The ITL Policy Builder wraps policy definitions in Python classes. "
                    "Run 'itl-policy list' to see available templates, and "
                    "'itl-policy generate --template cis-azure' to produce ARM-compatible "
                    "policy definition JSON."
                ),
            },
        ],
    },
    "policy-initiative": {
        "title": "Policy Initiatives (Policy Set Definitions)",
        "summary": (
            "An Initiative (formerly called a Policy Set Definition) bundles "
            "multiple Policy Definitions into a single unit that can be assigned "
            "together. This simplifies compliance tracking across many policies."
        ),
        "sections": [
            {
                "heading": "Why use initiatives?",
                "body": (
                    "Instead of assigning 30 individual policies for CIS compliance, "
                    "you assign one initiative. Compliance reporting is then aggregated "
                    "at the initiative level, giving you a single overall score."
                ),
            },
            {
                "heading": "Structure",
                "body": (
                    "  • displayName  — e.g. 'CIS Microsoft Azure Foundations 2.0.0'\n"
                    "  • policyDefinitions  — list of {policyDefinitionId, parameters}\n"
                    "  • parameters  — initiative-level parameters forwarded to policies"
                ),
            },
            {
                "heading": "Built-in examples",
                "body": (
                    "  • CIS Microsoft Azure Foundations Benchmark\n"
                    "  • NIST SP 800-53 Rev 5\n"
                    "  • ISO 27001:2013\n"
                    "  • Azure Security Benchmark"
                ),
            },
            {
                "heading": "Inventory",
                "body": (
                    "Run 'itl-policy inventory --target azure --include initiatives' "
                    "to list all initiative definitions in your subscription."
                ),
            },
        ],
    },
    "policy-assignment": {
        "title": "Policy Assignments",
        "summary": (
            "A Policy Assignment attaches a Policy Definition or Initiative to "
            "a specific scope. Only resources within that scope are evaluated "
            "against the policy rule."
        ),
        "sections": [
            {
                "heading": "Scope",
                "body": (
                    "The scope determines which resources are evaluated. "
                    "Valid scopes (from broadest to narrowest):\n"
                    "  1. Management Group\n"
                    "  2. Subscription\n"
                    "  3. Resource Group\n"
                    "  4. Individual resource\n"
                    "Child scopes inherit assignments from parent scopes."
                ),
            },
            {
                "heading": "Exclusions",
                "body": (
                    "You can exclude specific Resource Groups or resources from a "
                    "broadly-scoped assignment using 'notScopes'. Useful when a "
                    "subscription-level policy should not apply to one legacy RG."
                ),
            },
            {
                "heading": "Parameters",
                "body": (
                    "Assignments can pass parameter values to the policy. For example, "
                    "a policy that checks allowed VM SKUs takes an 'allowedSKUs' "
                    "parameter — different assignments can provide different values "
                    "for different subscriptions."
                ),
            },
            {
                "heading": "Enforcement mode",
                "body": (
                    "  • Default  — policy effect is enforced (Deny blocks deployment)\n"
                    "  • DoNotEnforce  — policy evaluates and reports but does NOT block\n"
                    "                   (useful for testing a new policy before enforcing)"
                ),
            },
            {
                "heading": "Remediation",
                "body": (
                    "Policies with effect 'DeployIfNotExists' or 'Modify' require a "
                    "Managed Identity on the assignment so Azure Policy can remediate "
                    "existing non-compliant resources automatically."
                ),
            },
            {
                "heading": "Inventory",
                "body": (
                    "Run 'itl-policy inventory --target azure --include assignments' "
                    "to list all policy assignments in your subscription."
                ),
            },
        ],
    },
    "policy-effect": {
        "title": "Policy Effects",
        "summary": (
            "The 'effect' in a policy rule determines what happens when a resource "
            "is evaluated and matches the policy condition. Effects range from "
            "blocking deployment to simply logging a finding."
        ),
        "sections": [
            {
                "heading": "Deny",
                "body": (
                    "Blocks the resource operation if the condition is met. "
                    "The deployment returns a 403 error with the policy name. "
                    "Use for hard security requirements (e.g. deny public storage accounts)."
                ),
            },
            {
                "heading": "Audit",
                "body": (
                    "Does NOT block the resource. Marks the resource as 'Non-compliant' "
                    "in the Azure Policy compliance dashboard. Use for visibility and "
                    "reporting before you are ready to enforce (Deny)."
                ),
            },
            {
                "heading": "AuditIfNotExists",
                "body": (
                    "Audits if a related resource (e.g. a diagnostic setting) does NOT "
                    "exist. For example: audit VMs that do not have the MMA extension "
                    "installed. The condition checks for the absence of a child resource."
                ),
            },
            {
                "heading": "DeployIfNotExists",
                "body": (
                    "Automatically deploys a related resource if it does not exist. "
                    "Requires a Managed Identity on the assignment. Example: "
                    "automatically deploy a diagnostic setting on new storage accounts. "
                    "Use for auto-remediation of new resources."
                ),
            },
            {
                "heading": "Modify",
                "body": (
                    "Adds, updates, or removes tags and properties on a resource "
                    "during creation or update. Requires a Managed Identity. "
                    "Example: automatically add an 'environment' tag to all resources "
                    "created in a subscription."
                ),
            },
            {
                "heading": "Append",
                "body": (
                    "Adds fields to a resource during creation or update without "
                    "blocking or replacing existing values. Limited to appending "
                    "to arrays (e.g. adding an IP rule to a storage firewall). "
                    "Does NOT require a Managed Identity."
                ),
            },
            {
                "heading": "Disabled",
                "body": (
                    "The policy condition is not evaluated. Used to temporarily "
                    "disable a policy without removing the assignment — e.g. during "
                    "a maintenance window or when testing parameter changes."
                ),
            },
            {
                "heading": "Effect evaluation order",
                "body": (
                    "When multiple policies apply to a resource, Azure evaluates them "
                    "in this order (first match wins for blocking):\n"
                    "  Disabled > Append > Deny > Audit > Modify >\n"
                    "  AuditIfNotExists > DeployIfNotExists"
                ),
            },
        ],
    },
}


def _explain_about(topic: str, as_json: bool) -> None:
    """Render a human-readable explanation of an Azure governance concept."""
    data = _ABOUT_TOPICS.get(topic)
    if not data:
        click.echo(f"Unknown topic: {topic}", err=True)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps({"topic": topic, **data}, indent=2))
        return

    click.echo()
    click.secho(f"  {data['title']}", bold=True, fg="cyan")
    click.echo()

    # Summary paragraph
    summary = data.get("summary", "")
    _echo_wrapped(summary, indent="  ")
    click.echo()

    for sec in data.get("sections", []):
        click.secho(f"  ── {sec['heading']} ──", bold=True)
        body = sec.get("body", "")
        # Body may contain intentional newlines (bullet lists) — preserve them
        for line in body.split("\n"):
            if line.strip():
                _echo_wrapped(line, indent="     ")
            else:
                click.echo()
        click.echo()

    # Cross-reference tip
    all_topics = list(_ABOUT_TOPICS.keys())
    other = [t for t in all_topics if t != topic]
    click.secho("  Related topics:", fg="bright_black")
    click.secho("    " + "  |  ".join(other), fg="bright_black")
    click.echo()


def _echo_wrapped(text: str, indent: str = "  ", width: int = 76) -> None:
    """Print text word-wrapped at `width` chars with a consistent indent."""
    effective_width = width - len(indent)
    text = text.strip()
    while len(text) > effective_width:
        cut = text.rfind(" ", 0, effective_width)
        if cut == -1:
            cut = effective_width
        click.echo(f"{indent}{text[:cut]}")
        text = text[cut:].lstrip()
    if text:
        click.echo(f"{indent}{text}")


def _explain_cis_azure(
    section: Optional[str],
    severity: Optional[str],
    as_json: bool,
) -> None:
    from itl_policy_builder.templates.cis_azure import (
        CIS_SECTIONS,
        _CIS_POLICIES,
    )

    # Validate --section argument early
    if section and section not in CIS_SECTIONS:
        available = ", ".join(CIS_SECTIONS.keys())
        click.echo(
            f"❌ Unknown section '{section}'. Available: {available}", err=True
        )
        sys.exit(1)

    # Build a grouped structure: {section_key: [class, ...]}
    grouped: dict = {}
    for cls in _CIS_POLICIES.values():
        if section and cls.cis_section != section:
            continue
        if severity and cls.severity.lower() != severity.lower():
            continue
        grouped.setdefault(cls.cis_section, []).append(cls)

    if as_json:
        output = {
            "template": "cis-azure",
            "title": "CIS Microsoft Azure Foundations Benchmark",
            "total_policies": sum(len(v) for v in grouped.values()),
            "sections": [
                {
                    "key": sec_key,
                    "title": CIS_SECTIONS.get(sec_key, sec_key),
                    "policies": [
                        {
                            "name": cls.name,
                            "display_name": cls.display_name,
                            "cis_control": cls.cis_control,
                            "severity": cls.severity,
                            "description": cls.description,
                        }
                        for cls in classes
                    ],
                }
                for sec_key, classes in grouped.items()
            ],
        }
        click.echo(json.dumps(output, indent=2))
        return

    # ── Human-readable output ────────────────────────────────────────────────
    total = sum(len(v) for v in grouped.values())
    filters = []
    if section:
        filters.append(f"section={section}")
    if severity:
        filters.append(f"severity={severity}")
    filter_str = f"  [{', '.join(filters)}]" if filters else ""

    click.echo()
    click.secho(
        "  CIS Microsoft Azure Foundations Benchmark",
        bold=True,
        fg="cyan",
    )
    click.secho(
        f"  Template: cis-azure{filter_str}   Policies: {total}",
        fg="bright_black",
    )
    click.echo()

    for sec_key, classes in grouped.items():
        sec_title = CIS_SECTIONS.get(sec_key, sec_key)
        click.secho(f"  ── {sec_key}: {sec_title} ({len(classes)}) ──", bold=True)

        for cls in classes:
            sev_color = _severity_color(cls.severity)
            severity_label = click.style(f"[{cls.severity:<6}]", fg=sev_color, bold=True)
            control_label = click.style(f"({cls.cis_control})", fg="bright_black")
            click.echo(f"    {severity_label} {cls.display_name} {control_label}")
            click.echo(f"           {click.style('name:', fg='bright_black')} {cls.name}")

            # Wrap description at 72 chars
            desc = cls.description.strip().replace("\n", " ")
            while len(desc) > 72:
                cut = desc.rfind(" ", 0, 72)
                if cut == -1:
                    cut = 72
                click.echo(f"           {desc[:cut]}")
                desc = desc[cut:].lstrip()
            if desc:
                click.echo(f"           {desc}")
            click.echo()

    if not grouped:
        click.echo("  No policies match the given filters.")
        click.echo()

    if not section and not severity:
        click.echo(
            "  Tip: use --section <KEY> to focus on one section. "
            "Available sections: " + ", ".join(CIS_SECTIONS.keys())
        )
        click.echo()


def _explain_kyverno(template: str, as_json: bool) -> None:
    from itl_policy_builder.templates.kyverno import (
        KYVERNO_CATEGORIES,
        list_kyverno_policies,
        get_talos_security_bundle,
        get_pqc_transition_bundle,
    )

    bundle_fn = (
        get_talos_security_bundle if template == "talos-security" else get_pqc_transition_bundle
    )
    bundle = bundle_fn()

    titles = {
        "talos-security": "Talos OS Security Bundle (Kyverno)",
        "pqc-transition": "Post-Quantum Cryptography Transition Bundle (Kyverno)",
    }

    if as_json:
        output = {
            "template": template,
            "title": titles[template],
            "total_policies": len(bundle),
            "policies": [
                {
                    "name": p.get("metadata", {}).get("name", ""),
                    "kind": p.get("kind", ""),
                }
                for p in bundle
            ],
        }
        click.echo(json.dumps(output, indent=2))
        return

    click.echo()
    click.secho(f"  {titles[template]}", bold=True, fg="cyan")
    click.secho(f"  Template: {template}   Policies: {len(bundle)}", fg="bright_black")
    click.echo()

    for policy in bundle:
        name = policy.get("metadata", {}).get("name", "<unnamed>")
        kind = policy.get("kind", "ClusterPolicy")
        rules = policy.get("spec", {}).get("rules", [])
        click.secho(f"  • {name}", bold=True)
        click.echo(f"    kind:  {kind}")
        click.echo(f"    rules: {len(rules)}")
        for rule in rules:
            click.echo(f"      - {rule.get('name', '')}")
        click.echo()


# ============================================================================
# DESCRIBE COMMAND  (live data per Azure governance level)
# ============================================================================

@cli.command()
@click.argument(
    "level",
    type=click.Choice([
        "management-group",
        "subscription",
        "resource-group",
        "policy-definition",
        "policy-initiative",
        "policy-assignment",
    ]),
)
@click.argument("name")
@click.option("--subscription-id", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID (required for resource-group / policy-* levels)")
@click.option("--tenant-id", envvar="AZURE_TENANT_ID", help="Azure tenant ID")
@click.option(
    "--azure-auth",
    type=click.Choice(["default", "cli", "env"]),
    default="default",
    show_default=True,
    help="Azure authentication method",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format",
)
def describe(
    level: str,
    name: str,
    subscription_id: Optional[str],
    tenant_id: Optional[str],
    azure_auth: str,
    output_format: str,
):
    """Fetch and display live Azure details for a specific governance level.

    \b
    LEVEL is the governance level to describe.
    NAME  is the resource name, ID, or display name to look up.

    \b
    Examples:
      itl-policy describe management-group  MyRootMG
      itl-policy describe subscription      00000000-0000-0000-0000-000000000000
      itl-policy describe resource-group    my-rg  --subscription-id <sub>
      itl-policy describe policy-definition /providers/Microsoft.Authorization/policyDefinitions/<id>
      itl-policy describe policy-initiative <initiative-name>  --subscription-id <sub>
      itl-policy describe policy-assignment <assignment-name>  --subscription-id <sub>
    """
    try:
        credential = _get_azure_credential(azure_auth)
        data = _describe_azure(level=level, name=name, subscription_id=subscription_id,
                               tenant_id=tenant_id, credential=credential)
        if output_format == "json":
            click.echo(json.dumps(data, indent=2, default=str))
        else:
            _render_describe(level=level, name=name, data=data)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


def _describe_azure(
    level: str,
    name: str,
    subscription_id: Optional[str],
    tenant_id: Optional[str],
    credential,
) -> dict:
    """Route to the appropriate Azure describe helper."""
    if level == "management-group":
        return _describe_management_group(name, credential)
    elif level == "subscription":
        return _describe_subscription(name, credential)
    elif level == "resource-group":
        if not subscription_id:
            click.echo("❌ --subscription-id is required for resource-group level", err=True)
            sys.exit(1)
        return _describe_resource_group(name, subscription_id, credential)
    elif level == "policy-definition":
        return _describe_policy_definition(name, subscription_id, credential)
    elif level == "policy-initiative":
        if not subscription_id:
            click.echo("❌ --subscription-id is required for policy-initiative level", err=True)
            sys.exit(1)
        return _describe_policy_initiative(name, subscription_id, credential)
    elif level == "policy-assignment":
        if not subscription_id:
            click.echo("❌ --subscription-id is required for policy-assignment level", err=True)
            sys.exit(1)
        return _describe_policy_assignment(name, subscription_id, credential)
    return {"error": f"Unknown level: {level}"}


def _describe_management_group(name: str, credential) -> dict:
    try:
        from azure.mgmt.managementgroups import ManagementGroupsAPI
    except ImportError:
        return {"error": "azure-mgmt-managementgroups not installed"}

    client = ManagementGroupsAPI(credential=credential)
    try:
        mg = client.management_groups.get(
            group_id=name,
            expand="children",
            recurse=False,
        )
    except Exception as e:
        return {"error": str(e)}

    children = []
    if hasattr(mg, "children") and mg.children:
        for c in mg.children:
            children.append({
                "name": getattr(c, "name", None),
                "display_name": getattr(c, "display_name", None),
                "type": getattr(c, "type", None),
            })

    return {
        "id": mg.id,
        "name": mg.name,
        "display_name": mg.display_name,
        "type": mg.type,
        "tenant_id": getattr(mg, "tenant_id", None),
        "parent": {
            "id": getattr(getattr(mg, "details", None), "parent", None) and mg.details.parent.id,
            "name": getattr(getattr(mg, "details", None), "parent", None) and mg.details.parent.name,
        } if hasattr(mg, "details") and mg.details else None,
        "children": children,
        "children_count": len(children),
    }


def _describe_subscription(name: str, credential) -> dict:
    try:
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-resource not installed"}

    client = SubscriptionClient(credential=credential)
    # name may be subscription ID or display name — try both
    target = None
    for sub in client.subscriptions.list():
        if sub.subscription_id == name or (sub.display_name or "").lower() == name.lower():
            target = sub
            break

    if not target:
        return {"error": f"Subscription '{name}' not found"}

    policies = getattr(target, "subscription_policies", None)
    return {
        "subscription_id": target.subscription_id,
        "display_name": target.display_name,
        "state": str(target.state),
        "tenant_id": target.tenant_id,
        "authorization_source": getattr(target, "authorization_source", None),
        "spending_limit": str(policies.spending_limit) if policies else None,
        "quota_id": policies.quota_id if policies else None,
        "tags": target.tags or {},
    }


def _describe_resource_group(name: str, subscription_id: str, credential) -> dict:
    try:
        from azure.mgmt.resource import ResourceManagementClient
    except ImportError:
        return {"error": "azure-mgmt-resource not installed"}

    client = ResourceManagementClient(credential=credential, subscription_id=subscription_id)
    try:
        rg = client.resource_groups.get(name)
    except Exception as e:
        return {"error": str(e)}

    # Also count resources in this group
    resource_count = 0
    try:
        resource_count = sum(1 for _ in client.resources.list_by_resource_group(name))
    except Exception:
        resource_count = -1

    return {
        "id": rg.id,
        "name": rg.name,
        "location": rg.location,
        "provisioning_state": rg.properties.provisioning_state if rg.properties else None,
        "managed_by": getattr(rg, "managed_by", None),
        "tags": rg.tags or {},
        "resource_count": resource_count,
    }


def _describe_policy_definition(name: str, subscription_id: Optional[str], credential) -> dict:
    try:
        from azure.mgmt.resource.policy import PolicyClient
    except ImportError:
        return {"error": "azure-mgmt-resource not installed"}

    # Built-in policies use a subscription-less scope; custom ones need a subscription
    if subscription_id:
        client = PolicyClient(credential=credential, subscription_id=subscription_id)
    else:
        # Try to get a subscription from the environment
        try:
            from azure.mgmt.resource import SubscriptionClient
            sc = SubscriptionClient(credential=credential)
            first_sub = next(iter(sc.subscriptions.list()), None)
            if not first_sub:
                return {"error": "No subscription found; pass --subscription-id"}
            client = PolicyClient(credential=credential, subscription_id=first_sub.subscription_id)
        except Exception as e:
            return {"error": str(e)}

    # Try built-in first, then custom
    pd = None
    try:
        # name may be the short name or the full /providers/… path
        short_name = name.split("/")[-1]
        pd = client.policy_definitions.get_built_in(short_name)
    except Exception:
        pass

    if pd is None and subscription_id:
        try:
            short_name = name.split("/")[-1]
            pd = client.policy_definitions.get(short_name)
        except Exception:
            pass

    if pd is None:
        return {"error": f"Policy definition '{name}' not found"}

    rule = {}
    if pd.policy_rule:
        rule = pd.policy_rule if isinstance(pd.policy_rule, dict) else dict(pd.policy_rule)

    return {
        "id": pd.id,
        "name": pd.name,
        "display_name": pd.display_name,
        "description": pd.description,
        "policy_type": str(pd.policy_type),
        "mode": pd.mode,
        "metadata": pd.metadata or {},
        "parameters": {k: v.as_dict() if hasattr(v, "as_dict") else v
                       for k, v in (pd.parameters or {}).items()},
        "policy_rule_effect": (
            rule.get("then", {}).get("effect") if isinstance(rule, dict) else None
        ),
    }


def _describe_policy_initiative(name: str, subscription_id: str, credential) -> dict:
    try:
        from azure.mgmt.resource.policy import PolicyClient
    except ImportError:
        return {"error": "azure-mgmt-resource not installed"}

    client = PolicyClient(credential=credential, subscription_id=subscription_id)
    ps = None
    try:
        ps = client.policy_set_definitions.get(name)
    except Exception:
        pass

    if ps is None:
        try:
            ps = client.policy_set_definitions.get_built_in(name)
        except Exception:
            pass

    if ps is None:
        return {"error": f"Policy initiative '{name}' not found"}

    policies = []
    for pd_ref in (ps.policy_definitions or []):
        policies.append({
            "policy_definition_id": getattr(pd_ref, "policy_definition_id", None),
            "policy_definition_reference_id": getattr(pd_ref, "policy_definition_reference_id", None),
        })

    return {
        "id": ps.id,
        "name": ps.name,
        "display_name": ps.display_name,
        "description": ps.description,
        "policy_type": str(ps.policy_type),
        "metadata": ps.metadata or {},
        "policy_count": len(policies),
        "policies": policies,
    }


def _describe_policy_assignment(name: str, subscription_id: str, credential) -> dict:
    try:
        from azure.mgmt.resource.policy import PolicyClient
    except ImportError:
        return {"error": "azure-mgmt-resource not installed"}

    client = PolicyClient(credential=credential, subscription_id=subscription_id)
    pa = None
    try:
        # name may be the short assignment name; scope defaults to sub
        scope = f"/subscriptions/{subscription_id}"
        pa = client.policy_assignments.get(scope=scope, policy_assignment_name=name)
    except Exception:
        pass

    if pa is None:
        # Try to find by iterating (name match)
        try:
            for a in client.policy_assignments.list():
                if a.name == name or (a.display_name or "").lower() == name.lower():
                    pa = a
                    break
        except Exception:
            pass

    if pa is None:
        return {"error": f"Policy assignment '{name}' not found in subscription {subscription_id}"}

    return {
        "id": pa.id,
        "name": pa.name,
        "display_name": pa.display_name,
        "description": pa.description,
        "scope": pa.scope,
        "not_scopes": pa.not_scopes or [],
        "enforcement_mode": str(pa.enforcement_mode) if pa.enforcement_mode else None,
        "policy_definition_id": pa.policy_definition_id,
        "parameters": {k: getattr(v, "value", v) for k, v in (pa.parameters or {}).items()},
        "metadata": pa.metadata or {},
        "identity": {
            "type": str(pa.identity.type) if pa.identity else None,
            "principal_id": pa.identity.principal_id if pa.identity else None,
        },
    }


def _render_describe(level: str, name: str, data: dict) -> None:
    """Human-readable rendering of a describe result."""
    if "error" in data:
        click.echo(f"❌ {data['error']}", err=True)
        sys.exit(1)

    _LEVEL_TITLES = {
        "management-group":  "Management Group",
        "subscription":      "Subscription",
        "resource-group":    "Resource Group",
        "policy-definition": "Policy Definition",
        "policy-initiative": "Policy Initiative",
        "policy-assignment": "Policy Assignment",
    }
    title = _LEVEL_TITLES.get(level, level)

    click.echo()
    click.secho(f"  {title}", bold=True, fg="cyan")
    click.secho(f"  {data.get('display_name') or data.get('name') or name}", fg="white", bold=True)
    click.echo()

    # Generic key-value pairs (skip complex nested fields; render those separately)
    _SKIP_KEYS = {"children", "policies", "parameters", "metadata", "tags", "not_scopes", "identity", "parent"}

    for key, value in data.items():
        if key in _SKIP_KEYS or value is None or value == {} or value == []:
            continue
        label = key.replace("_", " ").title()
        if isinstance(value, (dict, list)):
            continue
        click.echo(f"  {'  ' + label + ':':<30} {value}")

    # Parent (management group)
    parent = data.get("parent")
    if parent and parent.get("name"):
        click.echo()
        click.secho("  Parent:", bold=True)
        click.echo(f"    Name : {parent.get('name')}")
        click.echo(f"    ID   : {parent.get('id')}")

    # Tags
    tags = data.get("tags")
    if tags:
        click.echo()
        click.secho("  Tags:", bold=True)
        for k, v in tags.items():
            click.echo(f"    {k} = {v}")

    # Parameters
    params = data.get("parameters")
    if params:
        click.echo()
        click.secho("  Parameters:", bold=True)
        for k, v in params.items():
            click.echo(f"    {k}: {v}")

    # Metadata (selected keys)
    meta = data.get("metadata") or {}
    if isinstance(meta, dict) and meta:
        interesting = {k: v for k, v in meta.items()
                       if k in ("category", "version", "preview", "deprecated")}
        if interesting:
            click.echo()
            click.secho("  Metadata:", bold=True)
            for k, v in interesting.items():
                click.echo(f"    {k}: {v}")

    # Identity
    identity = data.get("identity") or {}
    if identity and identity.get("type"):
        click.echo()
        click.secho("  Identity:", bold=True)
        click.echo(f"    Type         : {identity.get('type')}")
        if identity.get("principal_id"):
            click.echo(f"    Principal ID : {identity.get('principal_id')}")

    # Not-scopes
    not_scopes = data.get("not_scopes") or []
    if not_scopes:
        click.echo()
        click.secho("  Excluded scopes:", bold=True)
        for s in not_scopes:
            click.echo(f"    - {s}")

    # Children (management group)
    children = data.get("children")
    if children is not None:
        click.echo()
        click.secho(f"  Children ({len(children)}):", bold=True)
        for c in children:
            kind = "📁" if "/managementGroups/" in (c.get("type") or "") else "🔑"
            click.echo(f"    {kind} {c.get('display_name') or c.get('name')}  ({c.get('name')})")

    # Policies (initiative)
    policies = data.get("policies")
    if policies is not None:
        click.echo()
        click.secho(f"  Included policies ({len(policies)}):", bold=True)
        for p in policies[:20]:
            ref_id = p.get("policy_definition_reference_id") or ""
            def_id = (p.get("policy_definition_id") or "").split("/")[-1]
            click.echo(f"    • {ref_id or def_id}")
        if len(policies) > 20:
            click.echo(f"    … and {len(policies) - 20} more. Use --format json for full list.")

    click.echo()
    click.secho("  Tip: use --format json for the full raw API response.", fg="bright_black")
    click.echo()


# ============================================================================
# INVENTORY COMMAND
# ============================================================================

@cli.command()
@click.option(
    "--target",
    type=click.Choice(["azure", "kubernetes", "itl-api", "all"]),
    default="azure",
    help="Platform to inventory",
)
@click.option("--subscription-id", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID")
@click.option("--all-subscriptions", is_flag=True, default=False, help="Inventory all accessible subscriptions")
@click.option("--tenant-id", envvar="AZURE_TENANT_ID", help="Azure tenant ID")
@click.option(
    "--azure-auth",
    type=click.Choice(["default", "cli", "env"]),
    default="default",
    help="Azure authentication method",
)
@click.option("--kubeconfig", type=click.Path(), help="Path to kubeconfig (kubernetes target)")
@click.option("--api-endpoint", envvar="ITL_API_ENDPOINT", help="ITL API endpoint (itl-api target)")
@click.option("--api-key", envvar="ITL_API_KEY", help="ITL API key")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.option(
    "--include",
    multiple=True,
    type=click.Choice(["policies", "initiatives", "assignments", "management-groups"]),
    default=["policies", "initiatives", "assignments", "management-groups"],
    show_default=True,
    help="What to include (repeatable)",
)
@click.option("--output", "-o", type=click.Path(), help="Write output to file")
def inventory(
    target: str,
    subscription_id: Optional[str],
    all_subscriptions: bool,
    tenant_id: Optional[str],
    azure_auth: str,
    kubeconfig: Optional[str],
    api_endpoint: Optional[str],
    api_key: Optional[str],
    output_format: str,
    include: tuple,
    output: Optional[str],
):
    """Inventory existing policies, initiatives, assignments, and management groups."""
    result: dict = {}

    targets = ["azure", "kubernetes", "itl-api"] if target == "all" else [target]

    for t in targets:
        if t == "azure":
            if all_subscriptions:
                result["azure"] = _inventory_azure_all_subscriptions(tenant_id, azure_auth, set(include))
            else:
                result["azure"] = _inventory_azure(subscription_id, tenant_id, azure_auth, set(include))
        elif t == "kubernetes":
            result["kubernetes"] = _inventory_kubernetes(kubeconfig)
        elif t == "itl-api":
            result["itl-api"] = _inventory_itl_api(api_endpoint, api_key)

    # Render
    if output_format == "json":
        text = json.dumps(result, indent=2, default=str)
        if output:
            Path(output).write_text(text)
            click.echo(f"Inventory written to {output}")
        else:
            click.echo(text)
    else:
        _render_inventory_table(result, include)
        if output:
            # Write plain JSON to file even in table mode
            Path(output).write_text(json.dumps(result, indent=2, default=str))
            click.echo(f"\nInventory (JSON) also written to {output}")


def _get_azure_credential(azure_auth: str):
    """Return an Azure credential based on the auth method."""
    from azure.identity import DefaultAzureCredential, AzureCliCredential, EnvironmentCredential
    if azure_auth == "cli":
        return AzureCliCredential()
    elif azure_auth == "env":
        return EnvironmentCredential()
    return DefaultAzureCredential()


def _list_azure_subscriptions(azure_auth: str) -> list:
    """Return all accessible Azure subscriptions as list of {id, name, state}."""
    try:
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        return []
    credential = _get_azure_credential(azure_auth)
    client = SubscriptionClient(credential)
    return [
        {"id": s.subscription_id, "name": s.display_name, "state": s.state}
        for s in client.subscriptions.list()
    ]


def _inventory_azure_all_subscriptions(
    tenant_id: Optional[str],
    azure_auth: str,
    include: set,
) -> dict:
    """Inventory all accessible Azure subscriptions and return per-subscription results."""
    subscriptions = _list_azure_subscriptions(azure_auth)
    if not subscriptions:
        return {"error": "No subscriptions found or azure-mgmt-resource not installed"}

    click.secho(f"  {len(subscriptions)} subscription(s) gevonden", fg="cyan", err=True)
    result: dict = {}
    for sub in subscriptions:
        sub_id = sub["id"]
        sub_name = sub["name"]
        click.secho(f"\n  ▶ {sub_name} ({sub_id})", err=True)
        result[sub_id] = {
            "name": sub_name,
            "state": sub["state"],
            **_inventory_azure(sub_id, tenant_id, azure_auth, include),
        }
    return result


def _inventory_azure(
    subscription_id: Optional[str],
    tenant_id: Optional[str],
    azure_auth: str,
    include: set,
) -> dict:
    """Fetch Azure policies, initiatives, assignments, and management groups."""
    data: dict = {}

    try:
        from azure.mgmt.resource.policy import PolicyClient
        from azure.mgmt.managementgroups import ManagementGroupsAPI
    except ImportError:
        click.secho(
            "  Azure SDK niet beschikbaar. Installeer: pip install azure-mgmt-resource azure-mgmt-managementgroups azure-identity",
            fg="red",
            err=True,
        )
        return {"error": "Azure SDK not installed"}

    if not subscription_id:
        click.secho(
            "  --subscription-id vereist voor Azure inventory (of zet AZURE_SUBSCRIPTION_ID)",
            fg="red",
            err=True,
        )
        return {"error": "subscription_id required"}

    try:
        credential = _get_azure_credential(azure_auth)
        policy_client = PolicyClient(credential=credential, subscription_id=subscription_id)

        # Policy definitions
        if "policies" in include:
            click.echo("  Ophalen: policy definitions...", err=True)
            policies = []
            for p in policy_client.policy_definitions.list():
                policies.append({
                    "name": p.name,
                    "display_name": p.display_name,
                    "policy_type": p.policy_type,
                    "mode": p.mode,
                    "category": (p.metadata or {}).get("category", ""),
                    "id": p.id,
                })
            # Also list builtin (subscription-level)
            for p in policy_client.policy_definitions.list_built_in():
                policies.append({
                    "name": p.name,
                    "display_name": p.display_name,
                    "policy_type": p.policy_type,
                    "mode": p.mode,
                    "category": (p.metadata or {}).get("category", ""),
                    "id": p.id,
                })
            data["policies"] = policies

        # Policy set definitions (initiatives)
        if "initiatives" in include:
            click.echo("  Ophalen: policy set definitions (initiatives)...", err=True)
            initiatives = []
            for i in policy_client.policy_set_definitions.list():
                initiatives.append({
                    "name": i.name,
                    "display_name": i.display_name,
                    "policy_type": i.policy_type,
                    "category": (i.metadata or {}).get("category", ""),
                    "policy_count": len(i.policy_definitions or []),
                    "id": i.id,
                })
            for i in policy_client.policy_set_definitions.list_built_in():
                initiatives.append({
                    "name": i.name,
                    "display_name": i.display_name,
                    "policy_type": i.policy_type,
                    "category": (i.metadata or {}).get("category", ""),
                    "policy_count": len(i.policy_definitions or []),
                    "id": i.id,
                })
            data["initiatives"] = initiatives

        # Policy assignments
        if "assignments" in include:
            click.echo("  Ophalen: policy assignments...", err=True)
            assignments = []
            for a in policy_client.policy_assignments.list():
                assignments.append({
                    "name": a.name,
                    "display_name": a.display_name,
                    "scope": a.scope,
                    "policy_definition_id": a.policy_definition_id,
                    "enforcement_mode": a.enforcement_mode,
                    "id": a.id,
                })
            data["assignments"] = assignments

        # Management groups
        if "management-groups" in include:
            click.echo("  Ophalen: management groups...", err=True)
            try:
                mg_client = ManagementGroupsAPI(credential=credential)
                groups = []
                for mg in mg_client.management_groups.list():
                    groups.append({
                        "name": mg.name,
                        "display_name": mg.display_name,
                        "type": mg.type,
                        "id": mg.id,
                    })
                data["management_groups"] = groups
            except Exception as e:
                data["management_groups"] = {"error": str(e)}

    except Exception as e:
        data["error"] = str(e)

    return data


def _inventory_kubernetes(kubeconfig: Optional[str]) -> dict:
    """List Kyverno policies from a Kubernetes cluster."""
    data: dict = {}
    try:
        from kubernetes import client, config
    except ImportError:
        return {"error": "kubernetes package not installed. Install with: pip install kubernetes"}

    try:
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()

        api = client.CustomObjectsApi()

        # ClusterPolicies
        try:
            cp = api.list_cluster_custom_object(
                group="kyverno.io", version="v1", plural="clusterpolicies"
            )
            data["cluster_policies"] = [
                {
                    "name": item["metadata"]["name"],
                    "rules": len(item.get("spec", {}).get("rules", [])),
                    "background": item.get("spec", {}).get("background", True),
                }
                for item in cp.get("items", [])
            ]
        except Exception as e:
            data["cluster_policies"] = {"error": str(e)}

        # Namespaced Policies
        try:
            np = api.list_cluster_custom_object(
                group="kyverno.io", version="v1", plural="policies"
            )
            data["policies"] = [
                {
                    "name": item["metadata"]["name"],
                    "namespace": item["metadata"].get("namespace", ""),
                    "rules": len(item.get("spec", {}).get("rules", [])),
                }
                for item in np.get("items", [])
            ]
        except Exception as e:
            data["policies"] = {"error": str(e)}

    except Exception as e:
        data["error"] = str(e)

    return data


def _inventory_itl_api(api_endpoint: Optional[str], api_key: Optional[str]) -> dict:
    """List policies from ITL ControlPlane API."""
    if not api_endpoint:
        return {"error": "--api-endpoint or ITL_API_ENDPOINT required"}

    data: dict = {}
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed. Install with: pip install httpx"}

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        with httpx.Client(timeout=15) as http:
            resp = http.get(f"{api_endpoint}/policies", headers=headers)
            if resp.status_code == 200:
                data["policies"] = resp.json()
            else:
                data["policies"] = {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        data["error"] = str(e)

    return data


def _render_azure_inventory(data: dict, indent: str = "  ") -> None:
    """Render a single Azure subscription's inventory data."""
    if "error" in data:
        click.secho(f"{indent}Fout: {data['error']}", fg="red")
        return

    if "policies" in data:
        pols = data["policies"]
        custom = [p for p in pols if p.get("policy_type") == "Custom"]
        builtin = [p for p in pols if p.get("policy_type") != "Custom"]
        click.secho(f"\n{indent}Policy Definitions ({len(pols)} totaal, {len(custom)} custom, {len(builtin)} builtin)", bold=True)
        for p in custom:
            cat = f"  [{p['category']}]" if p.get("category") else ""
            click.echo(f"{indent}  • {p['display_name'] or p['name']}{cat}")
            click.echo(f"{indent}    id: {p['id']}")

    if "initiatives" in data:
        inits = data["initiatives"]
        custom = [i for i in inits if i.get("policy_type") == "Custom"]
        click.secho(f"\n{indent}Initiatives / Policy Sets ({len(inits)} totaal, {len(custom)} custom)", bold=True)
        for i in custom:
            cat = f"  [{i['category']}]" if i.get("category") else ""
            click.echo(f"{indent}  • {i['display_name'] or i['name']}{cat}  ({i['policy_count']} policies)")
            click.echo(f"{indent}    id: {i['id']}")

    if "assignments" in data:
        asgn = data["assignments"]
        click.secho(f"\n{indent}Policy Assignments ({len(asgn)})", bold=True)
        for a in asgn:
            click.echo(f"{indent}  • {a['display_name'] or a['name']}")
            click.echo(f"{indent}    scope:  {a.get('scope', '')}")
            click.echo(f"{indent}    mode:   {a.get('enforcement_mode', '')}")
            click.echo(f"{indent}    policy: {a['policy_definition_id']}")

    if "management_groups" in data:
        mgs = data["management_groups"]
        if isinstance(mgs, dict) and "error" in mgs:
            click.secho(f"\n{indent}Management Groups: {mgs['error']}", fg="yellow")
        else:
            click.secho(f"\n{indent}Management Groups ({len(mgs)})", bold=True)
            for mg in mgs:
                click.echo(f"{indent}  • {mg['display_name'] or mg['name']}")
                click.echo(f"{indent}    id: {mg['id']}")


def _render_inventory_table(result: dict, include: tuple) -> None:
    """Render inventory result as a human-readable table."""
    for platform, data in result.items():
        click.secho(f"\n{'='*60}", bold=True)
        click.secho(f"  {platform.upper()}", bold=True, fg="cyan")
        click.secho(f"{'='*60}", bold=True)

        if "error" in data:
            click.secho(f"  Fout: {data['error']}", fg="red")
            continue

        if platform == "azure":
            # Multi-subscription: keys are subscription IDs (UUIDs)
            first_key = next(iter(data), None)
            is_multi_sub = (
                first_key is not None
                and isinstance(data[first_key], dict)
                and "name" in data[first_key]
                and "policies" in data[first_key] or "assignments" in data[first_key] or "error" in data[first_key]
            ) and first_key not in ("policies", "initiatives", "assignments", "management_groups", "error")

            if is_multi_sub:
                for sub_id, sub_data in data.items():
                    sub_name = sub_data.get("name", sub_id)
                    state = sub_data.get("state", "")
                    click.secho(f"\n  ── Subscription: {sub_name} ({sub_id})  [{state}]", bold=True, fg="yellow")
                    _render_azure_inventory(sub_data, indent="    ")
            else:
                _render_azure_inventory(data)

        elif platform == "kubernetes":
            cp = data.get("cluster_policies", [])
            np = data.get("policies", [])
            if isinstance(cp, dict) and "error" in cp:
                click.secho(f"\n  ClusterPolicies: {cp['error']}", fg="yellow")
            else:
                click.secho(f"\n  ClusterPolicies ({len(cp)})", bold=True)
                for p in cp:
                    click.echo(f"    • {p['name']}  ({p['rules']} rules)")
            if isinstance(np, dict) and "error" in np:
                click.secho(f"\n  Policies: {np['error']}", fg="yellow")
            else:
                click.secho(f"\n  Policies ({len(np)})", bold=True)
                for p in np:
                    click.echo(f"    • {p['namespace']}/{p['name']}  ({p['rules']} rules)")

        elif platform == "itl-api":
            pols = data.get("policies", [])
            if isinstance(pols, dict) and "error" in pols:
                click.secho(f"\n  Policies: {pols['error']}", fg="yellow")
            elif isinstance(pols, list):
                click.secho(f"\n  Policies ({len(pols)})", bold=True)
                for p in pols:
                    name = p.get("name") or p.get("id", "?")
                    click.echo(f"    • {name}")
            else:
                click.echo(f"  {pols}")


# ============================================================================
# PUBLISH COMMAND
# ============================================================================

@cli.command()
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True),
    required=True,
    help="Policy file (YAML or JSON) to publish",
)
@click.option(
    "--registry",
    type=click.Choice(["itl-api", "oci", "git"]),
    default="itl-api",
    help="Target registry: ITL policy catalog, OCI artifact registry, or Git repository",
)
@click.option(
    "--name",
    required=True,
    help="Bundle name in the registry (e.g. 'cis-azure-baseline')",
)
@click.option(
    "--version",
    "bundle_version",
    default="1.0.0",
    show_default=True,
    help="Semantic version tag for this bundle",
)
@click.option(
    "--tag",
    multiple=True,
    metavar="TAG",
    help="Additional tags (repeatable). e.g. --tag cis --tag azure",
)
@click.option(
    "--api-endpoint",
    envvar="ITL_API_ENDPOINT",
    help="ITL API endpoint (for itl-api registry)",
)
@click.option(
    "--api-key",
    envvar="ITL_API_KEY",
    help="ITL API key (for itl-api registry)",
)
@click.option(
    "--oci-registry",
    envvar="ITL_OCI_REGISTRY",
    metavar="HOST",
    help="OCI registry host, e.g. ghcr.io/itlusions (for oci registry)",
)
@click.option(
    "--git-repo",
    envvar="ITL_GIT_REPO",
    metavar="URL",
    help="Remote Git repository URL (for git registry)",
)
@click.option(
    "--git-branch",
    envvar="ITL_GIT_BRANCH",
    default="main",
    show_default=True,
    help="Branch to push to (for git registry)",
)
@click.option(
    "--git-path",
    default="policies",
    show_default=True,
    help="Sub-directory inside the repo to write policies into (for git registry)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Simulate publish without making remote changes",
)
def publish(
    file: str,
    registry: str,
    name: str,
    bundle_version: str,
    tag: tuple,
    api_endpoint: Optional[str],
    api_key: Optional[str],
    oci_registry: Optional[str],
    git_repo: Optional[str],
    git_branch: str,
    git_path: str,
    dry_run: bool,
):
    """Publish a policy bundle to a remote registry.

    \b
    Supported registries:
      itl-api  — ITL Control Plane policy catalog (default)
      oci      — OCI artifact registry (e.g. GHCR, ACR, ECR)
      git      — Git repository with policies-as-code layout

    \b
    Examples:
      itl-policy publish -f policies.yaml --name cis-azure --version 2.0.0
      itl-policy publish -f bundle.yaml --registry oci --oci-registry ghcr.io/itlusions --name cis-azure
      itl-policy publish -f policies.yaml --registry git --git-repo https://github.com/org/policies.git
    """
    import hashlib

    file_path = Path(file)
    content = file_path.read_text()

    try:
        import yaml as _yaml
        policies = [p for p in _yaml.safe_load_all(content) if p is not None]
    except ImportError:
        click.echo("Error: PyYAML required. Install with: pip install itl-policy-builder[cli]", err=True)
        sys.exit(1)

    policy_count = len(policies)
    digest = hashlib.sha256(content.encode()).hexdigest()[:12]
    all_tags = list(tag) + [bundle_version]

    click.echo(f"\n📦 Publishing bundle '{name}' v{bundle_version}")
    click.echo(f"   Policies : {policy_count}")
    click.echo(f"   Tags     : {', '.join(all_tags)}")
    click.echo(f"   Digest   : sha256:{digest}")
    click.echo(f"   Registry : {registry}")
    if dry_run:
        click.secho("   (DRY RUN — no remote changes will be made)", fg="yellow")

    try:
        if registry == "itl-api":
            _publish_to_itl_api(
                policies=policies,
                name=name,
                version=bundle_version,
                tags=all_tags,
                api_endpoint=api_endpoint,
                api_key=api_key,
                dry_run=dry_run,
            )

        elif registry == "oci":
            _publish_to_oci(
                file_path=file_path,
                name=name,
                version=bundle_version,
                tags=all_tags,
                oci_registry=oci_registry,
                dry_run=dry_run,
            )

        elif registry == "git":
            _publish_to_git(
                policies=policies,
                content=content,
                name=name,
                version=bundle_version,
                git_repo=git_repo,
                git_branch=git_branch,
                git_path=git_path,
                dry_run=dry_run,
            )

    except Exception as e:
        click.secho(f"\n❌ Publish failed: {e}", fg="red", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Publish helpers
# ---------------------------------------------------------------------------

def _publish_to_itl_api(
    policies: list,
    name: str,
    version: str,
    tags: list,
    api_endpoint: Optional[str],
    api_key: Optional[str],
    dry_run: bool,
) -> None:
    if not api_endpoint:
        raise click.UsageError("--api-endpoint or ITL_API_ENDPOINT is required for itl-api registry")
    if not api_key:
        raise click.UsageError("--api-key or ITL_API_KEY is required for itl-api registry")

    payload = {
        "name": name,
        "version": version,
        "tags": tags,
        "policies": policies,
    }

    if dry_run:
        click.echo(f"\n[dry-run] POST {api_endpoint.rstrip('/')}/policy-catalog/bundles")
        click.echo(f"[dry-run] Payload size: {len(str(payload))} chars, {len(policies)} policies")
        click.secho(f"\n✅ Dry-run complete — bundle '{name}' v{version} would be published to ITL catalog", fg="green")
        return

    try:
        import urllib.request
        import urllib.error

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url=f"{api_endpoint.rstrip('/')}/policy-catalog/bundles",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "X-Bundle-Name": name,
                "X-Bundle-Version": version,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            click.secho(f"\n✅ Published '{name}' v{version} to ITL catalog", fg="green")
            click.echo(f"   Response: {body[:200]}")
    except Exception as exc:
        raise RuntimeError(f"ITL API publish failed: {exc}") from exc


def _publish_to_oci(
    file_path: Path,
    name: str,
    version: str,
    tags: list,
    oci_registry: Optional[str],
    dry_run: bool,
) -> None:
    if not oci_registry:
        raise click.UsageError("--oci-registry or ITL_OCI_REGISTRY is required for oci registry")

    image_ref = f"{oci_registry.rstrip('/')}/{name}"
    tag_args = " ".join(f"--tag {image_ref}:{t}" for t in tags)

    click.echo(f"\n   Image ref: {image_ref}:{version}")

    if dry_run:
        click.echo(f"[dry-run] oras push {image_ref}:{version} {file_path} {tag_args}")
        click.secho(f"\n✅ Dry-run complete — bundle would be pushed to {image_ref}:{version}", fg="green")
        return

    import shutil
    import subprocess

    tool = "oras" if shutil.which("oras") else None
    if tool is None:
        raise RuntimeError(
            "OCI publish requires 'oras' CLI. Install from https://oras.land or run:\n"
            "  winget install OrasProject.Oras  (Windows)\n"
            "  brew install oras               (macOS/Linux)"
        )

    cmd = ["oras", "push", f"{image_ref}:{version}", str(file_path)]
    for t in tags:
        cmd += ["--tag", t]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    click.secho(f"\n✅ Pushed '{name}' v{version} to {image_ref}", fg="green")
    click.echo(result.stdout.strip())


def _publish_to_git(
    policies: list,
    content: str,
    name: str,
    version: str,
    git_repo: Optional[str],
    git_branch: str,
    git_path: str,
    dry_run: bool,
) -> None:
    if not git_repo:
        raise click.UsageError("--git-repo or ITL_GIT_REPO is required for git registry")

    import shutil
    import subprocess
    import tempfile

    if dry_run:
        click.echo(f"[dry-run] git clone {git_repo} → {git_path}/{name}/v{version}/policies.yaml")
        click.secho(f"\n✅ Dry-run complete — bundle would be committed to {git_repo} ({git_branch})", fg="green")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        def _git(*args: str) -> None:
            result = subprocess.run(["git", *args], cwd=tmpdir, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"git {args[0]} failed: {result.stderr.strip()}")

        _git("clone", "--depth", "1", "--branch", git_branch, git_repo, ".")

        dest = tmp / git_path / name / f"v{version}"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "policies.yaml").write_text(content)

        _git("add", "-A")
        _git("commit", "-m", f"chore: publish policy bundle {name} v{version}")
        _git("push", "origin", git_branch)

    click.secho(f"\n✅ Published '{name}' v{version} to {git_repo} ({git_branch}/{git_path}/{name}/v{version}/)", fg="green")


# ============================================================================
# RENDER COMMAND  (generate IaC files from resource/policy specs)
# ============================================================================

@cli.command("render")
@click.option(
    "--resources",
    "-r",
    type=click.Path(exists=True),
    default=None,
    help="JSON file with a list of ITL resource specs.",
)
@click.option(
    "--policies",
    "-p",
    type=click.Path(exists=True),
    default=None,
    help="JSON file with a list of policy specs (optional).",
)
@click.option(
    "--renderer",
    type=click.Choice(["arm", "bicep", "terraform", "pulumi"]),
    default="bicep",
    show_default=True,
    help="IaC renderer to use.",
)
@click.option(
    "--platform",
    type=click.Choice(["azure", "kubernetes", "talos"]),
    default="azure",
    show_default=True,
    help="Target platform.",
)
@click.option(
    "--location",
    default="westeurope",
    show_default=True,
    help="Azure region (azure platform only).",
)
@click.option(
    "--stack",
    default="itl-stack",
    show_default=True,
    help="Stack / project name embedded in generated files.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./iac-output",
    show_default=True,
    help="Directory to write generated files into.",
)
def render(
    resources: Optional[str],
    policies: Optional[str],
    renderer: str,
    platform: str,
    location: str,
    stack: str,
    output: str,
) -> None:
    """Render ITL resources/policies to IaC files (ARM, Bicep, Terraform, Pulumi)."""
    try:
        from itl_controlplane_sdk.iac import (
            ComponentType,
            Platform,
            RenderContext,
            get_renderer,
        )
    except ImportError:
        click.echo(
            "❌ itl-controlplane-sdk[iac] is required. "
            "Install with: pip install itl-controlplane-sdk[iac]",
            err=True,
        )
        sys.exit(1)

    resource_list: list = []
    policy_list: list = []

    if resources:
        resource_list = json.loads(Path(resources).read_text())
        if not isinstance(resource_list, list):
            click.echo("❌ --resources file must contain a JSON array.", err=True)
            sys.exit(1)

    if policies:
        policy_list = json.loads(Path(policies).read_text())
        if not isinstance(policy_list, list):
            click.echo("❌ --policies file must contain a JSON array.", err=True)
            sys.exit(1)

    if not resource_list and not policy_list:
        click.echo("❌ Provide at least --resources or --policies.", err=True)
        sys.exit(1)

    component_type = ComponentType.ALL
    if resource_list and not policy_list:
        component_type = ComponentType.RESOURCE
    elif policy_list and not resource_list:
        component_type = ComponentType.POLICY

    ctx = RenderContext(
        platform=Platform(platform),
        component_type=component_type,
        resources=resource_list,
        policies=policy_list,
        location=location,
        stack_name=stack,
    )

    r = get_renderer(renderer)
    out = r.render(ctx)
    written = out.write_to(output)

    click.secho(f"\n✅ Rendered {len(written)} file(s) to {output}/", fg="green")
    for f in written:
        rel = Path(f).relative_to(Path(output).resolve()) if Path(f).is_absolute() else Path(f)
        click.echo(f"   {rel}")


# ============================================================================
# PROVISION COMMAND  (render + pulumi up/preview/destroy)
# ============================================================================

@cli.command("provision")
@click.option(
    "--resources",
    "-r",
    type=click.Path(exists=True),
    required=True,
    help="JSON file with a list of ITL resource specs.",
)
@click.option(
    "--policies",
    "-p",
    type=click.Path(exists=True),
    default=None,
    help="JSON file with Azure policy specs (optional).",
)
@click.option(
    "--stack",
    default="itl-stack",
    show_default=True,
    help="Pulumi stack name.",
)
@click.option(
    "--project",
    default="itl-infrastructure",
    show_default=True,
    help="Pulumi project name.",
)
@click.option(
    "--location",
    default="westeurope",
    show_default=True,
    help="Azure region.",
)
@click.option(
    "--profile",
    default=None,
    help="ITL profile name (applied as tag to all resources).",
)
@click.option(
    "--action",
    type=click.Choice(["preview", "up", "destroy"]),
    default="preview",
    show_default=True,
    help="Pulumi action to run.",
)
@click.option(
    "--work-dir",
    default=None,
    type=click.Path(),
    help="Directory for generated Pulumi program (default: temporary dir).",
)
@click.option(
    "--config",
    multiple=True,
    help="Extra Pulumi config as key=value (repeatable).",
)
def provision(
    resources: str,
    policies: Optional[str],
    stack: str,
    project: str,
    location: str,
    profile: Optional[str],
    action: str,
    work_dir: Optional[str],
    config: tuple,
) -> None:
    """Provision ITL Azure resources using Pulumi (preview / up / destroy).

    \b
    Examples:
      itl-policy provision -r resources.json --action preview
      itl-policy provision -r resources.json --stack prod --action up
      itl-policy provision -r resources.json --stack prod --action destroy
    """
    try:
        from itl_controlplane_sdk.pulumi.azure import ITLAzureStack
    except ImportError:
        click.echo(
            "❌ itl-controlplane-sdk[iac-azure] is required. "
            "Install with: pip install itl-controlplane-sdk[iac-azure]",
            err=True,
        )
        sys.exit(1)

    resource_list = json.loads(Path(resources).read_text())
    if not isinstance(resource_list, list):
        click.echo("❌ --resources file must contain a JSON array.", err=True)
        sys.exit(1)

    policy_list: list = []
    if policies:
        policy_list = json.loads(Path(policies).read_text())

    # Parse extra config values
    extra_config: dict = {}
    for item in config:
        if "=" not in item:
            click.echo(f"❌ --config must be key=value, got: {item}", err=True)
            sys.exit(1)
        k, v = item.split("=", 1)
        extra_config[k] = v

    az_stack = ITLAzureStack(
        stack_name=stack,
        project_name=project,
        location=location,
        resources=resource_list,
        policies=policy_list,
        profile_name=profile,
        work_dir=work_dir,
        pulumi_config=extra_config,
    )

    click.echo(
        f"🔧 Stack: {project}/{stack}  |  {len(resource_list)} resource(s)  |  action: {action}"
    )

    if action == "preview":
        click.echo("Running pulumi preview …\n")
        output_text = asyncio.run(az_stack.preview())
        click.echo(output_text)
    elif action == "up":
        click.echo("Running pulumi up …\n")
        result = asyncio.run(az_stack.up())
        if result["outputs"]:
            click.secho("\nOutputs:", fg="cyan")
            for k, v in result["outputs"].items():
                click.echo(f"  {k}: {v}")
        changes = result["summary"].get("resource_changes") or {}
        click.secho(
            f"\n✅ Done  —  {changes}",
            fg="green",
        )
    elif action == "destroy":
        if not click.confirm("This will DESTROY all resources in this stack. Continue?"):
            click.echo("Aborted.")
            return
        click.echo("Running pulumi destroy …\n")
        asyncio.run(az_stack.destroy())
        click.secho("✅ Stack destroyed.", fg="green")


if __name__ == "__main__":
    cli()
