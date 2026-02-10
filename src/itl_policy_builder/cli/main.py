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

@cli.command()
@click.option(
    "--template",
    type=click.Choice(["talos-security", "pqc-transition", "custom"]),
    default="talos-security",
    help="Policy template to use",
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
            if template == "talos-security":
                policies = get_talos_security_bundle()
            elif template == "pqc-transition":
                policies = get_pqc_transition_bundle()
            else:
                click.echo(f"Unknown template: {template}", err=True)
                sys.exit(1)
        
        elif style == "azure":
            # Azure ARM-style policies
            try:
                from itl_policy_builder.templates import get_builtin_policy
                
                if template == "talos-security":
                    # Azure security baseline
                    policies = [
                        get_builtin_policy("allowed-locations"),
                        get_builtin_policy("require-nsg"),
                        get_builtin_policy("deny-public-ip"),
                    ]
                elif template == "pqc-transition":
                    # PQC-related compliance policies
                    policies = [
                        get_builtin_policy("require-tag-environment"),
                        get_builtin_policy("require-tag-owner"),
                    ]
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
                    # Convert to ARM JSON format
                    arm_policies = [
                        p.to_arm_json() if hasattr(p, 'to_arm_json') else p
                        for p in policies
                    ]
                    output_str = yaml.dump({"policies": arm_policies}, default_flow_style=False, sort_keys=False)
                except ImportError:
                    click.echo("Error: PyYAML required", err=True)
                    sys.exit(1)
            else:  # json
                arm_policies = [
                    p.to_arm_json() if hasattr(p, 'to_arm_json') else p
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
    help="Filter by category",
)
def list(category: Optional[str]):
    """List available policy templates."""
    try:
        from itl_policy_builder.templates.kyverno import (
            KYVERNO_CATEGORIES,
            list_kyverno_policies,
        )
        
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
    type=click.Choice(["kubernetes", "itl-api", "both"]),
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


if __name__ == "__main__":
    cli()
