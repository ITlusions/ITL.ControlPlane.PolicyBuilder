"""
Policy Format Converter: YaRM ↔ ARM ↔ Bicep

Converts Azure Policy definitions between different formats:
- YAML ARM (YaRM) ↔ JSON ARM
- JSON ARM → Bicep (using `az bicep decompile`)
- Bicep → JSON ARM (using `az bicep build`)

Requirements:
    - PyYAML: pip install pyyaml
    - Azure CLI with Bicep: az bicep install

Usage:
    python convert_formats.py yaml-to-json input.yaml output.json
    python convert_formats.py json-to-yaml input.json output.yaml
    python convert_formats.py arm-to-bicep input.json output.bicep
    python convert_formats.py bicep-to-arm input.bicep output.json
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Union

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed. Install with: pip install pyyaml")


class ConversionError(Exception):
    """Raised when format conversion fails."""


def yaml_to_json(yaml_path: Union[str, Path], json_path: Union[str, Path]) -> None:
    """Convert YAML ARM template to JSON ARM template."""
    if not YAML_AVAILABLE:
        raise ConversionError("PyYAML required. Install with: pip install pyyaml")
    
    yaml_path = Path(yaml_path)
    json_path = Path(json_path)
    
    if not yaml_path.exists():
        raise FileNotFoundError(f"Input YAML file not found: {yaml_path}")
    
    # Load YAML
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    # Write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Converted {yaml_path.name} → {json_path.name}")


def json_to_yaml(json_path: Union[str, Path], yaml_path: Union[str, Path]) -> None:
    """Convert JSON ARM template to YAML ARM template."""
    if not YAML_AVAILABLE:
        raise ConversionError("PyYAML required. Install with: pip install pyyaml")
    
    json_path = Path(json_path)
    yaml_path = Path(yaml_path)
    
    if not json_path.exists():
        raise FileNotFoundError(f"Input JSON file not found: {json_path}")
    
    # Load JSON
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Write YAML
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    print(f"✅ Converted {json_path.name} → {yaml_path.name}")


def arm_to_bicep(arm_path: Union[str, Path], bicep_path: Union[str, Path]) -> None:
    """
    Convert ARM JSON template to Bicep using Azure CLI.
    
    Requires: az bicep install
    """
    arm_path = Path(arm_path)
    bicep_path = Path(bicep_path)
    
    if not arm_path.exists():
        raise FileNotFoundError(f"Input ARM file not found: {arm_path}")
    
    # Check if az bicep is available
    try:
        subprocess.run(
            ["az", "bicep", "version"],
            capture_output=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ConversionError(
            "Azure CLI with Bicep required. Install with:\n"
            "  az bicep install"
        )
    
    # Run decompile
    result = subprocess.run(
        ["az", "bicep", "decompile", "--file", str(arm_path)],
        capture_output=True,
        text=True,
    )
    
    if result.returncode != 0:
        raise ConversionError(
            f"Bicep decompilation failed for '{arm_path}':\n{result.stderr.strip()}"
        )
    
    # az bicep decompile creates <filename>.bicep in same directory
    generated_bicep = arm_path.with_suffix(".bicep")
    
    if generated_bicep.exists():
        # Move to desired output path
        if bicep_path != generated_bicep:
            generated_bicep.rename(bicep_path)
        print(f"✅ Converted {arm_path.name} → {bicep_path.name}")
    else:
        raise ConversionError("Bicep decompilation succeeded but output file not found")


def bicep_to_arm(bicep_path: Union[str, Path], arm_path: Union[str, Path]) -> None:
    """
    Convert Bicep template to ARM JSON using Azure CLI.
    
    Requires: az bicep install
    """
    bicep_path = Path(bicep_path)
    arm_path = Path(arm_path)
    
    if not bicep_path.exists():
        raise FileNotFoundError(f"Input Bicep file not found: {bicep_path}")
    
    # Check if az bicep is available
    try:
        subprocess.run(
            ["az", "bicep", "version"],
            capture_output=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ConversionError(
            "Azure CLI with Bicep required. Install with:\n"
            "  az bicep install"
        )
    
    # Run build
    result = subprocess.run(
        ["az", "bicep", "build", "--file", str(bicep_path), "--outfile", str(arm_path)],
        capture_output=True,
        text=True,
    )
    
    if result.returncode != 0:
        raise ConversionError(
            f"Bicep compilation failed for '{bicep_path}':\n{result.stderr.strip()}"
        )
    
    print(f"✅ Converted {bicep_path.name} → {arm_path.name}")


def convert_directory(
    input_dir: Union[str, Path],
    output_dir: Union[str, Path],
    conversion_func,
    input_ext: str,
    output_ext: str,
) -> None:
    """Batch convert all files in a directory."""
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    files = list(input_dir.glob(f"*{input_ext}"))
    if not files:
        print(f"⚠️  No {input_ext} files found in {input_dir}")
        return
    
    print(f"Converting {len(files)} files from {input_dir}...")
    for file in files:
        output_file = output_dir / file.name.replace(input_ext, output_ext)
        try:
            conversion_func(file, output_file)
        except Exception as e:
            print(f"❌ Failed to convert {file.name}: {e}")


def main():
    """CLI entry point."""
    if len(sys.argv) < 4:
        print(__doc__)
        print("\nExamples:")
        print("  python convert_formats.py yaml-to-json input.yaml output.json")
        print("  python convert_formats.py json-to-yaml input.json output.yaml")
        print("  python convert_formats.py arm-to-bicep input.json output.bicep")
        print("  python convert_formats.py bicep-to-arm input.bicep output.json")
        print("\nBatch conversion:")
        print("  python convert_formats.py yaml-to-json-dir yaml/ json/")
        sys.exit(1)
    
    command = sys.argv[1]
    input_path = sys.argv[2]
    output_path = sys.argv[3]
    
    try:
        if command == "yaml-to-json":
            yaml_to_json(input_path, output_path)
        elif command == "json-to-yaml":
            json_to_yaml(input_path, output_path)
        elif command == "arm-to-bicep":
            arm_to_bicep(input_path, output_path)
        elif command == "bicep-to-arm":
            bicep_to_arm(input_path, output_path)
        elif command == "yaml-to-json-dir":
            convert_directory(input_path, output_path, yaml_to_json, ".yaml", ".json")
        elif command == "json-to-yaml-dir":
            convert_directory(input_path, output_path, json_to_yaml, ".json", ".yaml")
        elif command == "arm-to-bicep-dir":
            convert_directory(input_path, output_path, arm_to_bicep, ".json", ".bicep")
        elif command == "bicep-to-arm-dir":
            convert_directory(input_path, output_path, bicep_to_arm, ".bicep", ".json")
        else:
            print(f"❌ Unknown command: {command}")
            print("Valid commands: yaml-to-json, json-to-yaml, arm-to-bicep, bicep-to-arm")
            print("Batch commands: yaml-to-json-dir, json-to-yaml-dir, arm-to-bicep-dir, bicep-to-arm-dir")
            sys.exit(1)
    
    except ConversionError as e:
        print(f"❌ Conversion failed: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
