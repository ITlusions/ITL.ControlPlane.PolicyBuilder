"""
Bicep-to-ARM-JSON compilation support for DINE policy templates.

DINE (DeployIfNotExists) policies require embedded ARM JSON for the remediation
deployment template. This module wraps the `az bicep build` CLI to compile
Bicep source (file or string) into the ARM JSON dict that the policy builder
expects.

Requirements:
    - Azure CLI with the Bicep extension installed:
      ``az bicep install``

Example::

    from itl_policy_builder.bicep import BicepCompiler

    arm_template = BicepCompiler.from_file("remediation.bicep")
    arm_template = BicepCompiler.from_string("resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = { ... }")
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Union


class BicepCompilationError(Exception):
    """Raised when Bicep compilation fails."""


class BicepCompiler:
    """
    Compiles Bicep source to ARM JSON.

    Uses ``az bicep build`` under the hood. Both a file path and an inline
    Bicep string are supported.
    """

    @staticmethod
    def from_file(bicep_path: Union[str, Path]) -> dict:
        """
        Compile a ``.bicep`` file and return the ARM JSON as a Python dict.

        Args:
            bicep_path: Path to the Bicep source file.

        Returns:
            Parsed ARM JSON template as a dict.

        Raises:
            BicepCompilationError: If ``az bicep build`` exits non-zero.
            FileNotFoundError: If ``bicep_path`` does not exist.
        """
        bicep_path = Path(bicep_path).resolve()
        if not bicep_path.exists():
            raise FileNotFoundError(f"Bicep file not found: {bicep_path}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = Path(tmp.name)

        try:
            result = subprocess.run(
                ["az", "bicep", "build", "--file", str(bicep_path), "--outfile", str(out_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise BicepCompilationError(
                    f"Bicep compilation failed for '{bicep_path}':\n{result.stderr.strip()}"
                )
            return json.loads(out_path.read_text(encoding="utf-8"))
        finally:
            out_path.unlink(missing_ok=True)

    @staticmethod
    def from_string(bicep_content: str) -> dict:
        """
        Compile an inline Bicep string and return the ARM JSON as a Python dict.

        A temporary ``.bicep`` file is written, compiled, and cleaned up.

        Args:
            bicep_content: Bicep source code as a string.

        Returns:
            Parsed ARM JSON template as a dict.

        Raises:
            BicepCompilationError: If ``az bicep build`` exits non-zero.
        """
        with tempfile.NamedTemporaryFile(
            suffix=".bicep", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            tmp.write(bicep_content)
            bicep_path = Path(tmp.name)

        try:
            return BicepCompiler.from_file(bicep_path)
        finally:
            bicep_path.unlink(missing_ok=True)
