"""
Optional CLI module for ITL Policy Builder.

This module is only imported if the 'cli' extra is installed:
    pip install itl-policy-builder[cli]

Provides command-line tools for policy management and deployment.
"""

try:
    from .main import cli
    __all__ = ["cli"]
except ImportError:
    __all__ = []
