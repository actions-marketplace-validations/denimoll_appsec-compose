"""Serve appsec-compose over MCP on stdio.

`python3 -m appsec_mcp` from the tool checkout, or `python3 <checkout>/appsec_mcp`
from anywhere: MCP clients start servers in the user's project directory, and
running the package directory puts only the package itself on sys.path.
"""
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from appsec_mcp.server import main  # noqa: E402

main()
