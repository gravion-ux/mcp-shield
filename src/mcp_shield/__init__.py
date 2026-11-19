"""mcp-shield: a defensive security auditor for MCP server configurations.

Audits MCP (Model Context Protocol) server configs and tool definitions for
overly broad permissions, leaked secrets, unpinned package execution, tool
description poisoning, tool-name shadowing, weak input schemas, and rug-pull
drift against a pinned baseline. Standard library only.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
