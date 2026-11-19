"""Loaders for MCP server config files and tool-definition files.

Config format (Claude Desktop / Cursor / VS Code style)::

    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
          "env": {"SOME_KEY": "value"}
        }
      }
    }

Tool definitions are a JSON list of objects (or an object with a "tools"
list), each shaped like::

    {"name": "read_file", "description": "...", "inputSchema": {...}}
"""

import json
from pathlib import Path


class LoadError(Exception):
    """Raised when an input file cannot be read or has an unexpected shape."""


def _read_json(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise LoadError("cannot read %s: %s" % (path, exc))
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoadError("invalid JSON in %s: %s" % (path, exc))


def load_config(path):
    """Return {server_name: server_config_dict} from an MCP config file."""
    data = _read_json(path)
    if not isinstance(data, dict):
        raise LoadError("%s: config root must be a JSON object" % (path,))
    servers = data.get("mcpServers")
    if servers is None:
        servers = data.get("servers")
    if servers is None and "command" in data:
        # A bare single-server object.
        servers = {"<unnamed>": data}
    if servers is None:
        servers = {}
    if not isinstance(servers, dict):
        raise LoadError("%s: 'mcpServers' must be a JSON object" % (path,))
    return {name: cfg for name, cfg in servers.items() if isinstance(cfg, dict)}


def load_tools(path):
    """Return a list of tool definition dicts from a tool-definition file."""
    data = _read_json(path)
    tools = None
    if isinstance(data, list):
        tools = data
    elif isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            tools = data["tools"]
        elif "name" in data:
            tools = [data]
    if tools is None:
        raise LoadError(
            "%s: expected a JSON list of tools or an object with a 'tools' list"
            % (path,)
        )
    return [t for t in tools if isinstance(t, dict)]
