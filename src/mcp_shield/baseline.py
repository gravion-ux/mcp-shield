"""Rug-pull detection: pin tool/server definitions to a baseline and diff.

A "rug pull" is when an MCP server you already approved silently changes its
tool descriptions or schemas (or its launch command) in an update, so the
tool the model sees today is not the tool you reviewed. `pin` records
SHA-256 fingerprints of every tool definition and server config; `check`
re-fingerprints the current files and reports every difference.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .loader import LoadError
from .models import Finding

BASELINE_FORMAT = "mcp-shield-baseline/1"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hash_obj(obj):
    return _hash_text(_canonical(obj))


def tool_fingerprints(tool):
    """Separate hashes so a diff can say *what* changed about a tool."""
    description = tool.get("description")
    schema = tool.get("inputSchema")
    return {
        "definition": _hash_obj(tool),
        "description": _hash_text(description if isinstance(description, str) else ""),
        "input_schema": _hash_obj(schema if isinstance(schema, dict) else {}),
    }


def build_baseline(tools, servers):
    return {
        "format": BASELINE_FORMAT,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {
            str(t.get("name", "<unnamed>")): tool_fingerprints(t) for t in tools
        },
        "servers": {
            name: {"definition": _hash_obj(cfg)} for name, cfg in sorted(servers.items())
        },
    }


def write_baseline(path, baseline):
    Path(path).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def load_baseline(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise LoadError("cannot read baseline %s: %s" % (path, exc))
    except json.JSONDecodeError as exc:
        raise LoadError("invalid JSON in baseline %s: %s" % (path, exc))
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT:
        raise LoadError("%s is not an mcp-shield baseline file" % (path,))
    for section in ("tools", "servers"):
        entries = data.get(section)
        if entries is None:
            continue
        if not isinstance(entries, dict) or not all(
            isinstance(v, dict) for v in entries.values()
        ):
            raise LoadError(
                "%s: baseline %r section must map names to objects"
                % (path, section)
            )
    return data


def diff_baseline(baseline, tools, servers):
    """Compare current tools/servers against a baseline; return findings."""
    findings = []
    base_tools = baseline.get("tools") or {}
    current_tools = {
        str(t.get("name", "<unnamed>")): tool_fingerprints(t) for t in tools
    }

    for name in sorted(current_tools):
        if name not in base_tools:
            findings.append(Finding(
                check_id="rugpull-tool-added",
                severity="medium",
                title="New tool appeared since baseline",
                location="tool '%s'" % name,
                detail=(
                    "Tool '%s' was not in the pinned baseline. New tools "
                    "expand what the model can do and should be reviewed "
                    "before use." % name
                ),
                remediation="Review the new tool, then re-run 'mcp-shield pin' to accept it into the baseline.",
            ))
    for name in sorted(base_tools):
        if name not in current_tools:
            findings.append(Finding(
                check_id="rugpull-tool-removed",
                severity="low",
                title="Tool disappeared since baseline",
                location="tool '%s'" % name,
                detail="Tool '%s' was in the pinned baseline but is gone now." % name,
                remediation="Confirm the removal is expected, then re-run 'mcp-shield pin' to update the baseline.",
            ))
    for name in sorted(set(base_tools) & set(current_tools)):
        before, now = base_tools[name], current_tools[name]
        if before.get("definition") == now.get("definition"):
            continue
        if before.get("description") != now.get("description"):
            findings.append(Finding(
                check_id="rugpull-description-changed",
                severity="high",
                title="Tool description changed since baseline (possible rug pull)",
                location="tool '%s'" % name,
                detail=(
                    "The description of '%s' differs from the pinned baseline "
                    "while the tool name stayed the same. Silent description "
                    "changes are the classic MCP rug-pull: the tool you "
                    "approved is no longer the tool being described to the "
                    "model." % name
                ),
                remediation=(
                    "Diff the new description against the reviewed one, look "
                    "for added instructions, and only re-pin once the change "
                    "is understood and trusted."
                ),
            ))
        elif before.get("input_schema") != now.get("input_schema"):
            findings.append(Finding(
                check_id="rugpull-schema-changed",
                severity="medium",
                title="Tool inputSchema changed since baseline",
                location="tool '%s'" % name,
                detail="The inputSchema of '%s' differs from the pinned baseline." % name,
                remediation="Review the schema change (new parameters widen the attack surface), then re-pin if it is expected.",
            ))
        else:
            findings.append(Finding(
                check_id="rugpull-definition-changed",
                severity="medium",
                title="Tool definition changed since baseline",
                location="tool '%s'" % name,
                detail="The definition of '%s' differs from the pinned baseline." % name,
                remediation="Review the change, then re-run 'mcp-shield pin' if it is expected.",
            ))

    base_servers = baseline.get("servers") or {}
    current_servers = {
        name: {"definition": _hash_obj(cfg)} for name, cfg in servers.items()
    }
    for name in sorted(current_servers):
        if name not in base_servers:
            findings.append(Finding(
                check_id="rugpull-server-added",
                severity="medium",
                title="New MCP server since baseline",
                location="server '%s'" % name,
                detail="Server '%s' was not in the pinned baseline." % name,
                remediation="Review the new server's command, args and env, then re-pin.",
            ))
        elif base_servers[name].get("definition") != current_servers[name].get("definition"):
            findings.append(Finding(
                check_id="rugpull-server-changed",
                severity="high",
                title="Server launch configuration changed since baseline",
                location="server '%s'" % name,
                detail=(
                    "The command/args/env of server '%s' differ from the "
                    "pinned baseline. Launch-configuration changes alter what "
                    "code actually executes." % name
                ),
                remediation="Review the command, args and env diff carefully before re-pinning the baseline.",
            ))
    for name in sorted(base_servers):
        if name not in current_servers:
            findings.append(Finding(
                check_id="rugpull-server-removed",
                severity="low",
                title="MCP server removed since baseline",
                location="server '%s'" % name,
                detail="Server '%s' was in the pinned baseline but is gone now." % name,
                remediation="Confirm the removal is expected, then re-run 'mcp-shield pin'.",
            ))
    return findings
