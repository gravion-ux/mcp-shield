"""End-to-end CLI tests: exit codes, JSON output, pin/check workflow."""

import json

from mcp_shield.cli import main

RISKY_CONFIG = {
    "mcpServers": {
        "bad": {"command": "bash", "args": ["-c", "srv"],
                "env": {"TOKEN": "ghp_1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r"}}
    }
}
CLEAN_CONFIG = {
    "mcpServers": {
        "fs": {"command": "npx",
               "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0",
                        "/home/user/project"],
               "env": {"TOKEN": "${TOKEN}"}}
    }
}
CLEAN_TOOLS = [
    {"name": "summarize_text", "description": "Summarizes the given text.",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string", "maxLength": 500}},
                     "additionalProperties": False}},
]


def _write(tmp_path, name, obj):
    path = tmp_path / name
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def test_audit_risky_exits_1_and_reports(tmp_path, capsys):
    cfg = _write(tmp_path, "cfg.json", RISKY_CONFIG)
    code = main(["audit", "--config", cfg, "--format", "json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["risk_score"] > 0
    assert report["summary"]["critical"] >= 1
    assert any(f["check_id"] == "shell-command" for f in report["findings"])


def test_audit_clean_exits_0(tmp_path, capsys):
    cfg = _write(tmp_path, "cfg.json", CLEAN_CONFIG)
    tools = _write(tmp_path, "tools.json", CLEAN_TOOLS)
    code = main(["audit", "--config", cfg, "--tools", tools])
    assert code == 0
    assert "No findings" in capsys.readouterr().out


def test_audit_missing_file_exits_2(tmp_path):
    assert main(["audit", "--config", str(tmp_path / "nope.json")]) == 2


def test_audit_fail_on_threshold(tmp_path):
    # A lone low-severity finding passes with the default --fail-on=high
    # but fails with --fail-on=low.
    tools = _write(tmp_path, "tools.json", [
        {"name": "loose_tool", "description": "x",
         "inputSchema": {"type": "object",
                         "properties": {"t": {"type": "string"}},
                         "additionalProperties": True}},
    ])
    assert main(["audit", "--tools", tools]) == 0
    assert main(["audit", "--tools", tools, "--fail-on", "low"]) == 1


def test_pin_check_roundtrip_via_cli(tmp_path, capsys):
    tools = _write(tmp_path, "tools.json", CLEAN_TOOLS)
    baseline = str(tmp_path / "base.json")
    assert main(["pin", "--tools", tools, "--baseline", baseline]) == 0
    capsys.readouterr()
    assert main(["check", "--tools", tools, "--baseline", baseline]) == 0

    changed = [dict(CLEAN_TOOLS[0], description="Totally different description.")]
    tools2 = _write(tmp_path, "tools2.json", changed)
    assert main(["check", "--tools", tools2, "--baseline", baseline]) == 1
    out = capsys.readouterr().out
    assert "rugpull-description-changed" in out
