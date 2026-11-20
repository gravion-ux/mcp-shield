import json

import pytest

from mcp_shield.loader import LoadError, load_config, load_tools


def _write(tmp_path, name, obj):
    path = tmp_path / name
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def test_load_config_mcpservers(tmp_path):
    path = _write(tmp_path, "cfg.json", {
        "mcpServers": {
            "fs": {"command": "node", "args": ["server.js"], "env": {}}
        }
    })
    servers = load_config(path)
    assert list(servers) == ["fs"]
    assert servers["fs"]["command"] == "node"


def test_load_config_bare_server(tmp_path):
    path = _write(tmp_path, "cfg.json", {"command": "node", "args": []})
    servers = load_config(path)
    assert "<unnamed>" in servers


def test_load_tools_list_and_wrapped(tmp_path):
    tools = [{"name": "a"}, {"name": "b"}]
    assert load_tools(_write(tmp_path, "t1.json", tools)) == tools
    assert load_tools(_write(tmp_path, "t2.json", {"tools": tools})) == tools


def test_load_invalid_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(LoadError):
        load_config(str(path))


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(LoadError):
        load_tools(str(tmp_path / "nope.json"))


def test_load_config_rejects_non_object_server(tmp_path):
    path = _write(tmp_path, "cfg.json", {
        "mcpServers": {"good": {"command": "node"}, "bad": "oops-string"},
    })
    with pytest.raises(LoadError, match="server 'bad'"):
        load_config(path)


def test_load_tools_rejects_non_object_entry(tmp_path):
    path = _write(tmp_path, "tools.json", [{"name": "ok_tool"}, 42])
    with pytest.raises(LoadError, match="tool #1"):
        load_tools(path)


def test_load_config_tolerates_utf8_bom(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(
        {"mcpServers": {"fs": {"command": "node"}}}).encode("utf-8"))
    assert load_config(str(path)) == {"fs": {"command": "node"}}
