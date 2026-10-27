import io
import json
from pathlib import Path

import pytest

from cheoyong.hook import main

POLICY = str(Path(__file__).parents[1] / "examples" / "claude-code" / "policy.yaml")


def run(monkeypatch, capsys, stdin: str, policy: str = POLICY):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(["--policy", policy])
    out = capsys.readouterr()
    return code, out.out, out.err


def event(tool, **tool_input):
    return json.dumps({"tool_name": tool, "tool_input": tool_input, "session_id": "s"})


def test_allowed_call_exits_zero_silently(monkeypatch, capsys) -> None:
    code, out, err = run(monkeypatch, capsys, event("Bash", command="git status"))
    assert (code, out, err) == (0, "", "")


@pytest.mark.parametrize(
    ("tool", "tool_input", "policy"),
    [
        ("Bash", {"command": "rm -rf /"}, "arg_rules:bash.command"),
        ("Bash", {"command": "ls", "dangerouslyDisableSandbox": True}, "arg_rules:bash.dangerouslydisablesandbox"),
        ("Write", {"file_path": "/home/you/src/../x", "content": ""}, "arg_rules:write.file_path"),
        ("WebFetch", {"url": "https://evil.example/", "prompt": ""}, "arg_rules:webfetch.url"),
        ("mcp__mail__send", {}, "default"),
    ],
)
def test_denied_call_exits_two_with_reason(monkeypatch, capsys, tool, tool_input, policy) -> None:
    code, out, err = run(monkeypatch, capsys, event(tool, **tool_input))
    assert code == 2
    assert out == ""
    assert f"denied by {policy}:" in err


def test_sensitive_tool_asks_claude_code_permission_prompt(monkeypatch, capsys) -> None:
    code, out, _ = run(monkeypatch, capsys, event("Task", prompt="x"))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.mark.parametrize(
    ("stdin", "policy"),
    [
        pytest.param("not json", POLICY, id="bad-json"),
        pytest.param('{"tool_name": "Bash"}', POLICY, id="missing-tool-input"),
        pytest.param(event("Bash", command="ls"), "/nonexistent.yaml", id="missing-policy"),
    ],
)
def test_errors_block_with_exit_two(monkeypatch, capsys, stdin, policy) -> None:
    code, _, err = run(monkeypatch, capsys, stdin, policy)
    assert code == 2
    assert "hook error, blocking" in err


def test_redaction_blocks_because_hook_cannot_rewrite_input(monkeypatch, capsys, tmp_path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\ndefault: allow\ntools:\n  '*':\n    args:\n"
        "      '*': {denies: SECRET, on_violation: redact}\n"
    )
    code, _, err = run(monkeypatch, capsys, event("Bash", command="echo SECRET"), str(policy))
    assert code == 2
    assert "rewrote the input" in err
