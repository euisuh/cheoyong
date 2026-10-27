"""Claude Code PreToolUse hook: stdin event JSON -> exit 0 (allow) or 2 (deny).

Exit 2 blocks the tool call and Claude Code shows stderr to the model. Any
error (bad JSON, unreadable policy, policy exception) also exits 2: a hook that
exits 1 is a non-blocking error in Claude Code, which would fail open.
"""

from __future__ import annotations

import argparse
import json
import sys

from .engine import Cheoyong
from .types import Effect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cheoyong-hook")
    parser.add_argument("--policy", required=True, help="YAML or JSON policy file")
    args = parser.parse_args(argv)
    escalated = []
    try:
        event = json.load(sys.stdin)
        # Escalation is approved here only to hand the question to Claude
        # Code's own permission prompt via permissionDecision "ask" below.
        wall = Cheoyong.from_file(
            args.policy, escalate=lambda call, decision: escalated.append(decision) or True
        )
        tool_input = event["tool_input"]
        decision = wall.check(
            event["tool_name"],
            tool_input,
            {"session_id": event.get("session_id"), "cwd": event.get("cwd")},
        )
    except Exception as exc:  # noqa: BLE001 - every failure must block
        print(f"cheoyong: hook error, blocking: {exc!r}", file=sys.stderr)
        return 2
    if decision.effect is not Effect.ALLOW:
        print(f"cheoyong: denied by {decision.policy}: {decision.reason}", file=sys.stderr)
        return 2
    if decision.args != tool_input:
        # ponytail: exit codes cannot rewrite tool input, so redaction blocks.
        print(f"cheoyong: {decision.policy} rewrote the input; blocking", file=sys.stderr)
        return 2
    if escalated:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": f"cheoyong: {escalated[0].reason}",
                    }
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
